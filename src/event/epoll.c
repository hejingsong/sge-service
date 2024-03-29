#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <string.h>

#include "core/sge.h"
#include "core/log.h"
#include "core/string.h"
#include "core/event.h"
#include "core/server.h"


static int convert_fd__(void* p) {
    return (int)(unsigned long)p;
}

static int set_nonblock__(int fd) {
    int flags = 0;

    flags = fcntl(fd, F_GETFL);
    if (flags & O_NONBLOCK) {
        return SGE_OK;
    }

    flags |= O_NONBLOCK;
    fcntl(fd, F_SETFL, flags);

    return SGE_OK;
}

static struct sge_message* create_message__(unsigned long cid, enum sge_msg_type type, ssize_t ret, void* ud) {
    struct sge_message* msg = NULL;

    sge_alloc_message(&msg);
    msg->custom_id = cid;
    msg->msg = NULL;
    msg->msg_type = type;
    msg->ret = ret;
    msg->ud = ud;

    return msg;
}

static int handle_accept__(struct sge_event* evt) {
    int fd = 0;
    struct sockaddr_in addr;
    socklen_t socklen = 0;
    struct sge_list dummy;
    struct sge_message* msg = NULL;

    SGE_LIST_INIT(&dummy);
    while(1) {
        fd = accept(evt->fd, (struct sockaddr*)&addr, &socklen);
        if (fd < 0) {
            if (EAGAIN == errno) {
                break;
            }
            if (EINTR == errno) {
                continue;
            }
            SGE_LOG(SGE_LOG_LEVEL_SYS_ERROR, "accept error. reason(%s) fd(%d)", strerror(errno), evt->fd);
            break;
        }
        sge_alloc_message(&msg);
        msg->custom_id = 0;
        msg->msg = NULL;
        msg->msg_type = SGE_MSG_TYPE_NEW_CONN;
        msg->ret = fd;
        msg->ud = evt->arg;
        SGE_LIST_ADD_TAIL(&dummy, &msg->entry);
    }

    if (!SGE_LIST_EMPTY(&dummy)) {
        evt->cb(&dummy);
    }

    return SGE_OK;
}

static int do_handle_read__(struct sge_event* evt) {
    ssize_t ret = 0, offset = 0;
    char data[SGE_STRING_SIZE];
    unsigned char closed = 0;
    struct sge_list dummy;
    struct sge_message* msg = NULL;

    offset = 0;
    SGE_LIST_INIT(&dummy);
    while(1) {
        ret = read(evt->fd, data + offset, SGE_STRING_SIZE - offset);
        if (ret < 0) {
            if (EAGAIN == errno) {
                break;
            }
            if (EINTR == errno) {
                continue;
            }
            SGE_LOG(SGE_LOG_LEVEL_SYS_ERROR, "read socket error. fd(%d) cid(%ld) errno(%d) reason(%s)", evt->fd, evt->custom_id, errno, strerror(errno));
            msg = create_message__(evt->custom_id, SGE_MSG_TYPE_CLOSED, ret, evt->arg);
            SGE_LIST_ADD_TAIL(&dummy, &msg->entry);
            break;
        }

        // peer closed
        if (ret == 0) {
            closed = 1;
            break;
        }

        offset += ret;
        if (offset == SGE_STRING_SIZE) {
            msg = create_message__(evt->custom_id, SGE_MSG_TYPE_NEW_MSG, offset, evt->arg);
            sge_dup_string(&msg->msg, data, offset);
            SGE_LIST_ADD_TAIL(&dummy, &msg->entry);
            offset = 0;
        }
    }

    if (offset > 0) {
        msg = create_message__(evt->custom_id, SGE_MSG_TYPE_NEW_MSG, offset, evt->arg);
        sge_dup_string(&msg->msg, data, offset);
        SGE_LIST_ADD_TAIL(&dummy, &msg->entry);
    }

    if (closed) {
        msg = create_message__(evt->custom_id, SGE_MSG_TYPE_CLOSED, ret, evt->arg);
        SGE_LIST_ADD_TAIL(&dummy, &msg->entry);
    }

    if (!SGE_LIST_EMPTY(&dummy)) {
        evt->cb(&dummy);
    }

    return SGE_OK;
}

static int handle_read__(struct sge_event* evt) {
    if (evt->event_type & EVENT_TYPE_ACCEPTABLE) {
        return handle_accept__(evt);
    }
    
    if (evt->event_type & EVENT_TYPE_READABLE) {
        return do_handle_read__(evt);
    }

    SGE_LOG(SGE_LOG_LEVEL_ERROR, "unknown error type. fd(%d), cid(%ld), event_type(%d)", evt->fd, evt->custom_id, evt->event_type);
    return SGE_ERR;
}

static int handle_write__(struct sge_event* evt) {
    ssize_t ret = 0;
    const char* data = NULL;
    size_t nwrite = 0, datalen = 0, total = 0;
    struct sge_socket* sock = NULL;
    struct sge_message* msg = NULL;
    struct sge_list msg_list;
    struct sge_list* iter = NULL, *next = NULL;

    total = 0;
    SGE_LIST_INIT(&msg_list);

    sock = (struct sge_socket*)evt->arg;
    if (SGE_ERR == sge_get_sock_msg(sock, &msg_list)) {
        goto done;
    }

    SGE_LIST_FOREACH_SAFE(iter, next, &msg_list) {
        msg = sge_container_of(iter, struct sge_message, entry);
        datalen = sge_string_data(msg->msg, &data);

        nwrite = 0;
        while(nwrite < datalen) {
            ret = write(evt->fd, data + nwrite, SGE_STRING_SIZE);
            if (ret < 0) {
                if (EAGAIN == errno) {
                    usleep(100000);
                }
                if (EINTR == errno) {
                    continue;
                }
                SGE_LOG(SGE_LOG_LEVEL_SYS_ERROR, "write socket error. fd(%d) cid(%ld), reason(%s)", evt->fd, evt->custom_id, strerror(errno));
                goto done;
            }
            nwrite += ret;
            total += ret;
        }

        SGE_LIST_REMOVE(iter);
        sge_destroy_string(msg->msg);
        sge_destroy_message(msg);
    }

done:
    SGE_LIST_INIT(&msg_list);
    sge_alloc_message(&msg);
    msg->custom_id = evt->custom_id;
    msg->ud = evt->arg;
    msg->ret = total;
    msg->msg = NULL;
    msg->msg_type = SGE_MSG_TYPE_WRITE_DONE;
    SGE_LIST_ADD_TAIL(&msg_list, &msg->entry);
    evt->write_cb(&msg_list);

    return SGE_OK;
}

static uint32_t calc_events__(int types) {
    uint32_t event = 0;

    if (types & EVENT_TYPE_READABLE || types & EVENT_TYPE_ACCEPTABLE) {
        event |= EPOLLIN | EPOLLET;
    }

    if (types & EVENT_TYPE_WRITEABLE) {
        event |= EPOLLOUT | EPOLLET;
    }

    return event;
}


static int epoll_init__(struct sge_event_mgr* mgr) {
    int fd = 0;

    fd = epoll_create(1024);
    if (fd < 0) {
        goto error;
    }

    mgr->private_data = (void*)(unsigned long)fd;
    return SGE_OK;
error:
    SGE_LOG(SGE_LOG_LEVEL_SYS_ERROR, "create epoll error. reason(%s)", strerror(errno));
    return SGE_ERR;
}

static int epoll_add__(struct sge_event_mgr* mgr, struct sge_event* new_evt, enum sge_event_type old_event_type) {
    int fd = 0, ret = 0, op = 0;
    enum sge_event_type event_type;
    struct epoll_event event;

    if (old_event_type && old_event_type == new_evt->event_type) {
        return SGE_OK;
    }

    event_type = old_event_type;
    event_type |= new_evt->event_type;
    event.events = calc_events__(event_type);
    event.data.ptr = new_evt;

    set_nonblock__(new_evt->fd);
    fd = convert_fd__(mgr->private_data);
    if (old_event_type) {
        op = EPOLL_CTL_MOD;
    } else {
        op = EPOLL_CTL_ADD;
    }
    ret = epoll_ctl(fd, op, new_evt->fd, &event);

    if (0 != ret) {
        SGE_LOG(SGE_LOG_LEVEL_SYS_ERROR, "epoll_ctl op(%d) fd(%d) error. reason(%s)", op, new_evt->fd, strerror(errno));
        return SGE_ERR;
    }
    return SGE_OK;
}

static int epoll_del__(struct sge_event* evt, struct sge_event* req_evt) {
    int fd = 0, ret = 0, op = 0;
    uint32_t epoll_event = 0;
    enum sge_event_type event_type;
    struct epoll_event event;

    event_type = evt->event_type & (~req_evt->event_type);
    epoll_event = calc_events__(event_type);
    event.events = epoll_event;
    event.data.ptr = evt;

    fd = convert_fd__(evt->event_mgr->private_data);
    if (0 == epoll_event) {
        op = EPOLL_CTL_DEL;
    } else {
        op = EPOLL_CTL_MOD;
    }
    ret = epoll_ctl(fd, op, evt->fd, &event);

    if (0 != ret) {
        SGE_LOG(SGE_LOG_LEVEL_SYS_ERROR, "epoll_ctl op(%d) fd(%d) error. reason(%s)", op, evt->fd, strerror(errno));
        return SGE_ERR;
    }

    return (0 == epoll_event) ? SGE_OK : 1;
}

static int epoll_poll__(struct sge_event_mgr* mgr) {
    int fd = 0, i = 0, ret = 0;
    struct epoll_event* event = NULL;
    struct epoll_event events[1024];

    fd = convert_fd__(mgr->private_data);
    ret = epoll_wait(fd, events, 1024, -1);
    if (ret < 0) {
        if (EAGAIN == errno) {
            return SGE_OK;
        }
        if (EINTR == errno) {
            return SGE_OK;
        }
        SGE_LOG(SGE_LOG_LEVEL_SYS_ERROR, "epoll wait error. reason(%s)", strerror(errno));
        return SGE_ERR;
    }

    for (i = 0; i < ret; ++i) {
        event = &events[i];
        if (event->events & EPOLLIN) {
            handle_read__(event->data.ptr);
        }

        if (event->events & EPOLLOUT) {
            handle_write__(event->data.ptr);
        }
    }

    return ret;
}

static int epoll_destroy__(struct sge_event_mgr* mgr) {
    int fd = 0;

    if (mgr->private_data) {
        fd = (int)(unsigned long)mgr->private_data;
        close(fd);
    }

    return SGE_OK;
}

static struct sge_event_mgr_ops epoll_event_ops = {
    .add = epoll_add__,
    .del = epoll_del__,
    .poll = epoll_poll__,
    .init = epoll_init__,
    .destroy = epoll_destroy__
};

static struct sge_event_mgr epoll_event_mgr = {
    .type_name = "EPOLL",
    .ops = &epoll_event_ops
};

__attribute__((constructor)) static void __init__(void) {
    sge_register_event_mgr(&epoll_event_mgr);
}
