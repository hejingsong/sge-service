#include <errno.h>
#include <unistd.h>
#include <assert.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>

#include "core/sge.h"
#include "core/log.h"
#include "core/list.h"
#include "core/dict.h"
#include "core/buffer.h"
#include "event/event_pool.h"
#include "event/event_mgr.h"

struct sge_epoll_event {
    socket_id sid;
    uint32_t events;
    unsigned long eids[2];
    struct sge_list entry;
};

struct sge_epoll_mgr {
    int fd;
    struct sge_dict* fd_ht;
    struct sge_list fd_list;
};

static struct sge_epoll_event*
sge_get_epoll_event(struct sge_epoll_mgr* mgr, socket_id sid) {
    void* d;

    d = sge_get_dict(mgr->fd_ht, (void*)sid, 0);
    return (struct sge_epoll_event*)d;
}

static struct sge_epoll_event*
sge_create_epoll_event(struct sge_epoll_mgr* mgr, socket_id sid) {
    struct sge_epoll_event* e;

    e = sge_malloc(sizeof(*e));
    e->sid = sid;
    e->events = 0;
    SGE_LIST_INIT(&e->entry);

    sge_insert_dict(mgr->fd_ht, (void*)sid, 0, e);
    SGE_LIST_ADD_TAIL(&mgr->fd_list, &e->entry);

    return e;
}

static uint32_t
sge_calc_events(int event_type) {
    uint32_t c = 0;

    if (EVENT_TYPE_ACCEPTABLE & event_type) {
        c |= EPOLLIN;
    }

    if (EVENT_TYPE_READABLE & event_type) {
        c |= EPOLLIN;
    }

    if (EVENT_TYPE_WRITEABLE & event_type) {
        c |= EPOLLOUT;
    }

    c |= EPOLLET;

    return c;
}

static int
on_acceptable(struct sge_event_mgr* mgr, struct sge_event* evt) {
    int ret;
    struct sockaddr_in sockaddr;
    socklen_t socklen;
    struct sge_socket* s;
    struct sge_event_result* result;
    struct sge_event_acceptor_result* r;

    if (SGE_ERR == sge_get_socket(evt->src_id, &s)) {
        SGE_LOG_ERROR("can't found socket sid(%ld)", evt->src_id);
        return SGE_ERR;
    }

    result = sge_create_event_result(evt, s->sid, s->fd);
    while(1) {
        ret = accept(s->fd, (struct sockaddr*)&sockaddr, &socklen);
        if (ret < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN) {
                break;
            }
            SGE_LOG_SYS_ERROR("accept error.");
            break;
        }

        r = sge_malloc(sizeof(*r));
        r->fd = ret;
        r->socklen = socklen;
        r->sockaddr = sge_malloc(sizeof(struct sockaddr_in));
        memcpy(r->sockaddr, &sockaddr, socklen);
        SGE_LIST_INIT(&r->entry);

        SGE_LIST_ADD_TAIL(&result->result_list, &r->entry);
    }

    return sge_exec_event(result);
}

static int
on_readable(struct sge_event_mgr* mgr, struct sge_event* evt) {
    int ret;
    int nread;
    int error;
    int closed;
    char buf[1024];
    struct sge_socket* s;
    struct sge_buffer* buffer;
    struct sge_event_result* result;
    struct sge_event_io_result* r;

    if (SGE_ERR == sge_get_socket(evt->src_id, &s)) {
        SGE_LOG_ERROR("can't found socket sid(%ld)", evt->src_id);
        return SGE_ERR;
    }

    result = sge_create_event_result(evt, s->sid, s->fd);
    buffer = sge_create_buffer(1024);
    nread = closed = error = 0;
    while(1) {
        ret = read(s->fd, buf, 1024);
        if (ret < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN) {
                break;
            }
            SGE_LOG_SYS_ERROR("read error. sid(%ld) fd(%d)", evt->src_id, s->fd);
            error = 1;
            break;
        }

        if (ret == 0) {
            closed = 1;
            break;
        }

        sge_append_buffer(buffer, buf, ret);
        nread += ret;

        if (ret < 1024) {
            break;
        }
    }

    if (nread > 0) {
        r = sge_malloc(sizeof(*r));
        r->buffer = buffer;
        r->ret = nread;
        SGE_LIST_INIT(&r->entry);
        SGE_LIST_ADD_TAIL(&result->result_list, &r->entry);
    } else {
        sge_destroy_buffer(buffer);
    }

    if (closed == 1) {
        sge_del_event(evt->eid);
        shutdown(s->fd, SHUT_RD);

        r = sge_malloc(sizeof(*r));
        r->ret = 0;
        r->buffer = NULL;
        SGE_LIST_INIT(&r->entry);
        SGE_LIST_ADD_TAIL(&result->result_list, &r->entry);
    }

    if (nread > 0 || closed == 1) {
        sge_exec_event(result);
    } else {
        sge_destroy_event_result(result);
    }

    return error ? SGE_ERR : SGE_OK;
}

static int
on_writeable(struct sge_event_mgr* mgr, struct sge_event* evt) {
    int ret;
    int nwrite;
    int offset;
    int error;
    char* p;
    struct sge_socket* s;
    struct sge_event_result* result;

    if (NULL == evt->arg) {
        sge_del_event(evt->eid);
        return SGE_ERR;
    }

    if (SGE_ERR == sge_get_socket(evt->src_id, &s)) {
        SGE_LOG_ERROR("can't found socket sid(%ld)", evt->src_id);
        return SGE_ERR;
    }

    offset = error = 0;
    nwrite = sge_buffer_data((struct sge_buffer*)evt->arg, &p);
    while(offset < nwrite) {
        ret = write(s->fd, p + offset, 1024);
        if (ret < 0) {
            if (errno == EAGAIN || errno == EINTR) {
                continue;
            }
            SGE_LOG_SYS_ERROR("write error. sid(%ld), fd(%d)", evt->src_id, s->fd);
            error = 1;
            break;
        }

        offset += ret;
    }

    sge_destroy_buffer((struct sge_buffer*)evt->arg);
    evt->arg = NULL;

    if (evt->complete_cb) {
        result = sge_create_event_result(evt, s->sid, s->fd);
        sge_exec_event(result);
    }

    return SGE_OK;
}


static int
sge_epoll_init(struct sge_event_mgr* mgr) {
    int ret;
    struct sge_epoll_mgr* e_mgr;

    e_mgr = sge_malloc(sizeof(*e_mgr));
    SGE_LIST_INIT(&e_mgr->fd_list);
    e_mgr->fd_ht = sge_create_dict(integer_hash_fn, integer_compare_fn);
    assert(e_mgr->fd_ht != NULL);

    ret = epoll_create(1024);
    if (ret < 0) {
        SGE_LOG_SYS_ERROR("create epoll error.");
        return SGE_ERR;
    }

    e_mgr->fd = ret;
    mgr->private_data = e_mgr;
    return SGE_OK;

ERR:
    sge_destroy_dict(e_mgr->fd_ht);
    sge_free(e_mgr);
}

static int
sge_epoll_add(struct sge_event_mgr* mgr, struct sge_event* event) {
    int ret;
    int old_events, events;
    struct epoll_event e_event;
    struct sge_epoll_mgr* e_mgr;
    struct sge_epoll_event* e;
    struct sge_socket* s;

    if (SGE_ERR == sge_get_socket(event->src_id, &s)) {
        SGE_LOG_ERROR("can't found socket sid(%ld)", event->src_id);
        return SGE_ERR;
    }

    e_mgr = (struct sge_epoll_mgr*)mgr->private_data;
    e = sge_get_epoll_event(e_mgr, event->src_id);
    if (!e) {
        e = sge_create_epoll_event(e_mgr, event->src_id);
    }

    sge_insert_dict(e_mgr->fd_ht, (void*)event->src_id, 0, e);
    events = old_events = e->events;
    events |= sge_calc_events(event->evt_type);

    e->events = e_event.events = events;
    e_event.data.u64 = event->src_id;

    if (old_events == 0) {
        ret = epoll_ctl(e_mgr->fd, EPOLL_CTL_ADD, s->fd, &e_event);
    } else {
        ret = epoll_ctl(e_mgr->fd, EPOLL_CTL_MOD, s->fd, &e_event);
    }

    if (ret < 0) {
        SGE_LOG_SYS_ERROR("sge_epoll_add epoll_ctl failed, fd(%d), events(%04x)", s->fd, e_event.events);
        sge_free(e);
        return SGE_ERR;
    }

    if (event->evt_type == EVENT_TYPE_ACCEPTABLE || event->evt_type == EVENT_TYPE_READABLE) {
        e->eids[0] = event->eid;
    } else if (event->evt_type == EVENT_TYPE_WRITEABLE) {
        e->eids[1] = event->eid;
    }

    return SGE_OK;
}

static int
sge_epoll_del(struct sge_event_mgr* mgr, unsigned long eid) {
    int ret;
    uint32_t old_events, new_events, events;
    struct epoll_event e_event;
    struct sge_epoll_mgr* e_mgr;
    struct sge_epoll_event* e;
    struct sge_socket* s;
    struct sge_event* evt;

    if (SGE_ERR == sge_find_event(eid, &evt)) {
        SGE_LOG_ERROR("can't found event object eid(%ld)", eid);
        return SGE_ERR;
    }

    e_mgr = (struct sge_epoll_mgr*)mgr->private_data;
    e = sge_get_epoll_event(e_mgr, evt->src_id);
    if (NULL == e) {
        SGE_LOG_ERROR("can't found event id(%ld)", evt->src_id);
        return SGE_ERR;
    }

    if (SGE_ERR == sge_get_socket(evt->src_id, &s)) {
        SGE_LOG_ERROR("can't found socket sid(%ld)", evt->src_id);
        return SGE_ERR;
    }

    old_events = e->events;
    events = sge_calc_events(evt->evt_type);
    new_events = old_events & ~events;
    e_event.data.u64 = evt->src_id;
    e->events = e_event.events = new_events;

    if (new_events == 0) {
        ret = epoll_ctl(e_mgr->fd, EPOLL_CTL_DEL, s->fd, NULL);
    } else {
        ret = epoll_ctl(e_mgr->fd, EPOLL_CTL_MOD, s->fd, &e_event);
    }

    if (ret < 0) {
        SGE_LOG_SYS_ERROR("sge_epoll_del epoll_ctl failed");
    }

    if (events == 0) {
        sge_remove_dict(e_mgr->fd_ht, (void*)evt->src_id, 0);
        SGE_LIST_REMOVE(&e->entry);
        sge_free(e);
    } else {
        e->events = events;
        if (evt->evt_type == EVENT_TYPE_ACCEPTABLE || evt->evt_type == EVENT_TYPE_READABLE) {
            e->eids[0] = 0;
        } else if (evt->evt_type == EVENT_TYPE_WRITEABLE) {
            e->eids[1] = 0;
        }
    }

    return SGE_OK;
}

static int
sge_epoll_destroy(struct sge_event_mgr* mgr) {
    struct sge_epoll_mgr* e_mgr;
    struct sge_epoll_event* e;
    struct sge_list* head, *iter;

    e_mgr = (struct sge_epoll_mgr*)mgr->private_data;
    head = &e_mgr->fd_list;

    SGE_LIST_FOREACH_START
    SGE_LIST_FOREACH_SAFE(iter, head) {
        e = SGE_CONTAINER_OF(iter, struct sge_epoll_event, entry);
        sge_free(e);
    }
    SGE_LIST_FOREACH_END

    close(e_mgr->fd);
    sge_destroy_dict(e_mgr->fd_ht);
    sge_free(e_mgr);

    return SGE_OK;
}

static int
sge_epoll_dispatch(struct sge_event_mgr* mgr) {
    int i, ret;
    unsigned long sid, eid;
    struct epoll_event* e_evt;
    struct epoll_event events[1024];
    struct sge_epoll_mgr* e_mgr;
    struct sge_epoll_event* epoll_evt;
    struct sge_event* evt;

    e_mgr = (struct sge_epoll_mgr*)mgr->private_data;

    ret = epoll_wait(e_mgr->fd, events, 1024, 100);
    if (ret < 0) {
        if (errno == EINTR || errno == EAGAIN) {
            return SGE_ERR;
        }
    }

    for (i = 0; i < ret; ++i) {
        e_evt = &events[i];
        sid = e_evt->data.u64;
        epoll_evt = sge_get_epoll_event(e_mgr, sid);
        if (NULL == epoll_evt) {
            SGE_LOG_DEBUG("can't found epoll event sid(%ld)", sid);
            continue;
        }

        if (e_evt->events & EPOLLIN) {
            sge_find_event(epoll_evt->eids[0], &evt);
            if (NULL == evt) {
                continue;
            }

            if (evt->evt_type == EVENT_TYPE_ACCEPTABLE) {
                on_acceptable(mgr, evt);
            } else {
                on_readable(mgr, evt);
            }
        }

        if (e_evt->events & EPOLLOUT) {
            sge_find_event(epoll_evt->eids[1], &evt);
            if (NULL == evt) {
                continue;
            }
            on_writeable(mgr, evt);
        }
    }
}


struct sge_event_op EVENT_MGR_API = {
    .init = sge_epoll_init,
    .add = sge_epoll_add,
    .del = sge_epoll_del,
    .destroy = sge_epoll_destroy,
    .dispatch = sge_epoll_dispatch
};
