#include <errno.h>
#include <unistd.h>
#include <string.h>

#include "core/sge.h"
#include "core/log.h"
#include "core/event.h"
#include "core/server.h"
#include "core/res_pool.h"

#include "include/liburing.h"

struct io_uring_mgr {
    int fd;
    struct io_uring ring;
};

static int handle_accept__(struct sge_event_mgr* mgr, struct sge_message* msg, int ret) {
    struct sge_list dummy;
    struct sge_event* evt = NULL, new_evt;
    fn_event_cb cb = NULL;

    evt = (struct sge_event*)msg->ud;
    cb = evt->cb;

    msg->ret = ret;
    msg->ud = evt->arg;
    msg->msg = NULL;

    sge_copy_event(evt, &new_evt);
    new_evt.event_type = EVENT_TYPE_ACCEPTABLE;
    sge_add_event(mgr, &new_evt);

    SGE_LIST_INIT(&dummy);
    SGE_LIST_ADD_TAIL(&dummy, &msg->entry);
    cb(&dummy);

    return SGE_OK;
}

static int handle_read__(struct sge_event_mgr* mgr, struct sge_message* msg, int ret) {
    fn_event_cb cb = NULL;
    struct sge_list dummy;
    struct sge_event* evt = NULL, new_evt;

    evt = (struct sge_event*)msg->ud;
    cb = evt->cb;

    if (ret > 0) {
        sge_copy_event(evt, &new_evt);
        new_evt.event_type = EVENT_TYPE_READABLE;
        sge_add_event(mgr, &new_evt);
    }

    // close by peer
    if (ret <= 0) {
        sge_destroy_string(msg->msg);
        msg->msg = NULL;
        msg->msg_type = SGE_MSG_TYPE_CLOSED;
        if (ret < 0) {
            SGE_LOG(SGE_LOG_LEVEL_SYS_ERROR, "read socket error. fd(%d) cid(%ld) errno(%d) reason(%s)", evt->fd, evt->custom_id, -ret, strerror(-ret));
        }
    } else {
        sge_set_string_len(msg->msg, ret);
        msg->msg_type = SGE_MSG_TYPE_NEW_MSG;
    }

    msg->ud = evt->arg;
    msg->ret = ret;
    msg->custom_id = evt->custom_id;
    SGE_LIST_INIT(&dummy);
    SGE_LIST_ADD_TAIL(&dummy, &msg->entry);
    cb(&dummy);

    return SGE_OK;
}

static int handle_write__(struct sge_event_mgr* mgr, struct sge_message* msg, int ret) {
    const char* p = NULL;
    fn_event_cb cb = NULL;
    struct sge_event* evt = NULL;
    struct sge_message* ret_msg = NULL;
    struct sge_list dummy;

    sge_unused(mgr);
    sge_unused(ret);
    sge_unused(p);

    evt = (struct sge_event*)msg->ud;
    cb = evt->write_cb;

    sge_alloc_message(&ret_msg);
    ret_msg->custom_id = evt->custom_id;
    ret_msg->ud = evt->arg;
    ret_msg->ret = sge_string_data(msg->msg, &p);
    ret_msg->msg = NULL;
    ret_msg->msg_type = SGE_MSG_TYPE_WRITE_DONE;

    SGE_LIST_INIT(&dummy);
    SGE_LIST_ADD_TAIL(&dummy, &ret_msg->entry);

    cb(&dummy);

    sge_destroy_string(msg->msg);
    sge_destroy_message(msg);
    return SGE_OK;
}

static int prep_accept__(struct io_uring_mgr* io_mgr, struct sge_event* evt) {
    struct sge_message* msg = NULL;
    struct io_uring_sqe* sqe = NULL;

    sqe = io_uring_get_sqe(&io_mgr->ring);
    if (NULL == sqe) {
        SGE_LOG(SGE_LOG_LEVEL_ERROR, "get io_uring sqe error.");
        return SGE_ERR;
    }

    sge_alloc_message(&msg);
    msg->ud = evt;
    msg->msg_type = SGE_MSG_TYPE_NEW_CONN;

    io_uring_prep_accept(sqe, evt->fd, NULL, NULL, 0);
    io_uring_sqe_set_data(sqe, msg);

    return SGE_OK;
}

static int prep_read__(struct io_uring_mgr* io_mgr, struct sge_event* evt) {
    const char* data = NULL;
    struct sge_message* msg = NULL;
    struct io_uring_sqe* sqe = NULL;

    sqe = io_uring_get_sqe(&io_mgr->ring);
    if (NULL == sqe) {
        SGE_LOG(SGE_LOG_LEVEL_ERROR, "get io_uring sqe error.");
        return SGE_ERR;
    }

    sge_alloc_message(&msg);
    msg->msg_type = SGE_MSG_TYPE_NEW_MSG;
    msg->custom_id = evt->custom_id;
    msg->ud = evt;
    sge_alloc_string(SGE_STRING_SIZE, &msg->msg);
    sge_string_data(msg->msg, &data);
    io_uring_prep_read(sqe, evt->fd, (void*)data, SGE_STRING_SIZE, 0);
    io_uring_sqe_set_data(sqe, msg);

    return SGE_OK;
}

static int prep_write__(struct io_uring_mgr* io_mgr, struct sge_event* evt) {
    size_t msglen = 0;
    const char* data = NULL;
    struct io_uring_sqe* sqe = NULL;
    struct sge_list* iter = NULL, *next = NULL;
    struct sge_socket* sock = NULL;
    struct sge_message* msg = NULL;
    struct sge_list head;

    if (SGE_ERR == sge_get_socket(evt->custom_id, &sock)) {
        return SGE_ERR;
    }

    sge_get_sock_msg(sock, &head);
    if (SGE_LIST_EMPTY(&head)) {
        return SGE_OK;
    }

    SGE_LIST_FOREACH_SAFE(iter, next, &head) {
        msg = sge_container_of(iter, struct sge_message, entry);
        msg->ud = evt;
        sqe = io_uring_get_sqe(&io_mgr->ring);
        if (NULL == sqe) {
            SGE_LOG(SGE_LOG_LEVEL_WARN, "no enough submit item in io_uring.");
            return SGE_OK;
        }

        msglen = sge_string_data(msg->msg, &data);
        io_uring_prep_write(sqe, evt->fd, data, msglen, 0);
        io_uring_sqe_set_data(sqe, msg);

        SGE_LIST_REMOVE(&msg->entry);
    }

    return SGE_OK;
}

static int io_uring_init__(struct sge_event_mgr* mgr) {
    int ret = 0;
    struct io_uring_mgr* io_mgr = NULL;

    io_mgr = sge_malloc(sizeof(struct io_uring_mgr));
    ret = io_uring_queue_init(1024, &io_mgr->ring, 0);
    if (ret < 0) {
        SGE_LOG(SGE_LOG_LEVEL_SYS_ERROR, "init io_uring error. reason(%s)", strerror(errno));
        return SGE_ERR;
    }

    io_mgr->fd = ret;
    mgr->private_data = io_mgr;
    return SGE_OK;
}

static int io_uring_add__(struct sge_event_mgr* mgr, struct sge_event* new_evt, enum sge_event_type old_event_type) {
    struct io_uring_mgr* io_mgr = NULL;

    sge_unused(old_event_type);

    io_mgr = (struct io_uring_mgr*)mgr->private_data;
    if (new_evt->event_type & EVENT_TYPE_ACCEPTABLE) {
        prep_accept__(io_mgr, new_evt);
    }
    if (new_evt->event_type & EVENT_TYPE_READABLE) {
        prep_read__(io_mgr, new_evt);
    }
    if (new_evt->event_type & EVENT_TYPE_WRITEABLE) {
        prep_write__(io_mgr, new_evt);
    }

    io_uring_submit(&io_mgr->ring);
    return SGE_OK;
}

static int io_uring_del__(struct sge_event* evt, struct sge_event* req_evt) {
    enum sge_event_type event_type;

    event_type = evt->event_type & ~(req_evt->event_type);
    if (0 == event_type) {
        return SGE_OK;
    } else {
        return 1;
    }
}

static int io_uring_poll__(struct sge_event_mgr* mgr) {
    int ret = 0;
    struct sge_message* msg = NULL;
    struct io_uring_cqe *cqe = NULL;
    struct io_uring_mgr* io_mgr = (struct io_uring_mgr*)mgr->private_data;

    io_uring_wait_cqe_timeout(&io_mgr->ring, &cqe, NULL);
    if (NULL == cqe) {
        return SGE_OK;
    }

    ret = cqe->res;
    msg = io_uring_cqe_get_data(cqe);

    io_uring_cqe_seen(&io_mgr->ring, cqe);
    if (msg->msg_type & SGE_MSG_TYPE_NEW_CONN) {
        handle_accept__(mgr, msg, ret);
    }
    if (msg->msg_type & SGE_MSG_TYPE_NEW_MSG) {
        handle_read__(mgr, msg, ret);
    }
    if (msg->msg_type & SGE_MSG_TYPE_WRITE_DONE) {
        handle_write__(mgr, msg, ret);
    }

    return 1;
}

static int io_uring_destroy__(struct sge_event_mgr* mgr) {
    struct io_uring_mgr* io_mgr = (struct io_uring_mgr*)mgr->private_data;

    io_uring_queue_exit(&io_mgr->ring);
    close(io_mgr->fd);
    sge_free(io_mgr);

    return SGE_OK;
}

static struct sge_event_mgr_ops io_uring_event_ops = {
    .add = io_uring_add__,
    .del = io_uring_del__,
    .poll = io_uring_poll__,
    .init = io_uring_init__,
    .destroy = io_uring_destroy__
};

static struct sge_event_mgr io_uring_event_mgr = {
    .type_name = "IO_URING",
    .ops = &io_uring_event_ops
};

__attribute__((constructor)) static void __init__(void) {
    sge_register_event_mgr(&io_uring_event_mgr);
}
