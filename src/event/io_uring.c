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

struct io_arg {
    enum sge_event_type event_type;
    struct sge_event* evt;
    struct sge_event_buff* evt_buff;
};

static size_t io_arg_size__(void) {
    return sizeof(struct io_arg);
}

static struct sge_res_pool_ops io_arg_pool_ops = {
    .size = io_arg_size__
};
static struct sge_res_pool* io_arg_pool;

static int init_pool__(void) {
    return sge_alloc_res_pool(&io_arg_pool_ops, 1024, &io_arg_pool);
}

static void destroy_pool__(void) {
    sge_destroy_res_pool(io_arg_pool);
}

static int handle_accept__(struct sge_event_mgr* mgr, struct io_arg* arg, int ret) {
    struct sge_event* evt, new_evt;
    struct sge_event_buff* buff;
    fn_event_cb cb;

    evt = arg->evt;
    buff = arg->evt_buff;

    cb = evt->cb;
    buff->ret = ret;
    buff->arg = evt->arg;

    sge_copy_event(evt, &new_evt);
    new_evt.event_type = EVENT_TYPE_ACCEPTABLE;
    sge_add_event(mgr, &new_evt);

    cb(buff);

    sge_release_resource(arg);

    return SGE_OK;
}

static int handle_read__(struct sge_event_mgr* mgr, struct io_arg* arg, int ret) {
    struct sge_event_buff* buff;
    struct sge_event* evt, new_evt;
    fn_event_cb cb;

    evt = arg->evt;
    buff = arg->evt_buff;

    SGE_LOG(SGE_LOG_LEVEL_DEBUG, "handle read fd(%d), sid(%ld), ret(%d)", evt->fd, evt->custom_id, ret);
    if (0 != ret) {
        sge_copy_event(evt, &new_evt);
        SGE_LOG(SGE_LOG_LEVEL_DEBUG, "new_evt fd(%d), sid(%ld)", new_evt.fd, new_evt.custom_id);
        new_evt.event_type = EVENT_TYPE_READABLE;
        sge_add_event(mgr, &new_evt);
    }

    cb = evt->cb;
    buff->ret = ret;

    // close by peer
    if (0 == buff->ret) {
        sge_destroy_string(buff->buf);
        buff->buf = NULL;
    } else {
        sge_set_string_len(buff->buf, ret);
    }

    cb(buff);

    sge_release_resource(arg);

    return SGE_OK;
}

static int handle_write__(struct sge_event_mgr* mgr, struct io_arg* arg, int ret) {
    struct sge_event_buff* evt_buff;
    struct sge_event* evt, new_evt;
    struct sge_string* buf;

    evt = arg->evt;
    evt_buff = arg->evt_buff;
    buf = evt_buff->buf;

    if (SGE_OK != sge_sock_msg_empty(evt->custom_id)) {
        sge_copy_event(evt, &new_evt);
        new_evt.event_type = EVENT_TYPE_WRITEABLE;
        sge_add_event(mgr, &new_evt);
    } else {
        evt_buff->buf = NULL;
        evt->write_cb(evt_buff);
    }

    sge_destroy_string(buf);
    sge_release_event_buff(evt_buff);
    sge_release_resource(arg);

    return SGE_OK;
}

static int prep_accept__(struct io_uring_mgr* io_mgr, struct sge_event* evt) {
    struct io_arg* arg;
    struct io_uring_sqe* sqe;

    sqe = io_uring_get_sqe(&io_mgr->ring);
    if (NULL == sqe) {
        SGE_LOG(SGE_LOG_LEVEL_ERROR, "get io_uring sqe error.");
        return SGE_ERR;
    }

    sge_get_resource(io_arg_pool, (void**)&arg);
    sge_alloc_event_buff(&arg->evt_buff);
    arg->evt = evt;
    arg->evt_buff->arg = evt->arg;
    arg->evt_buff->buf = NULL;
    arg->event_type = EVENT_TYPE_ACCEPTABLE;

    io_uring_prep_accept(sqe, evt->fd, NULL, NULL, 0);
    io_uring_sqe_set_data(sqe, arg);

    return SGE_OK;
}

static int prep_read__(struct io_uring_mgr* io_mgr, struct sge_event* evt) {
    const char* data;
    struct io_arg* arg;
    struct io_uring_sqe* sqe;

    sqe = io_uring_get_sqe(&io_mgr->ring);
    if (NULL == sqe) {
        SGE_LOG(SGE_LOG_LEVEL_ERROR, "get io_uring sqe error.");
        return SGE_ERR;
    }

    sge_get_resource(io_arg_pool, (void**)&arg);
    sge_alloc_event_buff(&arg->evt_buff);
    arg->evt = evt;
    arg->event_type = EVENT_TYPE_READABLE;
    arg->evt_buff->arg = evt->arg;
    sge_alloc_string(SGE_STRING_SIZE, &arg->evt_buff->buf);
    sge_string_data(arg->evt_buff->buf, &data);
    io_uring_prep_read(sqe, evt->fd, (void*)data, SGE_STRING_SIZE, 0);
    io_uring_sqe_set_data(sqe, arg);

    return SGE_OK;
}

static int prep_write__(struct io_uring_mgr* io_mgr, struct sge_event* evt) {
    size_t msglen;
    const char* data;
    struct io_arg* arg;
    struct io_uring_sqe* sqe;
    struct sge_msg_chain* chain;

    sge_get_first_msg_by_sid(evt->custom_id, &chain);
    if (NULL == chain) {
        return SGE_OK;
    }

    sqe = io_uring_get_sqe(&io_mgr->ring);
    if (NULL == sqe) {
        SGE_LOG(SGE_LOG_LEVEL_ERROR, "get io_uring sqe error.");
        return SGE_ERR;
    }

    sge_get_resource(io_arg_pool, (void**)&arg);
    sge_alloc_event_buff(&arg->evt_buff);
    arg->event_type = EVENT_TYPE_WRITEABLE;
    arg->evt = evt;
    arg->evt_buff->arg = evt->arg;

    msglen = sge_string_data(chain->msg, &data);
    sge_dup_string(&arg->evt_buff->buf, data, msglen);
    sge_string_data(arg->evt_buff->buf, &data);
    io_uring_prep_write(sqe, evt->fd, data, msglen, 0);
    io_uring_sqe_set_data(sqe, arg);

    sge_destroy_string(chain->msg);
    sge_destroy_msg_chain(chain);

    return SGE_OK;
}

static int io_uring_init__(struct sge_event_mgr* mgr) {
    int ret;
    struct io_uring_mgr* io_mgr;

    ret = init_pool__();
    if (SGE_ERR == ret) {
        return SGE_ERR;
    }

    io_mgr = sge_malloc(sizeof(struct io_uring_mgr));
    ret = io_uring_queue_init(1024, &io_mgr->ring, 0);
    if (ret < 0) {
        SGE_LOG(SGE_LOG_LEVEL_SYS_ERROR, "init io_uring error. reason(%s)", strerror(errno));
        destroy_pool__();
        return SGE_ERR;
    }

    io_mgr->fd = ret;
    mgr->private_data = io_mgr;
    return SGE_OK;
}

static int io_uring_add__(struct sge_event_mgr* mgr, struct sge_event* new_evt, enum sge_event_type old_event_type) {
    struct io_uring_sqe* sqe;
    struct io_uring_mgr* io_mgr;
    struct sge_msg_chain* chain;
    struct sge_event_buff* evt_buff, *buff;
    const char* data;
    size_t msglen;

    SGE_LOG(SGE_LOG_LEVEL_DEBUG, "new_evt(%x) fd(%d), sid(%ld), old_event_type(%d)", new_evt, new_evt->fd, new_evt->custom_id, old_event_type);

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
    int ret;
    struct io_arg* arg;
    struct io_uring_cqe *cqe;
    struct __kernel_timespec timespec = {
        .tv_nsec = 100000000,
        .tv_sec = 0
    };
    struct io_uring_mgr* io_mgr = (struct io_uring_mgr*)mgr->private_data;

    io_uring_wait_cqe_timeout(&io_mgr->ring, &cqe, &timespec);
    if (NULL == cqe) {
        return SGE_OK;
    }

    ret = cqe->res;
    arg = io_uring_cqe_get_data(cqe);

    io_uring_cqe_seen(&io_mgr->ring, cqe);
    if (arg->event_type & EVENT_TYPE_ACCEPTABLE) {
        handle_accept__(mgr, arg, ret);
    }
    if (arg->event_type & EVENT_TYPE_READABLE) {
        handle_read__(mgr, arg, ret);
    }
    if (arg->event_type & EVENT_TYPE_WRITEABLE) {
        handle_write__(mgr, arg, ret);
    }

    return 1;
}

static int epoll_destroy__(struct sge_event_mgr* mgr) {
    struct io_uring_mgr* io_mgr;

    io_mgr = (struct io_uring_mgr*)mgr->private_data;
    io_uring_queue_exit(&io_mgr->ring);
    close(io_mgr->fd);
    sge_free(io_mgr);

    destroy_pool__();

    return SGE_OK;
}

static struct sge_event_mgr_ops io_uring_event_ops = {
    .add = io_uring_add__,
    .del = io_uring_del__,
    .poll = io_uring_poll__,
    .init = io_uring_init__,
    .destroy = epoll_destroy__
};

struct sge_event_mgr io_uring_event_mgr = {
    .type_name = "IO_URING",
    .ops = &io_uring_event_ops
};
