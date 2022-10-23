#include <unistd.h>
#include <netinet/in.h>

#include "core/sge.h"
#include "core/log.h"
#include "core/list.h"
#include "core/buffer.h"
#include "event/event_mgr.h"
#include "include/liburing.h"


struct sge_io_uring_event_mgr {
    int fd;
    struct io_uring ring;
};


static int
on_accept_done(struct sge_event_mgr* mgr, struct sge_event_result* result, struct io_uring_cqe* cqe) {
    struct sge_event* evt;
    struct sge_list* iter, *head;
    struct sge_event_result* r;
    struct sge_event_acceptor_result* ar;

    evt = result->evt;
    if (cqe->res < 0) {
        SGE_LOG_SYS_ERROR("accept error fd(%d) sid(%ld).", cqe->res, evt->src_id);
        goto ERR;
    }

    head = &result->result_list;
    SGE_LIST_FOREACH_START
    SGE_LIST_FOREACH(iter, head) {
        ar = SGE_CONTAINER_OF(iter, struct sge_event_acceptor_result, entry);
        ar->fd = cqe->res;
    }
    SGE_LIST_FOREACH_END

    sge_exec_event(result);
    goto RET;

ERR:
    head = &result->result_list;
    SGE_LIST_FOREACH_START
    SGE_LIST_FOREACH_SAFE(iter, head) {
        ar = SGE_CONTAINER_OF(iter, struct sge_event_acceptor_result, entry);
        sge_free(ar->sockaddr);
        SGE_LIST_REMOVE(&ar->entry);
        sge_free(ar);
    }
    SGE_LIST_FOREACH_END
RET:
    sge_add_event(evt->src_id, evt->evt_type, evt->mode, evt->arg, evt->complete_arg, evt->complete_cb);
    return SGE_OK;
}

static int
on_read_done(struct sge_event_mgr* mgr, struct sge_event_result* result, struct io_uring_cqe* cqe) {
    struct sge_event* evt;
    struct sge_list* iter, *head;
    struct sge_event_result* r;
    struct sge_event_io_result* ir;

    evt = result->evt;
    if (cqe->res < 0) {
        goto ERR;
    }

    head = &result->result_list;
    SGE_LIST_FOREACH_START
    SGE_LIST_FOREACH(iter, head) {
        ir = SGE_CONTAINER_OF(iter, struct sge_event_io_result, entry);
        ir->ret = cqe->res;
    }
    SGE_LIST_FOREACH_END

    if (cqe->res > 0) {
        sge_add_event(evt->src_id, evt->evt_type, evt->mode, evt->arg, evt->complete_arg, evt->complete_cb);
    } else {
        shutdown(result->fd, SHUT_RD);
    }
    return sge_exec_event(result);

ERR:
    head = &result->result_list;
    SGE_LIST_FOREACH_START
    SGE_LIST_FOREACH(iter, head) {
        ir = SGE_CONTAINER_OF(iter, struct sge_event_io_result, entry);
        SGE_LIST_REMOVE(&ir->entry);
        sge_free(ir);
    }
    SGE_LIST_FOREACH_END

    sge_add_event(evt->src_id, evt->evt_type, evt->mode, evt->arg, evt->complete_arg, evt->complete_cb);
    sge_del_event(evt->eid);
    return SGE_OK;
}

static int
on_write_done(struct sge_event_mgr* mgr, struct sge_event_result* result, struct io_uring_cqe* cqe) {
    struct sge_event* evt;
    struct sge_list* iter, *head;
    struct sge_event_result* r;
    struct sge_event_io_result* ir;

    evt = result->evt;
    if (!evt->complete_arg) {
        goto RET;
    }

    sge_exec_event(result);

RET:
    sge_destroy_buffer((struct sge_buffer*)evt->arg);
    sge_del_event(evt->eid);
    return SGE_OK;
}

static int
sge_add_accept_event(struct io_uring_sqe* sqe, struct sge_socket* s, struct sge_event* evt) {
    struct sge_event_result* result;
    struct sge_event_acceptor_result* ar;

    result = sge_create_event_result(evt, s->sid, s->fd);
    ar = sge_malloc(sizeof(struct sge_event_acceptor_result));
    ar->socklen = sizeof(struct sockaddr_in);
    ar->sockaddr = sge_malloc(ar->socklen);
    SGE_LIST_INIT(&ar->entry);
    SGE_LIST_ADD_TAIL(&result->result_list, &ar->entry);

    io_uring_prep_accept(sqe, s->fd, ar->sockaddr, &ar->socklen, 0);
    io_uring_sqe_set_data(sqe, result);
    return SGE_OK;
}

static int
sge_add_read_event(struct io_uring_sqe* sqe, struct sge_socket* s, struct sge_event* evt) {
    struct sge_event_result* result;
    struct sge_event_io_result* ir;
    char* p;

    result = sge_create_event_result(evt, s->sid, s->fd);
    ir = sge_malloc(sizeof(struct sge_event_io_result));
    SGE_LIST_INIT(&ir->entry);
    SGE_LIST_ADD_TAIL(&result->result_list, &ir->entry);

    ir->buffer = sge_create_buffer(1024);
    sge_buffer_data(ir->buffer, &p);
    io_uring_prep_read(sqe, s->fd, p, 1024, 0);
    io_uring_sqe_set_data(sqe, result);

    return SGE_OK;
}

static int
sge_add_write_event(struct io_uring_sqe* sqe, struct sge_socket* s, struct sge_event* evt) {
    struct sge_event_result* result;
    struct sge_buffer* buffer = (struct sge_buffer*)evt->arg;
    int len;
    char* p;

    result = sge_create_event_result(evt, s->sid, s->fd);

    len = sge_buffer_data(buffer, &p);
    io_uring_prep_write(sqe, s->fd, p, len, 0);
    io_uring_sqe_set_data(sqe, result);

    return SGE_OK;
}

static int
sge_io_uring_init(struct sge_event_mgr* mgr) {
    int ret;
    struct sge_io_uring_event_mgr* io_uring_mgr;

    io_uring_mgr = sge_malloc(sizeof(*io_uring_mgr));
    ret = io_uring_queue_init(1024, &io_uring_mgr->ring, 0);
    if (ret < 0) {
        SGE_LOG_SYS_ERROR("init io_uring error.");
        return SGE_ERR;
    }

    io_uring_mgr->fd = ret;
    mgr->private_data = io_uring_mgr;
    return SGE_OK;
}

static int
sge_io_uring_add(struct sge_event_mgr* mgr, struct sge_event* evt) {
    struct sge_socket* s;
    struct io_uring_sqe* sqe;
    struct sge_io_uring_event_mgr* io_uring_mgr;

    if (SGE_ERR == sge_get_socket(evt->src_id, &s)) {
        SGE_LOG_DEBUG("can't found socket object sid(%ld)", evt->src_id);
        return SGE_ERR;
    }

    if (SGE_OK != sge_socket_available(s)) {
        SGE_LOG_DEBUG("socket unavailable sid(%ld)", evt->src_id);
        return SGE_ERR;
    }

    io_uring_mgr = (struct sge_io_uring_event_mgr*)mgr->private_data;
    sqe = io_uring_get_sqe(&io_uring_mgr->ring);
    if (NULL == sqe) {
        SGE_LOG_DEBUG("io_uring get seq failed.");
        return SGE_ERR;
    }

    if (EVENT_TYPE_ACCEPTABLE == evt->evt_type) {
        sge_add_accept_event(sqe, s, evt);
    } else if (EVENT_TYPE_READABLE == evt->evt_type) {
        sge_add_read_event(sqe, s, evt);
    } else if (EVENT_TYPE_WRITEABLE == evt->evt_type) {
        sge_add_write_event(sqe, s, evt);
    }

    return SGE_OK;
}

static int
sge_io_uring_del(struct sge_event_mgr* mgr, unsigned long eid) {
    return SGE_OK;
}

static int
sge_io_uring_destroy(struct sge_event_mgr* mgr) {
    struct sge_io_uring_event_mgr* io_uring_mgr;

    io_uring_mgr = (struct sge_io_uring_event_mgr*)mgr->private_data;

    io_uring_queue_exit(&io_uring_mgr->ring);
    close(io_uring_mgr->fd);
    sge_free(io_uring_mgr);
    return SGE_OK;
}

static int
sge_io_uring_dispatch(struct sge_event_mgr* mgr) {
    struct io_uring_cqe *cqe;
    struct sge_event_result* result;
    struct __kernel_timespec timespec = {
        .tv_nsec = 100000000,
        .tv_sec = 0
    };
    struct sge_io_uring_event_mgr* io_uring_mgr = (struct sge_io_uring_event_mgr*)mgr->private_data;

    io_uring_wait_cqe_timeout(&io_uring_mgr->ring, &cqe, &timespec);
    if (NULL == cqe) {
        return SGE_OK;
    }

    result = io_uring_cqe_get_data(cqe);

    io_uring_cqe_seen(&io_uring_mgr->ring, cqe);
    if (result->evt->evt_type == EVENT_TYPE_ACCEPTABLE) {
        on_accept_done(mgr, result, cqe);
    } else if (result->evt->evt_type == EVENT_TYPE_READABLE) {
        on_read_done(mgr, result, cqe);
    } else if (result->evt->evt_type == EVENT_TYPE_WRITEABLE) {
        on_write_done(mgr, result, cqe);
    }

    return SGE_OK;
}


struct sge_event_op EVENT_MGR_API = {
    .add = sge_io_uring_add,
    .del = sge_io_uring_del,
    .destroy = sge_io_uring_destroy,
    .dispatch = sge_io_uring_dispatch,
    .init = sge_io_uring_init
};
