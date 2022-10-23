#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "core/sge.h"
#include "core/log.h"
#include "core/list.h"
#include "core/dict.h"
#include "core/buffer.h"
#include "task/task.h"
#include "utils/config.h"
#include "server/server.h"
#include "server/acceptor.h"
#include "server/connection.h"
#include "event/event_mgr.h"


static pthread_once_t INIT_CONNECTION_POOL = PTHREAD_ONCE_INIT;


struct sge_server {
    const char* host;
    int port;

    struct sge_acceptor* acceptor;
    struct sge_server_op* op;
};

static int sge_handle_new_connection(struct sge_event_mgr* mgr, struct sge_event_result* result);
static int sge_handle_new_message(struct sge_event_mgr* mgr, struct sge_event_result* result);
static int sge_handle_write_done(struct sge_event_mgr* mgr, struct sge_event_result* result);


static void
init_connection_pool() {
    sge_create_conn_res_pool(sge_get_connection_pool_size());
}

static int
sge_new_connection(struct sge_server* server, int fd, struct sockaddr* sockaddr, socklen_t socklen) {
    struct sge_socket* sock;
    struct sge_connection* conn;

    if (SGE_ERR == sge_get_connection(&conn)) {
        SGE_LOG_ERROR("get connection error.");
        return SGE_ERR;
    }
    sock = (struct sge_socket*)conn;

    sge_init_socket(sock, server, fd, sockaddr, socklen);
    sge_add_event(sock->sid, EVENT_TYPE_READABLE, EVENT_MODE_ASYNC, NULL, NULL, sge_handle_new_message);

    SGE_LOG_DEBUG("accept new connection fd(%d), sid(%ld)", fd, sock->sid);

    if (server->op->handle_new_connect) {
        server->op->handle_new_connect(sock->sid);
    }

    return SGE_OK;
}

static int
sge_handle_new_message(struct sge_event_mgr* mgr, struct sge_event_result* result) {
    struct sge_event* evt;
    struct sge_list* head, *iter;
    struct sge_event_io_result* ir;
    struct sge_socket* s;
    struct sge_server* srv;
    int err;
    char* p;

    evt = result->evt;
    if (SGE_ERR == sge_get_socket(evt->src_id, &s)) {
        err = SGE_ERR;
        SGE_LOG_ERROR("can't fount connection sid(%ld)", evt->src_id);
        goto RET;
    }

    srv = s->server;
    head = &result->result_list;
    SGE_LIST_FOREACH_START
    SGE_LIST_FOREACH_SAFE(iter, head) {
        ir = SGE_CONTAINER_OF(iter, struct sge_event_io_result, entry);

        // closed
        if (ir->ret == 0) {
            s->status = SGE_SOCKET_HALF_CLOSED;

            if (srv->op->handle_closed) {
                srv->op->handle_closed(s->sid);
            }
            goto NEXT;
        }

        sge_buffer_data(ir->buffer, &p);
        srv->op->handle_message(s->sid, p, ir->ret);

        sge_destroy_buffer(ir->buffer);
NEXT:
        SGE_LIST_REMOVE(&ir->entry);
        sge_free(ir);
    }
    SGE_LIST_FOREACH_END

    err = SGE_OK;

RET:
    if (EVENT_MGR_TYPE_IO_URING == sge_get_event_type()) {
        sge_del_event(evt->eid);
    }

    return err;
}

static int
sge_handle_write_done(struct sge_event_mgr* mgr, struct sge_event_result* result) {
    struct sge_socket* s;

    if (SGE_ERR == sge_get_socket(result->sid, &s)) {
        SGE_LOG_ERROR("can't found socket sid(%ld)", result->sid);
        return SGE_ERR;
    }

    if (s->server->op->handle_write_done) {
        s->server->op->handle_write_done(result->sid);
    }

    sge_destroy_event_result(result);

    return SGE_OK;
}

static int
sge_handle_new_connection(struct sge_event_mgr* mgr, struct sge_event_result* result) {
    struct sge_list* head, *iter;
    struct sge_event_acceptor_result* ar;
    struct sge_socket* s;
    struct sge_server* srv;
    struct sge_event* evt;
    int err;

    evt = result->evt;
    if (SGE_ERR == sge_get_socket(evt->src_id, &s)) {
        err = SGE_ERR;
        SGE_LOG_ERROR("can't fount acceptor sid(%ld)", evt->src_id);
        goto RET;
    }

    srv = s->server;
    head = &result->result_list;
    SGE_LIST_FOREACH_START
    SGE_LIST_FOREACH_SAFE(iter, head) {
        ar = SGE_CONTAINER_OF(iter, struct sge_event_acceptor_result, entry);
        sge_new_connection(srv, ar->fd, ar->sockaddr, ar->socklen);

        SGE_LIST_REMOVE(&ar->entry);
        sge_free(ar);
    }
    SGE_LIST_FOREACH_END

    err = SGE_OK;
RET:
    if (EVENT_MGR_TYPE_IO_URING == sge_get_event_type()) {
        sge_del_event(evt->eid);
    }

    return err;
}

struct sge_server* sge_create_server(const char* host, int port, struct sge_server_op* op) {
    struct sge_server* server;
    struct sge_socket* sock;
    struct sge_acceptor* acceptor;

    pthread_once(&INIT_CONNECTION_POOL, init_connection_pool);

    server = sge_malloc(sizeof(struct sge_server));
    server->host = host;
    server->port = port;
    server->op = op;
    acceptor = sge_create_acceptor(host, port);
    if (NULL == acceptor) {
        goto RET;
    }
    sock = (struct sge_socket*)acceptor;
    sock->server = server;
    server->acceptor = acceptor;
    sge_add_event(sock->sid, EVENT_TYPE_ACCEPTABLE, EVENT_MODE_ASYNC, NULL, NULL, sge_handle_new_connection);

    return server;

RET:
    sge_free(server);
    exit(-1);
}

int sge_close_connection(socket_id sid) {
    struct sge_socket* sock;

    if (SGE_ERR == sge_get_socket(sid, &sock)) {
        SGE_LOG_WARN("can't found socket sid(%ld)", sid);
        return SGE_OK;
    }

    SGE_LOG_DEBUG("connection was closed. fd(%d), sid(%ld)", sock->fd, sid);

    sge_release_connection((struct sge_connection*)sock);
    return sge_unregister_socket(sock);
}

int sge_send_message(socket_id sid, char* p, int len) {
    int ret, remain_len;
    struct sge_socket* s;
    struct sge_buffer* buffer;

    if (SGE_ERR == sge_get_socket(sid, &s)) {
        SGE_LOG_ERROR("can't found socket sid(%ld)", sid);
        return SGE_ERR;
    }

    ret = write(s->fd, p, len);
    if (ret == len) {
        if (s->server->op->handle_write_done) {
            s->server->op->handle_write_done(sid);
        }
        return SGE_OK;
    }

    if (ret < 0) {
        remain_len = len;
    } else {
        remain_len = len - ret;
    }

    buffer = sge_create_buffer(remain_len);
    buffer = sge_append_buffer(buffer, p + ret, remain_len);

    sge_add_event(sid, EVENT_TYPE_WRITEABLE, EVENT_MODE_SYNC, buffer, NULL, sge_handle_write_done);

    return SGE_OK;
}
