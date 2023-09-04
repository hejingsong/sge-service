#include <errno.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>


#include <stdio.h>
#include <string.h>

#include "core/sge.h"
#include "core/log.h"
#include "core/dict.h"
#include "core/task.h"
#include "core/server.h"
#include "core/spinlock.h"
#include "core/res_pool.h"


extern struct sge_dict_ops integer_dict_ops;
static struct sge_socket_mgr* g_socket_mgr;

struct sge_socket_mgr {
    atomic_ulong socket_id;
    struct sge_spinlock lock;
    struct sge_dict* ht_sock;
};

struct sge_socket_addr {
    struct sockaddr_in sockaddr;
    socklen_t socklen;
};

static size_t socket_size__(void) {
    return sizeof(struct sge_socket);
}

static size_t msg_chain_size__(void) {
    return sizeof(struct sge_msg_chain);
}

static struct sge_res_pool* socket_res_pool;
static struct sge_res_pool_ops socket_res_pool_ops = {
    .size = socket_size__
};
static struct sge_res_pool* msg_chain_res_pool;
static struct sge_res_pool_ops msg_chain_res_pool_ops = {
    .size = msg_chain_size__
};

static unsigned long alloc_sid__(struct sge_socket_mgr* mgr) {
    return atomic_fetch_add_explicit(&mgr->socket_id, 1, memory_order_relaxed);
}

static int task_cb__(void* data) {
    int ret;
    struct sge_module* module;
    const char* module_name;

    module = (struct sge_module*)data;
    ret = sge_handle_module(module);
    if (SGE_OK != ret) {
        sge_string_data(module->name, &module_name);
        SGE_LOG(SGE_LOG_LEVEL_ERROR, "module(%s) exec handle error. ret(%d)", module_name, ret);
    }

    return ret;
}

static struct sge_msg_chain* alloc_msg_chain__(struct sge_string* str, enum sge_msg_type msg_type, unsigned long cid) {
    struct sge_msg_chain* chain;

    sge_get_resource(msg_chain_res_pool, (void**)&chain);

    chain->custom_id = cid;
    chain->msg = str;
    chain->msg_type = msg_type;
    SGE_LIST_INIT(&chain->list);

    return chain;
}

static int append_msg__(struct sge_socket* sock, struct sge_msg_chain* chain) {
    if (NULL == sock || NULL == chain) {
        return SGE_ERR;
    }

    SGE_SPINLOCK_LOCK(&sock->lock);
    SGE_LIST_ADD_TAIL(&sock->msg_list, &chain->list);
    SGE_SPINLOCK_UNLOCK(&sock->lock);

    return SGE_OK;
}

static int notify_module__(struct sge_module* module) {
    int status;

    // Make sure only one thread handles module messages
    status = atomic_load_explicit(&module->handle_status, memory_order_acquire);
    if (status == 0) {
        sge_delivery_task(task_cb__, module, SGE_TASK_NORMAL);
    }

    return SGE_OK;
}

static int handle_write_done__(struct sge_event_buff* event_buff) {
    struct sge_socket* sock;

    sock = (struct sge_socket*)event_buff->arg;
    if (NULL == sock) {
        goto ret;
    }

    sge_del_event(sock->srv->event_mgr, sock->sid, EVENT_TYPE_WRITEABLE);
ret:
    sge_release_event_buff(event_buff);
    return SGE_OK;
}

static int handle_new_msg__(struct sge_event_buff* event_buff) {
    int ret;
    struct sge_string* str;
    struct sge_socket* conn;
    struct sge_msg_chain* chain;
    struct sge_module* module;
    enum sge_msg_type msg_type;

    conn = (struct sge_socket*)event_buff->arg;
    str = event_buff->buf;
    module = conn->srv->module;

    if (NULL == str) {
        // peer closed.
        shutdown(conn->fd, SHUT_RD);
        ret = sge_del_event(conn->srv->event_mgr, conn->sid, EVENT_TYPE_READABLE);
        if (SGE_ERR == ret) {
            SGE_LOG(SGE_LOG_LEVEL_ERROR, "del event error. fd(%d), sid(%ld)", conn->fd, conn->sid);
        }
        conn->status = SGE_SOCKET_PEER_CLOSED;
        msg_type = SGE_MSG_TYPE_CLOSED;
    } else {
        msg_type = SGE_MSG_TYPE_NEW_MSG;
    }

    chain = alloc_msg_chain__(str, msg_type, conn->sid);
    sge_add_module_msg(module, &chain->list);
    notify_module__(module);

    sge_release_event_buff(event_buff);
    return SGE_OK;
}

static int handle_new_conn__(struct sge_event_buff* event_buff) {
    int fd, ret;
    struct sge_server* server;
    struct sge_socket* conn;
    struct sge_module* module;
    struct sge_event conn_evt;
    struct sge_msg_chain* chain;

    server = (struct sge_server*)event_buff->arg;
    module = server->module;
    fd = event_buff->ret;
    ret = sge_alloc_socket(fd, &conn);
    if (SGE_ERR == ret) {
        SGE_LOG(SGE_LOG_LEVEL_ERROR, "accept new conn error. fd(%d).", fd);
        goto error;
    }
    conn->srv = server;

    SGE_LOG(SGE_LOG_LEVEL_DEBUG, "new conn fd(%d), sid(%ld)", fd, conn->sid);

    conn_evt.arg = conn;
    conn_evt.custom_id = conn->sid;
    conn_evt.event_type = EVENT_TYPE_READABLE;
    conn_evt.fd = conn->fd;
    conn_evt.cb = handle_new_msg__;
    conn_evt.write_cb = NULL;
    ret = sge_add_event(server->event_mgr, &conn_evt);
    if (SGE_ERR == ret) {
        sge_destroy_socket(conn);
        goto error;
    }

    chain = alloc_msg_chain__(NULL, SGE_MSG_TYPE_NEW_CONN, conn->sid);
    sge_add_module_msg(module, &chain->list);
    notify_module__(module);

    return SGE_OK;
error:
    sge_release_event_buff(event_buff);
    return SGE_ERR;
}

static int create_port_listener__(const char* addr, const char* port, struct sge_socket** sockp) {
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    struct sge_socket_addr sockaddr;
    int sfd, s;
    int retcode = SGE_OK;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    s = getaddrinfo(addr, port, &hints, &result);
    if (s != 0) {
        SGE_LOG(SGE_LOG_LEVEL_SYS_ERROR, "getaddrinfo error. try again. reason(%d)", s);
        return SGE_ERR;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sfd == -1)
            continue;

        if (bind(sfd, rp->ai_addr, rp->ai_addrlen) == 0) {
            break;
        }
        SGE_LOG(SGE_LOG_LEVEL_SYS_ERROR, "bind error. reason(%s)", strerror(errno));
        close(sfd);
    }

    if (NULL == rp) {
        retcode = SGE_ERR;
        goto RET;
    }

    retcode = listen(sfd, 512);
    if (retcode < 0) {
        close(sfd);
        SGE_LOG(SGE_LOG_LEVEL_SYS_ERROR, "listen error. reason(%s)", strerror(errno));
        retcode = SGE_ERR;
        goto RET;
    }

    memcpy(&sockaddr.sockaddr, rp->ai_addr, rp->ai_addrlen);
    sockaddr.socklen = rp->ai_addrlen;
    retcode = sge_alloc_socket(sfd, sockp);
RET:
    freeaddrinfo(result);
    return retcode;
}

int sge_init_server_pool(size_t size) {
    int ret;
    ret = sge_alloc_res_pool(&socket_res_pool_ops, size, &socket_res_pool);
    if (SGE_OK == ret) {
        ret = sge_alloc_res_pool(&msg_chain_res_pool_ops, size, &msg_chain_res_pool);
    }
    return ret;
}

void sge_destroy_server_pool(void) {
    sge_destroy_res_pool(socket_res_pool);
    sge_destroy_res_pool(msg_chain_res_pool);
}

int sge_alloc_server(struct sge_module* module, struct sge_server** srvp) {
    struct sge_server* srv;

    srv = sge_malloc(sizeof(struct sge_server));
    srv->listener = NULL;
    srv->event_mgr = NULL;
    srv->module = module;
    sge_alloc_dict(&integer_dict_ops, &srv->ht_conn);

    *srvp = srv;

    return SGE_OK;
}

int sge_destroy_server(struct sge_server* srv) {
    if (NULL == srv) {
        return SGE_ERR;
    }

    sge_destroy_dict(srv->ht_conn);
    sge_destroy_socket(srv->listener);
    sge_free(srv);

    return SGE_OK;
}

int sge_init_socket_mgr(void) {
    struct sge_socket_mgr* mgr;

    mgr = sge_calloc(sizeof(struct sge_socket_mgr));
    sge_alloc_dict(&integer_dict_ops, &mgr->ht_sock);
    atomic_store_explicit(&mgr->socket_id, 100, memory_order_relaxed);
    SGE_SPINLOCK_INIT(&mgr->lock);

    g_socket_mgr = mgr;
    return SGE_OK;
}

int sge_destroy_socket_mgr(void) {
    if (NULL == g_socket_mgr) {
        return SGE_ERR;
    }

    sge_destroy_dict(g_socket_mgr->ht_sock);
    sge_free(g_socket_mgr);

    return SGE_OK;
}

int sge_alloc_socket(int fd, struct sge_socket** sockp) {
    struct sge_socket* sock;

    if (NULL == g_socket_mgr || fd <= 0) {
        return SGE_ERR;
    }

    sge_get_resource(socket_res_pool, (void**)&sock);

    sock->fd = fd;
    sock->status = SGE_SOCKET_AVAILABLE;
    sock->srv = NULL;
    sock->sid = alloc_sid__(g_socket_mgr);
    SGE_LIST_INIT(&sock->msg_list);
    SGE_SPINLOCK_INIT(&sock->lock);

    SGE_SPINLOCK_LOCK(&g_socket_mgr->lock);
    sge_insert_dict(g_socket_mgr->ht_sock, (const void*)sock->sid, 1, sock);
    SGE_SPINLOCK_UNLOCK(&g_socket_mgr->lock);
    *sockp = sock;

    return SGE_OK;
}

int sge_destroy_socket(struct sge_socket* sock) {
    if (NULL == sock) {
        return SGE_ERR;
    }

    // ignore error
    sge_del_event(sock->srv->event_mgr, sock->sid, EVENT_TYPE_ACCEPTABLE | EVENT_TYPE_READABLE | EVENT_TYPE_WRITEABLE);
    close(sock->fd);
    sge_remove_dict(g_socket_mgr->ht_sock, (const void*)sock->sid, 1);
    sge_release_resource(sock);

    return SGE_OK;
}

int sge_destroy_socket_by_sid(sge_socket_id sid) {
    struct sge_socket* sock;

    sge_get_dict(g_socket_mgr->ht_sock, (const void*)sid, 1, (void**)&sock);
    return sge_destroy_socket(sock);
}

int sge_create_listener(const char* server_addr, struct sge_server* server) {
    int ret;
    char *p;
    char addr[512];
    size_t len;
    struct sge_event evt;
    struct sge_socket* listener;

    if (NULL == server_addr) {
        return SGE_ERR;
    }

    p = strstr(server_addr, ":");
    if (NULL == p) {
        SGE_LOG(SGE_LOG_LEVEL_ERROR, "server_addr(%s) error.", server_addr);
        return SGE_ERR;
    }

    len = p - server_addr;
    strncpy(addr, server_addr, len);
    addr[len] = '\0';

    ret = create_port_listener__(addr, p + 1, &listener);
    if (SGE_ERR == ret) {
        return SGE_ERR;
    }
    listener->srv = server;
    server->listener = listener;

    evt.arg = server;
    evt.custom_id = server->listener->sid;
    evt.event_mgr = server->event_mgr;
    evt.event_type = EVENT_TYPE_ACCEPTABLE;
    evt.fd = server->listener->fd;
    evt.cb = handle_new_conn__;
    evt.write_cb = NULL;

    ret = sge_add_event(server->event_mgr, &evt);
    if (SGE_ERR == ret) {
        sge_destroy_socket(server->listener);
        return SGE_ERR;
    }

    return SGE_OK;
}

int sge_destroy_msg_chain(struct sge_msg_chain* chain) {
    if (NULL == chain) {
        return SGE_ERR;
    }

    return sge_release_resource(chain);
}

int sge_send_msg(sge_socket_id sid, const char* msg, size_t len) {
    int ret;
    size_t nwrite;
    struct sge_socket* sock;
    struct sge_string* str;
    struct sge_msg_chain* chain;
    struct sge_event evt;

    sge_get_dict(g_socket_mgr->ht_sock, (const void*)sid, 1, (void**)&sock);
    if (NULL == sock) {
        return SGE_ERR;
    }

    nwrite = 0;
    while(nwrite < len) {
        ret = write(sock->fd, msg + nwrite, len - nwrite);
        if (ret < 0) {
            if (EAGAIN == errno) {
                break;
            }
            if (EINTR == errno) {
                continue;
            }
            SGE_LOG(SGE_LOG_LEVEL_SYS_ERROR, "write msg error. fd(%d), reason(%s)", sock->fd, strerror(errno));
            return SGE_ERR;
        }

        nwrite += ret;
    }

    if (nwrite != len) {
        sge_dup_string(&str, msg + nwrite, len - nwrite);
        chain = alloc_msg_chain__(str, SGE_MSG_TYPE_NEW_MSG, sock->sid);
        append_msg__(sock, chain);

        evt.arg = sock;
        evt.custom_id = sock->sid;
        evt.fd = sock->fd;
        evt.event_type = EVENT_TYPE_WRITEABLE;
        evt.cb = NULL;
        evt.write_cb = handle_write_done__;
        ret = sge_add_event(sock->srv->event_mgr, &evt);
        if (SGE_ERR == ret) {
            SGE_LIST_REMOVE(&chain->list);
            sge_destroy_string(chain->msg);
            sge_destroy_msg_chain(chain);
            return nwrite;
        }
    }

    return nwrite;
}

int sge_get_sock_msg(struct sge_socket* sock, struct sge_list* head) {
    if (NULL == sock) {
        return SGE_ERR;
    }

    SGE_SPINLOCK_LOCK(&sock->lock);
    SGE_LIST_MOVE(&sock->msg_list, head);
    SGE_SPINLOCK_UNLOCK(&sock->lock);

    return SGE_OK;
}

int sge_get_first_msg_by_sid(sge_socket_id sid, struct sge_msg_chain** chainp) {
    struct sge_list* last;
    struct sge_socket* sock;

    sge_get_dict(g_socket_mgr->ht_sock, (const void*)sid, 1, (void**)&sock);
    if (NULL == sock) {
        *chainp = NULL;
        return SGE_ERR;
    }

    if (SGE_LIST_EMPTY(&sock->msg_list)) {
        *chainp = NULL;
        return SGE_ERR;
    }

    SGE_SPINLOCK_LOCK(&sock->lock);
    last = SGE_LIST_LAST(&sock->msg_list);
    SGE_LIST_REMOVE(last);
    *chainp = sge_container_of(last, struct sge_msg_chain, list);
    SGE_SPINLOCK_UNLOCK(&sock->lock);

    return SGE_OK;
}

int sge_sock_msg_empty(sge_socket_id sid) {
    struct sge_socket* sock;

    sge_get_dict(g_socket_mgr->ht_sock, (const void*)sid, 1, (void**)&sock);
    if (NULL == sock) {
        return SGE_OK;
    }

    if (SGE_LIST_EMPTY(&sock->msg_list)) {
        return SGE_OK;
    } else {
        return SGE_ERR;
    }
}
