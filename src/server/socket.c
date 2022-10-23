#include <stdatomic.h>
#include <string.h>

#include <fcntl.h>
#include <assert.h>
#include <unistd.h>

#include "core/sge.h"
#include "core/log.h"
#include "core/dict.h"
#include "utils/config.h"
#include "server/socket.h"
#include "event/event_mgr.h"

#define SOCKET_ID_START 10000

struct sge_socket_mgr {
    struct sge_dict* socket_ht;
    atomic_ulong sid_counter;
};


static struct sge_socket_mgr* g_socket_mgr;


static socket_id
sge_get_sid() {
    return atomic_fetch_add_explicit(&g_socket_mgr->sid_counter, 1, memory_order_relaxed);
}

int sge_init_socket_mgr() {
    g_socket_mgr = sge_malloc(sizeof(*g_socket_mgr));

    g_socket_mgr->socket_ht = sge_create_dict(integer_hash_fn, integer_compare_fn);
    atomic_store_explicit(&g_socket_mgr->sid_counter, SOCKET_ID_START, memory_order_relaxed);

    assert(g_socket_mgr->socket_ht != NULL);
    assert(g_socket_mgr->sid_counter == 10000);
    return SGE_OK;
}

int sge_register_socket(struct sge_socket* sock) {
    sock->status = SGE_SOCKET_AVAILABLE;
    return sge_insert_dict(g_socket_mgr->socket_ht, (void*)sock->sid, 0, sock);
}

int sge_unregister_socket(struct sge_socket* sock) {
    sock->status = SGE_SOCKET_CLOSED;
    return sge_remove_dict(g_socket_mgr->socket_ht, (void*)sock->sid, 0);
}

int sge_get_socket(socket_id sid, struct sge_socket** sock) {
    struct sge_socket* s;
    s = sge_get_dict(g_socket_mgr->socket_ht, (void*)sid, 0);
    if (NULL == s) {
        return SGE_ERR;
    }

    *sock = s;
    return SGE_OK;
}

int sge_set_io_unblock(int fd) {
    int flags;

    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return flags;
    }
    if (flags & O_NONBLOCK) {
        return 0;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int sge_close_socket(struct sge_socket* sock) {
    close(sock->fd);
    return SGE_OK;
}

int sge_init_socket(struct sge_socket* sock, struct sge_server* server, int fd, struct sockaddr* sockaddr, socklen_t socklen) {
    sock->fd = fd;
    sock->events = 0;
    sock->server = server;
    sock->sid = sge_get_sid();
    sock->socklen = socklen;
    sock->sockaddr = sockaddr;
    sock->status = SGE_SOCKET_INIT;

    if (sge_get_event_type() == EVENT_MGR_TYPE_EPOLL) {
        sge_set_io_unblock(sock->fd);
    }
    sge_register_socket(sock);

    return SGE_OK;
}

int sge_socket_available(struct sge_socket* sock) {
    return (sock->status == SGE_SOCKET_AVAILABLE || sock->status == SGE_SOCKET_HALF_CLOSED) ? SGE_OK : SGE_ERR;
}
