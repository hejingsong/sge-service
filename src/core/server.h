#ifndef SGE_SOCKET_H_
#define SGE_SOCKET_H_

#include <stdatomic.h>


#include "core/list.h"
#include "core/dict.h"
#include "core/event.h"
#include "core/module.h"
#include "core/string.h"
#include "core/spinlock.h"


typedef unsigned long sge_socket_id;

enum sge_socket_status {
    SGE_SOCKET_INIT = 1,
    SGE_SOCKET_AVAILABLE,
    SGE_SOCKET_PEER_CLOSED,
    SGE_SOCKET_CLOSED
};

struct sge_server;

enum sge_msg_type {
    SGE_MSG_TYPE_NEW_CONN = 1 << 0,
    SGE_MSG_TYPE_NEW_MSG = 1 << 1,
    SGE_MSG_TYPE_CLOSED = 1 << 2,
    SGE_MSG_TYPE_WRITE_DONE = 1 << 3
};

struct sge_message {
    unsigned long custom_id;
    ssize_t ret;
    struct sge_string* msg;
    enum sge_msg_type msg_type;
    struct sge_list entry;
    void* ud;
};

struct sge_socket {
    int fd;
    sge_socket_id sid;
    enum sge_socket_status status;
    struct sge_server* srv;
    struct sge_spinlock lock;
    struct sge_list msg_list;
};

struct sge_server {
    struct sge_socket* listener;
    struct sge_dict* ht_conn;
    struct sge_event_mgr* event_mgr;
    struct sge_module* module;
};

int sge_init_server_pool(size_t size);
void sge_destroy_server_pool(void);

int sge_alloc_server(struct sge_module* module, struct sge_server** srvp);
int sge_destroy_server(struct sge_server* srv);

int sge_init_socket_mgr(void);
int sge_destroy_socket_mgr(void);

int sge_alloc_socket(int fd, struct sge_socket** sockp);
int sge_destroy_socket(struct sge_socket* sock);
int sge_destroy_socket_by_sid(sge_socket_id sid);
int sge_get_socket(sge_socket_id sid, struct sge_socket** sock);

int sge_create_listener(const char* server_addr, struct sge_server* server);

int sge_send_msg(sge_socket_id sid, const char* msg, size_t len);
int sge_get_sock_msg(struct sge_socket* sock, struct sge_list* head);

int sge_alloc_message(struct sge_message** msgp);
int sge_destroy_message(struct sge_message* msg);

#endif
