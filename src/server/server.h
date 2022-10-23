#ifndef SGE_SERVER_H_
#define SGE_SERVER_H_

#include "server/socket.h"
#include "server/acceptor.h"
#include "server/connection.h"

struct sge_server;

struct sge_server_op {
    int (*handle_new_connect)(socket_id);
    int (*handle_closed)(socket_id);
    int (*handle_write_done)(socket_id);
    int (*handle_message)(socket_id, char*, int);
};

struct sge_server* sge_create_server(const char* host, int port, struct sge_server_op* op);
int sge_close_connection(socket_id sid);
int sge_send_message(socket_id sid, char* p, int len);

#endif
