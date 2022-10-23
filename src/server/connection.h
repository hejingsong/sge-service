#ifndef SGE_CONNECTION_H_
#define SGE_CONNECTION_H_

#include "server/socket.h"

struct sge_connection;

int sge_create_conn_res_pool(int size);
int sge_get_connection(struct sge_connection** conn);
int sge_release_connection(struct sge_connection* conn);
int sge_destroy_conn_res_pool();

#endif
