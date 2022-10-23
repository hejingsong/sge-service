#ifndef SGE_ACCEPTOR_H_
#define SGE_ACCEPTOR_H_

#include "server/server.h"

struct sge_acceptor;

struct sge_acceptor* sge_create_acceptor(const char* host, int port);
struct sge_socket* sge_get_prepare_conn(struct sge_acceptor* acceptor);

#endif
