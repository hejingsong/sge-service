#include "core/sge.h"
#include "core/res_pool.h"
#include "server/connection.h"


struct sge_connection {
    struct sge_socket base;
};


static void
sge_init_connection(void* data) {
    struct sge_connection* conn;
    conn = (struct sge_connection*)data;
    conn->base.sockaddr = NULL;
}

static int
sge_destroy_connection(void* data) {
    struct sge_connection* conn;
    conn = (struct sge_connection*)data;

    sge_free(conn);
    return SGE_OK;
}

static void
sge_reset_connection(void* data) {
    socket_id sid;
    struct sge_connection* conn;
    conn = (struct sge_connection*)data;
    if (conn->base.sockaddr) {
        sge_free(conn->base.sockaddr);
    }
    conn->base.sockaddr = NULL;
}

static int
sge_connection_size() {
    return sizeof(struct sge_connection);
}


static struct sge_res_pool_op CONNECTION_POOL_OP = {
    .init = sge_init_connection,
    .destroy = sge_destroy_connection,
    .reset = sge_reset_connection,
    .size = sge_connection_size
};
static struct sge_res_pool* g_connection_pool;


int sge_create_conn_res_pool(int size) {
    g_connection_pool = sge_create_res_pool(&CONNECTION_POOL_OP, size);
}

int sge_get_connection(struct sge_connection** conn) {
    return sge_get_resource(g_connection_pool, (void**)conn);
}

int sge_release_connection(struct sge_connection* conn) {
    sge_close_socket((struct sge_socket*)conn);
    return sge_release_resource(conn);
}

int sge_destroy_conn_res_pool() {
    return sge_destroy_resource(g_connection_pool);
}
