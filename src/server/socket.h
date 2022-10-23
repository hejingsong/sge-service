#ifndef SGE_SOCKET_H_
#define SGE_SOCKET_H_

#include <sys/socket.h>


typedef unsigned long socket_id;

enum SGE_SOCKET_STATUS {
    SGE_SOCKET_INIT = 1,
    SGE_SOCKET_AVAILABLE,
    SGE_SOCKET_HALF_CLOSED,
    SGE_SOCKET_CLOSED
};


struct sge_socket {
    int fd;
    int events;
    socket_id sid;
    struct sockaddr* sockaddr;
    socklen_t socklen;
    struct sge_server* server;
    enum SGE_SOCKET_STATUS status;
};

int sge_init_socket_mgr();
int sge_register_socket(struct sge_socket* sock);
int sge_get_socket(socket_id sid, struct sge_socket** sock);
int sge_unregister_socket(struct sge_socket* sock);
int sge_set_io_unblock(int fd);
int sge_close_socket(struct sge_socket* sock);

int sge_init_socket(struct sge_socket* sock, struct sge_server* server, int fd, struct sockaddr* sockaddr, socklen_t socklen);
int sge_socket_available(struct sge_socket* sock);


#endif
