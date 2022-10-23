#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <stdio.h>
#include <string.h>

#include "core/sge.h"
#include "core/log.h"
#include "utils/config.h"
#include "event/event_mgr.h"
#include "server/socket.h"
#include "server/acceptor.h"


struct sge_acceptor {
    struct sge_socket base;
    struct sge_socket prepare_conn;
};

static int
sge_start_acceptor(struct sge_socket* sock, const char* host, int port) {
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int sfd, s;
    int port_len;
    char str_port[6];
    int retcode = SGE_OK;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    port_len = sprintf(str_port, "%d", port);
    str_port[port_len] = '\0';

    s = getaddrinfo(host, str_port, &hints, &result);
    if (s != 0) {
        SGE_LOG_SYS_ERROR("getaddrinfo error.");
        return SGE_ERR;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sfd == -1)
            continue;

        if (bind(sfd, rp->ai_addr, rp->ai_addrlen) == 0) {
            break;
        }
        close(sfd);
    }

    if (NULL == rp) {
        retcode = SGE_ERR;
        SGE_LOG_ERROR("create server error");
        goto RET;
    }

    retcode = listen(sfd, 512);
    if (retcode < 0) {
        close(sfd);
        SGE_LOG_SYS_ERROR("listen error.");
        retcode = SGE_ERR;
        goto RET;
    }

    sock->fd = sfd;
    sock->sockaddr = sge_malloc(sizeof(struct sockaddr_in));
    memcpy(sock->sockaddr, rp->ai_addr, rp->ai_addrlen);
    sock->socklen = rp->ai_addrlen;
    retcode = SGE_OK;

RET:
    freeaddrinfo(result);
    return retcode;
}

struct sge_acceptor* sge_create_acceptor(const char* host, int port) {
    struct sge_acceptor* acceptor;

    acceptor = sge_malloc(sizeof(struct sge_acceptor));

    if (SGE_ERR == sge_start_acceptor((struct sge_socket*)acceptor, host, port)) {
        sge_free(acceptor);
        return NULL;
    }

    sge_init_socket((struct sge_socket*)acceptor, NULL, acceptor->base.fd, acceptor->base.sockaddr, acceptor->base.socklen);
    acceptor->base.events = 0;
    sge_register_socket((struct sge_socket*)acceptor);
    if (sge_get_event_type() == EVENT_MGR_TYPE_EPOLL) {
        sge_set_io_unblock(acceptor->base.fd);
    }

    return acceptor;
}

struct sge_socket* sge_get_prepare_conn(struct sge_acceptor* acceptor) {
    return &acceptor->prepare_conn;
}
