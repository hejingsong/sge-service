#ifndef SGE_EVENT_MGR_H_
#define SGE_EVENT_MGR_H_

#include "core/list.h"
#include "server/socket.h"

struct sge_event;
struct sge_event_mgr;
struct sge_event_result;
typedef int (*complete_fn)(struct sge_event_mgr*, struct sge_event_result*);

enum sge_event_mgr_type {
    EVENT_MGR_TYPE_EPOLL = 1 << 0,
    EVENT_MGR_TYPE_IO_URING = 1 << 1,
    EVENT_MGR_TYPE_TIMER = 1 << 2
};

enum sge_event_type {
    EVENT_TYPE_READABLE = 1 << 0,
    EVENT_TYPE_WRITEABLE = 1 << 1,
    EVENT_TYPE_ACCEPTABLE = 1 << 2,
    EVENT_TYPE_EXECUTABLE = 1 << 3
};

enum sge_event_mode {
    EVENT_MODE_SYNC = 1 << 0,
    EVENT_MODE_ASYNC = 1 << 1
};

struct sge_event_result {
    int fd;
    socket_id sid;
    struct sge_event* evt;
    struct sge_list result_list;
};

struct sge_event_io_result {
    struct sge_list entry;
    int ret;
    struct sge_buffer* buffer;
};

struct sge_event_acceptor_result {
    struct sge_list entry;
    int fd;
    struct sockaddr* sockaddr;
    socklen_t socklen;
};

struct sge_event {
    unsigned long eid;
    unsigned long src_id;
    enum sge_event_type evt_type;
    enum sge_event_mode mode;
    struct sge_event_mgr* mgr;
    void* arg;
    void* complete_arg;
    complete_fn complete_cb;
};

struct sge_event_op {
    int (*init)(struct sge_event_mgr*);
    int (*dispatch)(struct sge_event_mgr*);
    int (*destroy)(struct sge_event_mgr*);
    int (*add)(struct sge_event_mgr*, struct sge_event*);
    int (*del)(struct sge_event_mgr*, unsigned long);
};

struct sge_event_mgr {
    struct sge_event_op* op;
    enum sge_event_mgr_type type;
    struct sge_dict* event_ht;
    void* private_data;
};


struct sge_event_mgr* sge_create_event_mgr(int type);
unsigned long sge_add_event(unsigned long src_id, enum sge_event_type event_type, enum sge_event_mode mode, void* arg, void* complete_arg, complete_fn complete_cb);
int sge_del_event(unsigned long eid);
int sge_dispatch_event(struct sge_event_mgr* mgr);
int sge_find_event(unsigned long eid, struct sge_event** event);
int sge_exec_event(struct sge_event_result* result);
struct sge_event_result* sge_create_event_result(struct sge_event* evt, socket_id sid, int fd);
int sge_destroy_event_result(struct sge_event_result* result);

#endif
