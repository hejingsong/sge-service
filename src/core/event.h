#ifndef SGE_EVENT_H_
#define SGE_EVENT_H_

#include "core/dict.h"
#include "core/string.h"


enum sge_event_type {
    EVENT_TYPE_READABLE = 1 << 0,
    EVENT_TYPE_ACCEPTABLE = 1 << 1,
    EVENT_TYPE_WRITEABLE = 1 << 2,
    EVENT_TYPE_TIMER = 1 << 3
};
struct sge_event_mgr;
struct sge_event_buff;
struct sge_event;
typedef int (*fn_event_cb)(struct sge_event_buff*);

struct sge_event_buff {
    int ret;
    void* arg;
    struct sge_string* buf;
};
struct sge_event {
    unsigned long custom_id;
    enum sge_event_type event_type;
    struct sge_event_mgr* event_mgr;
    int fd;
    void* arg;
    fn_event_cb cb;
    fn_event_cb write_cb;
};
struct sge_event_mgr_ops {
    int (*init)(struct sge_event_mgr*);
    int (*poll)(struct sge_event_mgr*);
    int (*add)(struct sge_event_mgr*, struct sge_event*, enum sge_event_type);
    int (*del)(struct sge_event*, struct sge_event*);
    int (*destroy)(struct sge_event_mgr*);
};
struct sge_event_mgr {
    const char* type_name;
    struct sge_dict* ht_events;
    struct sge_event_mgr_ops* ops;
    void* private_data;
};

int sge_init_event_pool(void);
void sge_destroy_event_pool(void);

int sge_init_event_mgr(void);
int sge_get_event_mgr(const char* event_type_name, struct sge_event_mgr** mgrp);
int sge_add_event(struct sge_event_mgr* mgr, struct sge_event* evt);
int sge_del_event(struct sge_event_mgr* mgr, unsigned long custom_id, enum sge_event_type event_type);
int sge_poll_event(void);
int sge_destroy_event_mgr(void);

int sge_alloc_event_buff(struct sge_event_buff** buffp);
int sge_release_event_buff(struct sge_event_buff* buff);

int sge_copy_event(struct sge_event* src, struct sge_event* dest);


#endif
