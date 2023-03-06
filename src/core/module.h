#ifndef SGE_MODULE_H_
#define SGE_MODULE_H_

#include <stdatomic.h>

#include "core/list.h"
#include "core/string.h"
#include "core/context.h"
#include "core/spinlock.h"

struct sge_module;

struct sge_req {
    struct sge_module* module;
    void* payload;
};

struct sge_module_ops {
    int (*init)(struct sge_module*);
    int (*destroy)(struct sge_module*);
    int (*handle)(struct sge_module*, struct sge_list*);
};

struct sge_module {
    struct sge_list list;
    struct sge_string* name;
    struct sge_context* ctx;
    struct sge_module_ops* ops;
    struct sge_list msg_list;
    struct sge_spinlock lock;
    atomic_bool handle_status;
    void* handler;
    void* private_data;

    char initialized:1;
    char pad[3];
};


int sge_alloc_module(const char* name, size_t name_len, struct sge_module** module);
int sge_init_module(struct sge_module* module);
int sge_destroy_module(struct sge_module* module);
int sge_add_module_msg(struct sge_module* module, struct sge_list* msg);
int sge_handle_module(struct sge_module* module);

#endif
