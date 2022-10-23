#include <dlfcn.h>
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdatomic.h>

#include "core/sge.h"
#include "core/log.h"
#include "core/dict.h"
#include "task/task.h"
#include "core/config.h"
#include "core/res_pool.h"
#include "event/event_mgr.h"
#include "event/event_pool.h"

#define EVENT_POOL_SIZE 1024

static pthread_once_t event_pool_th = PTHREAD_ONCE_INIT;
static atomic_ulong eid_counter;


static void
sge_init_event_pool() {
    int ret;

    ret = sge_create_event_pool(EVENT_POOL_SIZE);
    assert(ret == SGE_OK);

    atomic_store_explicit(&eid_counter, 100, memory_order_relaxed);
    assert(eid_counter == 100);
}

static unsigned long
sge_get_event_id() {
    return atomic_fetch_add_explicit(&eid_counter, 1, memory_order_relaxed);
}

int sge_dispatch_event(struct sge_event_mgr* mgr) {
    return mgr->op->dispatch(mgr);
}

struct sge_event_mgr* sge_create_event_mgr(int type) {
    int len;
    void* handle = NULL;
    char dlname[1024];
    struct sge_event_op* op = NULL;
    struct sge_event_mgr* mgr = NULL;

    switch (type) {
        case EVENT_MGR_TYPE_EPOLL:
            len = sprintf(dlname, "%s/lib%s.so", EVENT_MGR_LIBRARY_DIR, "epoll");
            dlname[len] = '\0';
            break;
        
        case EVENT_MGR_TYPE_IO_URING:
            len = sprintf(dlname, "%s/lib%s.so", EVENT_MGR_LIBRARY_DIR, "iouring");
            dlname[len] = '\0';
            break;
        
        default:
            SGE_LOG_ERROR("unknown event type.");
            break;
    }

    if (NULL == dlname) {
        return NULL;
    }

    handle = dlopen(dlname, RTLD_NOW);
    if (NULL == handle) {
        SGE_LOG_ERROR("can't load library %s", dlname);
        return NULL;
    }

    op = dlsym(handle, "EVENT_MGR_API");
    if (NULL == op) {
        SGE_LOG_ERROR("can't found variable EVENT_MGR_API in %s", dlname);
        goto DL_ERR;
    }

    mgr = sge_malloc(sizeof(*mgr));
    mgr->op = op;
    mgr->type = type;
    mgr->event_ht = sge_create_dict(integer_hash_fn, integer_compare_fn);
    assert(mgr->event_ht != NULL);

    if (SGE_ERR == mgr->op->init(mgr)) {
        goto INIT_ERR;
    }

    pthread_once(&event_pool_th, sge_init_event_pool);

    return mgr;

INIT_ERR:
    sge_destroy_dict(mgr->event_ht);
    sge_free(mgr);
DL_ERR:
    dlclose(handle);
    return NULL;
}

unsigned long sge_add_event(unsigned long src_id, enum sge_event_type event_type, enum sge_event_mode mode, void* arg, void* complete_arg, complete_fn complete_cb) {
    unsigned long eid;
    struct sge_event* evt;
    struct sge_event_mgr* mgr;

    if (SGE_ERR == sge_get_event(&evt)) {
        return 0;
    }

    mgr = current_event_mgr();

    eid = sge_get_event_id();
    evt->eid = eid;
    evt->src_id = src_id;
    evt->mode = mode;
    evt->mgr = mgr;
    evt->arg = arg;
    evt->evt_type = event_type;
    evt->complete_cb = complete_cb;
    evt->complete_arg = complete_arg;

    if (SGE_ERR == mgr->op->add(mgr, evt)) {
        goto ERR;
    }

    sge_insert_dict(mgr->event_ht, (void*)eid, 0, evt);
    return eid;

ERR:
    sge_release_event(evt);
    return 0;
}

int sge_del_event(unsigned long eid) {
    struct sge_event_mgr* mgr;
    struct sge_event* evt;

    if (SGE_ERR == sge_find_event(eid, &evt)) {
        SGE_LOG_ERROR("can't found event eid(%ld)", eid);
        return SGE_ERR;
    }

    mgr = evt->mgr;
    if (SGE_ERR == mgr->op->del(mgr, eid)) {
        sge_remove_dict(mgr->event_ht, (void*)eid, 0);
        sge_release_event(evt);
    }

    return SGE_OK;
}

int sge_find_event(unsigned long eid, struct sge_event** event) {
    void* data;
    struct sge_event_mgr* mgr;

    mgr = current_event_mgr();
    data = sge_get_dict(mgr->event_ht, (void*)eid, 0);
    if (NULL == data) {
        *event = NULL;
        return SGE_ERR;
    }

    *event = (struct sge_event*)data;
    return SGE_OK;
}

int async_run(void* arg) {
    struct sge_event_result* result = (struct sge_event_result*)arg;
    struct sge_event* evt = result->evt;

    return evt->complete_cb(evt->mgr, result);
}

int sge_exec_event(struct sge_event_result* result) {
    struct sge_event* evt = result->evt;

    if (evt->mode == EVENT_MODE_ASYNC) {
        return sge_async_execute(async_run, result, 0);
    }
    return evt->complete_cb(evt->mgr, result);
}

struct sge_event_result* sge_create_event_result(struct sge_event* evt, socket_id sid, int fd) {
    struct sge_event_result* r = sge_malloc(sizeof(*r));
    r->fd = fd;
    r->evt = evt;
    r->sid = sid;
    SGE_LIST_INIT(&r->result_list);

    return r;
}

int sge_destroy_event_result(struct sge_event_result* result) {
    sge_free(result);

    return SGE_OK;
}
