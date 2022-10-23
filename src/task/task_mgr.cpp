#ifdef __cplusplus
extern "C"{
#endif

#include <pthread.h>

#include "core/sge.h"
#include "core/log.h"
#include "core/queue.h"
#include "core/spinlock.h"
#include "core/res_pool.h"
#include "task/task.h"
#include "libcontext.h"


struct sge_task_meta {
    fn_task_cb fn;
    void* arg;
    unsigned long stack_size;
    fcontext_t context;
    void* stack;
    int flags;
};

struct sge_task_meta_pool {
    struct sge_spinlock lock;
    struct sge_queue* pool;
};

struct sge_task_mgr {
    struct sge_task_meta main_task;
    struct sge_task_meta* cur_task;
    struct sge_queue* task_queue;
    pthread_mutex_t task_queue_mutex;
    pthread_cond_t task_queue_cond;
};


static __thread struct sge_task_mgr* tls_task_mgr = NULL;
static struct sge_res_pool* g_meta_pool = NULL;
static const struct timespec g_timespec = {.tv_sec = 0, .tv_nsec = 300000000};
// 默认栈大小为1M
static unsigned long g_page_size = 1 * 1024 * 1024;


static int
sge_sched_to(struct sge_task_mgr* mgr, struct sge_task_meta* from, struct sge_task_meta* to) {
    mgr->cur_task = to;

    if (from != &mgr->main_task && from->context) {
        sge_release_resource(from);
    }

    jump_fcontext(&from->context, to->context, (intptr_t)from);
    return SGE_OK;
}

static void
sge_task_entry(intptr_t p) {
    struct sge_task_mgr* mgr = tls_task_mgr;
    struct sge_task_meta* meta;

    meta = mgr->cur_task;
    meta->fn(meta->arg);

    sge_sched_to(mgr, meta, &(mgr->main_task));
}

static void
sge_clean_task_meta(void* data) {
    struct sge_task_meta* meta = (struct sge_task_meta*)data;
    if (meta->stack) {
        sge_free(meta->stack);
    }
    meta->arg = NULL;
    meta->fn = NULL;
    meta->stack = NULL;
    meta->stack_size = 0;
    meta->context = NULL;
    meta->flags = 0;
}

static void
sge_init_task_meta(void* data) {
    struct sge_task_meta* meta;

    meta = (struct sge_task_meta*)data;

    meta->stack = NULL;
    sge_clean_task_meta(meta);
}

static int
sge_destroy_task_meta(void* data) {
    struct sge_task_meta* meta = (struct sge_task_meta*)data;
    if (meta->stack) {
        sge_free(meta->stack);
    }
    return SGE_OK;
}

static int
sge_task_meta_size() {
    return sizeof(struct sge_task_meta);
}

struct sge_task_mgr* sge_create_task_mgr() {
    int ret;
    struct sge_task_mgr* mgr;

    mgr = (struct sge_task_mgr*)sge_malloc(sizeof(struct sge_task_mgr));
    ret = pthread_mutex_init(&mgr->task_queue_mutex, NULL);
    if (ret != 0) {
        SGE_LOG_SYS_ERROR("init mutex error.");
        return NULL;
    }
    ret = pthread_cond_init(&mgr->task_queue_cond, NULL);
    if (ret != 0) {
        SGE_LOG_SYS_ERROR("init cond error.");
        return NULL;
    }

    mgr->task_queue = sge_create_queue(1024);
    sge_clean_task_meta(&mgr->main_task);
    mgr->cur_task = &mgr->main_task;

    tls_task_mgr = mgr;

    return mgr;
}

int sge_wait_task(struct sge_task_mgr* mgr, struct sge_task_meta** task) {
    int ret;
    void* data;

    pthread_mutex_lock(&mgr->task_queue_mutex);
    pthread_cond_timedwait(&mgr->task_queue_cond, &mgr->task_queue_mutex, &g_timespec);
    ret = sge_dequeue(mgr->task_queue, &data);
    pthread_mutex_unlock(&mgr->task_queue_mutex);

    if (ret == SGE_ERR) {
        return SGE_ERR;
    }

    *task = (struct sge_task_meta*)data;
    return ret;
}

int sge_sched(struct sge_task_mgr* mgr, struct sge_task_meta* task) {
    if (mgr->cur_task == task) {
        return SGE_ERR;
    }

    if (NULL == task->stack) {
        task->stack_size = g_page_size;
        task->stack = sge_malloc(task->stack_size);
        task->context = make_fcontext(task->stack + task->stack_size, task->stack_size, sge_task_entry);
    }

    return sge_sched_to(mgr, mgr->cur_task, task);
}

int sge_add_task(struct sge_task_mgr* mgr, struct sge_task_meta* task) {
    int ret;

    pthread_mutex_lock(&(mgr->task_queue_mutex));
    if (SGE_ERR == sge_enqueue(mgr->task_queue, (void*)task)) {
        SGE_LOG_ERROR("add task error, queue full.");
        ret = SGE_ERR;
    } else {
        pthread_cond_broadcast(&mgr->task_queue_cond);
        ret = SGE_OK;
    }
    pthread_mutex_unlock(&(mgr->task_queue_mutex));

    return ret;
}

struct sge_task_mgr* sge_get_task_mgr() {
    return tls_task_mgr;
}

struct sge_task_meta* sge_get_task_meta(fn_task_cb fn, void* args, int flags) {
    void* data;
    struct sge_task_meta* meta;

    sge_get_resource(g_meta_pool, &data);
    meta = (struct sge_task_meta*)data;

    meta->arg = args;
    meta->fn = fn;
    meta->flags = flags;

    return meta;
}

struct sge_res_pool_op OP = {
    .init = sge_init_task_meta,
    .reset = sge_clean_task_meta,
    .destroy = sge_destroy_task_meta,
    .size = sge_task_meta_size
};

int sge_create_task_meta_pool(int size) {
    g_meta_pool = sge_create_res_pool(&OP, size);
    return SGE_OK;
}

int sge_destroy_task_meta_pool() {
    return sge_destroy_resource(g_meta_pool);
}

#ifdef __cplusplus
};
#endif
