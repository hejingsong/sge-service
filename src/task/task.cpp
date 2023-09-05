#ifdef __cplusplus
extern "C"{
#endif

#include <errno.h>
#include <assert.h>
#include <pthread.h>
#include <sys/time.h>

#include <string.h>

#include "core/sge.h"
#include "core/task.h"
#include "core/cond.h"
#include "core/list.h"
#include "core/queue.h"
#include "core/context.h"
#include "core/spinlock.h"
#include "core/res_pool.h"

#include "libcontext.h"


#define SGE_TASK_STACK_SIZE 1024 * 1024

static struct sge_task_ctrl* g_task_ctrl;
static __thread struct sge_task* tls_task = NULL;


struct sge_task_ctrl {
    int task_num;
    struct sge_task* tasks;
    struct sge_context* ctx;

    int reload:1;
};

struct sge_task_meta {
    fn_task_cb cb;
    void* arg;
    unsigned long stack_size;
    void* fcontext;
    void* stack;
    enum sge_task_flags flags;
};

struct sge_task {
    int worker_idx;
    pthread_t tid;
    struct sge_context* ctx;
    struct sge_task_meta main_task;
    struct sge_task_meta* cur_task;
    struct sge_task_meta* last_task;
    struct sge_queue* task_queue;
    struct sge_spinlock lock;
    struct sge_cond* cond;
};

static size_t task_meta_size__(void) {
    return sizeof(struct sge_task);
}

static size_t task_stack_size__(void) {
    return SGE_TASK_STACK_SIZE;
}

static struct sge_res_pool* task_meta_res_pool;
static struct sge_res_pool_ops task_meta_res_pool_ops = {
    .size = task_meta_size__
};

static struct sge_res_pool* task_stack_res_pool;
static struct sge_res_pool_ops task_stack_res_pool_ops = {
    .size = task_stack_size__
};

static int rand_worker__() {
    return rand() % g_task_ctrl->task_num;
}

static int steal_task__(int exclude_idx, struct sge_task_meta** metap) {
    int ret;
    int worker_idx;
    void* data;
    struct sge_task* task;

    while(1) {
        worker_idx = rand_worker__();
        if (worker_idx == exclude_idx) {
            continue;
        }
        break;
    }
    task = &(g_task_ctrl->tasks[worker_idx]);

    SGE_SPINLOCK_LOCK(&task->lock);
    ret = sge_dequeue(task->task_queue, &data);
    SGE_SPINLOCK_UNLOCK(&task->lock);
    *metap = (struct sge_task_meta*)data;

    return ret;
}

static int get_task__(struct sge_task* task, struct sge_task_meta** metap) {
    int ret;
    void* data;

    SGE_SPINLOCK_LOCK(&task->lock);
    ret = sge_dequeue(task->task_queue, &data);
    SGE_SPINLOCK_UNLOCK(&task->lock);

    if (SGE_ERR == ret) {
        // steal other task
        ret = steal_task__(task->worker_idx, metap);
    } else {
        *metap = (struct sge_task_meta*)data;
    }

    return ret;
}

static int wait_task__(struct sge_task* task) {
    return sge_wait_cond(task->cond, 200);
}

static int sched_task__(struct sge_task* task, struct sge_task_meta* meta) {
    struct sge_task_meta* cur;

    cur = task->cur_task;
    task->cur_task = meta;
    task->last_task = cur;

    jump_fcontext(&cur->fcontext, meta->fcontext, 0);

    return SGE_OK;
}

static void task_entry__(intptr_t v) {
    struct sge_task* task = tls_task;
    struct sge_task_meta* meta;

    sge_unused(v);

    meta = task->cur_task;
    meta->cb(meta->arg);

    sched_task__(task, &task->main_task);
}

static int alloc_task_meta__(struct sge_task_meta** metap) {
    
    *metap = (struct sge_task_meta*)sge_get_resource(task_meta_res_pool);
    return SGE_OK;
}

static int add_task_queue__(struct sge_task* task, struct sge_task_meta* meta) {
    SGE_SPINLOCK_LOCK(&task->lock);
    sge_enqueue(task->task_queue, meta);
    SGE_SPINLOCK_UNLOCK(&task->lock);
    sge_notify_cond(task->cond);

    return SGE_OK;
}

static int init_task__(struct sge_task* task) {
    task->main_task.fcontext = NULL;
    task->main_task.stack = NULL;
    task->main_task.stack_size = 0;
    task->main_task.flags = SGE_TASK_NORMAL;
    task->cur_task = &task->main_task;

    SGE_SPINLOCK_INIT(&task->lock);
    sge_alloc_cond(&task->cond);
    sge_alloc_queue(1024, &task->task_queue);

    return SGE_OK;
}

static void destroy_task__(struct sge_task* task) {
    sge_destroy_queue(task->task_queue);
    sge_destroy_cond(task->cond);
    SGE_SPINLOCK_DESTROY(&task->lock);
}

static void* task_main_loop__(void* arg) {
    struct sge_task* task;
    struct sge_task_meta* meta;

    task = (struct sge_task*)arg;
    tls_task = task;

    while(task->ctx->run) {
        if (SGE_ERR == get_task__(task, &meta)) {
            wait_task__(task);
            continue;
        }
        sched_task__(task, meta);
        if (task->last_task && task->last_task->flags == SGE_TASK_PERMANENT) {
            add_task_queue__(task, task->last_task);
        }
        if (task->last_task && task->last_task->flags == SGE_TASK_NORMAL) {
            sge_release_resource(task->last_task->stack);
            sge_release_resource(task->last_task);
        }
    }

    return NULL;
}

int sge_init_task_pool(size_t size) {
    int ret;
    ret = sge_alloc_res_pool(&task_meta_res_pool_ops, size, &task_meta_res_pool);
    if (SGE_OK == ret) {
        ret = sge_alloc_res_pool(&task_stack_res_pool_ops, size, &task_stack_res_pool);
    }
    return ret;
}

void sge_destroy_task_pool(void) {
    sge_destroy_res_pool(task_meta_res_pool);
    sge_destroy_res_pool(task_stack_res_pool);
}

int sge_init_task_ctrl(struct sge_context* ctx) {
    int i;
    struct timeval tv;
    struct sge_task* task;
    struct sge_task_ctrl* ctrl;

    ctrl = (struct sge_task_ctrl*)sge_calloc(sizeof(struct sge_task_ctrl));
    ctrl->ctx = ctx;
    ctrl->reload = 0;
    ctrl->task_num = ctx->cfg->worker_num;
    ctrl->tasks = (struct sge_task*)sge_calloc(sizeof(struct sge_task) * ctrl->task_num);
    if (NULL == ctrl->tasks) {
        goto error;
    }
    for (i = 0; i < ctrl->task_num; ++i) {
        task = &(ctrl->tasks[i]);
        if (SGE_ERR == init_task__(task)) {
            goto init_task_error;
        }
        task->worker_idx = i;
        task->ctx = ctx;
    }

    g_task_ctrl = ctrl;

    gettimeofday(&tv, NULL);
    srand(tv.tv_sec);

    return SGE_OK;

init_task_error:
    for (i = 0; i < ctrl->task_num; ++i) {
        destroy_task__(&(ctrl->tasks[i]));
    }
    sge_free(ctrl->tasks);
error:
    sge_free(ctrl);
    return SGE_ERR;
}

int sge_run_task_ctrl(void) {
    int i, ret;
    struct sge_task* task;

    if (NULL == g_task_ctrl) {
        return SGE_ERR;
    }

    for (i = 0; i < g_task_ctrl->task_num; ++i) {
        task = &(g_task_ctrl->tasks[i]);
        ret = pthread_create(&task->tid, NULL, task_main_loop__, task);
        if (0 != ret) {
            SGE_LOG(SGE_LOG_LEVEL_SYS_ERROR, "create thread error. reason(%s)", strerror(errno));
            goto error;
        }
    }

    for (i = 0; i < g_task_ctrl->task_num; ++i) {
        task = &(g_task_ctrl->tasks[i]);
        // dont care return
        pthread_join(task->tid, NULL);
    }

    return SGE_OK;
error:
    return SGE_ERR;
}

int sge_destroy_task_ctrl() {
    int i;

    if (NULL == g_task_ctrl) {
        return SGE_ERR;
    }

    for (i = 0; i < g_task_ctrl->task_num; ++i) {
        destroy_task__(&(g_task_ctrl->tasks[i]));
    }
    sge_free(g_task_ctrl->tasks);
    sge_free(g_task_ctrl);
    
    return SGE_OK;
}

int sge_delivery_task(fn_task_cb cb, void* arg, enum sge_task_flags flags) {
    int worker_idx;
    struct sge_task* task;
    struct sge_task_meta* meta;

    alloc_task_meta__(&meta);
    meta->cb = cb;
    meta->arg = arg;
    meta->flags = flags;
    meta->stack_size = SGE_TASK_STACK_SIZE;
    meta->stack = sge_get_resource(task_stack_res_pool);
    meta->fcontext = make_fcontext((char*)meta->stack + meta->stack_size, meta->stack_size, task_entry__);

    if (tls_task) {
        task = tls_task;
    } else {
        worker_idx = rand_worker__();
        task = &(g_task_ctrl->tasks[worker_idx]);
    }

    return add_task_queue__(task, meta);
}

int sge_yield_task() {
    struct sge_task* task;

    assert(tls_task != NULL);

    task = tls_task;
    return sched_task__(task, &task->main_task);
}

#ifdef __cplusplus
};
#endif
