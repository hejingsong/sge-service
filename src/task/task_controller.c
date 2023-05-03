#define _GNU_SOURCE
#include <unistd.h>
#include <signal.h>
#include <pthread.h>

#include "core/sge.h"
#include "core/log.h"
#include "task/task.h"
#include "utils/config.h"
#include "module/module.h"
#include "event/event_mgr.h"


struct sge_task_worker {
    int id;
    pthread_t tid;
    struct sge_task_mgr* mgr;
};

struct sge_task_controller {
    int quit;
    int worker_num;
    int reload_worker;
    struct sge_event_mgr* event_mgr;
    struct sge_task_worker* workers;
};


static struct sge_task_controller* g_task_ctrl = NULL;

static int
sge_get_rand_worker() {
    return rand() % g_task_ctrl->worker_num;
}

static void*
sge_worker_entry(void* arg) {
    int ret;
    cpu_set_t set;
    struct sge_task_meta* task;
    struct sge_task_worker* worker = (struct sge_task_worker*)arg;

    CPU_SET(worker->id, &set);
    pthread_setaffinity_np(worker->tid, sizeof(set), &set);
    SGE_LOG_SYS_ERROR("set thread affinity");
    worker->mgr = sge_create_task_mgr();
    while(!g_task_ctrl->quit) {
        ret = sge_wait_task(worker->mgr, &task, &g_task_ctrl->quit);
        if (ret == SGE_ERR) {
            continue;
        }
        sge_sched(worker->mgr, task);
        sge_recycle_task_meta(worker->mgr);
    }
}

static int
sge_destroy_task_controller() {
    if (g_task_ctrl) {
        sge_free(g_task_ctrl->workers);
        sge_free(g_task_ctrl);
    }
    return SGE_OK;
}

static void
sge_signal_handler(int signo) {
    if (signo == SIGTERM || signo == SIGINT) {
        g_task_ctrl->quit = 1;
    } else if (signo == SIGUSR1) {
        g_task_ctrl->reload_worker = 1;
    }
}

static int
sge_init_signal() {
    __sighandler_t ret;

    ret = signal(SIGTERM, sge_signal_handler);
    if (ret == SIG_ERR) {
        SGE_LOG_SYS_ERROR("set signal handler error.");
        return SGE_ERR;
    }

    ret = signal(SIGINT, sge_signal_handler);
    if (ret == SIG_ERR) {
        SGE_LOG_SYS_ERROR("set signal handler error.");
        return SGE_ERR;
    }

    ret = signal(SIGUSR1, sge_signal_handler);
    if (ret == SIG_ERR) {
        SGE_LOG_SYS_ERROR("set signal handler error.");
        return SGE_ERR;
    }

    return SGE_OK;
}

static int
sge_init_task_controller() {
    g_task_ctrl = (struct sge_task_controller*)sge_malloc(sizeof(struct sge_task_controller));
    g_task_ctrl->quit = 0;
    g_task_ctrl->worker_num = 0;
    g_task_ctrl->reload_worker = 0;
    g_task_ctrl->event_mgr = sge_create_event_mgr(sge_get_event_type());
    g_task_ctrl->workers = NULL;
    return SGE_OK;
}

static int
sge_start_worker(int worker_num) {
    int i;
    int ret;
    struct sge_task_worker* worker;

    g_task_ctrl->worker_num = worker_num;
    g_task_ctrl->workers = sge_malloc(sizeof(struct sge_task_worker) * worker_num);

    for (i = 0; i < worker_num; ++i) {
        worker = &(g_task_ctrl->workers[i]);
        worker->id = i;

        ret = pthread_create(&(worker->tid), NULL, sge_worker_entry, worker);
        if (ret != 0) {
            SGE_LOG_SYS_ERROR("create thread error.");
            return SGE_ERR;
        }
    }

    usleep(10000);

    return SGE_OK;
}

int sge_init_worker_dir(const char* worker_dir) {
    if (chdir(worker_dir) == -1) {
        SGE_LOG_SYS_ERROR("change worker dir error.");
        return SGE_ERR;
    }
    return SGE_OK;
}

int sge_init_task() {
    if (SGE_ERR == sge_init_signal()) {
        return SGE_ERR;
    }

    if (SGE_ERR == sge_init_task_controller()) {
        return SGE_ERR;
    }

    if (SGE_ERR == sge_create_task_meta_pool(sge_get_meta_pool_size())) {
        return SGE_ERR;
    }

    if (SGE_ERR == sge_start_worker(sge_get_thread_num())) {
        return SGE_ERR;
    }

    return SGE_OK;
}

int sge_wait_quit() {
    int i;
    void* ret;

    while(!g_task_ctrl->quit) {
        sge_dispatch_event(g_task_ctrl->event_mgr);
        if (g_task_ctrl->reload_worker) {
            g_task_ctrl->reload_worker = 0;
            sge_reload_modules();
        }
    }

    for (i = 0; i < g_task_ctrl->worker_num; ++i) {
        sge_wake_task(g_task_ctrl->workers[i].mgr);
        pthread_join(g_task_ctrl->workers[i].tid, &ret);
    }

    return SGE_OK;
}

int sge_async_execute(fn_task_cb fn, void* arg, int flags) {
    int i;
    struct sge_task_mgr* mgr;
    struct sge_task_meta* task;

    mgr = sge_get_task_mgr();
    if (NULL == mgr) {
        i = sge_get_rand_worker();
        mgr = g_task_ctrl->workers[i].mgr;
    }

    task = sge_get_task_meta(fn, arg, flags);
    return sge_add_task(mgr, task);
}

struct sge_event_mgr* current_event_mgr() {
    return g_task_ctrl->event_mgr;
}
