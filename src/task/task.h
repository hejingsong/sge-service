#ifndef SGE_TASK_H_
#define SGE_TASK_H_

typedef int (*fn_task_cb)(void* arg);

struct sge_task_mgr;
struct sge_task_meta;
struct sge_task_controller;

int sge_init_worker_dir(const char* worker_dir);

int sge_init_task();
int sge_wait_quit();
int sge_async_execute(fn_task_cb fn, void* arg, int flags);

struct sge_task_mgr* sge_create_task_mgr();
struct sge_task_mgr* sge_get_task_mgr();
int sge_wait_task(struct sge_task_mgr* mgr, struct sge_task_meta** task);
int sge_sched(struct sge_task_mgr* mgr, struct sge_task_meta* task);
int sge_add_task(struct sge_task_mgr* mgr, struct sge_task_meta* task);

int sge_create_task_meta_pool(int size);
struct sge_task_meta* sge_get_task_meta(fn_task_cb fn, void* args, int flags);
int sge_destroy_task_meta_pool();

struct sge_event_mgr* current_event_mgr();

#endif
