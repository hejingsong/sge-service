#ifndef SGE_TASK_H_
#define SGE_TASK_H_

typedef int (*fn_task_cb)(void*);

struct sge_context;
struct sge_task_ctrl;

enum sge_task_flags {
    SGE_TASK_NORMAL,
    SGE_TASK_PERMANENT
};

int sge_init_task_pool(void);
void sge_destroy_task_pool(void);

int sge_init_task_ctrl(struct sge_context* ctx);
int sge_run_task_ctrl(void);
int sge_destroy_task_ctrl(void);
int sge_delivery_task(fn_task_cb cb, void* arg, enum sge_task_flags flags);

int sge_yield_task();


#endif
