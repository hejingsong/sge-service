#ifndef SGE_TIMER_H_
#define SGE_TIMER_H_



typedef unsigned long sge_timer_id;
typedef int (*sge_timer_cb)(sge_timer_id, void*);

unsigned long sys_time_ms(void);

int sge_init_timer(unsigned long total_ms, unsigned long per_ms);
sge_timer_id sge_add_timer(unsigned long ms, sge_timer_cb cb, void* arg, int repeat);
int sge_cancel_timer(sge_timer_id id);
int sge_tick_timer(void);
int sge_destroy_timer(void);


#endif
