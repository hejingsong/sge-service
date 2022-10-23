#ifndef SGE_EVENT_POOL_H_
#define SGE_EVENT_POOL_H_

struct sge_event;

int sge_create_event_pool(int size);
int sge_get_event(struct sge_event** event);
int sge_release_event(struct sge_event* event);
int sge_destroy_event_pool();

#endif
