#ifndef SGE_QUEUE_H_
#define SGE_QUEUE_H_

struct sge_queue;

int sge_alloc_queue(size_t size, struct sge_queue** queuep);
int sge_enqueue(struct sge_queue* queue, void* data);
int sge_dequeue(struct sge_queue* queue, void** datap);
int sge_destroy_queue(struct sge_queue* queue);


#endif
