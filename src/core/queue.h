#ifndef SGE_QUEUE_H_
#define SGE_QUEUE_H_


struct sge_queue;

struct sge_queue* sge_create_queue(int length);
int sge_enqueue(struct sge_queue* queue, void* data);
int sge_dequeue(struct sge_queue* queue, void** data);
int sge_reset_queue(struct sge_queue* queue);
int sge_destroy_queue(struct sge_queue* queue);


#endif
