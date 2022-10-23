#include <stdio.h>

#include "core/sge.h"
#include "core/queue.h"

struct sge_queue {
    int cap;
    int r;
    int w;
    void* data[0];
};

static int
sge_queue_full(struct sge_queue* q) {
    return (q->w + 1) % q->cap == q->r;
}

static int
sge_queue_empty(struct sge_queue* q) {
    return q->r == q->w;
}

struct sge_queue* sge_create_queue(int length) {
    int alloc_size = sizeof(struct sge_queue) + sizeof(void*) * length;
    struct sge_queue* q = sge_malloc(alloc_size);
    q->cap = length;
    q->r = 0;
    q->w = 0;
    return q;
}

int sge_enqueue(struct sge_queue* queue, void* data) {
    if (sge_queue_full(queue)) {
        return SGE_ERR;
    }

    queue->data[queue->w] = data;
    queue->w = (queue->w + 1) % queue->cap;
    return SGE_OK;
}

int sge_dequeue(struct sge_queue* queue, void** data) {
    if (sge_queue_empty(queue)) {
        return SGE_ERR;
    }

    *data = queue->data[queue->r];
    queue->r = (queue->r + 1) % queue->cap;
    return SGE_OK;
}

int sge_reset_queue(struct sge_queue* queue) {
    queue->r = queue->w = 0;
    return SGE_OK;
}

int sge_destroy_queue(struct sge_queue* queue) {
    if (NULL == queue) {
        return SGE_ERR;
    }

    sge_free(queue);
    return SGE_OK;
}
