#include <stddef.h>

#include "core/sge.h"
#include "core/list.h"
#include "core/queue.h"

struct sge_queue {
    size_t cap;
    size_t r;
    size_t w;
    void* data[0];
};

static int queue_full__(struct sge_queue* q) {
    return (q->w + 1) % q->cap == q->r;
}

static int queue_empty__(struct sge_queue* q) {
    return q->r == q->w;
}

int sge_alloc_queue(size_t size, struct sge_queue** queuep) {
    size_t alloc_size = 0;
    struct sge_queue* queue = NULL;

    alloc_size = sizeof(struct sge_queue) + sizeof(void*) * size;
    queue = sge_calloc(alloc_size);
    queue->cap = size;
    queue->r = queue->w = 0;

    *queuep = queue;
    return SGE_OK;
}

int sge_enqueue(struct sge_queue* queue, void* data) {
    if (queue_full__(queue)) {
        return SGE_ERR;
    }

    queue->data[queue->w] = data;
    queue->w = (queue->w + 1) % queue->cap;
    return SGE_OK;
}

int sge_dequeue(struct sge_queue* queue, void** datap) {
    if (queue_empty__(queue)) {
        *datap = NULL;
        return SGE_ERR;
    }

    *datap = queue->data[queue->r];
    queue->r = (queue->r + 1) % queue->cap;
    return SGE_OK;
}

int sge_destroy_queue(struct sge_queue* queue) {
    if (NULL == queue) {
        return SGE_ERR;
    }

    sge_free(queue);
    return SGE_OK;
}

