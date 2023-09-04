#include <string.h>
#include <assert.h>

#include "core/sge.h"
#include "core/log.h"
#include "core/list.h"
#include "core/spinlock.h"
#include "core/res_pool.h"
#include "core/queue.h"

typedef unsigned long ulong;


struct __attribute__ ((__packed__)) sge_res {
    int in_pool:1;
    struct sge_res_pool* pool;
    char data[0];
};

struct sge_res_pool {
    ulong size;
    ulong used;
    ulong item_size;
    struct sge_res_pool_ops* ops;
    struct sge_spinlock lock;
    struct sge_res* items;
    struct sge_queue* frees;
};

static int alloc_res__(struct sge_res_pool* pool, struct sge_res** resp) {
    struct sge_res* res;

    res = sge_malloc(pool->item_size);
    res->in_pool = 0;
    *resp = res;
    return SGE_OK;
}

static int alloc_res_items__(struct sge_res_pool* pool) {
    size_t size;

    size = pool->item_size * pool->size;
    pool->items = sge_malloc(size);

    return SGE_OK;
}

int sge_alloc_res_pool(struct sge_res_pool_ops* ops, size_t size, struct sge_res_pool** poolp) {
    struct sge_res_pool* pool;

    pool = sge_calloc(sizeof(struct sge_res_pool));
    pool->ops = ops;
    pool->used = 0;
    pool->size = size;
    pool->item_size = ops->size() + sizeof(struct sge_res);
    SGE_SPINLOCK_INIT(&pool->lock);
    sge_alloc_queue(size, &pool->frees);
    alloc_res_items__(pool);

    *poolp = pool;
    return SGE_OK;
}

int sge_get_resource(struct sge_res_pool* pool, void** datap) {
    void* free;
    struct sge_res *res;

    SGE_SPINLOCK_LOCK(&pool->lock);
    do {
        if (SGE_OK == sge_dequeue(pool->frees, &free)) {
            res = free;
            break;
        }

        if (pool->used < pool->size) {
            res = pool->items + pool->used * pool->item_size;
            res->in_pool = 1;
            res->pool = pool;
            pool->used++;
            break;
        }

        alloc_res__(pool, &res);
    } while(0);

    SGE_SPINLOCK_UNLOCK(&pool->lock);

    *datap = &(res->data);
    return SGE_OK;
}

int sge_release_resource(void* data) {
    struct sge_res* res;
    struct sge_res_pool* pool;

    if (NULL == data) {
        return SGE_ERR;
    }

    res = sge_container_of(data, struct sge_res, data);
    pool = res->pool;

    if (res->in_pool) {
        SGE_SPINLOCK_LOCK(&pool->lock);
        sge_enqueue(pool->frees, res);
        SGE_SPINLOCK_UNLOCK(&pool->lock);
    } else {
        sge_free(res);
    }

    return SGE_OK;
}

int sge_destroy_res_pool(struct sge_res_pool* pool) {
    struct sge_list* iter, *next;
    struct sge_res* res;

    if (NULL == pool) {
        return SGE_ERR;
    }

    sge_destroy_queue(pool->frees);
    sge_free(pool->items);
    SGE_SPINLOCK_DESTROY(&pool->lock);
    sge_free(pool);
    return SGE_OK;
}
