#include <string.h>
#include <assert.h>

#include "core/sge.h"
#include "core/log.h"
#include "core/list.h"
#include "core/spinlock.h"
#include "core/res_pool.h"

typedef unsigned long ulong;


struct sge_res {
    int in_pool;
    struct sge_list list;
    struct sge_res_pool* pool;
    char data[0];
};

struct sge_res_pool {
    ulong size;
    struct sge_res_pool_ops* ops;
    struct sge_list pool_list;
    struct sge_spinlock lock;
};

static int alloc_res__(struct sge_res_pool* pool, struct sge_res** resp) {
    struct sge_res* res;
    size_t size;

    size = pool->ops->size();
    res = sge_calloc(sizeof(struct sge_res) + size);

    res->in_pool = 0;
    res->pool = pool;
    SGE_LIST_INIT(&res->list);

    *resp = res;
    return SGE_OK;
}

static int alloc_res_items__(struct sge_res_pool* pool) {
    ulong i;
    struct sge_res* res;

    for (i = 0; i < pool->size; ++i) {
        if (SGE_ERR == alloc_res__(pool, &res)) {
            goto error;
        }

        res->in_pool = 1;
        SGE_LIST_ADD_TAIL(&pool->pool_list, &res->list);
    }

    return SGE_OK;
error:
    return SGE_ERR;
}

int sge_alloc_res_pool(struct sge_res_pool_ops* ops, size_t size, struct sge_res_pool** poolp) {
    size_t alloc_size;
    struct sge_res_pool* pool;

    pool = sge_calloc(sizeof(struct sge_res_pool));
    pool->ops = ops;
    pool->size = size;
    SGE_SPINLOCK_INIT(&pool->lock);
    SGE_LIST_INIT(&pool->pool_list);

    if (SGE_ERR == alloc_res_items__(pool)) {
        goto error;
    }

    *poolp = pool;
    return SGE_OK;

error:
    sge_free(pool);
    *poolp = NULL;
    return SGE_ERR;
}

int sge_get_resource(struct sge_res_pool* pool, void** datap) {
    struct sge_res *res;
    struct sge_list* last;

    SGE_SPINLOCK_LOCK(&pool->lock);
    if (!SGE_LIST_EMPTY(&pool->pool_list)) {
        last = SGE_LIST_LAST(&pool->pool_list);
        SGE_LIST_REMOVE(last);
        res = sge_container_of(last, struct sge_res, list);
    } else {
        alloc_res__(pool, &res);
    }
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
        SGE_LIST_ADD_TAIL(&pool->pool_list, &res->list);
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

    SGE_LIST_FOREACH_SAFE(iter, next, &pool->pool_list) {
        res = sge_container_of(iter, struct sge_res, list);
        SGE_LIST_REMOVE(&res->list);
        sge_free(res);
    }
    SGE_SPINLOCK_DESTROY(&pool->lock);
    sge_free(pool);
    return SGE_OK;
}
