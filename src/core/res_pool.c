#include <math.h>
#include <string.h>
#include <assert.h>

#include "core/sge.h"
#include "core/log.h"
#include "core/list.h"
#include "core/spinlock.h"
#include "core/res_pool.h"

#define min(x, y) (((x) < (y)) ? (x) : (y))

static const unsigned long PRE_SIZE = sizeof(unsigned long) * 8;


struct sge_res {
    int in_pool;
    unsigned long idx;
    struct sge_res_pool* pool;
    char data[0];
};

struct sge_res_pool {
    struct sge_res_pool_op* op;
    unsigned long size;
    unsigned long res_size;
    struct sge_res* pool;
    struct sge_spinlock lock;
    char bitmap[0];
};

static unsigned long
fls(unsigned long x) {
    unsigned long i;
    unsigned long position;

    if (0 != x) {
        for (i = (x >> 1), position = 0; i != 0; ++position) {
            i >>= 1;
        }
    } else {
        position = -1;
    }

    return position + 1;
}

static unsigned long
roundup_pow_of_two(unsigned long n) {
    return 1UL << fls(n - 1);
}

static unsigned long
ffz(unsigned long v) {
    unsigned long i;
    unsigned long len = sizeof(unsigned long) * 8;

    for (i = 0; i < len; ++i) {
        if ((v & (1UL << i)) == 0) {
            return i;
        }
    }

    assert(1 == 0);
}

static unsigned long
find_first_zero_bit(const unsigned long *addr, unsigned long size) {
    unsigned long idx;

    for (idx = 0; idx * PRE_SIZE < size; idx++) {
        if (addr[idx] != ~0UL)
            return min(idx * PRE_SIZE + ffz(addr[idx]), size);
    }

    return size;
}

static void
set_bit(unsigned long* addr, unsigned long pos) {
    unsigned long idx;
    unsigned long sub_idx;

    idx = pos / PRE_SIZE;
    sub_idx = pos % PRE_SIZE;

    addr[idx] = addr[idx] | (1UL << sub_idx);
}

static void
reset_bit(unsigned long* addr, unsigned long pos) {
    unsigned long idx;
    unsigned long sub_idx;

    idx = pos / PRE_SIZE;
    sub_idx = pos % PRE_SIZE;

    addr[idx] = addr[idx] & ~(1UL << sub_idx);
}

static struct sge_res*
sge_get_res(struct sge_res_pool* pool, unsigned long idx) {
    return (void*)pool->pool + (pool->res_size * idx);
}

static void
sge_init_pool(struct sge_res_pool* pool) {
    unsigned long i;
    struct sge_res* res;

    pool->pool = sge_malloc(pool->res_size * pool->size);
    for (i = 0; i < pool->size; ++i) {
        res = sge_get_res(pool, i);
        res->idx = i;
        res->in_pool = 1;
        res->pool = pool;
        pool->op->init((void*)&res->data);
    }
    SGE_SPINLOCK_INIT(&pool->lock);
}

static void
sge_release_resource_(struct sge_res_pool* pool, struct sge_res* res) {
    SGE_SPINLOCK_LOCK(&pool->lock);
    reset_bit((unsigned long*)(&pool->bitmap), res->idx);
    SGE_SPINLOCK_UNLOCK(&pool->lock);
}

struct sge_res_pool* sge_create_res_pool(struct sge_res_pool_op* op, unsigned long size) {
    int alloc_size;
    struct sge_res_pool* pool;

    size = roundup_pow_of_two(size);
    alloc_size = sizeof(struct sge_res_pool) + size;
    pool = sge_malloc(alloc_size);
    pool->op = op;
    pool->size = size;
    pool->res_size = sizeof(struct sge_res) + pool->op->size();
    memset(&(pool->bitmap), 0, size);
    sge_init_pool(pool);
    return pool;
}

int sge_get_resource(struct sge_res_pool* pool, void** data) {
    int idx;
    struct sge_res *res;
    unsigned long *p = (unsigned long*)&pool->bitmap;

    SGE_SPINLOCK_LOCK(&pool->lock);

    idx = find_first_zero_bit(p, pool->size);
    if (idx < pool->size) {
        set_bit((unsigned long*)(&pool->bitmap), idx);
        res = sge_get_res(pool, idx);
    } else {
        res = sge_malloc(pool->res_size);
        res->in_pool = 0;
        res->idx = 0;
        res->pool = pool;
    }
    if (pool->op->reset) {
        pool->op->reset((void*)(&res->data));
    }
    *data = &(res->data);

    SGE_SPINLOCK_UNLOCK(&pool->lock);

    return SGE_OK;
}

int sge_release_resource(void* data) {
    struct sge_res* res;

    res = SGE_CONTAINER_OF(data, struct sge_res, data);
    if (res->in_pool == 0) {
        sge_free(res);
    } else {
        sge_release_resource_(res->pool, res);
    }

    return SGE_OK;
}

int sge_destroy_resource(struct sge_res_pool* pool) {
    unsigned long i;
    struct sge_res* res;

    SGE_SPINLOCK_LOCK(&pool->lock);

    if (pool->op->destroy) {
        for (i = 0; i < pool->size; ++i) {
            res = sge_get_res(pool, i);
            pool->op->destroy((void*)&res->data);
        }
    }

    sge_free(pool->pool);
    sge_free(pool);

    SGE_SPINLOCK_UNLOCK(&pool->lock);
    SGE_SPINLOCK_DESTROY(&pool->lock);
    return SGE_OK;
}
