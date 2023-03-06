#ifndef SGE_RES_POOL_H_
#define SGE_RES_POOL_H_

#include <stddef.h>

struct sge_res_pool;
struct sge_res_pool_ops {
    size_t (*size)(void);
};


int sge_alloc_res_pool(struct sge_res_pool_ops* ops, size_t size, struct sge_res_pool** poolp);
int sge_get_resource(struct sge_res_pool* p, void** datap);
int sge_release_resource(void* data);
int sge_destroy_res_pool(struct sge_res_pool* p);

#endif
