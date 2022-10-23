#ifndef SGE_RES_POOL_H_
#define SGE_RES_POOL_H_

struct sge_res_pool_op {
    void (*init)(void*);
    void (*reset)(void*);
    int (*destroy)(void*);
    int (*size)();
};

struct sge_res_pool;

struct sge_res_pool* sge_create_res_pool(struct sge_res_pool_op* op, unsigned long size);
int sge_get_resource(struct sge_res_pool* pool, void** data);
int sge_release_resource(void* data);
int sge_destroy_resource(struct sge_res_pool* pool);

#endif
