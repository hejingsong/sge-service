#ifndef SGE_DICT_H_
#define SGE_DICT_H_


struct sge_dict;
struct sge_dict_ops {
    size_t (*hash)(const void*, size_t);
    int (*compare)(const void*, size_t, const void*, size_t);
};

int sge_alloc_dict(struct sge_dict_ops* ops, struct sge_dict** dictp);
int sge_insert_dict(struct sge_dict* d, const void* key, size_t key_len, const void* data);
int sge_remove_dict(struct sge_dict* d, const void* key, size_t key_len);
int sge_get_dict(struct sge_dict* d, const void* key, size_t key_len, void** datap);
int sge_empty_dict(struct sge_dict* d);
int sge_destroy_dict(struct sge_dict* d);

#endif
