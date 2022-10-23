#ifndef SGE_DICT_H_
#define SGE_DICT_H_

#include "core/sge.h"

struct sge_dict;

typedef unsigned long (*fn_dict_hash)(const void*, int);
typedef int (*fn_dict_compare)(const void*, int, const void*, int);

unsigned long string_hash_fn(const void* str, int len);
int string_compare_fn(const void* left_str, int left_len, const void* right_str, int right_len);

unsigned long integer_hash_fn(const void* num, int len);
int integer_compare_fn(const void* left, int left_len, const void* right, int right_len);


struct sge_dict* sge_create_dict(fn_dict_hash hash_fn, fn_dict_compare compare_fn);
int sge_insert_dict(struct sge_dict* dict, const void* key, int len, const void* data);
int sge_remove_dict(struct sge_dict* dict, const void* key, int len);
void* sge_get_dict(struct sge_dict* dict, const void* key, int len);
int sge_empty_dict(struct sge_dict* dict);
int sge_destroy_dict(struct sge_dict* dict);


#endif
