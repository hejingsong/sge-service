#ifndef SGE_STRING_H_
#define SGE_STRING_H_

struct sge_string;

int sge_init_string_pool(size_t size);
int sge_destroy_string_pool(void);

int sge_alloc_string(int size, struct sge_string** sp);
int sge_dup_string(struct sge_string** sp, const char* p, int len);
int sge_destroy_string(struct sge_string* s);
int sge_string_data(struct sge_string* s, const char** p);

int sge_set_string_len(struct sge_string* s, size_t len);



#endif
