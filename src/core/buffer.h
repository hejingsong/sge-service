#ifndef SGE_BUFFER_H_
#define SGE_BUFFER_H_

struct sge_buffer;

struct sge_buffer* sge_create_buffer(int size);
struct sge_buffer* sge_append_buffer(struct sge_buffer* buf, const char* data, int len);
int sge_erase_buffer(struct sge_buffer* buf, int start, int end);
int sge_buffer_data(struct sge_buffer* buf, char** data);
int sge_destroy_buffer(struct sge_buffer* buf);


#endif
