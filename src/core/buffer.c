#include <string.h>

#include "core/sge.h"
#include "core/log.h"
#include "core/buffer.h"

struct sge_buffer {
    int used;
    int cap;
    char data[0];
};

static int
calc_alloc_size(int size) {
    return sizeof(struct sge_buffer) + sizeof(char) * (size + 1);
}

static struct sge_buffer*
sge_expand_buffer(struct sge_buffer* buf, const char* data, int len) {
    struct sge_buffer* new_buf;
    int remain = buf->cap - buf->used;
    int alloc_size = len - remain;

    alloc_size += calc_alloc_size(buf->cap);
    new_buf = sge_malloc(alloc_size);
    new_buf->cap = buf->cap + len;
    new_buf->used = buf->used + len;
    memcpy(new_buf->data, buf->data, buf->used);
    memcpy(new_buf->data + buf->used, data, len);
    sge_free(buf);
    return new_buf;
}


struct sge_buffer* sge_create_buffer(int size) {
    int alloc_size = calc_alloc_size(size);
    struct sge_buffer* buf = sge_malloc(alloc_size);
    buf->cap = size;
    buf->used = 0;
    return buf;
}

struct sge_buffer* sge_append_buffer(struct sge_buffer* buf, const char* data, int len) {
    int remain;

    if (NULL == buf || NULL == data || len <= 0) {
        SGE_LOG_ERROR("sge_append_buffer invalid arg.");
        return NULL;
    }

    remain = buf->cap - buf->used;
    if (remain >= len) {
        memcpy(buf->data + buf->used, data, len);
        buf->used += len;
    } else {
        buf = sge_expand_buffer(buf, data, len);
    }
    buf->data[buf->used] = '\0';

    return buf;
}

int sge_erase_buffer(struct sge_buffer* buf, int start, int end) {
    int erase_size;

    if (NULL == buf || start < 0 || end < 0 || (start > end)) {
        SGE_LOG_ERROR("sge_erase_buffer invalid arg.");
        return SGE_ERR;
    }

    if (0 == start && 0 == end) {
        return SGE_OK;
    }

    start = (start >= buf->used) ? buf->used : start;
    end = (end >= buf->used) ? buf->used : end;

    erase_size = end - start;
    memcpy(buf->data + start, buf->data + end, erase_size);
    buf->used -= erase_size;
    buf->data[buf->used] = '\0';
    return SGE_OK;
}

int sge_buffer_data(struct sge_buffer* buf, char** data) {
    if (NULL == buf || NULL == data) {
        SGE_LOG_ERROR("sge_buffer_data invalid arg.");
        return SGE_ERR;
    }

    *data = buf->data;
    return buf->used;
}

int sge_destroy_buffer(struct sge_buffer* buf) {
    if (NULL == buf) {
        SGE_LOG_ERROR("sge_destroy_buffer invalid arg.");
        return SGE_ERR;
    }
    sge_free(buf);
    return SGE_OK;
}
