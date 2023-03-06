#include <stdio.h>
#include <string.h>

#include "core/sge.h"
#include "core/string.h"
#include "core/res_pool.h"

struct sge_string {
    int len;
    int size;
    char data[0];
};

static size_t string_size__(void) {
    return sizeof(struct sge_string) + sizeof(char) * (SGE_STRING_SIZE + 1);
}

static int alloc_string_ex__(size_t size, struct sge_string** strp) {
    size_t msize;
    struct sge_string* s;

    msize = sizeof(struct sge_string) + sizeof(char) * (size + 1);
    s = sge_malloc(msize);
    s->size = size;
    s->len = 0;

    *strp = s;
    return SGE_OK;
}

static struct sge_res_pool* string_res_pool;
struct sge_res_pool_ops string_res_pool_ops = {
    .size = string_size__
};


int sge_init_string_pool(void) {
    return sge_alloc_res_pool(&string_res_pool_ops, 1024, &string_res_pool);
}

int sge_destroy_string_pool(void) {
    return sge_destroy_res_pool(string_res_pool);
}


int sge_alloc_string(int size, struct sge_string** sp) {
    int ret;

    if (size <= 0) {
        return SGE_ERR;
    }

    if (size <= SGE_STRING_SIZE) {
        ret = sge_get_resource(string_res_pool, (void**)sp);
        size = SGE_STRING_SIZE;
    } else {
        ret = alloc_string_ex__(size, sp);
    }

    if (SGE_OK == ret) {
        (*sp)->len = 0;
        (*sp)->size = size;
    }

    return ret;
}

int sge_dup_string(struct sge_string** sp, const char* p, int len) {
    int ret;
    struct sge_string* s;

    if (NULL == p || len <= 0) {
        return SGE_ERR;
    }

    ret = sge_alloc_string(len + 1, sp);
    if (SGE_ERR == ret) {
        return SGE_ERR;
    }

    s = *sp;
    s->len = len;
    s->size = len + 1;
    memcpy(s->data, p, len);
    s->data[len + 1] = '\0';

    return SGE_OK;
}

int sge_destroy_string(struct sge_string* s) {
    if (NULL == s) {
        return SGE_ERR;
    }

    if (s->size <= SGE_STRING_SIZE) {
        sge_release_resource(s);
    } else {
        sge_free(s);
    }

    return SGE_OK;
}

int sge_string_data(struct sge_string* s, const char** p) {
    if (NULL == s) {
        return SGE_ERR;
    }

    *p = (const char*)(&s->data);
    return s->len;
}

int sge_set_string_len(struct sge_string* s, size_t len) {
    if (NULL == s) {
        return SGE_ERR;
    }

    s->len = len;
    return SGE_OK;
}
