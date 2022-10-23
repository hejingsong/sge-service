#include <string.h>

#include "core/sge.h"
#include "core/dict.h"
#include "core/list.h"

#define SGE_DICT_SLOT_SIZE 512

struct sge_dict_node {
    struct sge_list l;
    const void* data;
    const void* key;
    int keylen;
};

struct sge_dict {
    fn_dict_hash hash_fn;
    fn_dict_compare compare_fn;
    int mask;
    int count;
    struct sge_list slots[SGE_DICT_SLOT_SIZE];
};

static struct sge_dict_node*
find_dict_(struct sge_dict* dict, const void* key, int keylen) {
    int slot;
    struct sge_list* head, *iter;
    struct sge_dict_node* node;

    slot = dict->hash_fn(key, keylen) & dict->mask;
    head = &(dict->slots[slot]);

    SGE_LIST_FOREACH_START
    SGE_LIST_FOREACH(iter, head) {
        node = SGE_CONTAINER_OF(iter, struct sge_dict_node, l);
        if (0 == dict->compare_fn(node->key, node->keylen, key, keylen)) {
            return node;
        }
    }
    SGE_LIST_FOREACH_END

    return NULL;
}

unsigned long string_hash_fn(const void* str, int len) {
    const char* pstr = (const char*)str;
    register unsigned long hash = 5381;

    for (; len >= 8; len -= 8) {
        hash = ((hash << 5) + hash) + *pstr++;
        hash = ((hash << 5) + hash) + *pstr++;
        hash = ((hash << 5) + hash) + *pstr++;
        hash = ((hash << 5) + hash) + *pstr++;
        hash = ((hash << 5) + hash) + *pstr++;
        hash = ((hash << 5) + hash) + *pstr++;
        hash = ((hash << 5) + hash) + *pstr++;
        hash = ((hash << 5) + hash) + *pstr++;
    }

    switch (len) {
        case 7: hash = ((hash << 5) + hash) + *pstr++;
        case 6: hash = ((hash << 5) + hash) + *pstr++;
        case 5: hash = ((hash << 5) + hash) + *pstr++;
        case 4: hash = ((hash << 5) + hash) + *pstr++;
        case 3: hash = ((hash << 5) + hash) + *pstr++;
        case 2: hash = ((hash << 5) + hash) + *pstr++;
        case 1: hash = ((hash << 5) + hash) + *pstr++; break;
        case 0: break;
        default: break;
    }

    return hash;
}

int string_compare_fn(const void* left_str, int left_len, const void* right_str, int right_len) {
    const char* left = (const char*)left_str;
    const char* right = (const char*)right_str;
    int len = (left_len > right_len) ? right_len : left_len;
    
    return strncmp(left, right, (size_t)len);
}

unsigned long integer_hash_fn(const void* num, int len) {
    return (unsigned long)num;
}

int integer_compare_fn(const void* left, int left_len, const void* right, int right_len) {
    unsigned long left_val, right_val;

    left_val = (unsigned long)left;
    right_val = (unsigned long)right;

    if (left < right) {
        return -1;
    } else if (left > right) {
        return 1;
    } else {
        return 0;
    }
}

struct sge_dict* sge_create_dict(fn_dict_hash hash_fn, fn_dict_compare compare_fn) {
    int i;
    struct sge_dict* dict;

    dict = sge_malloc(sizeof(struct sge_dict));
    dict->compare_fn = compare_fn;
    dict->hash_fn = hash_fn;
    dict->mask = SGE_DICT_SLOT_SIZE - 1;
    dict->count = 0;
    for (i = 0; i < SGE_DICT_SLOT_SIZE; ++i) {
        SGE_LIST_INIT(&(dict->slots[i]));
    }
    return dict;
}

int sge_insert_dict(struct sge_dict* dict, const void* key, int len, const void* data) {
    int slot;
    struct sge_dict_node* node;
    struct sge_list* head;

    node = find_dict_(dict, key, len);
    if (node) {
        node->data = data;
        return SGE_OK;
    }

    node = sge_malloc(sizeof(struct sge_dict_node));
    node->data = data;
    node->key = key;
    node->keylen = len;
    SGE_LIST_INIT(&(node->l));

    slot = dict->hash_fn(key, len) & dict->mask;
    head = &(dict->slots[slot]);
    SGE_LIST_ADD_TAIL(head, &(node->l));
    dict->count += 1;

    return SGE_OK;
}

int sge_remove_dict(struct sge_dict* dict, const void* key, int len) {
    struct sge_dict_node* node;

    node = find_dict_(dict, key, len);
    if (NULL == node) {
        return SGE_OK;
    }

    SGE_LIST_REMOVE(&(node->l));
    sge_free(node);
    dict->count -= 1;

    return SGE_OK;
}

void* sge_get_dict(struct sge_dict* dict, const void* key, int len) {
    struct sge_dict_node* node;

    node = find_dict_(dict, key, len);
    if (NULL == node) {
        return NULL;
    }
    return (void*)node->data;
}

int sge_empty_dict(struct sge_dict* dict) {
    if (0 == dict->count) {
        return SGE_OK;
    } else {
        return SGE_ERR;
    }
}

int sge_destroy_dict(struct sge_dict* dict) {
    int slot;
    struct sge_list* head, *iter;
    struct sge_dict_node* node;

    for (slot = 0; slot < SGE_DICT_SLOT_SIZE; ++slot) {
        head = &(dict->slots[slot]);
        SGE_LIST_FOREACH_START
        SGE_LIST_FOREACH_SAFE(iter, head) {
            node = SGE_CONTAINER_OF(iter, struct sge_dict_node, l);
            sge_free(node);
        }
        SGE_LIST_FOREACH_END
    }

    sge_free(dict);
    return SGE_OK;
}
