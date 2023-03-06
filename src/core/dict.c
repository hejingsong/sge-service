#include <string.h>

#include "core/sge.h"
#include "core/list.h"
#include "core/dict.h"

struct sge_dict_node {
    struct sge_list list;
    const void* key;
    size_t key_len;
    const void* data;
};

struct sge_dict_entry {
    int slot;
    struct sge_list list;
};

struct sge_dict {
    size_t count;
    size_t mask;
    struct sge_dict_ops* ops;
    struct sge_dict_entry entries[SGE_DICT_SLOT_SIZE];
};

static size_t string_hash_fn__(const void* key, size_t len) {
    const char* pkey = (const char*)key;
    register unsigned long hash = 5381;

    for (; len >= 8; len -= 8) {
        hash = ((hash << 5) + hash) + *pkey++;
        hash = ((hash << 5) + hash) + *pkey++;
        hash = ((hash << 5) + hash) + *pkey++;
        hash = ((hash << 5) + hash) + *pkey++;
        hash = ((hash << 5) + hash) + *pkey++;
        hash = ((hash << 5) + hash) + *pkey++;
        hash = ((hash << 5) + hash) + *pkey++;
        hash = ((hash << 5) + hash) + *pkey++;
    }

    switch (len) {
        case 7: hash = ((hash << 5) + hash) + *pkey++;
        case 6: hash = ((hash << 5) + hash) + *pkey++;
        case 5: hash = ((hash << 5) + hash) + *pkey++;
        case 4: hash = ((hash << 5) + hash) + *pkey++;
        case 3: hash = ((hash << 5) + hash) + *pkey++;
        case 2: hash = ((hash << 5) + hash) + *pkey++;
        case 1: hash = ((hash << 5) + hash) + *pkey++; break;
        case 0: break;
        default: break;
    }

    return hash;
};

static int string_compare_fn__(const void* key1, size_t key_len1, const void* key2, size_t key_len2) {
    const char* left = (const char*)key1;
    const char* right = (const char*)key2;
    size_t len = (key_len1 > key_len2) ? key_len2 : key_len1;
    
    return strncmp(left, right, len);
}

static size_t integer_hash_fn__(const void* key, size_t _len) {
    return (size_t)key;
}

static int integer_compare_fn__(const void* key1, size_t _key_len1, const void* key2, size_t _key_len2) {
    unsigned long left_val, right_val;

    left_val = (unsigned long)key1;
    right_val = (unsigned long)key2;

    if (left_val < right_val) {
        return -1;
    } else if (left_val > right_val) {
        return 1;
    } else {
        return 0;
    }
}

static void get_dict_entry__(struct sge_dict* d, const void* key, size_t key_len, struct sge_dict_entry** entryp) {
    size_t hash;

    hash = d->ops->hash(key, key_len) & d->mask;
    *entryp = &d->entries[hash];
}

static int find_dict__(struct sge_dict_ops* ops, struct sge_dict_entry* entry, const void* key, size_t key_len, struct sge_dict_node** nodep) {
    struct sge_list* iter;
    struct sge_dict_node* node;

    SGE_LIST_FOREACH(iter, &entry->list) {
        node = sge_container_of(iter, struct sge_dict_node, list);
        if (0 == ops->compare(node->key, node->key_len, key, key_len)) {
            *nodep = node;
            return SGE_OK;
        }
    }

    *nodep = NULL;
    return SGE_ERR;
}

struct sge_dict_ops string_dict_ops = {
    .compare = string_compare_fn__,
    .hash = string_hash_fn__
};

struct sge_dict_ops integer_dict_ops = {
    .compare = integer_compare_fn__,
    .hash = integer_hash_fn__
};

int sge_alloc_dict(struct sge_dict_ops* ops, struct sge_dict** dictp) {
    int i;
    struct sge_dict* dict;
    struct sge_dict_entry* entry;

    if (NULL == ops) {
        return SGE_ERR;
    }

    dict = sge_calloc(sizeof(struct sge_dict));
    dict->count = 0;
    dict->mask = SGE_DICT_SLOT_SIZE - 1;
    dict->ops = ops;
    for (i = 0; i < SGE_DICT_SLOT_SIZE; ++i) {
        entry = &(dict->entries[i]);
        SGE_LIST_INIT(&entry->list);
        entry->slot = i;
    }

    *dictp = dict;
    return SGE_OK;
}

int sge_insert_dict(struct sge_dict* d, const void* key, size_t key_len, const void* data) {
    struct sge_dict_node* node;
    struct sge_dict_entry* entry;

    if (NULL == d || NULL == key || key_len <= 0 || NULL == data) {
        return SGE_ERR;
    }

    get_dict_entry__(d, key, key_len, &entry);
    if (SGE_ERR == find_dict__(d->ops, entry, key, key_len, &node)) {
        node = sge_calloc(sizeof(struct sge_dict_node));
        node->data = data;
        node->key = key;
        node->key_len = key_len;
        SGE_LIST_INIT(&node->list);
        SGE_LIST_ADD_TAIL(&entry->list, &node->list);
        d->count++;
    } else {
        node->data = data;
    }

    return SGE_OK;
}

int sge_remove_dict(struct sge_dict* d, const void* key, size_t key_len) {
    struct sge_dict_node* node;
    struct sge_dict_entry* entry;

    if (NULL == d || NULL == key || key_len <= 0) {
        return SGE_ERR;
    }

    get_dict_entry__(d, key, key_len, &entry);
    if (SGE_ERR == find_dict__(d->ops, entry, key, key_len, &node)) {
        return SGE_ERR;
    }

    SGE_LIST_REMOVE(&node->list);
    sge_free(node);
    d->count--;

    return SGE_OK;
}

int sge_get_dict(struct sge_dict* d, const void* key, size_t key_len, void** datap) {
    struct sge_dict_node* node;
    struct sge_dict_entry* entry;

    if (NULL == d || NULL == key || key_len <= 0) {
        *datap = NULL;
        return SGE_ERR;
    }

    get_dict_entry__(d, key, key_len, &entry);
    if (SGE_ERR == find_dict__(d->ops, entry, key, key_len, &node)) {
        *datap = NULL;
        return SGE_ERR;
    }

    *datap = (void*)node->data;
    return SGE_OK;
}

int sge_destroy_dict(struct sge_dict* d) {
    int i;
    struct sge_dict_node* node;
    struct sge_dict_entry* entry;
    struct sge_list* iter, *next;

    for (i = 0; i < SGE_DICT_SLOT_SIZE; ++i) {
        entry = &(d->entries[i]);
        SGE_LIST_FOREACH_SAFE(iter, next, &entry->list) {
            node = sge_container_of(iter, struct sge_dict_node, list);
            SGE_LIST_REMOVE(&node->list);
            sge_free(node);
        }
    }
    sge_free(d);

    return SGE_OK;
}

