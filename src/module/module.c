#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

#include "core/sge.h"
#include "core/log.h"
#include "core/list.h"
#include "core/dict.h"
#include "utils/config.h"
#include "module/module.h"


struct sge_module_mgr {
    struct sge_list module_list;
    struct sge_dict* module_ht;
};


struct sge_module {
    struct sge_module_op* op;
    struct sge_list entry;
    void* handle;
    int initialized:1;
    char name[0];
};


static struct sge_module_mgr* g_module_mgr = NULL;

static struct sge_module_mgr*
sge_create_module_mgr() {
    struct sge_module_mgr* mgr;

    mgr = sge_malloc(sizeof(*mgr));
    mgr->module_ht = sge_create_dict(string_hash_fn, string_compare_fn);
    SGE_LIST_INIT(&mgr->module_list);

    return mgr;
}

static void
sge_init_module(struct sge_module* module) {
    int len;
    void* handle;
    const char* dir;
    char module_dir[1024];
    struct sge_module_op* op;

    if (module->initialized == 1) {
        SGE_LOG_WARN("module(%s) already init.", module->name);
        return;
    }

    dir = sge_get_config(module->name, "dir");
    if (dir) {
        len = sprintf(module_dir, "%s/lib%s.so", dir, module->name);
    } else {
        len = sprintf(module_dir, "./lib%s.so", module->name);
    }
    module_dir[len] = '\0';

    handle = dlopen(module_dir, RTLD_NOW);
    if (NULL == handle) {
        SGE_LOG_ERROR("can't load dynamic library(%s)", module->name);
        exit(-1);
    }
    op = dlsym(handle, "MODULE_API");
    if (NULL == op) {
        SGE_LOG_ERROR("can't found MODULE_API in library(%s) ", module->name);
        exit(-1);
    }
    module->op = op;
    module->handle = handle;

    if (SGE_ERR == module->op->init(module)) {
        SGE_LOG_ERROR("global init module(%s) error", module->name);
        exit(-1);
    }
    module->initialized = 1;
    SGE_LOG_DEBUG("module(%s) initialized", module->name);
}

static void
sge_reload_module(struct sge_module* module) {
    int ret;

    if (module->op->reload) {
        ret = module->op->reload(module);
        SGE_LOG_DEBUG("reload module(%s), status(%d)", module->name, ret);
    }
}

static void
sge_destroy_module(struct sge_module* module) {
    if (module->op->destroy) {
        if (SGE_ERR == module->op->destroy(module)) {
            SGE_LOG_DEBUG("module(%s) destroy error.", module->name);
        } else {
            SGE_LOG_DEBUG("module(%s) destroy complete.", module->name);
        }
    }
}


int sge_create_modules(const char* str_modules) {
    int name_len, alloc_size;
    const char *p1, *p2;
    struct sge_module* module;

    if (NULL == g_module_mgr) {
        g_module_mgr = sge_create_module_mgr();
    }

    if (NULL == str_modules) {
        return SGE_ERR;
    }

    p2 = p1 = str_modules;
    while(1) {
        p1 = strstr(p1, ",");
        if (NULL == p1) {
            name_len = strlen(p2);
        } else {
            name_len = p1 - p2;
        }

        alloc_size = sizeof(struct sge_module) + name_len + 1;
        module = sge_malloc(alloc_size);
        module->initialized = 0;
        strncpy(module->name, p2, name_len);
        module->name[name_len] = '\0';

        SGE_LIST_INIT(&module->entry);
        SGE_LIST_ADD_HEAD(&g_module_mgr->module_list, &module->entry);
        sge_insert_dict(g_module_mgr->module_ht, module->name, name_len, module);

        if (p1) {
            p1 += 1;
            p2 = p1;
        } else {
            break;
        }
    }

    return SGE_OK;
}

int sge_init_modules() {
    struct sge_list* head, *iter;
    struct sge_module* m;

    head = &g_module_mgr->module_list;

    SGE_LIST_FOREACH_START
    SGE_LIST_FOREACH(iter, head) {
        m = SGE_CONTAINER_OF(iter, struct sge_module, entry);
        sge_init_module(m);
    }
    SGE_LIST_FOREACH_END
    return SGE_OK;
}

int sge_reload_modules() {
    SGE_LOG_DEBUG("begin reload modules");
    struct sge_list* head, *iter;
    struct sge_module* m;

    head = &g_module_mgr->module_list;

    SGE_LIST_FOREACH_START
    SGE_LIST_FOREACH(iter, head) {
        m = SGE_CONTAINER_OF(iter, struct sge_module, entry);
        sge_reload_module(m);
    }
    SGE_LIST_FOREACH_END
    return SGE_OK;
}

int sge_destroy_modules() {
    SGE_LOG_DEBUG("begin destroy modules");
    struct sge_list* head, *iter;
    struct sge_module* m;

    head = &g_module_mgr->module_list;

    SGE_LIST_FOREACH_START
    SGE_LIST_FOREACH_SAFE(iter, head) {
        m = SGE_CONTAINER_OF(iter, struct sge_module, entry);
        sge_destroy_module(m);
        sge_free(m);
    }
    SGE_LIST_FOREACH_END

    sge_destroy_dict(g_module_mgr->module_ht);

    return SGE_OK;
}

