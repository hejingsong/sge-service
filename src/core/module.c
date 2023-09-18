#include <dlfcn.h>
#include <string.h>

#include "core/sge.h"
#include "core/list.h"
#include "core/string.h"
#include "core/module.h"
#include "core/res_pool.h"


int sge_alloc_module(const char* name, size_t name_len, struct sge_module** modulep) {
    struct sge_module* module;

    if (NULL == name || name_len <= 0) {
        return SGE_ERR;
    }

    module = sge_calloc(sizeof(struct sge_module));
    module->initialized = 0;
    sge_dup_string(&module->name, name, name_len);
    SGE_LIST_INIT(&module->list);
    SGE_LIST_INIT(&module->msg_list);
    atomic_store(&module->handle_status, 0);
    SGE_SPINLOCK_INIT(&module->lock);

    *modulep = module;
    return SGE_OK;
}

int sge_init_module(struct sge_module* module) {
    void* handler;
    char dlpath[1024];
    const char* module_name, *dldir;
    struct sge_config* cfg;
    struct sge_module_ops* ops;

    if (NULL == module) {
        return SGE_ERR;
    }

    if (module->initialized) {
        return SGE_OK;
    }

    sge_string_data(module->name, &module_name);
    cfg = module->ctx->cfg;
    sge_get_config(cfg, module_name, "dldir", &dldir);
    if (!dldir) {
        sprintf(dlpath, "lib%s.so", module_name);
    } else {
        sprintf(dlpath, "%s/lib%s.so", dldir, module_name);
    }
    handler = dlopen(dlpath, RTLD_LAZY | RTLD_GLOBAL);
    if (NULL == handler) {
        SGE_LOG(SGE_LOG_LEVEL_ERROR, "can't found module(%s), reason(%s)", dlpath, dlerror());
        goto error;
    }
    ops = dlsym(handler, "module_ops");
    if (NULL == ops) {
        goto dlsym_error;
    }
    if (SGE_ERR == ops->init(module)) {
        SGE_LOG(SGE_LOG_LEVEL_ERROR, "initialize module(%s) error.", module_name);
        goto dlsym_error;
    }
    module->handler = handler;
    module->ops = ops;
    module->initialized = 1;
    SGE_LOG(SGE_LOG_LEVEL_INFO, "module(%s) init success.", module_name);
    return SGE_OK;

dlsym_error:
    dlclose(handler);
error:
    return SGE_ERR;
}

int sge_destroy_module(struct sge_module* module) {
    if (NULL == module) {
        return SGE_ERR;
    }

    SGE_LIST_REMOVE(&module->list);
    if (module->initialized) {
        module->ops->destroy(module);
        dlclose(module->handler);
    }
    sge_destroy_string(module->name);
    SGE_SPINLOCK_DESTROY(&module->lock);
    sge_free(module);

    return SGE_OK;
}

int sge_add_module_msg(struct sge_module* module, struct sge_list* msg) {
    if (NULL == module || NULL == msg) {
        return SGE_ERR;
    }

    SGE_SPINLOCK_LOCK(&module->lock);
    SGE_LIST_ADD_TAIL(&module->msg_list, msg);
    SGE_SPINLOCK_UNLOCK(&module->lock);

    return SGE_OK;
}

int sge_handle_module(struct sge_module* module) {
    int status, ret;
    const char* module_name;
    struct sge_list msg_list;

    if (NULL == module) {
        return SGE_ERR;
    }

    SGE_LIST_INIT(&msg_list);
    sge_string_data(module->name, &module_name);
    status = atomic_load_explicit(&module->handle_status, memory_order_acquire);

    if (status == 1) {
        SGE_LOG(SGE_LOG_LEVEL_DEBUG, "module(%s) already execute handler", module_name);
        return SGE_OK;
    }

    atomic_store_explicit(&module->handle_status, 1, memory_order_release);
    while(1) {
        SGE_SPINLOCK_LOCK(&module->lock);
        SGE_LIST_MOVE(&module->msg_list, &msg_list);
        SGE_SPINLOCK_UNLOCK(&module->lock);

        ret = module->ops->handle(module, &msg_list);
        if (SGE_OK != ret) {
            SGE_LOG(SGE_LOG_LEVEL_ERROR, "module(%s) execute handle callback error. error(%d)", module_name, ret);
        }

        if (SGE_LIST_EMPTY(&module->msg_list)) {
            break;
        }
    }

    atomic_store_explicit(&module->handle_status, 0, memory_order_release);
    return SGE_OK;
}
