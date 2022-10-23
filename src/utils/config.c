#include <unistd.h>

#include <string.h>

#include "core/sge.h"
#include "core/log.h"
#include "utils/config.h"
#include "event/event_mgr.h"

#include "ini.h"


struct sge_config {
    int log_lv;
    int event_type;
    int thread_num;
    int meta_pool_size;
    int connection_pool_size;
    const char* worker_dir;
    const char* modules;
    void* private;
};

static struct sge_config* g_cfg = NULL;


static int
sge_parse_log_level(struct sge_config* cfg) {
    int i, lv;
    ini_t* ini = (ini_t*)cfg->private;
    const char* p, *val;
    const char** LEVEL_EN = get_log_level_string();

    val = ini_get(ini, "core", "log_level");
    if (val) {
        for (i = 0, p = LEVEL_EN[0]; p != NULL; p = LEVEL_EN[++i]) {
            if (0 == strcmp(p, val)) {
                lv = i;
                break;
            }
        }
    }

    cfg->log_lv = lv;
    return SGE_OK;
}

static int
sge_parse_event_type(struct sge_config* cfg) {
    const char* p;
    int type = EVENT_MGR_TYPE_EPOLL;
    ini_t* ini = (ini_t*)cfg->private;

    p = ini_get(ini, "core", "event_type");
    if (p) {
        if (0 == strcmp(p, "EPOLL")) {
            type = EVENT_MGR_TYPE_EPOLL;
        } else if (0 == strcmp(p, "IO_URING")) {
            type = EVENT_MGR_TYPE_IO_URING;
        }
    }

    cfg->event_type = type;
    return SGE_OK;
}

static int
sge_parse_meta_pool_size(struct sge_config* cfg) {
    int size;
    const char* p;

    p = ini_get((ini_t*)cfg->private, "core", "meta_pool_size");
    if (NULL == p) {
        size = 100;
    } else {
        size = atoi(p);
    }

    cfg->meta_pool_size = size;
    return SGE_OK;
}

static int
sge_parse_connection_pool_size(struct sge_config* cfg) {
    int size;
    const char* p;

    p = ini_get((ini_t*)cfg->private, "core", "connection_pool_size");
    if (NULL == p) {
        size = 100;
    } else {
        size = atoi(p);
    }

    cfg->connection_pool_size = size;
    return SGE_OK;
}

static int
sge_parse_modules(struct sge_config* cfg) {
    const char* p;

    p = ini_get((ini_t*)cfg->private, "core", "modules");
    cfg->modules = p;

    return SGE_OK;
}

static int
sge_parse_worker_dir(struct sge_config* cfg) {
    const char* p;

    p = ini_get((ini_t*)cfg->private, "core", "worker_dir");
    if (NULL == p) {
        cfg->worker_dir = "./";
    } else {
        cfg->worker_dir = p;
    }

    return SGE_OK;
}


int sge_parse_config(const char* cfg_file) {
    ini_t* handler = ini_load(cfg_file);
    if (NULL == handler) {
        SGE_LOG_ERROR("parse config file error.");
        return SGE_ERR;
    }

    g_cfg = sge_malloc(sizeof(struct sge_config));
    g_cfg->private = (void*)handler;
    g_cfg->thread_num = sysconf(_SC_NPROCESSORS_ONLN);

    sge_parse_log_level(g_cfg);
    sge_parse_event_type(g_cfg);
    sge_parse_modules(g_cfg);
    sge_parse_worker_dir(g_cfg);
    sge_parse_meta_pool_size(g_cfg);
    sge_parse_connection_pool_size(g_cfg);

    return SGE_OK;
}

int sge_get_log_level() {
    return g_cfg->log_lv;
}

int sge_get_thread_num() {
    return g_cfg->thread_num;
}

int sge_get_event_type() {
    return g_cfg->event_type;
}

int sge_get_meta_pool_size() {
    return g_cfg->meta_pool_size;
}

int sge_get_connection_pool_size() {
    return g_cfg->connection_pool_size;
}

const char* sge_get_worker_dir() {
    return g_cfg->worker_dir;
}

const char* sge_get_modules() {
    return g_cfg->modules;
}

const char* sge_get_config(const char *section, const char *key) {
    return ini_get((ini_t*)g_cfg->private, section, key);
}
