#include <unistd.h>

#include <string.h>

#include "core/sge.h"
#include "core/log.h"
#include "core/string.h"
#include "core/config.h"
#include "ini.h"

extern const char* LEVEL_EN[];


static int parse_integer(ini_t* ini, const char *section, const char *key, int* p) {
    const char* val;
    int v = 0;

    val = ini_get(ini, section, key);
    if (val) {
        v = atoi(val);
    }

    if (v == 0) {
        return SGE_ERR;
    }

    *p = v;
    return SGE_OK;
}

static int parse_string(ini_t* ini, const char *section, const char *key, const char** p) {
    const char *val;
    int ret = SGE_OK;

    val = ini_get(ini, section, key);
    if (NULL == val) {
        ret = SGE_ERR;
    }

    *p = val;
    return ret;
}


static int parse_log_level(ini_t* ini, struct sge_config* cfg) {
    int i;
    const char *p, *val;

    if (SGE_ERR == parse_string(ini, "core", "log_level", &val)) {
        val = "DEBUG";
    }

    for (i = 0; LEVEL_EN[i] != NULL; ++i) {
        p = LEVEL_EN[i];
        if (0 == strcmp(p, val)) {
            cfg->log_level = i;
            break;
        }
    }

    return SGE_OK;
}

static int parse_worker_num(ini_t* ini, struct sge_config* cfg) {
    int size;

    if (SGE_ERR == parse_integer(ini, "core", "worker_num", &size)) {
        size = sysconf(_SC_NPROCESSORS_ONLN);
    }

    cfg->worker_num = size;
    return SGE_OK;
}

static void parse_default_integer(ini_t *ini, const char* section, const char* key, int default_val, int *pval) {
    int val;

    if (SGE_ERR == parse_integer(ini, section, key, &val)) {
        val = default_val;
    }

    *pval = val;
}

static void parse_string_common(ini_t *ini, const char* section, const char* key, char* default_val, char** pval) {
    const char* p;
    char* v;
    size_t len;

    parse_string(ini, section, key, &p);
    if (NULL == p) {
        v = default_val;
    } else {
        len = strlen(p);
        v = sge_malloc(len + 1);
        strncpy(v, p, len);
        v[len + 1] = '\0';
    }

    *pval = v;
}

static int parse_daemonize(ini_t* ini, struct sge_config* cfg) {
    int status;

    if (SGE_ERR == parse_integer(ini, "core", "daemonize", &status)) {
        status = 0;
    }

    cfg->daemonize = status;
    return SGE_OK;
}

int sge_alloc_config(const char* cfg_file, struct sge_config** cfgp) {
    struct sge_config* cfg;
    size_t config_file_len = strlen(cfg_file);

    cfg = sge_calloc(sizeof(struct sge_config));
    cfg->config_file = sge_malloc(config_file_len + 1);
    strncpy(cfg->config_file, cfg_file, config_file_len);
    cfg->config_file[config_file_len + 1] = '\0';

    *cfgp = cfg;
    return SGE_OK;
}

int sge_parse_config(struct sge_config* cfg) {
    ini_t* ini;

    if (NULL == cfg || NULL == cfg->config_file) {
        return SGE_ERR;
    }

    ini = ini_load(cfg->config_file);
    if (NULL == ini) {
        goto err;
    }

    parse_log_level(ini, cfg);
    parse_worker_num(ini, cfg);
    parse_default_integer(ini, "core", "string_pool_size", 1024, &cfg->string_pool_size);
    parse_default_integer(ini, "core", "event_pool_size", 1024, &cfg->event_pool_size);
    parse_default_integer(ini, "core", "socket_pool_size", 1024, &cfg->socket_pool_size);
    parse_default_integer(ini, "core", "task_pool_size", 1024, &cfg->task_pool_size);
    parse_string_common(ini, "core", "modules", NULL, &cfg->ori_modules);
    parse_string_common(ini, "core", "logname", NULL, &cfg->logname);
    parse_string_common(ini, "core", "user", NULL, &cfg->user);
    parse_daemonize(ini, cfg);

    cfg->private_data = ini;
    return SGE_OK;
err:
    return SGE_ERR;
}

int sge_get_config(struct sge_config* cfg, const char *section, const char *key, const char** p) {
    if (NULL == cfg || NULL == section || NULL == key) {
        return SGE_ERR;
    }

    *p = ini_get((ini_t *)cfg->private_data, section, key);
    return SGE_OK;
}

int sge_destroy_config(struct sge_config* cfg) {
    if (NULL == cfg) {
        return SGE_ERR;
    }

    if (cfg->ori_modules) sge_free(cfg->ori_modules);
    if (cfg->logname) sge_free(cfg->logname);
    if (cfg->user) sge_free(cfg->user);
    sge_free(cfg->config_file);
    if (cfg->private_data) {
        ini_free(cfg->private_data);
    }
    sge_free(cfg);

    return SGE_OK;
}

