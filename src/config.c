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

static int parse_user(ini_t* ini, struct sge_config* cfg) {
    const char* p;

    if (SGE_ERR == parse_string(ini, "core", "user", &p)) {
        cfg->user = NULL;
        return SGE_OK;
    }

    cfg->user = p;
    return SGE_OK;
}

static int parse_daemonize(ini_t* ini, struct sge_config* cfg) {
    int status;

    if (SGE_ERR == parse_integer(ini, "core", "daemonize", &status)) {
        status = 0;
    }

    cfg->daemonize = status;
    return SGE_OK;
}

static int parse_modules(ini_t* ini, struct sge_config* cfg) {
    const char* p;

    parse_string(ini, "core", "modules", &p);
    if (NULL == p) {
        cfg->ori_modules = NULL;
    } else {
        sge_dup_string(&cfg->ori_modules, p, strlen(p));
    }

    return SGE_OK;
}

static int parse_logname(ini_t* ini, struct sge_config* cfg) {
    const char* p;

    parse_string(ini, "core", "logname", &p);
    if (NULL == p) {
        cfg->logname = NULL;
    } else {
        sge_dup_string(&cfg->logname, p, strlen(p));
    }

    return SGE_OK;
}


int sge_alloc_config(const char* cfg_file, struct sge_config** cfgp) {
    int ret;
    struct sge_config* cfg;

    cfg = sge_calloc(sizeof(struct sge_config));
    ret = sge_dup_string(&cfg->config_file, cfg_file, strlen(cfg_file));
    if (SGE_ERR == ret) {
        goto error;
    }

    *cfgp = cfg;
    return SGE_OK;

error:
    sge_free(cfg);
    return SGE_ERR;
}

int sge_parse_config(struct sge_config* cfg) {
    int ret;
    ini_t* ini;
    const char* cfg_file;

    if (NULL == cfg || NULL == cfg->config_file) {
        return SGE_ERR;
    }

    sge_string_data(cfg->config_file, &cfg_file);
    ini = ini_load(cfg_file);
    if (NULL == ini) {
        goto err;
    }

    parse_log_level(ini, cfg);
    parse_modules(ini, cfg);
    parse_logname(ini, cfg);
    parse_worker_num(ini, cfg);
    parse_user(ini, cfg);
    parse_daemonize(ini, cfg);

    cfg->private_data = ini;
    return SGE_OK;
err:
    return SGE_ERR;
}

int sge_get_config(struct sge_config* cfg, const char *section, const char *key, const char** p) {
    const char* val;

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

    sge_destroy_string(cfg->config_file);
    sge_destroy_string(cfg->ori_modules);
    if (cfg->private_data) {
        ini_free(cfg->private_data);
    }
    sge_free(cfg);

    return SGE_OK;
}

