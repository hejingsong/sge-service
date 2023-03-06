#ifndef SGE_CONFIG_H_
#define SGE_CONFIG_H_


#include "core/log.h"
#include "core/list.h"
#include "core/string.h"

struct sge_config {
    struct sge_string* config_file;
    struct sge_string* ori_modules;
    struct sge_string* logname;
    enum sge_log_level log_level;
    const char* user;
    int worker_num;
    int daemonize;

    void* private_data;
};


int sge_alloc_config(const char* cfg_file, struct sge_config** cfg);
int sge_parse_config(struct sge_config* cfg);
int sge_get_config(struct sge_config* cfg, const char *section, const char *key, const char** p);
int sge_destroy_config(struct sge_config* cfg);


#endif
