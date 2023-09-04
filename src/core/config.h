#ifndef SGE_CONFIG_H_
#define SGE_CONFIG_H_


#include "core/log.h"
#include "core/list.h"
#include "core/string.h"

struct sge_config {
    enum sge_log_level log_level;
    char* logname;
    char* config_file;
    char* ori_modules;
    char* user;
    int worker_num;
    int string_pool_size;
    int event_pool_size;
    int socket_pool_size;
    int task_pool_size;
    int daemonize;

    void* private_data;
};


int sge_alloc_config(const char* cfg_file, struct sge_config** cfg);
int sge_parse_config(struct sge_config* cfg);
int sge_get_config(struct sge_config* cfg, const char *section, const char *key, const char** p);
int sge_destroy_config(struct sge_config* cfg);


#endif
