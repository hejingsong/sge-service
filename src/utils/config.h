#ifndef CONFIG_H_
#define CONFIG_H_


int sge_parse_config(const char* cfg_file);
int sge_get_log_level();
int sge_get_thread_num();
int sge_get_event_type();
int sge_get_meta_pool_size();
int sge_get_connection_pool_size();
const char* sge_get_worker_dir();
const char* sge_get_modules();
const char* sge_get_config(const char *section, const char *key);



#endif
