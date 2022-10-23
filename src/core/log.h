#ifndef SGE_LOG_H_
#define SGE_LOG_H_

#include <stdlib.h>

enum log_level {
    LOG_LEVEL_DEBUG = 1,
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARN,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_SYS_ERROR
};


int init_logger(int log_lv);
const char** get_log_level_string();
int write_log(int log_lv, const char* filename, int lineno, const char* fmt, ...);

#define SGE_LOG_DEBUG(fmt, ...)     write_log(LOG_LEVEL_DEBUG, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define SGE_LOG_INFO(fmt, ...)      write_log(LOG_LEVEL_INFO, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define SGE_LOG_WARN(fmt, ...)      write_log(LOG_LEVEL_WARN, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define SGE_LOG_ERROR(fmt, ...)     write_log(LOG_LEVEL_ERROR, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define SGE_LOG_SYS_ERROR(fmt, ...) write_log(LOG_LEVEL_SYS_ERROR, __FILE__, __LINE__, fmt, ##__VA_ARGS__)


#endif
