#ifndef SGE_LOG_H_
#define SGE_LOG_H_

#include <stdio.h>

#include "core/list.h"

enum sge_log_level {
    SGE_LOG_LEVEL_DEBUG = 1,
    SGE_LOG_LEVEL_INFO,
    SGE_LOG_LEVEL_WARN,
    SGE_LOG_LEVEL_ERROR,
    SGE_LOG_LEVEL_SYS_ERROR
};
struct sge_log;
struct sge_log_format_ops {
    int (*init)(struct sge_log*);
    void (*destroy)(struct sge_log*);
    size_t (*format)(char*, struct sge_log*, enum sge_log_level, const char*, size_t, const char*, va_list);
};
struct sge_log_handle_ops {
    int (*init)(struct sge_log*);
    void (*destroy)(struct sge_log*);
    size_t (*handle)(struct sge_log*, const char*, size_t);
};

struct sge_log {
    struct sge_context* ctx;
    struct sge_log_format_ops* format_ops;
    struct sge_log_handle_ops* handle_ops;
    struct sge_list list;
    enum sge_log_level level;
    FILE* stream;
};


int sge_init_log(struct sge_context* ctx, struct sge_log_format_ops* fops, struct sge_log_handle_ops* hops);
int sge_destroy_log(void);
int sge_write_log(enum sge_log_level level, const char* filename, size_t lineno, const char* fmt, ...);
int sge_log_fd(void);


#define SGE_LOG_MAX_LINE_SIZE 1024
#define SGE_LOG(level, fmt, ...)              sge_write_log(level, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#endif
