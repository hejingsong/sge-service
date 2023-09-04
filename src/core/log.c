#include <time.h>
#include <errno.h>
#include <libgen.h>
#include <unistd.h>
#include <pthread.h>

#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include "core/sge.h"
#include "core/log.h"
#include "core/context.h"

const char* LEVEL_EN[] = {"UNKNOWN", "DEBUG", "INFO", "WARN", "ERROR", "SYS_ERROR", NULL};

static struct sge_log* g_log;


static int format_date(char* buf, int size) {
    struct tm lt;
    time_t t = time(NULL);

    localtime_r(&t, &lt);
    return strftime(buf, size, "[%Y-%m-%d %H:%M:%d] ", &lt);
}

static int format_log_level(enum sge_log_level log_lv, char* buf, int size) {
    const char* lv_en;

    lv_en = LEVEL_EN[log_lv];
    return snprintf(buf, size, "[%s] ", lv_en);
}

static int format_file_info(const char* filename, int lineno, char* buf, int size) {
    const char* bname = (const char*)basename((char*)filename);
    return snprintf(buf, size, "[%s:%d] ", bname, lineno);
}

static int format_tid(char* buf, int size) {
    return snprintf(buf, size, "[tid:%ld] ", pthread_self());
}

static size_t default_log_format(char* buf, struct sge_log* log, enum sge_log_level level, const char* filename, size_t lineno, const char* fmt, va_list ap) {
    size_t len;
    size_t remain_size = SGE_LOG_MAX_LINE_SIZE;

    len = format_date(buf, remain_size);
    len += format_log_level(level, buf + len, remain_size - len);
    len += format_file_info(filename, lineno, buf + len, remain_size - len);
    len += format_tid(buf + len, remain_size - len);
    len += vsnprintf(buf + len, remain_size - len, fmt, ap);
    buf[len] = '\n';
    buf[len + 1] = '\0';

    return len + 1;
}

static int default_handle_init(struct sge_log* log) {
    const char* p;

    if (log->ctx->cfg->logname) {
        p = log->ctx->cfg->logname;
        log->stream = fopen(p, "ab+");
    } else {
        log->stream = stderr;
    }

    if (NULL == log->stream) {
        fprintf(stderr, "can't open log file: %s\n", p);
        return SGE_ERR;
    }

    return SGE_OK;
}

static int default_handle_destroy(struct sge_log* log) {
    if (NULL == log) {
        return SGE_ERR;
    }

    if (log->stream != stderr) {
        fclose(log->stream);
    }

    return SGE_OK;
}

static size_t default_log_handle(struct sge_log* log, const char* data, size_t len) {
    if (NULL == log || NULL == data || len <= 0) {
        return SGE_ERR;
    }

    fwrite(data, len, 1, log->stream);
    return fflush(log->stream);
}

static struct sge_log_format_ops default_format_ops = {
    .init = NULL,
    .destroy = NULL,
    .format = default_log_format
};

static struct sge_log_handle_ops default_handle_ops = {
    .init = default_handle_init,
    .destroy = NULL,
    .handle = default_log_handle
};


int sge_init_log(struct sge_context* ctx, struct sge_log_format_ops* fops, struct sge_log_handle_ops* hops) {
    int ret;
    struct sge_log* log;

    log = sge_calloc(sizeof(struct sge_log));
    log->format_ops = fops ? fops : &default_format_ops;
    log->handle_ops = hops ? hops : &default_handle_ops;
    log->level = ctx->cfg->log_level;
    log->ctx = ctx;

    ret = log->format_ops->init ? log->format_ops->init(log) : SGE_OK;
    if (SGE_ERR == ret) {
        goto error;
    }

    ret = log->handle_ops->init ? log->handle_ops->init(log) : SGE_OK;
    if (SGE_ERR == ret) {
        goto handle_error;
    }

    g_log = log;
    return SGE_OK;

handle_error:
    if (log->format_ops->destroy) {
        log->format_ops->destroy(log);
    }
error:
    sge_free(log);
    return SGE_ERR;
}

int sge_destroy_log() {
    if (g_log) {
        if (g_log->format_ops->destroy) {
            g_log->format_ops->destroy(g_log);
        }
        if (g_log->handle_ops->destroy) {
            g_log->handle_ops->destroy(g_log);
        }
        sge_free(g_log);
    }

    return SGE_OK;
}

int sge_write_log(enum sge_log_level level, const char* filename, size_t lineno, const char* fmt, ...) {
    size_t len;
    va_list ap;
    char buf[SGE_LOG_MAX_LINE_SIZE];

    if (!g_log) {
        return SGE_ERR;
    }

    if (level < g_log->level) {
        return SGE_OK;
    }

    va_start(ap, fmt);
    len = g_log->format_ops->format(buf, g_log, level, filename, lineno, fmt, ap);
    va_end(ap);

    if (SGE_ERR == g_log->handle_ops->handle(g_log, buf, len)) {
        return SGE_ERR;
    }

    return SGE_OK;
}

int sge_log_fd(void) {
    if (!g_log) {
        return SGE_ERR;
    }

    return fileno(g_log->stream);
}
