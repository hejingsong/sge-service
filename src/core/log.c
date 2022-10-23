#include <time.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <libgen.h>
#include <unistd.h>

#include "core/sge.h"
#include "core/log.h"

#define MAX_LINE_SIZE 1024

static const char* LEVEL_EN[] = {"UNKNOWN", "DEBUG", "INFO", "WARN", "ERROR", "SYS_ERROR", NULL};


struct logger {
    enum log_level log_level;
    int fd;
};


static struct logger LOGGER = {
    .log_level = LOG_LEVEL_DEBUG,
    .fd = STDERR_FILENO
};


static int
format_date(char* buf, int size) {
    struct tm lt;
    time_t t = time(NULL);

    localtime_r(&t, &lt);
    return strftime(buf, size, "[%Y-%m-%d %H:%M:%d] ", &lt);
}

static int
format_log_level(enum log_level log_lv, char* buf, int size) {
    const char* lv_en;

    lv_en = LEVEL_EN[log_lv];
    return snprintf(buf, size, "[%s] ", lv_en);
}

static int
format_file_info(const char* filename, int lineno, char* buf, int size) {
    const char* bname = (const char*)basename((char*)filename);
    return snprintf(buf, size, "[%s:%d] ", bname, lineno);
}

int init_logger(int log_lv) {
    LOGGER.log_level = log_lv;
    LOGGER.fd = STDERR_FILENO;
    return SGE_OK;
}

const char** get_log_level_string() {
    return LEVEL_EN;
}

int write_log(int log_lv, const char* filename, int lineno, const char* fmt, ...) {
    va_list ap;
    char line[MAX_LINE_SIZE];
    int remain_size = MAX_LINE_SIZE;
    int buflen = 0;
    int error_no = errno;

    if (log_lv < LOGGER.log_level) {
        return SGE_OK;
    }

    buflen = format_date(line, remain_size);
    buflen += format_log_level(log_lv, line + buflen, remain_size - buflen);
    buflen += format_file_info(filename, lineno, line + buflen, remain_size - buflen);

    va_start(ap, fmt);
    buflen += vsnprintf(line + buflen, remain_size - buflen, fmt, ap);
    va_end(ap);

    if (log_lv == LOG_LEVEL_SYS_ERROR) {
        buflen += snprintf(line + buflen, remain_size - buflen, " [%s]", strerror(error_no));
    }
    line[buflen] = '\n';
    line[buflen + 1] = '\0';

    write(LOGGER.fd, line, buflen + 1);

    return SGE_OK;
}
