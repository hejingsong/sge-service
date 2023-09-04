#include <pwd.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>

#include "core/sge.h"
#include "core/event.h"
#include "core/server.h"
#include "core/module.h"
#include "core/context.h"


static struct sge_context* g_ctx;

static void usage(const char* pname) {
    fprintf(stderr, "%s config_file", pname);
}

static int alloc_modules__(struct sge_context* ctx) {
    int ret, name_len;
    const char *p1, *p2;
    struct sge_config* cfg = ctx->cfg;
    struct sge_module* module;
    struct sge_list *iter, *next;

    if (NULL == cfg->ori_modules) {
        return SGE_OK;
    }

    p1 = p2 = cfg->ori_modules;
    while(1) {
        p1 = strstr(p1, ",");
        if (NULL == p1) {
            name_len = strlen(p2);
        } else {
            name_len = p1 - p2;
        }

        ret = sge_alloc_module(p2, name_len, &module);
        if (SGE_ERR == ret) {
            break;
        }
        module->ctx = ctx;
        SGE_LIST_ADD_TAIL(&ctx->module_list, &module->list);

        if (p1) {
            p1 += 1;
            p2 = p1;
        } else {
            break;
        }
    }

    return SGE_OK;
error:
    SGE_LIST_FOREACH_SAFE(iter, next, &ctx->module_list) {
        module = sge_container_of(iter, struct sge_module, list);
        sge_destroy_module(module);
    }

    return SGE_ERR;
}

static int init_modules__(struct sge_context* ctx) {
    int ret;
    struct sge_list* iter, *next;
    struct sge_module* module;

    ret = alloc_modules__(ctx);
    if (SGE_ERR == ret) {
        goto alloc_error;
    }

    SGE_LIST_FOREACH(iter, &ctx->module_list) {
        module = sge_container_of(iter, struct sge_module, list);
        ret = sge_init_module(module);
        if (SGE_ERR == ret) {
            goto init_error;
        }
    }

    return SGE_OK;

init_error:
    SGE_LIST_FOREACH_SAFE(iter, next, &ctx->module_list) {
        module = sge_container_of(iter, struct sge_module, list);
        sge_destroy_module(module);
    }
alloc_error:
    return SGE_ERR;
}

static int init_config__(struct sge_config** cfg, const char* cfg_file) {
    int ret;

    ret = sge_alloc_config(cfg_file, cfg);
    if (SGE_ERR == ret) {
        return SGE_ERR;
    }

    ret = sge_parse_config(*cfg);
    if (SGE_ERR == ret) {
        sge_destroy_config(*cfg);
        return SGE_ERR;
    }

    return SGE_OK;
}

static int change_user(const char* user) {
    struct passwd pwd;
    struct passwd *result;
    char buf[1024];
    int ret = 0;

    SGE_LOG(SGE_LOG_LEVEL_DEBUG, "user(%s)", user);

    if (NULL == user) {
        return SGE_OK;
    }

    ret = getpwnam_r(user, &pwd, buf, 1024, &result);
    if (result == NULL) {
        if (ret == 0) {
            SGE_LOG(SGE_LOG_LEVEL_ERROR, "can't found user(%s)", user);
        } else {
            SGE_LOG(SGE_LOG_LEVEL_SYS_ERROR, "get user(%s) error. reason(%s)", user, strerror(errno));
        }
        return SGE_ERR;
    }

    if (seteuid(pwd.pw_uid) < 0) {
        SGE_LOG(SGE_LOG_LEVEL_SYS_ERROR, "seteuid user(%s) error(%s)", user, strerror(errno));
        return SGE_ERR;
    }

    if (setuid(pwd.pw_uid) < 0) {
        SGE_LOG(SGE_LOG_LEVEL_SYS_ERROR, "setuid user(%s) error(%s)", user, strerror(errno));
        return SGE_ERR;
    }

    return SGE_OK;
}

static int daemonize(struct sge_context* ctx) {
    int log_fd;
    pid_t pid;

    if (ctx->cfg->daemonize == 0) {
        return SGE_OK;
    }

    pid = fork();
    if (pid < 0) {
        SGE_LOG(SGE_LOG_LEVEL_SYS_ERROR, "daemonize fork error. reason(%s), ret(%ld)", strerror(errno), pid);
        return SGE_ERR;
    } else if (pid > 0) {
        exit(0);
    }
    setsid();

    log_fd = sge_log_fd();
    dup2(log_fd, STDOUT_FILENO);
    dup2(log_fd, STDERR_FILENO);

    pid = fork();
    if (pid < 0) {
        SGE_LOG(SGE_LOG_LEVEL_SYS_ERROR, "daemonize fork error. reason(%s), ret(%ld)", strerror(errno), pid);
        return SGE_ERR;
    } else if (pid > 0) {
        exit(0);
    }

    return change_user(ctx->cfg->user);
}

static int init_pool(struct sge_config* cfg) {
    int ret;

    ret = sge_init_string_pool(cfg->string_pool_size);
    if (SGE_ERR == ret) {
        fprintf(stderr, "init string pool error.\n");
        return SGE_ERR;
    }

    ret = sge_init_event_pool(cfg->event_pool_size);
    if (SGE_ERR == ret) {
        fprintf(stderr, "init event pool error.\n");
        goto event_pool_error;
    }

    ret = sge_init_server_pool(cfg->socket_pool_size);
    if (SGE_ERR == ret) {
        fprintf(stderr, "init server pool error.\n");
        goto socket_pool_error;
    }

    ret = sge_init_task_pool(cfg->task_pool_size);
    if (SGE_ERR == ret) {
        fprintf(stderr, "init task pool error.\n");
        goto task_pool_error;
    }

    return SGE_OK;

task_pool_error:
    sge_destroy_server_pool();
socket_pool_error:
    sge_destroy_event_pool();
event_pool_error:
    sge_destroy_string_pool();
    return SGE_ERR;
}

static void destroy_pool(void) {
    sge_destroy_task_pool();
    sge_destroy_server_pool();
    sge_destroy_event_pool();
    sge_destroy_string_pool();
}

static int init_context(struct sge_context* ctx) {
    int ret;

    ctx->run = 0;
    SGE_LIST_INIT(&ctx->module_list);

    ret = sge_init_socket_mgr();
    if (SGE_ERR == ret) {
        SGE_LOG(SGE_LOG_LEVEL_ERROR, "init socket error.");
        goto sock_error;
    }

    ret = sge_init_event_mgr();
    if (SGE_ERR == ret) {
        SGE_LOG(SGE_LOG_LEVEL_ERROR, "init event mgr error.");
        goto event_error;
    }

    ret = sge_init_task_ctrl(ctx);
    if (SGE_ERR == ret) {
        SGE_LOG(SGE_LOG_LEVEL_ERROR, "init task ctrl error.");
        goto task_error;
    }

    ret = init_modules__(ctx);
    if (SGE_ERR == ret) {
        SGE_LOG(SGE_LOG_LEVEL_ERROR, "init module error.");
        goto module_error;
    }

    return SGE_OK;
module_error:
    sge_destroy_task_ctrl();
task_error:
    sge_destroy_event_mgr();
event_error:
    sge_destroy_socket_mgr();
sock_error:
    sge_destroy_log();
parse_error:
    sge_destroy_config(ctx->cfg);
error:
    return SGE_ERR;
}

static int destroy_context(struct sge_context* ctx) {
    struct sge_module* module;
    struct sge_list *iter, *next;

    SGE_LIST_FOREACH_SAFE(iter, next, &ctx->module_list) {
        module = sge_container_of(iter, struct sge_module, list);
        sge_destroy_module(module);
    }

    sge_destroy_task_ctrl();
    sge_destroy_event_mgr();
    sge_destroy_socket_mgr();
    sge_destroy_config(ctx->cfg);
    sge_destroy_log();

    return SGE_OK;
}

static void signal_handler__(int signo) {
    if (signo == SIGTERM || signo == SIGINT) {
        g_ctx->run = 0;
    }
}

static int init_signal__(void) {
    __sighandler_t ret;

    ret = signal(SIGTERM, signal_handler__);
    if (ret == SIG_ERR) {
        SGE_LOG(SGE_LOG_LEVEL_SYS_ERROR, "set signal(SIGTERM) handler error.");
        return SGE_ERR;
    }

    ret = signal(SIGINT, signal_handler__);
    if (ret == SIG_ERR) {
        SGE_LOG(SGE_LOG_LEVEL_SYS_ERROR, "set signal(SIGINT) handler error.");
        return SGE_ERR;
    }

    return SGE_OK;
}

static int event_poll__(void* arg) {
    int n;
    struct sge_context* ctx;

    ctx = (struct sge_context*)arg;
    while(ctx->run) {
        n = sge_poll_event();
        if (n == 0) {
            sge_yield_task();
        }
    }

    return SGE_OK;
}

int main(int argc, char const *argv[]) {
    int ret = SGE_OK;
    struct sge_context ctx;

    if (argc < 2) {
        usage(argv[0]);
        return SGE_ERR;
    }

    g_ctx = &ctx;

    ret = init_config__(&ctx.cfg, argv[1]);
    if (SGE_ERR == ret) {
        fprintf(stderr, "parse config file(%s) error.", argv[1]);
        return SGE_ERR;
    }

    ret = sge_init_log(&ctx, NULL, NULL);
    if (SGE_ERR == ret) {
        fprintf(stderr, "init log error.\n");
        sge_destroy_config(ctx.cfg);
        return SGE_ERR;
    }

    SGE_LOG(SGE_LOG_LEVEL_DEBUG, "string pool size: %d", ctx.cfg->string_pool_size);
    SGE_LOG(SGE_LOG_LEVEL_DEBUG, "event pool size: %d", ctx.cfg->event_pool_size);
    SGE_LOG(SGE_LOG_LEVEL_DEBUG, "socket pool size: %d", ctx.cfg->socket_pool_size);
    SGE_LOG(SGE_LOG_LEVEL_DEBUG, "tassk pool size: %d", ctx.cfg->task_pool_size);

    if (SGE_ERR == init_pool(ctx.cfg)) {
        sge_destroy_config(ctx.cfg);
        sge_destroy_log();
        return SGE_ERR;
    }

    ret = daemonize(&ctx);
    if (SGE_OK != ret) {
        sge_destroy_log();
        sge_destroy_config(ctx.cfg);
        goto error;
    }

    if (SGE_ERR == init_context(&ctx)) {
        return SGE_ERR;
    }

    // The signal will be taken over by python, and the signal needs to be initialized after init_module
    if (SGE_ERR == init_signal__()) {
        ret = SGE_ERR;
        goto out;
    }

    sge_delivery_task(event_poll__, &ctx, SGE_TASK_PERMANENT);

    ctx.run = 1;
    sge_run_task_ctrl();

    SGE_LOG(SGE_LOG_LEVEL_INFO, "service shutdown... goodbye.");
out:
    destroy_context(&ctx);

error:
    destroy_pool();
    return ret;
}
