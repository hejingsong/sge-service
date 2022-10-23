#include "core/sge.h"
#include "core/log.h"

#include "task/task.h"
#include "server/socket.h"
#include "event/event_mgr.h"
#include "module/module.h"

#include "utils/config.h"


static void
usage(const char* pname) {
    SGE_LOG_ERROR("%s config_file", pname);
}

static int
sge_global_init() {
    init_logger(sge_get_log_level());

    if (SGE_ERR == sge_init_worker_dir(sge_get_worker_dir())) {
        return SGE_ERR;
    }

    sge_init_socket_mgr();
    sge_create_modules(sge_get_modules());

    if (SGE_ERR == sge_init_task()) {
        return SGE_ERR;
    }

    sge_init_modules();

    return SGE_OK;
}


int main(int argc, char const *argv[]) {
    if (argc < 2) {
        usage(argv[0]);
        return SGE_ERR;
    }

    if (SGE_ERR == sge_parse_config(argv[1])) {
        return SGE_ERR;
    }

    if (SGE_ERR == sge_global_init()) {
        return SGE_ERR;
    }

    if (SGE_ERR == sge_wait_quit()) {
        return SGE_ERR;
    }

    sge_destroy_modules();
    sge_destroy_task_meta_pool();

    return SGE_OK;
}
