#ifndef SGE_CONTEXT_H_
#define SGE_CONTEXT_H_

#include "core/list.h"
#include "core/task.h"
#include "core/config.h"

struct sge_context {
    int run;
    struct sge_config* cfg;
    struct sge_list module_list;
};

#endif
