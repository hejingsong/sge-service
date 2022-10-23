#ifndef SGE_MODULE_H_
#define SGE_MODULE_H_

struct sge_module;

struct sge_module_op {
    int (*init)(struct sge_module*);
    int (*destroy)(struct sge_module*);
    int (*reload)(struct sge_module*);
};


int sge_create_modules(const char* str_modules);
int sge_init_modules();
int sge_reload_modules();
int sge_destroy_modules();

#endif
