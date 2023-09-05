#ifndef SGE_H_
#define SGE_H_

#include <stdlib.h>
#include "core/const.h"

#define SGE_OK                          0
#define SGE_ERR                         -1


#define SGE_LOG_LINE_BUFFER_SIZE        1024
#define SGE_DICT_SLOT_SIZE              512
#define SGE_STRING_SIZE                 1024
#define SGE_MAX_EVENT_TYPE              12


#define sge_malloc(size)                malloc(size)
#define sge_calloc(size)                calloc(1, size)
#define sge_free                        free

#define sge_unused(expr)                (void)(expr)


#define sge_container_of(ptr, type, member) (type*)((void*)(ptr) - (void*)(&(((type*)0)->member)))

#endif
