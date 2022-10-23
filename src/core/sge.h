#ifndef SGE_H_
#define SGE_H_

#include <stdlib.h>

#define SGE_OK          0
#define SGE_ERR         -1

#define sge_malloc      malloc
#define sge_free        free

#define SGE_BUFFER_SIZE 1024

#define SGE_CONTAINER_OF(ptr, type, member) (type*)((void*)(ptr) - (void*)(&(((type*)0)->member)))

#endif
