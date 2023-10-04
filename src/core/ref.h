#ifndef SGE_REF_H_
#define SGE_REF_H_

#include <core/sge.h>


#define SGE_REF_HEADER(T)               struct sge_spinlock ref_lock; int refcnt; void (*release)(T*);
#define SGE_REF_INIT(r, f)              {                               \
    (r)->refcnt = 1;                                                    \
    (r)->release = f;                                                   \
    SGE_SPINLOCK_INIT(&((r)->ref_lock));                                \
}

#define SGE_REF_GET(r)                  {                               \
    SGE_SPINLOCK_LOCK(&((r)->ref_lock));                                \
    (r)->refcnt++;                                                      \
    SGE_SPINLOCK_UNLOCK(&((r)->ref_lock));                              \
}

#define SGE_REF_PUT(r)                  {                               \
    int c;                                                              \
    SGE_SPINLOCK_LOCK(&((r)->ref_lock));                                \
    c = --(r)->refcnt;                                                  \
    SGE_SPINLOCK_UNLOCK(&((r)->ref_lock));                              \
    if (c < 0) {                                              \
        SGE_LOG(SGE_LOG_LEVEL_ERROR, "fatal erro: refcnt < 0");         \
        exit(-1);                                                       \
    } else if (c == 0) {                                      \
        (r)->release(r);                                                \
    }                                                                   \
}


#endif
