#ifndef SGE_SPINLOCK_H_
#define SGE_SPINLOCK_H_

#define SGE_SPINLOCK_INIT(lock) spinlock_init(lock)
#define SGE_SPINLOCK_LOCK(lock) spinlock_lock(lock)
#define SGE_SPINLOCK_UNLOCK(lock) spinlock_unlock(lock)
#define SGE_SPINLOCK_DESTROY(lock) spinlock_destroy(lock)

struct sge_spinlock {
    int lock;
};

static inline void
spinlock_init(struct sge_spinlock *lock) {
    lock->lock = 0;
}

static inline void
spinlock_lock(struct sge_spinlock *lock) {
    while (__sync_lock_test_and_set(&lock->lock,1)) {}
}

static inline int
spinlock_trylock(struct sge_spinlock *lock) {
    return __sync_lock_test_and_set(&lock->lock,1) == 0;
}

static inline void
spinlock_unlock(struct sge_spinlock *lock) {
    __sync_lock_release(&lock->lock);
}

static inline void
spinlock_destroy(struct sge_spinlock *lock) {
    (void) lock;
}


#endif
