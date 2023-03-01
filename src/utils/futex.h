#ifndef SGE_FUTEX_H_
#define SGE_FUTEX_H_

#include <time.h>


int futex_wait_private(void* addr1, int expected, const struct timespec* timeout);
int futex_wake_private(void* addr1, int nwake);
int futex_requeue_private(void* addr1, int nwake, void* addr2);

#endif
