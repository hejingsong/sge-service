#include <unistd.h>
#include <syscall.h>
#include <linux/futex.h>

#include "utils/futex.h"


int futex_wait_private(void* addr1, int expected, const struct timespec* timeout) {
    return syscall(SYS_futex, addr1, FUTEX_WAIT_PRIVATE,
                   expected, timeout, NULL, 0);
}

int futex_wake_private(void* addr1, int nwake) {
    return syscall(SYS_futex, addr1, FUTEX_WAKE_PRIVATE,
                   nwake, NULL, NULL, 0);
}

int futex_requeue_private(void* addr1, int nwake, void* addr2) {
    return syscall(SYS_futex, addr1, FUTEX_REQUEUE_PRIVATE,
                   nwake, NULL, addr2, 0);
}
