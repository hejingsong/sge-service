#include <pthread.h>

#include "core/sge.h"
#include "core/cond.h"


struct sge_cond {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
};

int sge_alloc_cond(struct sge_cond** condp) {
    struct sge_cond* cond = NULL;

    cond = sge_calloc(sizeof(struct sge_cond));
    if (0 != pthread_mutex_init(&cond->mutex, NULL)) {
        goto error;
    }
    if (0 != pthread_cond_init(&cond->cond, NULL)) {
        goto cond_error;
    }

    *condp = cond;
    return SGE_OK;

cond_error:
    pthread_mutex_destroy(&cond->mutex);
error:
    sge_free(cond);
    *condp = NULL;
    return SGE_ERR;
}

int sge_wait_cond(struct sge_cond* cond, int ms) {
    struct timespec timeout;

    if (NULL == cond) {
        return SGE_ERR;
    }

    if (0 != pthread_mutex_lock(&cond->mutex)) {
        return SGE_ERR;
    }

    if (ms <= 0) {
        pthread_cond_wait(&cond->cond, &cond->mutex);
    } else {
        timeout.tv_sec = ms / 1000;
        timeout.tv_nsec = (ms % 1000) * 1000;
        pthread_cond_timedwait(&cond->cond, &cond->mutex, &timeout);
    }
    pthread_mutex_unlock(&cond->mutex);

    return SGE_OK;
}

int sge_notify_cond(struct sge_cond* cond) {
    if (NULL == cond) {
        return SGE_ERR;
    }

    pthread_mutex_lock(&cond->mutex);
    pthread_cond_signal(&cond->cond);
    pthread_mutex_unlock(&cond->mutex);

    return SGE_OK;
}

int sge_destroy_cond(struct sge_cond* cond) {
    if (NULL == cond) {
        return SGE_ERR;
    }

    pthread_mutex_destroy(&cond->mutex);
    pthread_cond_destroy(&cond->cond);
    sge_free(cond);

    return SGE_OK;
}
