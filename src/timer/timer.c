#include <sys/time.h>

#include <assert.h>

#include "core/log.h"
#include "core/ref.h"
#include "core/list.h"
#include "core/task.h"
#include "core/timer.h"
#include "core/spinlock.h"


struct sge_timer {
    unsigned int round_ms;
    unsigned int per_ms;
    unsigned int current_slot;
    unsigned int slot_size;
    unsigned long real_ms;              // system time
    unsigned long virtual_ms;           // virtual time begin with 0
    struct sge_spinlock lock;
    struct sge_list slots[0];
};

struct sge_timer_node {
    SGE_REF_HEADER(struct sge_timer_node)
    struct sge_list list;
    sge_timer_cb cb;
    void* arg;
    unsigned int ms;
    unsigned int expire_ms;
    unsigned int round:31;
    unsigned int repeat:1;
};

static struct sge_timer* g_timer = NULL;

static int timer_cb__(void* arg) {
    struct sge_timer_node* node = NULL;

    node = (struct sge_timer_node*)arg;
    node->cb((sge_timer_id)node, node->arg);
    SGE_REF_PUT(node);

    return SGE_OK;
}

static void destroy_node__(struct sge_timer_node* node) {
    if (NULL == node) {
        return;
    }

    assert(node->refcnt == 0);
    SGE_LIST_REMOVE(&node->list);
    sge_free(node);
}

static struct sge_timer_node* alloc_node__() {
    struct sge_timer_node* n = NULL;

    n = sge_malloc(sizeof(struct sge_timer_node));
    SGE_LIST_INIT(&n->list);
    SGE_REF_INIT(n, destroy_node__);

    return n;
}

unsigned long sys_time_ms(void) {
    struct timeval tv;

    gettimeofday(&tv, NULL);

    return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

int sge_init_timer(unsigned long round_ms, unsigned long per_ms) {
    struct sge_timer* tm = NULL;
    unsigned int i = 0, slot_size = 0;

    if (round_ms % per_ms) {
        SGE_LOG(SGE_LOG_LEVEL_ERROR, "round_ms must be an integer multiple of per_ms");
        return SGE_ERR;
    }

    slot_size = (round_ms / per_ms);

    tm = sge_malloc(sizeof(struct sge_timer) + sizeof(struct sge_list) * slot_size);
    tm->virtual_ms = 0;
    tm->current_slot = 0;
    tm->slot_size = slot_size;
    tm->per_ms = per_ms;
    tm->round_ms = round_ms;
    tm->real_ms = sys_time_ms();
    for (i = 0; i < slot_size; ++i) {
        SGE_LIST_INIT(&tm->slots[i]);
    }
    SGE_SPINLOCK_INIT(&tm->lock);

    g_timer = tm;

    return SGE_OK;
}

sge_timer_id sge_add_timer(unsigned long ms, sge_timer_cb cb, void* arg, int repeat) {
    unsigned int slot = 0;
    struct sge_timer_node* node = 0;

    if (NULL == g_timer) {
        return 0;
    }

    SGE_SPINLOCK_LOCK(&g_timer->lock);
    node = alloc_node__();
    node->arg = arg;
    node->cb = cb;
    node->repeat = repeat;
    node->ms = ms;
    node->expire_ms = g_timer->virtual_ms + ms;
    node->round = node->expire_ms / g_timer->round_ms;
    slot = node->expire_ms % g_timer->round_ms;
    SGE_LIST_ADD_TAIL(&g_timer->slots[slot], &node->list);
    SGE_SPINLOCK_UNLOCK(&g_timer->lock);

    return (unsigned long)node;
}

int sge_cancel_timer(sge_timer_id id) {
    struct sge_timer_node* node = NULL;

    if (0 == id || g_timer == NULL) {
        return SGE_ERR;
    }

    SGE_SPINLOCK_LOCK(&g_timer->lock);

    node = (struct sge_timer_node*)id;
    SGE_LIST_REMOVE(&node->list);
    SGE_REF_PUT(node);

    SGE_SPINLOCK_UNLOCK(&g_timer->lock);

    return SGE_OK;
}

int sge_tick_timer(void) {
    unsigned int round = 0, slot = 0;
    unsigned long i = 0, spend_ms = 0, real_ms = 0;
    struct sge_list *iter = NULL, *next = NULL;
    struct sge_timer_node* node = NULL;
    struct sge_list repeat_list;

    if (NULL == g_timer) {
        return SGE_ERR;
    }

    real_ms = sys_time_ms();

    SGE_SPINLOCK_LOCK(&g_timer->lock);
    spend_ms = real_ms - g_timer->real_ms;
    for (i = 0; i < spend_ms; ++i) {
        round = g_timer->virtual_ms / g_timer->round_ms;

        SGE_LIST_INIT(&repeat_list);
        SGE_LIST_FOREACH_SAFE(iter, next, &g_timer->slots[g_timer->current_slot]) {
            node = sge_container_of(iter, struct sge_timer_node, list);
            if (node->round != round) {
                continue;
            }

            SGE_LIST_REMOVE(&node->list);
            SGE_REF_GET(node);
            sge_delivery_task(timer_cb__, node, SGE_TASK_NORMAL);

            if (node->repeat) {
                SGE_LIST_ADD_TAIL(&repeat_list, &node->list);
            } else {
                SGE_REF_PUT(node);
            }
        }

        SGE_LIST_FOREACH_SAFE(iter, next, &repeat_list) {
            node = sge_container_of(iter, struct sge_timer_node, list);
            SGE_LIST_REMOVE(&node->list);

            node->expire_ms += node->ms;
            node->round = node->expire_ms / g_timer->round_ms;
            slot = node->expire_ms % g_timer->round_ms;
            SGE_LIST_ADD_TAIL(&g_timer->slots[slot], &node->list);
        }

        g_timer->virtual_ms += 1;
        if (0 == (g_timer->virtual_ms % g_timer->per_ms)) {
            ++g_timer->current_slot;
            g_timer->current_slot = g_timer->current_slot % g_timer->slot_size;
        }
    }
    g_timer->real_ms = real_ms;
    SGE_SPINLOCK_UNLOCK(&g_timer->lock);

    return SGE_OK;
}

int sge_destroy_timer(void) {
    unsigned long i = 0;
    struct sge_list *iter = NULL, *next = NULL;
    struct sge_timer_node* node = NULL;

    if (NULL == g_timer) {
        return SGE_ERR;
    }

    for (i = 0; i < g_timer->slot_size; ++i) {
        SGE_LIST_FOREACH_SAFE(iter, next, &(g_timer->slots[i])) {
            node = sge_container_of(iter, struct sge_timer_node, list);
            SGE_REF_PUT(node);
        }
    }

    SGE_SPINLOCK_DESTROY(&g_timer->lock);
    sge_free(g_timer);
    g_timer = NULL;

    return SGE_OK;
}
