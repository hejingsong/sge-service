#include "core/sge.h"
#include "core/res_pool.h"
#include "event/event_mgr.h"
#include "event/event_pool.h"


static struct sge_res_pool* g_event_pool = NULL;


static void
sge_init_event(void* data) {
    struct sge_event* evt;

    evt = (struct sge_event*)data;
    evt->complete_arg = NULL;
    evt->complete_cb = NULL;
    evt->eid = 0;
    evt->evt_type = 0;
}

static void
sge_reset_event(void* data) {
    struct sge_event* evt;

    evt = (struct sge_event*)data;
    sge_init_event(evt);
}

static int
sge_destroy_event(void* data) {
    struct sge_event* evt;

    evt = (struct sge_event*)data;
    sge_free(evt);

    return SGE_OK;
}

static int
sge_event_size() {
    return sizeof(struct sge_event);
}


struct sge_res_pool_op event_pool_op = {
    .init = sge_init_event,
    .reset = sge_reset_event,
    .destroy = sge_destroy_event,
    .size = sge_event_size
};


int sge_create_event_pool(int size) {
    g_event_pool = sge_create_res_pool(&event_pool_op, size);
    if (NULL == g_event_pool) {
        return SGE_ERR;
    }

    return SGE_OK;
}

int sge_get_event(struct sge_event** event) {
    return sge_get_resource(g_event_pool, (void**)event);
}

int sge_release_event(struct sge_event* event) {
    return sge_release_resource(event);
}

int sge_destroy_event_pool() {
    return sge_destroy_resource(g_event_pool);
}
