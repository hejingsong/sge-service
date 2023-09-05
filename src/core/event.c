#include <string.h>

#include "core/sge.h"
#include "core/log.h"
#include "core/event.h"
#include "core/res_pool.h"

extern struct sge_dict_ops integer_dict_ops;

static struct sge_event_mgr* event_mgr_types[SGE_MAX_EVENT_TYPE];

static size_t event_size__(void) {
    return sizeof(struct sge_event);
}

static size_t event_buff_size__(void) {
    return sizeof(struct sge_event_buff);
}

static struct sge_res_pool* event_res_pool;
static struct sge_res_pool_ops event_res_pool_ops = {
    .size = event_size__
};
static struct sge_res_pool* event_buff_res_pool;
static struct sge_res_pool_ops event_buff_res_pool_ops = {
    .size = event_buff_size__
};

static struct sge_event* dup_event__(struct sge_event* evt) {
    struct sge_event* event;

    event = sge_get_resource(event_res_pool);
    sge_copy_event(evt, event);

    return event;
}

int sge_init_event_pool(size_t size) {
    int ret;

    ret = sge_alloc_res_pool(&event_res_pool_ops, size, &event_res_pool);
    if (SGE_OK == ret) {
        ret = sge_alloc_res_pool(&event_buff_res_pool_ops, size, &event_buff_res_pool);
    }
    return ret;
}

void sge_destroy_event_pool(void) {
    sge_destroy_res_pool(event_res_pool);
    sge_destroy_res_pool(event_buff_res_pool);
}

void sge_register_event_mgr(struct sge_event_mgr* mgr) {
    int i;
    struct sge_event_mgr** p;

    if (NULL == mgr) {
        return;
    }

    for (i = 0, p = &event_mgr_types[i]; i < SGE_MAX_EVENT_TYPE && *p; ++i, p = &event_mgr_types[i]);
    if (i >= SGE_MAX_EVENT_TYPE) {
        fprintf(stderr,
            "adding event_mgr(%s) failed. "
            "since the number of event_mgr is greater than %d, "
            "if you want to add this event_mgr, please modify the SGE_MAX_EVENT_TYPE macro.\n", mgr->type_name, SGE_MAX_EVENT_TYPE);
        exit(-1);
    }

    *p = mgr;
}

int sge_init_event_mgr(void) {
    int i;
    struct sge_event_mgr* mgr;

    i = 0;
    for (mgr = event_mgr_types[i]; NULL != mgr; mgr = event_mgr_types[++i]) {
        if (SGE_ERR == mgr->ops->init(mgr)) {
            return SGE_ERR;
        }
        sge_alloc_dict(&integer_dict_ops, &mgr->ht_events);
    }

    return SGE_OK;
}

int sge_get_event_mgr(const char* event_type_name, struct sge_event_mgr** mgrp) {
    int i;
    struct sge_event_mgr* mgr;

    i = 0;
    for (mgr = event_mgr_types[i]; NULL != mgr; mgr = event_mgr_types[++i]) {
        if (0 == strcmp(mgr->type_name, event_type_name)) {
            *mgrp = mgr;
            return SGE_OK;
        }
    }

    *mgrp = NULL;
    return SGE_ERR;
}

int sge_add_event(struct sge_event_mgr* mgr, struct sge_event* evt) {
    enum sge_event_type old_event_type;
    struct sge_event* event, *old_event;

    if (NULL == mgr || NULL == evt || evt->custom_id <= 0) {
        return SGE_ERR;
    }

    sge_get_dict(mgr->ht_events, (const void*)evt->custom_id, 1, (void**)&old_event);

    if (old_event) {
        old_event_type = old_event->event_type;
        old_event->event_type |= evt->event_type;
        event = old_event;
    } else {
        event = dup_event__(evt);
        event->event_mgr = mgr;
        old_event_type = 0;
    }

    if (SGE_ERR == mgr->ops->add(mgr, event, old_event_type)) {
        goto error;
    }

    event->cb = (evt->cb) ? evt->cb : event->cb;
    event->write_cb = (evt->write_cb) ? evt->write_cb : event->write_cb;
    sge_insert_dict(mgr->ht_events, (const void*)event->custom_id, 1, event);

    return SGE_OK;
error:
    if (old_event) {
        old_event->event_type = old_event_type;
        return SGE_ERR;
    }

    sge_release_resource(event);
    return SGE_ERR;
}

int sge_del_event(struct sge_event_mgr* mgr, unsigned long custom_id, enum sge_event_type event_type) {
    int ret;
    struct sge_event* event, req_event;

    if (NULL == mgr) {
        return SGE_ERR;
    }

    ret = sge_get_dict(mgr->ht_events, (const void*)custom_id, 1, (void**)&event);
    if (SGE_ERR == ret) {
        return SGE_ERR;
    }

    req_event.custom_id = custom_id;
    req_event.event_type = event_type;
    ret = mgr->ops->del(event, &req_event);
    if (SGE_ERR == ret) {
        return SGE_ERR;
    }
    if (1 == ret) {
        event->event_type &= ~(event_type);
        return SGE_OK;
    }

    sge_remove_dict(mgr->ht_events, (const void*)event->custom_id, 1);
    sge_release_resource(event);

    return SGE_OK;
}

int sge_poll_event(void) {
    int i, ret, npoll;
    struct sge_event_mgr* mgr;

    npoll = i = 0;
    for (mgr = event_mgr_types[i]; NULL != mgr; mgr = event_mgr_types[++i]) {
        ret = mgr->ops->poll(mgr);
        if (SGE_ERR == ret) {
            return SGE_ERR;
        }
        npoll += ret;
    }

    return npoll;
}

int sge_destroy_event_mgr(void) {
    int i;
    struct sge_event_mgr* mgr;

    i = 0;
    for (mgr = event_mgr_types[i]; NULL != mgr; mgr = event_mgr_types[++i]) {
        mgr->ops->destroy(mgr);
    }

    return SGE_OK;
}

int sge_alloc_event_buff(struct sge_event_buff** buffp) {
    *buffp = sge_get_resource(event_buff_res_pool);
    return SGE_OK;
}

int sge_release_event_buff(struct sge_event_buff* buff) {
    if (NULL == buff) {
        return SGE_ERR;
    }

    sge_release_resource(buff);
    return SGE_OK;
}

int sge_copy_event(struct sge_event* src, struct sge_event* dest) {
    if (NULL == src || NULL == dest) {
        return SGE_ERR;
    }

    dest->custom_id = src->custom_id;
    dest->event_type = src->event_type;
    dest->event_mgr = src->event_mgr;
    dest->fd = src->fd;
    dest->arg = src->arg;
    dest->cb = src->cb;
    dest->write_cb = src->write_cb;

    return SGE_OK;
}
