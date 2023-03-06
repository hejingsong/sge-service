#ifndef SGE_LIST_H_
#define SGE_LIST_H_

struct sge_list {
    struct sge_list* prev;
    struct sge_list* next;
};

#define SGE_LIST_INIT(list)                                                         \
do {                                                                            \
    (list)->next = (list);                                                      \
    (list)->prev = (list);                                                      \
} while(0)

#define SGE_LIST_ADD_TAIL(list, node)                                               \
do {                                                                            \
    (node)->next = (list);                                                      \
    (node)->prev = (list)->prev;                                                \
    (list)->prev->next = (node);                                                \
    (list)->prev = (node);                                                      \
} while(0)

#define SGE_LIST_ADD_HEAD(list, node)                                               \
do {                                                                            \
    (node)->prev = (list);                                                      \
    (node)->next = (list)->next;                                                \
    (list)->next->prev = (node);                                                \
    (list)->next = (node);                                                      \
} while(0)

#define SGE_LIST_REMOVE(node)                                                       \
do {                                                                            \
    (node)->prev->next = (node)->next;                                          \
    (node)->next->prev = (node)->prev;                                          \
} while(0)

#define SGE_LIST_MOVE(ori_list, new_list)                                       \
do {                                                                            \
    (new_list)->next = (ori_list)->next;                                        \
    (new_list)->prev = (ori_list)->prev;                                        \
    (ori_list)->next->prev = (new_list);                                        \
    (ori_list)->prev->next = (new_list);                                        \
    (ori_list)->next = (ori_list)->prev = (ori_list);                           \
} while(0)

#define SGE_LIST_EMPTY(list)    ((list)->next == (list))

#define SGE_LIST_LAST(list)     (list)->prev

#define SGE_LIST_FOREACH(iter, list)                                               \
for ((iter) = (list)->next; (iter) != (list); (iter) = (iter)->next)


#define SGE_LIST_FOREACH_SAFE(iter, next, list)                                           \
for ((iter) = (list)->next, (next) = (iter)->next; (iter) != (list); (iter) = (next), (next) = (next)->next)


#endif
