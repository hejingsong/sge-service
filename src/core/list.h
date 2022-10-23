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

#define SGE_LIST_EMPTY(list)    ((list)->next == (list))


#define SGE_LIST_FOREACH_START  {

#define SGE_LIST_FOREACH(iter, list)                                               \
for ((iter) = (list)->next; (iter) != (list); (iter) = (iter)->next)


#define SGE_LIST_FOREACH_SAFE(iter, list)                                           \
struct sge_list* __next;                                                        \
for ((iter) = (list)->next, __next = (iter)->next; (iter) != (list); (iter) = __next, __next = __next->next)

#define SGE_LIST_FOREACH_END    }


#endif
