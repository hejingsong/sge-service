#ifndef SGE_COND_H_
#define SGE_COND_H_

struct sge_cond;

int sge_alloc_cond(struct sge_cond** condp);
int sge_wait_cond(struct sge_cond* cond, int ms);
int sge_notify_cond(struct sge_cond* cond);
int sge_destroy_cond(struct sge_cond* cond);

#endif
