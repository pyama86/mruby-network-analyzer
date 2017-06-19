// base: https://github.com/lsanotes/iftop
/*
 * iftop.h:
 *
 */

#include "mruby.h"
#ifndef __IFTOP_H_ /* include guard */
#define __IFTOP_H_

/* 40 / 2  */
#define HISTORY_LENGTH  20
#define RESOLUTION 2
#define DUMP_RESOLUTION 300

typedef struct {
    long recv[HISTORY_LENGTH];
    long sent[HISTORY_LENGTH];
    double long total_sent;
    double long total_recv;
    int last_write;
} history_type;

void *xmalloc(mrb_state *mrb, size_t n);
void *xcalloc(mrb_state *mrb, size_t n, size_t m);
#endif /* __IFTOP_H_ */
