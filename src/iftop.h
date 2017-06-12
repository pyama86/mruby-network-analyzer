// base: https://github.com/lsanotes/iftop
/*
 * iftop.h:
 *
 */

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

void *xmalloc(size_t n);
void *xcalloc(size_t n, size_t m);
void *xrealloc(void *w, size_t n);
char *xstrdup(const char *s);
void xfree(void *v);
#endif /* __IFTOP_H_ */
