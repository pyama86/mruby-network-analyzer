// base: https://github.com/lsanotes/iftop
/*
 * util.c:
 * Various utility functions.
 *
 * Copyright (c) 2002 Chris Lightfoot. All rights reserved.
 * Email: chris@ex-parrot.com; WWW: http://www.ex-parrot.com/~chris/
 *
 */

static const char rcsid[] = "$Id: util.c,v 1.1 2002/03/24 17:27:12 chris Exp $";

#include <sys/types.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "iftop.h"

/* xmalloc:
 * Malloc, and abort if malloc fails. */
void *xmalloc(mrb_state *mrb, size_t n) {
    void *v;
    v = mrb_malloc(mrb, n);
    if (!v) mrb_raise(mrb, E_RUNTIME_ERROR, "memory allocate error(xmalloc)");
    return v;
}

/* xcalloc:
 * As above. */
void *xcalloc(mrb_state *mrb, size_t n, size_t m) {
    void *v;
    v = mrb_calloc(mrb, n, m);
    if (!v) mrb_raise(mrb, E_RUNTIME_ERROR, "memory allocate error(xcalloc)");
    return v;
}
