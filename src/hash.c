// base: https://github.com/lsanotes/iftop
/* hash table */

#include <stdio.h>
#include <stdlib.h>
#include "hash.h"
#include "iftop.h"

hash_status_enum hash_insert(mrb_state *mrb, hash_type* hash_table, void* key, void* rec) {
    hash_node_type *p, *p0;
    int bucket;

   /************************************************
    *  allocate node for data and insert in table  *
    ************************************************/


    /* insert node at beginning of list */
    bucket = hash_table->hash(key);
    p = xmalloc(mrb, sizeof *p);
    p0 = hash_table->table[bucket];
    hash_table->table[bucket] = p;
    p->next = p0;
    p->key = hash_table->copy_key(mrb, key);
    p->rec = rec;
    return HASH_STATUS_OK;
}

hash_status_enum hash_find(hash_type* hash_table, void* key, void **rec) {
    hash_node_type *p;

   /*******************************
    *  find node containing data  *
    *******************************/
    p = hash_table->table[hash_table->hash(key)];

    while (p && !hash_table->compare(p->key, key))  {
        p = p->next;
    }
    if (!p) return HASH_STATUS_KEY_NOT_FOUND;
    *rec = p->rec;
    return HASH_STATUS_OK;
}

hash_status_enum hash_next_item(hash_type* hash_table, hash_node_type** ppnode) {
    int i;
    if(*ppnode != NULL) {
        if((*ppnode)->next != NULL) {
            *ppnode = (*ppnode)->next;
            return HASH_STATUS_OK;
        }
        i = hash_table->hash((*ppnode)->key) + 1;
    }
    else {
        /* first node */
        i = 0;
    }
    while(i < hash_table->size && hash_table->table[i] == NULL) {
         i++; 
    }
    if(i == hash_table->size) {
        *ppnode = NULL;
        return HASH_STATUS_KEY_NOT_FOUND;
    }
    *ppnode = hash_table->table[i];
    return HASH_STATUS_OK;
}

/*
 * Allocate and return a hash
 */
hash_status_enum hash_initialise(mrb_state *mrb, hash_type* hash_table) {
    hash_table->table = xcalloc(mrb, hash_table->size, sizeof *hash_table->table);
    return HASH_STATUS_OK;
}

