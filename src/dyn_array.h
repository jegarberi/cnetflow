//
// Created by jon on 6/9/25.
//

#ifndef DYN_ARRAY_H
#define DYN_ARRAY_H
#include <stddef.h>
#include "arena.h"
typedef struct {
  size_t len;
  size_t cap;
  void *data;
} dyn_array_t;


dyn_array_t *dyn_array_create(arena_struct_t* ,size_t,size_t elem_size);
dyn_array_t dyn_array_delete(dyn_array_t*);
int dyn_array_push(dyn_array_t*, void*);
void *dyn_array_pop(dyn_array_t* arr,void * dst);
void *dyn_array_get(dyn_array_t*, size_t);
void *dyn_array_set(dyn_array_t*, size_t, void*);
void dyn_array_free(dyn_array_t*);
#endif //DYN_ARRAY_H
