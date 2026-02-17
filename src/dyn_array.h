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
  size_t elem_size;
  void *data;
  arena_struct_t *arena; // Keep reference to arena for resizing
} dyn_array_t;


dyn_array_t *dyn_array_create(arena_struct_t* arena, size_t cap, size_t elem_size);
dyn_array_t dyn_array_delete(dyn_array_t* arr);
int dyn_array_push(dyn_array_t* arr, void* data);
void *dyn_array_pop(dyn_array_t* arr, void * dst);
void *dyn_array_get(dyn_array_t* arr, size_t index);
void *dyn_array_set(dyn_array_t* arr, size_t index, void* data);
void dyn_array_free(dyn_array_t* arr);
#endif //DYN_ARRAY_H
