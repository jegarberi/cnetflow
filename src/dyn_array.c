//
// Created by jon on 6/9/25.
//
#include "dyn_array.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "arena.h"
#include "log.h"

dyn_array_t *dyn_array_create(arena_struct_t *arena, size_t cap, size_t elem_size) {
  if (0 == cap) {
    cap = 16;
  }
  if (0 == elem_size) {
    return NULL;
  }

  // Allocate the struct itself
  dyn_array_t *arr = arena_alloc(arena, sizeof(dyn_array_t));
  if (NULL == arr) {
    return NULL;
  }

  // Initialize metadata
  arr->cap = cap;
  arr->len = 0;
  arr->elem_size = elem_size;
  arr->arena = arena;

  // Allocate the data buffer
  arr->data = arena_alloc(arena, cap * elem_size);
  if (NULL == arr->data) {
    // If we can't allocate data, we should ideally free arr, but arena doesn't support fine-grained free.
    // We just return NULL and leak the struct size in the arena.
    return NULL;
  }

  return arr;
}

int dyn_array_push(dyn_array_t *arr, void *data) {
  if (arr == NULL || data == NULL)
    return -1;

  if (arr->len >= arr->cap) {
    // Extend array
    size_t new_cap = arr->cap * 2;
    void *new_data = arena_alloc(arr->arena, new_cap * arr->elem_size);

    if (new_data == NULL) {
      return -1; // Allocation failed
    }

    // Copy old data to new buffer
    memcpy(new_data, arr->data, arr->len * arr->elem_size);

    // Update array struct
    arr->data = new_data;
    arr->cap = new_cap;
  }

  // Calculate position for new element
  char *dest = (char *) arr->data + (arr->len * arr->elem_size);
  memcpy(dest, data, arr->elem_size);
  arr->len++;

  return 0;
}

void *dyn_array_pop(dyn_array_t *arr, void *dst) {
  if (arr == NULL || arr->len == 0)
    return NULL;

  arr->len--;
  char *src = (char *) arr->data + (arr->len * arr->elem_size);

  if (dst != NULL) {
    memcpy(dst, src, arr->elem_size);
    return dst;
  }

  return (void *) src;
}

void *dyn_array_get(dyn_array_t *arr, size_t index) {
  if (arr == NULL || index >= arr->len)
    return NULL;
  return (char *) arr->data + (index * arr->elem_size);
}
