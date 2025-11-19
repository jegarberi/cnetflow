//
// Created by jon on 6/9/25.
//
#include "dyn_array.h"
#include <assert.h>

#include <string.h>

#include "arena.h"

dyn_array_t *dyn_array_create(arena_struct_t *arena,size_t cap,size_t elem_size) {
  if (0 == cap) {
    cap = 1024;
  }
  if (0 == elem_size) {
    return NULL;
  }
  dyn_array_t *arr;
  arr = arena_alloc(arena,cap*elem_size);
  if (NULL == arr) {
    return NULL;
  }
  arr->cap = cap;
  arr->len = 0;
  return arr;
}

int dyn_array_push(dyn_array_t* arr, void* data) {
  if (arr->len >= arr->cap) {
    //extend array
    assert("TO-DO: extend array");
  }
  dyn_array_t* ptr;
  ptr = arr->data + arr->len * sizeof(*data);
  memcpy(ptr, data, sizeof(*data));
  return 0;
}

void *dyn_array_pop(dyn_array_t* arr,void * dst) {
  dyn_array_t* ptr;
  ptr = arr->data + arr->len * sizeof(*dst);
  arr->len--;
  return (void*)ptr;
}