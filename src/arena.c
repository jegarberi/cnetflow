#include "arena.h"
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <stdio.h>
//
// Created by jon on 6/2/25.
//


arena_status arena_create(arena_struct_t *arena, const size_t capacity) {
  arena->base_address = (void *) malloc(capacity);
  arena->size = capacity;
  arena->offset = 0;
  arena->end = (size_t) arena->base_address + arena->size;
  if (arena->base_address == 0) {
    return error;
  }
  memset((void *) arena->base_address, 0, arena->size);
  return ok;
}
void *arena_alloc(arena_struct_t *arena, size_t bytes) {
  // void* arena_alloc(data_t *args) {
  if (arena->base_address + arena->offset + bytes > arena->end) {
    return NULL;
  }
  void *address = NULL;
  if (((size_t) arena->base_address + arena->offset) % 8 == 0) {
    address = (void *) ((arena->base_address) + arena->offset);
    arena->offset += bytes;
    return address;
  } else {
    size_t padding = (size_t) arena->base_address + arena->offset;
    address = (void *) ((arena->base_address) + arena->offset + padding);
    arena->offset += bytes + padding;
    return address;
  }
}
void arena_clean(arena_struct_t *arena) {
  arena->offset = 0;
  memset((void *) arena->base_address, 0, arena->size);
}
void arena_destroy(arena_struct_t *arena) {
  fprintf(stderr, "arena_destroy...\n");
  arena_clean(arena);
  free((void *) arena->base_address);
  arena->base_address = 0;
  arena->size = 0;
  arena->offset = 0;
  arena->end = 0;
}
void *area_realloc(arena_struct_t *arena);
