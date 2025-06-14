//
// Created by jon on 6/2/25.
//

#ifndef ARENA_H
#define ARENA_H
#include <stddef.h>

typedef enum { ok = 0, error = -1 } arena_status;

typedef struct arena {
  void *base_address;
  size_t offset;
  size_t size;
  size_t end;
} arena_struct_t;

typedef struct {
  arena_struct_t *arena;
  size_t bytes;
} data_t;

// static arena_struct_t arena;
arena_status arena_create(arena_struct_t *arena, const size_t capacity);
void *arena_alloc(arena_struct_t *arena, size_t bytes);
// void* arena_alloc(data_t *args);
int arena_clean(arena_struct_t *arena);
int arena_destroy(arena_struct_t *arena);
int arena_realloc(arena_struct_t *arena, size_t bytes);
#endif // ARENA_H
