//
// Created by jon on 6/2/25.
//

#ifndef ARENA_H
#define ARENA_H
#include <stddef.h>
#include <stdint.h>
#include <uv.h>

#define MAX_ALLOCATIONS 102400

typedef enum { ok = 0, error = -1 } arena_status;


typedef struct chunk {
  uint8_t occupied;
  uint8_t free;
  uint8_t writing;
  size_t padding;
  size_t size;
  size_t *end;
  struct chunk *next;
  size_t *data_address;
} arena_chunk_t;

typedef struct arena {
  size_t offset;
  size_t size;
  size_t end;
  size_t allocations;
  size_t max_allocations;
  size_t free_slots;
  uint8_t recycle;
  size_t capacity;
  uv_mutex_t mutex;
  arena_chunk_t *first_chunk;
  void *base_address;
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
int arena_free(arena_struct_t *arena, void *address);
#endif // ARENA_H
