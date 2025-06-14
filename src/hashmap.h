//
// Created by jon on 6/2/25.
//

#ifndef HASHMAP_H
#define HASHMAP_H
#include <stdint.h>


#include "arena.h"
#include <uv.h>
#define HASH_SEED 123456789

//#define BUCKETS (1000*10)
typedef struct {
  char* key;
  void* value;
  uint8_t occupied;
  uint8_t deleted;
} bucket_t;

typedef struct {
  void * buckets;
  uint32_t bucket_count;
  uint32_t size;
  uint32_t capacity;
  uint32_t (*hash)(void*);
  int (*compare)(void*, void*);
  uv_mutex_t *mutex;
} hashmap_t;

hashmap_t *hashmap_create(arena_struct_t *arena, size_t bucket_count);
size_t hashmap_hash(hashmap_t *hashmap, void *key, size_t len);
int hashmap_set(hashmap_t *hashmap, arena_struct_t *arena, void *key, size_t key_len, void *value);
void *hashmap_get(hashmap_t *hashmap, void *key, size_t key_len);
int hashmap_delete(hashmap_t *hashmap, void *key, size_t key_len);

#endif // HASHMAP_H
