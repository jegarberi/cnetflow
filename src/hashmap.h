//
// Created by jon on 6/2/25.
//

#ifndef HASHMAP_H
#define HASHMAP_H
#include <stdint.h>


#include <uv.h>
#include "arena.h"
#define HASH_SEED 123456789

// #define BUCKETS (1000*10)
typedef struct {
  char *key;
  size_t key_len;
  void *value;
  uint8_t occupied;
  uint8_t deleted;
} bucket_t;

typedef struct {
  void *buckets;
  uint32_t bucket_count;
  uint32_t size;
  uint32_t capacity;
  uint32_t (*hash)(void *);
  int (*compare)(void *, void *);
  uv_rwlock_t *rwlock;
  arena_struct_t *arena;
} hashmap_t;

/**
 * @brief TODO: Document hashmap_create
 *
 * @param arena TODO
 * @param bucket_count TODO
 * @return TODO
 */
hashmap_t *hashmap_create(arena_struct_t *arena, size_t bucket_count);
/**
 * @brief TODO: Document hashmap_hash
 *
 * @param hashmap TODO
 * @param key TODO
 * @param len TODO
 * @return TODO
 */
size_t hashmap_hash(hashmap_t *hashmap, void *key, size_t len);
/**
 * @brief TODO: Document hashmap_set
 *
 * @param hashmap TODO
 * @param arena TODO
 * @param key TODO
 * @param key_len TODO
 * @param value TODO
 * @return TODO
 */
int hashmap_set(hashmap_t *hashmap, arena_struct_t *arena, void *key, size_t key_len, void *value);
/**
 * @brief TODO: Document hashmap_get
 *
 * @param hashmap TODO
 * @param key TODO
 * @param key_len TODO
 * @return TODO
 */
void *hashmap_get(hashmap_t *hashmap, void *key, size_t key_len);
/**
 * @brief TODO: Document hashmap_delete
 *
 * @param hashmap TODO
 * @param key TODO
 * @param key_len TODO
 * @return TODO
 */
int hashmap_delete(hashmap_t *hashmap, void *key, size_t key_len);
/**
 * @brief TODO: Document hashmap_destroy
 *
 * @param hashmap TODO
 * @return TODO
 */
void hashmap_destroy(hashmap_t *hashmap);

#endif // HASHMAP_H
