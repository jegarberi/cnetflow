//
// Created by jon on 6/2/25.
//
#include "hashmap.h"
#include <string.h>


/**
 * Creates a new hashmap object with a specified number of buckets.
 *
 * This function allocates memory for a hashmap in the provided memory arena
 * and initializes it with a specified number of buckets. Each bucket is set
 * to its default state where it is unoccupied, not marked as deleted, and
 * has no associated keys or values.
 *
 * @param arena The memory arena used for allocating the hashmap and its buckets.
 * @param bucket_count The number of buckets to allocate for the hashmap.
 * @return Pointer to the newly created hashmap structure.
 */
hashmap_t *hashmap_create(arena_struct_t *arena, size_t bucket_count) {
  hashmap_t *hashmap = arena_alloc(arena, sizeof(hashmap_t));
  hashmap->buckets = arena_alloc(arena, sizeof(bucket_t)*bucket_count);
  hashmap->bucket_count = bucket_count;
  hashmap->mutex = arena_alloc(arena, sizeof(uv_mutex_t));
  uv_mutex_init(hashmap->mutex);
  bucket_t *buckets = (bucket_t *)hashmap->buckets;
  for (size_t i = 0; i < bucket_count; i++) {
    buckets[i].occupied = 0;
    buckets[i].deleted = 0;
    buckets[i].key = NULL;
    buckets[i].value = NULL;
  }


  return hashmap;
}

/**
 * Computes the hash value for a given key using the FNV-1a hashing algorithm.
 *
 * This function generates a hash value for the provided key of a specified length.
 * The hash value is bounded to the range of available buckets in the hashmap.
 * FNV-1a is a non-cryptographic hash function that is efficient for small keys.
 *
 * @param hashmap A pointer to the hashmap structure, which provides the bucket count for modulus operation.
 * @param key A pointer to the key data to be hashed.
 * @param len The length of the key in bytes.
 * @return The computed hash value, constrained to the range of 0 to (bucket_count - 1).
 */
size_t hashmap_hash(hashmap_t *hashmap, void *key, size_t len) {
  // FNV-1a hash constants
  const uint32_t FNV_PRIME = 16777619;
  const uint32_t FNV_OFFSET_BASIS = 2166136261;

  uint32_t hash = FNV_OFFSET_BASIS;
  unsigned char *bytes = (unsigned char *)key;

  for (size_t i = 0; i < len; i++) {
    hash ^= bytes[i];
    hash *= FNV_PRIME;
  }

  // Ensure hash is within bucket range
  size_t index = hash % hashmap->bucket_count;
  fprintf(stderr,"hashmap_hash key: %s =>  index: %u\n",key,index);
  return index;
}

/**
 * Inserts or updates a key-value pair in the hashmap.
 *
 * This function stores the provided key-value pair in the hashmap, handling
 * potential collisions using linear probing. If the key already exists, its
 * associated value is updated. If the key does not exist and the hashmap has
 * available capacity, the key-value pair is inserted. Memory for the key is
 * allocated from the provided arena.
 *
 * @param hashmap Pointer to the hashmap object where the key-value pair will be stored.
 * @param arena Pointer to the memory arena used for allocating memory for the key.
 * @param key Pointer to the key to be inserted or updated.
 * @param key_len Length of the key in bytes.
 * @param value Pointer to the value to be associated with the key.
 * @return 0 if the key-value pair was successfully inserted or updated, -1 if the
 *         operation failed (e.g., due to invalid parameters or lack of space in the hashmap).
 */
int hashmap_set(hashmap_t *hashmap, arena_struct_t *arena, void *key, size_t key_len, void *value) {
  uv_mutex_lock(hashmap->mutex);
  if (!hashmap || !key || !value) {
    goto hashmap_set_error; // Invalid parameters
  }

  // Calculate hash to find bucket index
  size_t index = hashmap_hash(hashmap, key, key_len);
  bucket_t *buckets = (bucket_t *)hashmap->buckets;

  // Linear probing to handle collisions
  size_t original_index = index;
  size_t first_deleted = hashmap->bucket_count; // Track first deleted bucket

  do {
    // If we find an empty bucket or a bucket with the same key
    if (!buckets[index].occupied || buckets[index].deleted) {
      // Remember first deleted bucket for potential reuse
      if (buckets[index].deleted && first_deleted == hashmap->bucket_count) {
        first_deleted = index;
      }

      // If bucket is truly empty (not just deleted), use it
      if (!buckets[index].occupied) {
        break;
      }
    } else if (buckets[index].occupied &&
               strlen(buckets[index].key) == key_len &&
               memcmp(buckets[index].key, key, key_len) == 0) {
      // Found existing key, update value
      buckets[index].value = value;
      goto hashmap_set_success;
    }

    // Move to next bucket (linear probing)
    index = (index + 1) % hashmap->bucket_count;
  } while (index != original_index); // Stop if we've checked all buckets

  // If we found a deleted bucket, use it
  if (first_deleted != hashmap->bucket_count) {
    index = first_deleted;
  }

  // If we couldn't find an empty bucket, the hashmap is full
  if (buckets[index].occupied && !buckets[index].deleted) {
    goto hashmap_set_error; // Hashmap is full
  }

  // Create a copy of the key in the arena
  char *key_copy = arena_alloc(arena, key_len + 1); // +1 for null terminator
  memcpy(key_copy, key, key_len);
  key_copy[key_len] = '\0';

  // Store the key-value pair
  buckets[index].key = key_copy;
  buckets[index].value = value;
  buckets[index].occupied = 1;
  buckets[index].deleted = 0;

  hashmap->size++;


  hashmap_set_success:
    uv_mutex_unlock(hashmap->mutex);
    return 0;
  hashmap_set_error:
    uv_mutex_unlock(hashmap->mutex);
    return -1;
}

/**
 * Retrieves a value associated with a given key in the hashmap.
 *
 * This function searches for a specific key in the hashmap using linear probing.
 * If the key is found, the associated value is returned. If the key is not found,
 * or the input arguments are invalid, the function will return NULL.
 *
 * @param hashmap A pointer to the hashmap structure from which to retrieve the value.
 * @param key A pointer to the key whose value needs to be retrieved.
 * @param key_len The length of the key in bytes.
 * @return A pointer to the value associated with the given key, or NULL if the key
 *         is not found or the input arguments are invalid.
 */
void *hashmap_get(hashmap_t *hashmap, void *key, size_t key_len) {
  if (!hashmap || !key) {
    return NULL;
  }

  // Calculate hash
  size_t index = hashmap_hash(hashmap, key, key_len);
  bucket_t *buckets = (bucket_t *)hashmap->buckets;

  // Linear probing to find the key
  size_t original_index = index;

  do {
    // Skip empty or deleted buckets
    if (!buckets[index].occupied) {
      return NULL; // Key not found
    }

    // Skip deleted buckets but continue searching
    if (buckets[index].deleted) {
      index = (index + 1) % hashmap->bucket_count;
      continue;
    }

    // Check if this is the key we're looking for
    if (strlen(buckets[index].key) == key_len &&
        memcmp(buckets[index].key, key, key_len) == 0) {
      return buckets[index].value;
        }

    // Move to next bucket
    index = (index + 1) % hashmap->bucket_count;
  } while (index != original_index);

  // If we've checked all buckets and found nothing
  return NULL;
}

/**
 * Removes a key-value pair from the hashmap, if present.
 *
 * This function searches the hashmap for the specified key using linear probing.
 * If the key is found, the corresponding bucket is marked as deleted and the
 * hashmap's size is decremented. If the key does not exist, the function returns
 * an error code.
 *
 * @param hashmap Pointer to the hashmap from which the key-value pair should be removed.
 * @param key Pointer to the key to be removed.
 * @param key_len The length of the key in bytes.
 * @return 0 if the key-value pair was successfully removed, or -1 if the
 *         key was not found or if invalid parameters were provided.
 */
int hashmap_delete(hashmap_t *hashmap, void *key, size_t key_len) {
  uv_mutex_lock(hashmap->mutex);
  if (!hashmap || !key) {
    goto hashmap_delete_error;
  }

  // Calculate hash
  size_t index = hashmap_hash(hashmap, key, key_len);
  bucket_t *buckets = (bucket_t *)hashmap->buckets;

  // Linear probing to find the key
  size_t original_index = index;

  do {
    // If bucket is empty, key doesn't exist
    if (!buckets[index].occupied) {
      goto hashmap_delete_error;
    }

    // Skip deleted buckets
    if (buckets[index].deleted) {
      index = (index + 1) % hashmap->bucket_count;
      continue;
    }

    // Check if this is the key we're looking for
    if (strlen(buckets[index].key) == key_len &&
        memcmp(buckets[index].key, key, key_len) == 0) {
        // Mark as deleted
        buckets[index].deleted = 1;
        hashmap->size--;
        goto hashmap_delete_success;
        }

    // Move to next bucket
    index = (index + 1) % hashmap->bucket_count;
  } while (index != original_index);

  // Key not found
  hashmap_delete_success:
    uv_mutex_unlock(hashmap->mutex);
    return 0;
  hashmap_delete_error:
    uv_mutex_unlock(hashmap->mutex);
    return -1;
}


