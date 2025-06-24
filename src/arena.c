#include "arena.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>

//
// Created by jon on 6/2/25.
//

/**
 * Creates and initializes an arena structure for memory management with the specified capacity.
 * Allocates a memory block of the specified size for the arena, initializes its fields,
 * and clears the allocated memory to zero.
 *
 * @param arena A pointer to an `arena_struct_t` structure that will hold the arena information.
 *              This structure must be allocated by the caller.
 * @param capacity The size (in bytes) of the memory region to be allocated and managed by the arena.
 * @return An `arena_status` indicating the result of the operation:
 *         - `ok` if the arena was successfully created and initialized.
 *         - `error` if memory allocation failed.
 */
arena_status arena_create(arena_struct_t *arena, const size_t capacity) {
  arena->base_address = malloc(capacity);
  if (arena->base_address == NULL) {
    return error;
  }
  arena->size = capacity;
  arena->offset = 0;
  arena->allocations = 0;
  arena->max_allocations = 0;
  arena->free_slots = 0;
  arena->capacity = capacity;
  arena->first_chunk = NULL;
  arena->end = (size_t) arena->base_address + arena->size;
  memset(arena->base_address, 0, arena->size);
  uv_mutex_init(&arena->mutex);
  return ok;
}

/**
 * Allocates a block of memory from the specified arena with the requested size.
 * Ensures that the allocated memory is aligned to an 8-byte boundary, and updates
 * the arena's internal state to reflect this allocation.
 *
 * If there's sufficient space and a free slot is available in previously
 * allocated chunks, it reuses that chunk. Otherwise, it allocates a new
 * memory region within the arena.
 *
 * @param arena A pointer to an `arena_struct_t` structure representing the memory
 *              arena from which memory should be allocated.
 * @param bytes The number of bytes to allocate, excluding alignment adjustment. Must be non-zero.
 * @return A pointer to the allocated memory block, or `NULL` if the allocation fails
 *         due to insufficient space or invalid input.
 */
void *arena_alloc(arena_struct_t *arena, size_t bytes) {
  void *address;
  uv_mutex_lock(&arena->mutex);
  if (bytes == 0) {
    uv_mutex_unlock(&arena->mutex);
    return NULL;
  }

  arena_chunk_t *chunk;
  bytes = bytes + sizeof(arena_chunk_t);

  // Calculate padding to ensure 8-byte alignment
  size_t current_addr = (size_t) ((char *) arena->base_address + arena->offset);
  size_t padding = (8 - (current_addr % 8)) % 8;

  // Check if there's enough space in the arena
  if (arena->offset + padding + bytes > arena->size) {
    uv_mutex_unlock(&arena->mutex);
    return NULL;
  }
  /*
  address = (void *) ((char *) arena->base_address + arena->offset + padding);
  arena->offset += padding + bytes;
  memset(address, 0, padding + bytes);
  uv_mutex_unlock(&arena->mutex);
  return address;
  */
  if (arena->free_slots > 0) {
    chunk = arena->first_chunk;
    while (chunk->next != NULL) {
      if (chunk->occupied == 0 && chunk->free == 1 && chunk->size >= bytes) {
        // we can use this chunk
        fprintf(stderr, "using freed chunk [%p]\n", chunk->data_address);
        chunk->occupied = 1;
        chunk->free = 0;
        arena->free_slots--;
        uv_mutex_unlock(&arena->mutex);
        return (void *) chunk->data_address;
      }
      chunk = chunk->next;
    }
  }

  // The aligned address for allocation
  address = (void *) ((char *) arena->base_address + arena->offset + padding);

  // Update the offset
  arena->offset += padding + bytes;
  memset(address, 0, padding + bytes);
  arena->allocations++;
  arena->max_allocations++;
  if (arena->first_chunk == NULL) {
    arena->first_chunk = address;
    chunk = arena->first_chunk;
    chunk->data_address = address + sizeof(arena_chunk_t);
    chunk->occupied = 1;
    chunk->free = 0;
    chunk->next = NULL;
    chunk->size = bytes;
  } else {
    chunk = arena->first_chunk;
    while (chunk->next != NULL) {
      chunk = chunk->next;
    }
    chunk->next = address;
    chunk = chunk->next;
    chunk->data_address = address + sizeof(arena_chunk_t);
    chunk->occupied = 1;
    chunk->free = 0;
    chunk->size = bytes;
    chunk->next = NULL;
  }
  uv_mutex_unlock(&arena->mutex);
  return chunk->data_address;
}

/**
 * Resets the offset of the arena and clears its memory region to zero.
 *
 * This function sets the arena's offset to 0 and overwrites the entire memory
 * region managed by the arena with zeros.
 *
 * @param arena A pointer to an `arena_struct_t` structure representing the arena
 *              whose memory will be cleared.
 * @return An integer value indicating the result of the operation:
 *         - Returns 0 upon successful completion.
 */
int arena_clean(arena_struct_t *arena) {
  arena->offset = 0;
  memset(arena->base_address, 0, arena->size);
  return 0;
}

/**
 * Destroys the memory arena and releases its allocated resources.
 * Cleans up the arena's memory, frees the allocated memory block,
 * and resets all its fields to zero.
 *
 * @param arena A pointer to the `arena_struct_t` structure that represents the memory arena.
 *              This structure must have been previously initialized.
 * @return An integer indicating the success status of the operation:
 *         - 0 if the arena was successfully destroyed.
 */
int arena_destroy(arena_struct_t *arena) {
  fprintf(stderr, "arena_destroy...\n");
  arena_clean(arena);
  free(arena->base_address);
  arena->base_address = NULL;
  arena->size = 0;
  arena->offset = 0;
  arena->end = 0;
  arena->allocations = 0;
  arena->max_allocations = 0;
  arena->free_slots = 0;
  arena->capacity = 0;
  return 0;
}

/**
 * Attempts to resize the memory region managed by the given arena by the specified number of bytes.
 *
 * Reallocates the currently managed memory block to increase its size, updating the arena's
 * structure to reflect the new memory allocation.
 *
 * @param arena A pointer to an `arena_struct_t` representing the current memory arena
 *              that needs resizing. This pointer must not be NULL.
 * @param bytes_to_add An additional number of bytes to allocate for resizing the arena's memory region.
 * @return An integer indicating the result of the operation:
 *         - `0` if the memory region was successfully extended without pointer relocation.
 *         - `1` if the memory region was successfully extended and the arena's pointers were relocated.
 *         - `-1` if the memory reallocation failed.
 */
int arena_realloc(arena_struct_t *arena, size_t bytes_to_add) {
  if (arena == NULL) {
    return -1;
  }
  if (bytes_to_add < 1) {
    return 0;
  }
  void *old_base_address = arena->base_address;
  size_t new_size = arena->size + bytes_to_add;

  void *new_base_address = realloc(old_base_address, new_size);
  if (new_base_address == NULL) {
    // Reallocation failed. The original memory block is untouched.
    return -1;
  }

  arena->base_address = new_base_address;
  arena->size = new_size;
  arena->end = (size_t) arena->base_address + arena->size;

  if (old_base_address == new_base_address) {
    // Memory was resized in-place
    return 0;
  } else {
    // Memory block was moved. Any existing pointers into the arena are now invalid.
    return 1;
  }
}


/**
 * Frees a memory chunk in the arena associated with the given address.
 * Updates the internal linked list of chunks to include the newly freed chunk
 * and marks it as occupied within the arena's management structure.
 *
 * @param arena A pointer to the `arena_struct_t` structure representing the memory arena.
 * @param address The starting address of the memory chunk to be freed.
 * @return An integer status code:
 *         - Returns `0` if the arena has no existing chunks.
 *         - Otherwise, performs the operation to logically "free" the address.
 */
int arena_free(arena_struct_t *arena, void *address) {
  uv_mutex_lock(&arena->mutex);
  if (arena->first_chunk == NULL) {
    uv_mutex_unlock(&arena->mutex);
    return 0;
  }

  arena_chunk_t *chunk = arena->first_chunk;
  while (chunk->next != NULL) {
    if (chunk->data_address == address) {
      break;
    }
    chunk = chunk->next;
  }
  chunk->occupied = 0;
  chunk->free = 1;

  arena->free_slots++;
  fprintf(stderr, "freeing chunk [%p]\n", chunk->data_address);
  uv_mutex_unlock(&arena->mutex);
  return 0;
}
