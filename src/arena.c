#include "arena.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>
#include "log.h"

// Definición de estructuras (Asumo que están en arena.h, pero las incluyo aquí para referencia/compilabilidad)
// Si esta definición es incorrecta, la lógica de punteros podría fallar.
/*

*/

#define __RECYCLE_TRESHOLD 0
//
// Created by jon on 6/2/25.
//

/**
 * Creates and initializes an arena structure for memory management with the specified capacity.
 * Allocates a memory block of the specified size for the arena, initializes its fields,
 * and clears the allocated memory to zero.
 *
 * @param arena A pointer to an `arena_struct_t` structure that will hold the arena information.
 * This structure must be allocated by the caller.
 * @param capacity The size (in bytes) of the memory region to be allocated and managed by the arena.
 * @return An `arena_status` indicating the result of the operation:
 * - `ok` if the arena was successfully created and initialized.
 * - `error` if memory allocation failed.
 */
#ifdef USE_ARENA_ALLOCATOR
arena_status arena_create(arena_struct_t *arena, const size_t capacity) {
  LOG_ERROR("%s %d %s \n", __FILE__, __LINE__, __func__);
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
  arena->last_chunk = NULL;
  arena->free_list = NULL;
  arena->recycle = 0;
  arena->end = (size_t) arena->base_address + arena->size;
  memset(arena->base_address, 0, arena->size);
  uv_mutex_init(&arena->mutex);
  return ok;
}
#else
arena_status arena_create(arena_struct_t *arena, const size_t capacity) {
  (void)arena;
  (void)capacity;
  return ok;
}
#endif

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
 * arena from which memory should be allocated.
 * @param bytes The number of bytes to allocate, excluding alignment adjustment. Must be non-zero.
 * @return A pointer to the allocated memory block, or `NULL` if the allocation fails
 * due to insufficient space or invalid input.
 */
#ifdef USE_ARENA_ALLOCATOR
void *arena_alloc(arena_struct_t *arena, size_t bytes) {
  if (unlikely(bytes == 0)) {
    return NULL;
  }

  void *address = NULL;
  uv_mutex_lock(&arena->mutex);

  // 1. Try to recycle from free list
  if (arena->free_list != NULL) {
    arena_chunk_t *chunk = arena->free_list;
    arena_chunk_t *prev = NULL;

    while (chunk != NULL) {
      if (chunk->size >= bytes) {
        // Found a suitable chunk
        if (prev == NULL) {
          arena->free_list = chunk->next_free;
        } else {
          prev->next_free = chunk->next_free;
        }

        chunk->occupied = 1;
        chunk->free = 0;
        arena->free_slots--;
        
        address = chunk->data_address;
        memset(address, 0, bytes);
        uv_mutex_unlock(&arena->mutex);
        return address;
      }
      prev = chunk;
      chunk = chunk->next_free;
    }
  }

  // 2. No recycled chunk found, allocate new
  const size_t overhead = sizeof(arena_chunk_t);
  char *current_addr = ((char *) arena->base_address + arena->offset);
  const size_t padding = (8 - ((size_t) current_addr % 8)) % 8;

  if (unlikely(arena->offset + padding + overhead + bytes > arena->size)) {
    LOG_ERROR("%s %d %s Insufficient space in arena (offset=%lu, requested=%lu)\n", __FILE__, __LINE__, __func__, arena->offset, bytes);
    uv_mutex_unlock(&arena->mutex);
    return NULL;
  }

  arena_chunk_t *new_chunk = (arena_chunk_t *) (current_addr + padding);
  address = (void *) ((char *) new_chunk + overhead);

  arena->offset += padding + overhead + bytes;
  memset(address, 0, bytes);

  arena->allocations++;
  arena->max_allocations++;

  // Initialize chunk metadata
  new_chunk->data_address = address;
  new_chunk->occupied = 1;
  new_chunk->free = 0;
  new_chunk->size = bytes;
  new_chunk->end = (size_t *) ((char *) address + bytes);
  new_chunk->next = NULL;
  new_chunk->next_free = NULL;

  // Add to the end of the global chunk list (O(1) using last_chunk)
  if (arena->first_chunk == NULL) {
    arena->first_chunk = new_chunk;
    arena->last_chunk = new_chunk;
  } else {
    arena->last_chunk->next = new_chunk;
    arena->last_chunk = new_chunk;
  }

  uv_mutex_unlock(&arena->mutex);
  return address;
}
#else
void *arena_alloc(arena_struct_t *arena, size_t bytes) {
  (void)arena;
  return calloc(1, bytes);
}
#endif

/**
 * Resets the offset of the arena and clears its memory region to zero.
 *
 * This function sets the arena's offset to 0 and overwrites the entire memory
 * region managed by the arena with zeros.
 *
 * @param arena A pointer to an `arena_struct_t` structure representing the arena
 * whose memory will be cleared.
 * @return An integer value indicating the result of the operation:
 * - Returns 0 upon successful completion.
 */
#ifdef USE_ARENA_ALLOCATOR
int arena_clean(arena_struct_t *arena) {
  uv_mutex_lock(&arena->mutex);
  arena->offset = 0;
  arena->allocations = 0;
  arena->free_slots = 0;
  arena->recycle = 0;
  arena->first_chunk = NULL;
  arena->last_chunk = NULL;
  arena->free_list = NULL;
  memset(arena->base_address, 0, arena->size);
  uv_mutex_unlock(&arena->mutex);
  return 0;
}
#else
int arena_clean(arena_struct_t *arena) {
  (void)arena;
  return 0;
}
#endif

/**
 * Destroys the memory arena and releases its allocated resources.
 * Cleans up the arena's memory, frees the allocated memory block,
 * and resets all its fields to zero.
 *
 * @param arena A pointer to the `arena_struct_t` structure that represents the memory arena.
 * This structure must have been previously initialized.
 * @return An integer indicating the success status of the operation:
 * - 0 if the arena was successfully destroyed.
 */
#ifdef USE_ARENA_ALLOCATOR
int arena_destroy(arena_struct_t *arena) {
  arena_clean(arena);
  uv_mutex_lock(&arena->mutex);
  free(arena->base_address);
  arena->base_address = NULL;
  arena->size = 0;
  arena->offset = 0;
  arena->end = 0;
  arena->allocations = 0;
  arena->max_allocations = 0;
  arena->free_slots = 0;
  arena->capacity = 0;
  arena->first_chunk = NULL;
  arena->last_chunk = NULL;
  arena->free_list = NULL;
  uv_mutex_unlock(&arena->mutex);
  uv_mutex_destroy(&arena->mutex); // Añadido: Destruir el mutex
  return 0;
}
#else
int arena_destroy(arena_struct_t *arena) {
  (void)arena;
  return 0;
}
#endif

/**
 * Attempts to resize the memory region managed by the given arena by the specified number of bytes.
 *
 * Reallocates the currently managed memory block to increase its size, updating the arena's
 * structure to reflect the new memory allocation.
 *
 * @param arena A pointer to an `arena_struct_t` representing the current memory arena
 * that needs resizing. This pointer must not be NULL.
 * @param bytes_to_add An additional number of bytes to allocate for resizing the arena's memory region.
 * @return An integer indicating the result of the operation:
 * - `0` if the memory region was successfully extended without pointer relocation.
 * - `1` if the memory region was successfully extended and the arena's pointers were relocated.
 * - `-1` if the memory reallocation failed.
 */
#ifdef USE_ARENA_ALLOCATOR
int arena_realloc(arena_struct_t *arena, size_t bytes_to_add) {
  LOG_ERROR("%s %d %s arena_realloc...\n", __FILE__, __LINE__, __func__);
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
    // NOTA: Si el bloque se mueve, debes re-calcular todas las direcciones en la lista ligada (chunk->data_address, chunk->next, etc.)
    // La implementación actual no maneja esta reubicación de punteros internos, lo cual podría ser un bug si se llama a realloc.
    return 1;
  }
}
#else
int arena_realloc(arena_struct_t *arena, size_t bytes_to_add) {
  (void)arena;
  (void)bytes_to_add;
  return 0;
}
#endif


/**
 * Frees a memory chunk in the arena associated with the given address.
 * Updates the internal linked list of chunks to include the newly freed chunk
 * and marks it as occupied within the arena's management structure.
 *
 * @param arena A pointer to the `arena_struct_t` structure representing the memory arena.
 * @param address The starting address of the memory chunk to be freed.
 * @return An integer status code:
 * - Returns `0` if the arena has no existing chunks.
 * - Otherwise, performs the operation to logically "free" the address.
 */
#ifdef USE_ARENA_ALLOCATOR
int arena_free(arena_struct_t *arena, void *address) {
  if (unlikely(address == NULL)) {
    return -1;
  }

  uv_mutex_lock(&arena->mutex);

  // Validate address is within arena bounds
  if (unlikely((size_t)address < (size_t)arena->base_address ||
               (size_t)address >= (size_t)arena->base_address + arena->size)) {
    LOG_ERROR("%s %d %s Address %p outside arena bounds\n", __FILE__, __LINE__, __func__, address);
    uv_mutex_unlock(&arena->mutex);
    return -1;
  }

  // Derive chunk from address (O(1))
  arena_chunk_t *chunk = (arena_chunk_t *)((char *)address - sizeof(arena_chunk_t));

  // Basic sanity check: data_address should match
  if (unlikely(chunk->data_address != address)) {
    LOG_ERROR("%s %d %s Corrupt chunk metadata at %p\n", __FILE__, __LINE__, __func__, address);
    uv_mutex_unlock(&arena->mutex);
    return -1;
  }

  // Prevent double-free
  if (unlikely(chunk->free == 1 && chunk->occupied == 0)) {
    LOG_ERROR("%s %d %s Double-free detected for address %p\n", __FILE__, __LINE__, __func__, address);
    uv_mutex_unlock(&arena->mutex);
    return -1;
  }

  // Mark as free
  chunk->occupied = 0;
  chunk->free = 1;

  // Add to free list (stack-like, O(1))
  chunk->next_free = arena->free_list;
  arena->free_list = chunk;

  arena->free_slots++;
  uv_mutex_unlock(&arena->mutex);
  return 0;
}
#else
int arena_free(arena_struct_t *arena, void *address) {
  (void)arena;
  free(address);
  return 0;
}
#endif