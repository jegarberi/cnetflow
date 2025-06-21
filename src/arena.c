#include "arena.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
  arena->end = (size_t) arena->base_address + arena->size;
  memset(arena->base_address, 0, arena->size);
  return ok;
}

/**
 * Allocates a block of memory from the specified arena.
 * Ensures the memory block is aligned to an 8-byte boundary,
 * and adjusts the arena's offset accordingly.
 *
 * @param arena A pointer to an `arena_struct_t` structure that manages the memory pool.
 *              The arena must be properly initialized before calling this function.
 * @param bytes The number of bytes to allocate from the arena.
 * @return A pointer to the allocated memory block if there is sufficient space
 *         in the arena; otherwise, returns `NULL`.
 */
void *arena_alloc(arena_struct_t *arena, size_t bytes) {
  if (bytes == 0) {
    return NULL;
  }

  // Calculate padding to ensure 8-byte alignment
  size_t current_addr = (size_t) ((char *) arena->base_address + arena->offset);
  size_t padding = (8 - (current_addr % 8)) % 8;

  // Check if there's enough space in the arena
  if (arena->offset + padding + bytes > arena->size) {
    return NULL;
  }

  // The aligned address for allocation
  void *address = (void *) ((char *) arena->base_address + arena->offset + padding);

  // Update the offset
  arena->offset += padding + bytes;

  return address;
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
