#include "arena.h"
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <stdio.h>
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
  // void* arena_alloc(data_t *args) {
  if (arena->base_address + arena->offset + bytes > arena->end) {
    return NULL;
  }
  void *address = NULL;
  size_t padding = ((size_t) arena->base_address + arena->offset) % 8;
  if (padding == 0) {
    address = (void *) ((arena->base_address) + arena->offset);
    arena->offset += bytes;

  } else {

    address = (void *) ((arena->base_address) + arena->offset + padding);
    arena->offset += bytes + padding;

  }
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
  memset((void *) arena->base_address, 0, arena->size);
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
 *         - Other values indicate failure, though no specific failure handling is implemented.
 */
int arena_destroy(arena_struct_t *arena) {
  fprintf(stderr, "arena_destroy...\n");
  arena_clean(arena);
  free((void *) arena->base_address);
  arena->base_address = 0;
  arena->size = 0;
  arena->offset = 0;
  arena->end = 0;
  return 0;
}
/**
 * Attempts to resize the memory region managed by the given arena by the specified number of bytes.
 *
 * Reallocates the currently managed memory block to increase its size, updating the arena's
 * structure to reflect the new memory allocation. Handles changes in pointers if the realloc
 * function moves the memory block. Provisions are made for failure cases where the memory
 * cannot be extended.
 *
 * @param arena A pointer to an `arena_struct_t` representing the current memory arena
 *              that needs resizing. This pointer must not be NULL.
 * @param bytes An additional number of bytes to allocate for resizing the arena's memory region.
 * @return An integer indicating the result of the operation:
 *         - `0` if the memory region was successfully extended without pointer relocation.
 *         - `1` if the memory region was successfully extended and the arena's pointers were relocated.
 *         - `-1` if the memory reallocation failed.
 */
int arena_realloc(arena_struct_t *arena, size_t bytes) {
  if (arena == NULL) {
    return (void*) NULL;
  }
  arena_struct_t * old_ptr;
  arena_struct_t * new_ptr;
  old_ptr = arena;
  new_ptr = realloc(old_ptr, old_ptr->size + bytes);
  if (new_ptr == NULL) {
    //could not extend
    return -1;
  }
  if (old_ptr == new_ptr) {
    //all is fine
    arena->base_address = new_ptr;
    arena->size += bytes;
    arena->end = (size_t) arena->base_address + arena->size;
    return 0;
  }
  //must handle change in pointers
    return 1;

}
