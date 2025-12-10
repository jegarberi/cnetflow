#include "arena.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>

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
arena_status arena_create(arena_struct_t *arena, const size_t capacity) {
  fprintf(stderr, "%s %d %s \n", __FILE__, __LINE__, __func__);
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
  arena->recycle = 0;
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
 * arena from which memory should be allocated.
 * @param bytes The number of bytes to allocate, excluding alignment adjustment. Must be non-zero.
 * @return A pointer to the allocated memory block, or `NULL` if the allocation fails
 * due to insufficient space or invalid input.
 */
void *arena_alloc(arena_struct_t *arena, size_t bytes) {
  fprintf(stderr, "%s %d %s \n", __FILE__, __LINE__, __func__);
  void *address = NULL; // address ahora representará la dirección de DATOS del usuario
  uv_mutex_lock(&arena->mutex);
  if (bytes == 0) {
    uv_mutex_unlock(&arena->mutex);
    return NULL;
  }

  const int overhead = sizeof(arena_chunk_t); // Usamos const int para el tamaño
  arena_chunk_t *chunk;

  // 1. Calcular la dirección actual no alineada
  char *current_addr = ((char *) arena->base_address + arena->offset);

  // 2. Calcular padding para alinear el inicio del METADATO (chunk)
  // El padding debe asegurar que (current_addr + padding) esté alineado a 8 bytes
  // Nota: Dado que offset puede ser cualquier cosa, esta lógica de padding es crucial.
  const size_t padding = (8 - ((size_t) current_addr % 8)) % 8;

  // 3. Revisar si hay suficiente espacio para: padding + metadatos (overhead) + datos (bytes)
  if (arena->offset + padding + overhead + bytes > arena->size) {
    fprintf(stderr, "%s %d %s Insufficient space in arena.\n", __FILE__, __LINE__, __func__);
    uv_mutex_unlock(&arena->mutex);
    return NULL;
  }

  /* --- Lógica de Reciclaje (Sin cambios significativos, se mantiene la estructura) --- */
  if (arena->free_slots > __RECYCLE_TRESHOLD || arena->recycle == 1) {
    arena->recycle = 1;
    fprintf(stderr, "%s %d %s trying to use freed chunk...\n", __FILE__, __LINE__, __func__);
    chunk = arena->first_chunk;
    do {
      if (chunk->occupied == 0 && chunk->free == 1 && chunk->size >= bytes) {
        // Usar este chunk
        fprintf(stderr, "%s %d %s using freed chunk [%p]\n", __FILE__, __LINE__, __func__, chunk->data_address);
        chunk->occupied = 1;
        chunk->free = 0;
        // Asumimos que no necesitamos cambiar el tamaño de la memoria de datos
        // Si el usuario pidió menos que chunk->size, es su responsabilidad usar solo 'bytes'.
        arena->free_slots--;
        if (arena->free_slots == 0) {
          arena->recycle = 0;
        }
        memset(chunk->data_address, 0, bytes); // Limpiar solo 'bytes'
        uv_mutex_unlock(&arena->mutex);
        return chunk->data_address;
      }
      chunk = chunk->next;
    } while (chunk != NULL);
  }

  /* --- Lógica de Nueva Asignación (Corregida) --- */
  fprintf(stderr, "%s %d %s cant use any freed chunk, allocating new...\n", __FILE__, __LINE__, __func__);

  // Dirección donde comienza la estructura arena_chunk_t (METADATOS)
  arena_chunk_t *new_chunk_start = (arena_chunk_t *) (current_addr + padding);

  // Dirección donde comienza el bloque de DATOS del usuario (se devuelve)
  address = (void *) ((char *) new_chunk_start + overhead);

  // 4. Actualizar el offset sumando el espacio total consumido
  arena->offset += padding + overhead + bytes;

  // 5. Inicializar el área de datos (solo los bytes solicitados)
  memset(address, 0, bytes);

  arena->allocations++;
  arena->max_allocations++;

  // 6. Configurar la lista ligada usando new_chunk_start (el puntero a la estructura)
  if (arena->first_chunk == NULL) {
    arena->first_chunk = new_chunk_start;
    chunk = arena->first_chunk;
  } else {
    chunk = arena->first_chunk;
    while (chunk->next != NULL) {
      chunk = chunk->next;
    }
    chunk->next = new_chunk_start;
    chunk = new_chunk_start; // chunk ahora apunta a la nueva estructura de metadatos
  }

  // 7. Inicializar los campos del CHUNK
  chunk->data_address = address; // Puntero a la dirección de datos del usuario
  chunk->occupied = 1;
  chunk->free = 0;
  chunk->size = bytes;

  // CORRECCIÓN CLAVE: Usar aritmética de punteros byte a byte para el fin (char*)
  // Esto previene la corrupción por multiplicación de sizeof(arena_chunk_t)
  chunk->end = (size_t *) ((char *) chunk->data_address + chunk->size);

  chunk->next = NULL;

  uv_mutex_unlock(&arena->mutex);
  return address; // Devolver la dirección de DATOS
}

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
int arena_clean(arena_struct_t *arena) {
  fprintf(stderr, "%s %d %s \n", __FILE__, __LINE__, __func__);
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
 * This structure must have been previously initialized.
 * @return An integer indicating the success status of the operation:
 * - 0 if the arena was successfully destroyed.
 */
int arena_destroy(arena_struct_t *arena) {
  fprintf(stderr, "%s %d %s arena_destroy...\n", __FILE__, __LINE__, __func__);
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
  uv_mutex_destroy(&arena->mutex); // Añadido: Destruir el mutex
  return 0;
}

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
int arena_realloc(arena_struct_t *arena, size_t bytes_to_add) {
  fprintf(stderr, "%s %d %s arena_realloc...\n", __FILE__, __LINE__, __func__);
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
int arena_free(arena_struct_t *arena, void *address) {
  uv_mutex_lock(&arena->mutex);
  fprintf(stderr, "%s %d %s arena_free...\n", __FILE__, __LINE__, __func__);
  if (arena->first_chunk == NULL) {
    uv_mutex_unlock(&arena->mutex);
    return 0;
  }

  arena_chunk_t *chunk = arena->first_chunk;
  // Bucle mejorado: iterar hasta encontrar la dirección de datos o hasta el final.
  while (chunk != NULL) {
    if (chunk->data_address == address) {
      break;
    }
    chunk = chunk->next;
  }

  if (chunk == NULL) {
    fprintf(stderr, "%s %d %s Address not found in arena.\n", __FILE__, __LINE__, __func__);
    uv_mutex_unlock(&arena->mutex);
    return -1; // Dirección no encontrada
  }

  // Marcar como libre
  chunk->occupied = 0;
  chunk->free = 1;

  arena->free_slots++;
  fprintf(stderr, "%s %d %s freeing chunk [%p]\n", __FILE__, __LINE__, __func__, chunk->data_address);
  uv_mutex_unlock(&arena->mutex);
  return 0;
}