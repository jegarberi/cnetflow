//
// Created by jon on 6/9/25.
//

#ifndef DYN_ARRAY_H
#define DYN_ARRAY_H
#include <stddef.h>
#include "arena.h"

typedef struct {
  size_t len;
  size_t cap;
  size_t elem_size;
  void *data;
  arena_struct_t *arena; // Keep reference to arena for resizing
} dyn_array_t;


/**
 * @brief TODO: Document dyn_array_create
 *
 * @param arena TODO
 * @param cap TODO
 * @param elem_size TODO
 * @return TODO
 */
dyn_array_t *dyn_array_create(arena_struct_t* arena, size_t cap, size_t elem_size);
/**
 * @brief TODO: Document dyn_array_delete
 *
 * @param arr TODO
 * @return TODO
 */
dyn_array_t dyn_array_delete(dyn_array_t* arr);
/**
 * @brief TODO: Document dyn_array_push
 *
 * @param arr TODO
 * @param data TODO
 * @return TODO
 */
int dyn_array_push(dyn_array_t* arr, void* data);
/**
 * @brief TODO: Document dyn_array_pop
 *
 * @param arr TODO
 * @param dst TODO
 * @return TODO
 */
void *dyn_array_pop(dyn_array_t* arr, void * dst);
/**
 * @brief TODO: Document dyn_array_get
 *
 * @param arr TODO
 * @param index TODO
 * @return TODO
 */
void *dyn_array_get(dyn_array_t* arr, size_t index);
/**
 * @brief TODO: Document dyn_array_set
 *
 * @param arr TODO
 * @param index TODO
 * @param data TODO
 * @return TODO
 */
void *dyn_array_set(dyn_array_t* arr, size_t index, void* data);
/**
 * @brief TODO: Document dyn_array_free
 *
 * @param arr TODO
 * @return TODO
 */
void dyn_array_free(dyn_array_t* arr);
#endif //DYN_ARRAY_H
