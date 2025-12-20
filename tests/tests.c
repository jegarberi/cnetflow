//
// Created by jon on 9/28/25.
//

#include "tests.h"
#include <criterion/criterion.h>
#include <criterion/logging.h>
#include <criterion/new/assert.h>
#include <string.h>
#include <stdint.h>
#include "../src/arena.h"
#include "../src/hashmap.h"
#include "../src/dyn_array.h"

Test(arena, create_and_alloc) {
  arena_struct_t *arena_test = malloc(sizeof(arena_struct_t));
  cr_assert_neq(arena_test, NULL);
#ifdef USE_ARENA_ALLOCATOR
  arena_status err = arena_create(arena_test, (size_t) 1 * 1024);
  cr_assert_eq(err, ok);
  cr_assert_neq(arena_test->base_address, NULL);
  cr_assert_eq(arena_test->capacity, 1024);
#endif

  int int_array[20];
  int * tmp1 = (int*)arena_alloc(arena_test, sizeof(int_array));
  cr_expect_neq(tmp1, NULL);
#ifdef USE_ARENA_ALLOCATOR
  cr_assert_eq(arena_test->allocations, 1);
#endif
  int * tmp2 = (int*)arena_alloc(arena_test, sizeof(int_array));
  cr_expect_neq(tmp2, NULL);
#ifdef USE_ARENA_ALLOCATOR
  cr_assert_eq(arena_test->allocations, 2);
#endif
  cr_assert_neq(tmp1,tmp2);

  arena_destroy(arena_test);
#ifdef USE_ARENA_ALLOCATOR
  cr_assert_eq(arena_test->base_address, NULL);
#endif
  free(arena_test);
}

Test(arena, clean_and_free_reuse) {
  arena_struct_t *arena_test = malloc(sizeof(arena_struct_t));
  cr_assert_neq(arena_test, NULL);
#ifdef USE_ARENA_ALLOCATOR
  cr_assert_eq(arena_create(arena_test, 4096), ok);
#endif

  // allocate two blocks and then free the first one
  void *a = arena_alloc(arena_test, 128);
  void *b = arena_alloc(arena_test, 128);
  cr_expect_neq(a, NULL);
  cr_expect_neq(b, NULL);
  cr_expect_neq(a, b);

  arena_free(arena_test, a);
  // new allocation should be able to reuse the freed chunk eventually
  void *c = arena_alloc(arena_test, 64);
  cr_expect_neq(c, NULL);

  // clean resets memory
  cr_assert_eq(arena_clean(arena_test), 0);
  arena_destroy(arena_test);
  free(arena_test);
}

Test(arena, realloc_grows) {
  arena_struct_t *arena_test = malloc(sizeof(arena_struct_t));
#ifdef USE_ARENA_ALLOCATOR
  cr_assert_eq(arena_create(arena_test, 1024), ok);
  size_t old_size = arena_test->size;
  (void)arena_realloc(arena_test, 1024);
  cr_assert(old_size < arena_test->size);
#else
  (void)arena_realloc(arena_test, 1024);
#endif
  arena_destroy(arena_test);
  free(arena_test);
}

Test(hashmap, set_get_delete) {
  arena_struct_t *arena_hashmap = malloc(sizeof(arena_struct_t));
#ifdef USE_ARENA_ALLOCATOR
  cr_assert_eq(arena_create(arena_hashmap, 1024*1024), ok);
#endif
  hashmap_t *hashmap = hashmap_create(arena_hashmap, 1024);
  cr_assert_neq(hashmap, NULL);

  char test1[] = "testing string1";
  char test2[] = "testing string2";
  cr_assert_eq(hashmap_set(hashmap, arena_hashmap, "key1",strlen("key1"),&test1), 0);
  cr_assert_eq(hashmap_set(hashmap, arena_hashmap, "key2",strlen("key2"),&test2), 0);

  char * get_test1 = (char *)hashmap_get(hashmap, "key1",strlen("key1"));
  char * get_test2 = (char *)hashmap_get(hashmap, "key2",strlen("key2"));
  void * must_be_null = hashmap_get(hashmap, "key3",strlen("key3"));
  cr_assert(get_test1 && strcmp(get_test1,"testing string1")==0);
  cr_assert(get_test2 && strcmp(get_test2,"testing string2")==0);
  cr_assert_eq(must_be_null,NULL);

  cr_assert_eq(hashmap_delete(hashmap,"key1",strlen("key1")), 0);
  get_test1 = (char *)hashmap_get(hashmap, "key1",strlen("key1"));
  cr_assert_eq(get_test1,NULL);
  arena_destroy(arena_hashmap);
  free(arena_hashmap);
}

Test(dyn_array, create_returns_null_on_zero_elem) {
  arena_struct_t *arena_test = malloc(sizeof(arena_struct_t));
#ifdef USE_ARENA_ALLOCATOR
  cr_assert_eq(arena_create(arena_test, 4096), ok);
#endif
  dyn_array_t *arr = dyn_array_create(arena_test, 10, 0);
  cr_assert_eq(arr, NULL);
  arena_destroy(arena_test);
  free(arena_test);
}

Test(dyn_array, create_nonnull_on_valid) {
  arena_struct_t *arena_test = malloc(sizeof(arena_struct_t));
#ifdef USE_ARENA_ALLOCATOR
  cr_assert_eq(arena_create(arena_test, 4096), ok);
#endif
  dyn_array_t *arr = dyn_array_create(arena_test, 4, sizeof(int));
  cr_assert_neq(arr, NULL);
  arena_destroy(arena_test);
  free(arena_test);
}
