//
// Created by jon on 9/28/25.
//

#include "tests.h"
#include <criterion/criterion.h>
#include <criterion/logging.h>
#include <criterion/new/assert.h>
#include "../src/arena.h"
#include "../src/hashmap.h"

Test(arena, create) {
  arena_struct_t *arena_test = NULL;
  arena_test = malloc(sizeof(arena_struct_t));

  arena_status err = arena_create(arena_test, (size_t) 1 * 1024);
  cr_assert_eq(err, ok);
  cr_assert_neq(arena_test->base_address, NULL);
  cr_assert_neq(arena_test, NULL);
  cr_assert_eq(arena_test->capacity, 1024);
  int * tmp1 = NULL;
  int * tmp2 = NULL;
  int int_array[20];

  tmp1 = (int*)arena_alloc(arena_test, sizeof(int_array));
  cr_assert_eq(arena_test->allocations, 1);
  tmp2 = (int*)arena_alloc(arena_test, sizeof(int_array));
  cr_assert_eq(arena_test->allocations, 2);
  cr_assert_neq(tmp1, NULL);
  cr_assert_neq(tmp2, NULL);
  cr_assert_neq(tmp1,tmp2);
  arena_destroy(arena_test);
  cr_assert_eq(arena_test->base_address, NULL);
}
/*
Test(hashmap, create) {
  arena_struct_t *arena_test = NULL;
  arena_test = malloc(sizeof(arena_struct_t));
  arena_status err = arena_create(arena_test, (size_t) 1 * 1024);
  if (arena_test != ok) {
    cr_log_info("Arena creation failed",0);
  }
  hashmap_t * hashmap = hashmap_create(arena_test, (size_t) 1 * 1024);
  hashmap_set(hashmap,arena_test, (size_t) 1 * 1024, (char *) "test");
  hashmap_set(hashmap, arena_test, (size_t) 1 * 1024, (char *) "test2");
  char *test1;
  char *test2;
  test1 = hashmap_get(hashmap, (size_t) 1 * 1024, (char *) "test");
  arena_destroy(arena_test);

}
*/