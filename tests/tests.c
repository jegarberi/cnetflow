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


Test(hashmap, set_get) {

  arena_struct_t *arena_hashmap = NULL;
  arena_hashmap = malloc(sizeof(arena_struct_t));
  arena_status err = arena_create(arena_hashmap, 1024*1024);
  hashmap_t *hashmap = NULL;
  hashmap = hashmap_create(arena_hashmap, 1024);
  char test1[] = "testing string1";
  char test2[] = "testing string2";
  hashmap_set(hashmap, arena_hashmap, "key1",strlen("key1"),&test1);
  hashmap_set(hashmap, arena_hashmap, "key2",strlen("key2"),&test2);

  char * get_test1 = (char *)hashmap_get(hashmap, "key1",strlen("key1"));
  char * get_test2 = (char *)hashmap_get(hashmap, "key2",strlen("key2"));
  fprintf(stderr,"%s\n",get_test1);
  fprintf(stderr,"%s\n",get_test2);
  cr_assert_eq(strcmp(get_test1,"testing string1"),0);
  cr_assert_eq(strcmp(get_test2,"testing string2"),0);
  arena_destroy(arena_hashmap);


}
