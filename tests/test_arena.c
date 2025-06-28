//
// Created by jon on 6/26/25.
//

#include "../src/arena.h"
int test(int argc, char **argv) {
  arena_struct_t *arena_test;
  arena_status status = arena_create(arena_test, 1024 * 1024 * 1024);
  if (status != ARENA_OK) {
    return -1;
  }
  uint8_t chunks[1024 * 1024] = {0};

  for (size_t i = 0; i < 1024 * 1024; i++) {
    chunks[i] = arena_alloc(arena_test, 800);
  }
}
