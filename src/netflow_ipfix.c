//
// Created by jon on 6/3/25.
//


#include "netflow_ipfix.h"
#include <assert.h>
#include <stdio.h>
#include "netflow_v5.h"
static hashmap_t *templates_ipfix_hashmap;
extern arena_struct_t *arena_collector;
extern arena_struct_t *arena_hashmap_ipfix;

void init_ipfix(arena_struct_t *arena, const size_t cap) {
  fprintf(stderr, "Initializing ipfix [templates_ipfix_hashmap]...\n");
  templates_ipfix_hashmap = hashmap_create(arena, cap);
}

void *parse_ipfix(uv_work_t *req) {

  parse_args_t *args = (parse_args_t *) req->data;
  args->status = collector_data_status_processing;
  goto unlock_mutex_parse_ipfix;


unlock_mutex_parse_ipfix:
  // uv_mutex_unlock(lock);
  args->status = collector_data_status_done;

  return NULL;
}
