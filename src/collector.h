//
// Created by jon on 6/2/25.
//

#ifndef COLLECTOR_H
#define COLLECTOR_H
#include <uv.h>
#include "arena.h"

typedef enum {
  collector_data_status_init = 0,
  collector_data_status_processing = 1,
  collector_data_status_done = 2,
} collector_data_status;

typedef struct {
  size_t len;
  // uv_mutex_t *mutex;
  uint32_t exporter;
  collector_data_status status;
  size_t index;
  uint8_t is_test;
  void *return_data;
  void *data;
} parse_args_t;

typedef struct {
  int (*detect_version)(void *);
  void *(*parse_v5)(uv_work_t *req);
  void(*(*parse_v9)(uv_work_t *req));
  void(*(*parse_ipfix)(uv_work_t *req));
  void(*(*alloc)(arena_struct_t *arena, size_t bytes));
  void(*(*realloc)(void *) );
  void(*(*free)(void *) );
} collector_t;
char *ip_int_to_str(const unsigned int addr);
void signal_handler(const int signal);
int8_t collector_default(collector_t *);
int8_t collector_setup(collector_t *);
int8_t collector_start(collector_t *);
char *get_ip_str(const struct sockaddr *sa, char *s, size_t maxlen);
void udp_handle(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf, const struct sockaddr *addr, unsigned flags);
void print_rss_max_usage(void);
void *after_work_cb(uv_work_t *req, int status);
#endif // COLLECTOR_H
