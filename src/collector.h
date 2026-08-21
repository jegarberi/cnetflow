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
  void *data;
  uint64_t processed_flows;
  uint32_t now;
  uint32_t flags;
  uint32_t frame_number;
} parse_args_t;

typedef struct {
  int (*detect_version)(void *);
  void *(*parse_v5)(uv_work_t *req);
  void(*(*parse_v9)(uv_work_t *req));
  void(*(*parse_ipfix)(uv_work_t *req));
  void(*(*alloc)(arena_struct_t *arena, size_t bytes));
  void(*(*realloc)(void *) );
  void(*(*free)(void *) );
  char *pcap_file;
} collector_t;
/**
 * @brief TODO: Document ip_int_to_str
 *
 * @param addr TODO
 * @return TODO
 */
char *ip_int_to_str(const unsigned int addr);
/**
 * @brief TODO: Document signal_handler
 *
 * @param signal TODO
 * @return TODO
 */
void signal_handler(const int signal);
/**
 * @brief TODO: Document collector_default
 *
 * @return TODO
 */
int8_t collector_default(collector_t *);
/**
 * @brief TODO: Document collector_setup
 *
 * @return TODO
 */
int8_t collector_setup(collector_t *);
/**
 * @brief TODO: Document collector_start
 *
 * @return TODO
 */
int8_t collector_start(collector_t *);
/**
 * @brief TODO: Document get_ip_str
 *
 * @param sa TODO
 * @param s TODO
 * @param maxlen TODO
 * @return TODO
 */
char *get_ip_str(const struct sockaddr *sa, char *s, size_t maxlen);
/**
 * @brief TODO: Document collector_inc_received_flows
 *
 * @param count TODO
 * @return TODO
 */
void collector_inc_received_flows(uint64_t count);
/**
 * @brief TODO: Document udp_handle
 *
 * @param handle TODO
 * @param nread TODO
 * @param buf TODO
 * @param addr TODO
 * @param flags TODO
 * @return TODO
 */
void udp_handle(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf, const struct sockaddr *addr, unsigned flags);
/**
 * @brief TODO: Document print_rss_max_usage
 *
 * @return TODO
 */
void print_rss_max_usage(void);
/**
 * @brief TODO: Document after_work_cb
 *
 * @param req TODO
 * @param status TODO
 * @return TODO
 */
void after_work_cb(uv_work_t *req, int status);
/**
 * @brief TODO: Document parse_pcap_file
 *
 * @param collector TODO
 * @param filename TODO
 * @return TODO
 */
int parse_pcap_file(collector_t *collector, const char *filename);

extern size_t max_unparsed_flows;

#endif // COLLECTOR_H
