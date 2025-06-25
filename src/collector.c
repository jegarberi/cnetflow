//
// Created by jon on 6/2/25.
//

#include "collector.h"
#include <assert.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <uv.h>
#include "arena.h"
#include "cnetflow_snmp.h"
#include "dyn_array.h"
#include "netflow.h"
#include "netflow_ipfix.h"
#include "netflow_v5.h"
#include "netflow_v9.h"
#define true 1
#define false 0
#define STDERR stderr
#define MALLOC(x, y) arena_alloc(x, y)
#define MALLOC(x, y) malloc(y)
#define POOL_SIZE 10240
#define MAX_THREAD_COUNTER 7
volatile arena_struct_t *arena_collector;
static collector_t *collector_config;

uv_loop_t *loop_udp;
uv_loop_t *loop_pool;
uv_loop_t *loop_timer_snmp;
uv_loop_t *loop_timer_rss;

// uv_thread_t threads[7];
size_t thread_counter;

void print_rss_max_usage() {
  struct rusage usage;
  getrusage(RUSAGE_SELF, &usage);
  if ((float) usage.ru_maxrss / (1024 * 1024) > 8.0) {
    printf("%s %d %s ru_maxrss reached... quitting...", __FILE__, __LINE__, __func__);
    signal_handler(SIGINT);
  }
  fprintf(STDERR, "ru_maxrss: %f GB\n", (float) (usage.ru_maxrss) / (1024 * 1024));
}

/**
 * Converts an IPv4 address in integer format to a string representation.
 *
 * @param addr The IPv4 address, represented as an unsigned integer.
 * @return A pointer to a statically allocated string containing the
 *         human-readable IPv4 address in dotted decimal notation.
 *         Note: The returned pointer is to a static buffer and should not
 *         be freed by the caller. Its content may be overwritten by
 *         subsequent calls to inet_ntoa or related functions.
 */
char *ip_int_to_str(const unsigned int addr) {

  struct in_addr ip_addr;
  ip_addr.s_addr = addr;
  char *ip_str = inet_ntoa(ip_addr);
  return ip_str;
}

// https://gist.github.com/jkomyno/45bee6e79451453c7bbdc22d033a282e


/**
 * Converts a sockaddr structure to a human-readable IP address string.
 *
 * @param sa A pointer to a sockaddr structure containing the address
 *           to be converted. It must be properly initialized.
 * @param s A pointer to a character array where the result will be stored.
 *          The array should have enough space to hold the resulting address.
 * @param maxlen The maximum length of the character array `s`.
 * @return A pointer to the resulting string containing the IP address.
 *         Returns NULL if the address family is unrecognized or if an
 *         error occurs. The content of `s` will be "Unknown AF" in such cases.
 */
char *get_ip_str(const struct sockaddr *sa, char *s, size_t maxlen) {
  switch (sa->sa_family) {
    case AF_INET:
      inet_ntop(AF_INET, &(((struct sockaddr_in *) sa)->sin_addr), s, maxlen);
      break;

    case AF_INET6:
      inet_ntop(AF_INET6, &(((struct sockaddr_in6 *) sa)->sin6_addr), s, maxlen);
      break;

    default:
      strncpy(s, "Unknown AF", maxlen);
      return NULL;
  }

  return s;
}

void signal_handler(const int signal) {
  fprintf(STDERR, "signal handler called with signal %d\n", signal);
  switch (signal) {
    case SIGUSR1:
    case SIGINT:
    case SIGABRT:
      fprintf(STDERR, "stopping loop_udp\n");
      uv_stop(loop_udp);
      fprintf(STDERR, "stopping loop_pool\n");
      uv_stop(loop_pool);
      break;
    default:
      break;
  }
}
/**
 * Initializes the given collector configuration with default function pointers
 * and memory management routines.
 *
 * @param col_conf A pointer to a collector_t structure to be initialized.
 *                 This structure will be updated with default configuration
 *                 values, including pointers to allocation, deallocation,
 *                 and parsing functions.
 * @return An int8_t value indicating success. Always returns 0.
 */
int8_t collector_default(collector_t *col_conf) {

  collector_config = col_conf;
  collector_config->alloc = arena_alloc;
  collector_config->free = free;
  collector_config->realloc = realloc;
  collector_config->detect_version = detect_version;
  collector_config->parse_v5 = parse_v5;
  collector_config->parse_v9 = parse_v9;
  collector_config->parse_ipfix = parse_ipfix;
  return 0;
}

int8_t collector_setup(collector_t *collector) {
  fprintf(STDERR, "%p\n", collector->alloc);
  return 0;
}

/**
 * Callback function for memory allocation used with libuv handles.
 *
 * This function is called when libuv requires a buffer to operate with during
 * asynchronous operations. It manages buffer allocation and ensures the buffer
 * is returned to the caller.
 *
 * @param handle A pointer to the libuv handle for which the buffer is being allocated.
 * @param suggested_size The recommended size for the buffer as determined by libuv.
 * @param buf A pointer to a uv_buf_t structure where the allocated buffer's
 *            base address and size will be stored.
 */
void alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
  // buf->base = malloc(suggested_size);
  // buf->len = suggested_size;
  // buf->base = malloc(suggested_size);
  // buf->len = suggested_size;
  // return;
  static int data_counter = 1;
  suggested_size = 65536;
  fprintf(stderr, "%s %d %s buf->base = (char *) collector_config->alloc(arena_collector, suggested_size);\n", __FILE__,
          __LINE__, __func__);
  buf->base = (char *) collector_config->alloc(arena_collector, suggested_size);
  buf->len = suggested_size;


  fprintf(STDERR,
          "%s %d %s alloc_cb: [%d] called for handle %p size: %lu buf->base: %p buf->len: %lu arena_offset: %lu\n",
          __FILE__, __LINE__, __func__, data_counter, (size_t *) handle, suggested_size, buf->base, buf->len,
          arena_collector->offset);
  // memset(buffer[buffer_index].base, 0, suggested_size);
}
/**
 * Initializes and starts the collector process, setting up signal handlers,
 * memory allocation, and UDP server for receiving data packets.
 *
 * @param collector A pointer to a `collector_t` structure containing
 *                  configuration and function pointers for the collector module.
 * @return Returns 0 on successful initialization and execution,
 *         or -1 if an error occurs during setup or runtime.
 *         Specific error messages are logged to standard error.
 */
int8_t collector_start(collector_t *collector) {

  thread_counter = 0;
  signal(SIGINT, signal_handler);
  signal(SIGUSR1, signal_handler);
  signal(SIGUSR2, signal_handler);
  signal(SIGHUP, signal_handler);
  arena_collector = malloc(sizeof(arena_struct_t));
  const arena_status err = arena_create(arena_collector, (size_t) 7 * 1024 * 1024 * 1024);
  if (err != ok) {
    fprintf(STDERR, "arena_create failed: %d\n", err);
    goto error_no_arena;
  }
  fprintf(stderr, "%s %d %s init_v9(arena_collector, 1000000);\n", __FILE__, __LINE__, __func__);
  init_v9(arena_collector, 1000000);
  dyn_array_t *dyn_arr;
  fprintf(stderr, "%s %d %s dyn_array_create(arena_collector, 1024, sizeof(int8_t));\n", __FILE__, __LINE__, __func__);
  dyn_array_create(arena_collector, 1024, sizeof(int8_t));
  fprintf(stderr, "%s %d %s collector_init...\n", __FILE__, __LINE__, __func__);
  loop_timer_rss = uv_default_loop();
  loop_timer_snmp = uv_default_loop();
  loop_udp = uv_default_loop();
  loop_pool = uv_default_loop();
  uv_timer_t timer_req_snmp;
  uv_timer_t timer_req_rss;
  uv_timer_init(loop_timer_snmp, &timer_req_snmp);
  uv_timer_init(loop_timer_rss, &timer_req_rss);
  uv_timer_start(&timer_req_snmp, snmp_test, 30000, 30000);
  uv_timer_start(&timer_req_rss, print_rss_max_usage, 1000, 1000);
  fprintf(stderr, "%s %d %s uv_udp_t *udp_server = collector_config->alloc(arena_collector, sizeof(uv_udp_t));\n",
          __FILE__, __LINE__, __func__);
  uv_udp_t *udp_server = collector_config->alloc(arena_collector, sizeof(uv_udp_t));
  uv_udp_init(loop_udp, udp_server);

  fprintf(stderr,
          "%s %d %s struct sockaddr *addr = (struct sockaddr *) collector_config->alloc(arena_collector, sizeof(struct "
          "sockaddr));\n",
          __FILE__, __LINE__, __func__);
  struct sockaddr *addr = (struct sockaddr *) collector_config->alloc(arena_collector, sizeof(struct sockaddr));
  const struct sockaddr *addr_const = addr;
  uv_ip4_addr("0.0.0.0", 2055, (struct sockaddr_in *) addr);
  fprintf(STDERR, "binding to udp port %d\n", 2055);
  const int bind_ret = uv_udp_bind(udp_server, addr_const, UV_UDP_REUSEADDR);
  if (bind_ret < 0) {
    fprintf(stderr, "bind failed: %s\n", uv_strerror(bind_ret));
    goto error_destroy_arena;
  }
  const int listen = uv_udp_recv_start(udp_server, (uv_alloc_cb) alloc_cb, udp_handle);
  if (listen < 0) {
    fprintf(STDERR, "listen failed: %s\n", uv_strerror(listen));
    goto error_destroy_arena;
  }

  uv_run(loop_udp, UV_RUN_DEFAULT);
ok:
  arena_destroy(arena_collector);
  fprintf(STDERR, "exit collector_thread\n");
  return 0;

error_destroy_arena:
  arena_destroy(arena_collector);
error_no_arena:
  fprintf(STDERR, "exit collector_thread\n");
  return -1;
}

void *after_work_cb(uv_work_t *req, int status) {
  parse_args_t *func_args = req->data;
  fprintf(stderr, "release func_args->data: %p\n", func_args->data);
  arena_free(arena_collector, func_args->data);
  // free(func_args->data);
  fprintf(stderr, "release func_args: %p\n", func_args);
  arena_free(arena_collector, func_args);
  fprintf(stderr, "release req: %p\n", req);
  arena_free(arena_collector, req);
  // free(req);
}
/**
 * Handles incoming UDP packets, parses the data, and processes it according
 * to the detected NetFlow version.
 *
 * @param handle Pointer to the UV UDP handle associated with the packet.
 * @param nread The number of bytes read from the UDP packet. If zero, no data was read.
 * @param buf Pointer to a `uv_buf_t` structure containing the data buffer associated with the packet.
 * @param addr Pointer to a `sockaddr` structure containing the address of the sender.
 *             If NULL, the sender's address is unavailable.
 * @param flags Flags associated with the received packet (e.g., status or additional information).
 */
void udp_handle(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf, const struct sockaddr *addr, unsigned flags) {
  fprintf(STDERR, "%s %d %s got udp packet! handle: %p flags: %d bytes: %ld\n", __FILE__, __LINE__, __func__,
          (void *) handle, flags, nread);
  if (nread > 65536 || nread == 0) {
    // fprintf(STDERR, "nread > 65536\n");
    goto udp_handle_free_and_return;
  }
  if (buf->base == NULL) {
    fprintf(STDERR, "got buf->base == NULL\n");
    exit(-1);
  }

  if (addr == NULL) {
    fprintf(STDERR, "%s %d %s got udp packet! handle: %p ip: NULL flags: %d\n", __FILE__, __LINE__, __func__,
            (void *) handle, flags);
    goto udp_handle_free_and_return;
  }
  char address_str[INET6_ADDRSTRLEN + 8]; // Enough space for IPv6 + port
  get_ip_str(addr, address_str, sizeof(address_str));
  // printf("Address: %s\n", address_str);
  fprintf(STDERR, "%s %d %s got udp packet! handle: %p ip: %s flags: %d bytes: %d\n", __FILE__, __LINE__, __func__,
          (void *) handle, address_str, flags, nread);

  NETFLOW_VERSION nf_version = collector_config->detect_version(buf->base);
  switch (nf_version) {
    case NETFLOW_V5:
    case NETFLOW_V9:
      break;
    default:
      goto udp_handle_free_and_return;
  }

  parse_args_t *func_args = NULL;
  fprintf(stderr, "%s %d %s func_args = collector_config->alloc(arena_collector, sizeof(parse_args_t));\n", __FILE__,
          __LINE__, __func__);

  func_args = collector_config->alloc(arena_collector, sizeof(parse_args_t));
  // func_args = malloc(sizeof(parse_args_t));
  func_args->exporter = 0;
  func_args->len = 0;
  func_args->data = NULL;
  func_args->status = collector_data_status_init;

  fprintf(stderr, "%s %d %s work_req = collector_config->alloc(arena_collector, sizeof(uv_work_t));\n", __FILE__,
          __LINE__, __func__);
  uv_work_t *work_req = collector_config->alloc(arena_collector, sizeof(uv_work_t));
  // work_req = malloc(sizeof(uv_work_t));
  uv_work_cb work_cb;
  static size_t data_counter = 1;
  uint32_t *exporter_ptr = NULL;
  exporter_ptr = &(addr->sa_data[2]);
  func_args->exporter = *(uint32_t *) exporter_ptr;
  func_args->data = buf->base;
  func_args->len = nread;
  func_args->status = collector_data_status_init;
  func_args->index = data_counter;
  work_req->data = (parse_args_t *) func_args;
  fprintf(STDERR, "%s %d %s [%d] work_req addr: %p   work_req->data addr: %p\n", __FILE__, __LINE__, __func__,
          data_counter, work_req, buf->base);
  switch (nf_version) {
    case NETFLOW_V5:
      work_cb = (void *) collector_config->parse_v5;
      break;
    case NETFLOW_V9:
      work_cb = (void *) collector_config->parse_v9;
      break;
    default:
      fprintf(STDERR, "unsupported nf version %d\n", nf_version);
      fprintf(stderr, "this should not happen at all...\n");
      assert(false);
  }
  uv_queue_work(loop_pool, work_req, work_cb, after_work_cb);
  data_counter++;
  // after_work_cb will release all mmemory chunks
  return;
// memset((void *) buf->base, 0, nread);
// memset((void *) buf, 0, sizeof(uv_buf_t));
udp_handle_free_and_return:
  arena_free(arena_collector, buf->base);
}
