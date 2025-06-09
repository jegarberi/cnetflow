//
// Created by jon on 6/2/25.
//

#include "collector.h"

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>
#include "arena.h"
#include "netflow.h"
#include "netflow_ipfix.h"
#include "netflow_v5.h"
#include "netflow_v9.h"
#define true 1
#define false 0
#define STDERR stderr
// #define MALLOC(x,y) arena_alloc(x,y)
// #define MALLOC(x,y) malloc(y)

arena_struct_t *arena_collector;
static collector_t *collector_config;

uv_loop_t *loop_udp;
uv_loop_t *loop_pool;


uv_thread_t threads[7];
size_t thread_counter;
char *ip_int_to_str(const unsigned int addr) {

  struct in_addr ip_addr;
  ip_addr.s_addr = addr;
  char *ip_str = inet_ntoa(ip_addr);
  return ip_str;
}

// https://gist.github.com/jkomyno/45bee6e79451453c7bbdc22d033a282e
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

void alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
  static uv_buf_t buffer[1024] = {0};
  static volatile int buffer_index = 0;

  if (buffer[buffer_index].base == NULL) {
    buffer[buffer_index].base = (char *) collector_config->alloc(arena_collector, suggested_size);
    if (buffer[buffer_index].base == NULL) {
      buffer[buffer_index].base = 0;
      buffer[buffer_index].len = 0;
    } else {
      buffer[buffer_index].len = suggested_size;
    }
    /*
    memset(buffer[buffer_index], 0, sizeof(uv_buf_t));
    char *tmp = NULL;
    uv_buf_t buf_tmp = {0};
    tmp = (char *)collector_config->alloc(arena_collector, suggested_size*10);
    //tmp = malloc(suggested_size);
    if (tmp == NULL) {
      buffer[buffer_index]->len = 0;
      buffer[buffer_index]->base = NULL;
    } else {
      buf_tmp.base = tmp;
      buf_tmp.len = suggested_size;
      memcpy(buffer[buffer_index], (void*)&buf_tmp, sizeof(uv_buf_t));

    }
    */
  }

  buf->base = buffer[buffer_index].base;
  buf->len = buffer[buffer_index].len;
  fprintf(STDERR, "alloc_cb: [%d] called for handle %p size: %lu buf->base: %p buf->len: %lu arena_offset: %lu\n",
          buffer_index, (size_t *) handle, suggested_size, buf->base, buf->len, arena_collector->offset);
  // memset(buffer[buffer_index].base, 0, suggested_size);
  buffer_index++;
  if (buffer_index >= 1024) {
    buffer_index = 0;
  }

  /*buf->base = (char*)MALLOC(arena_collector,suggested_size);
  if (buf->base == NULL) {
    fprintf(STDERR, "failed to allocate memory\n");
    uv_stop(loop_udp);
    buf->len = 0;
  } else {
    buf->len = suggested_size;
  }
  fprintf(stderr, "alloc_cb: called for handle %p size: %lu base_address:
  %p\n",(size_t*)handle,suggested_size,buf->base);

  return buf;
  */
}
int8_t collector_start(collector_t *collector) {
  thread_counter = 0;
  signal(SIGINT, signal_handler);
  signal(SIGUSR1, signal_handler);
  signal(SIGUSR2, signal_handler);
  signal(SIGHUP, signal_handler);
  arena_collector = malloc(sizeof(arena_struct_t));
  const arena_status err = arena_create(arena_collector, (size_t) 1024 * 1024 * 1024);
  if (err != ok) {
    fprintf(STDERR, "arena_create failed: %d\n", err);
    goto error_no_arena;
  }
  fprintf(stderr, "collector_init...\n");

  loop_udp = uv_default_loop();
  loop_pool = uv_default_loop();

  uv_udp_t *udp_server = collector_config->alloc(arena_collector, sizeof(uv_udp_t));
  uv_udp_init(loop_udp, udp_server);


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
void udp_handle(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf, const struct sockaddr *addr, unsigned flags) {
  static parse_args_t *func_args;
  if (nread == 0) {
    return;
  }
  if (addr == NULL) {
    fprintf(STDERR, "got udp packet! handle: %p ip: NULL flags: %d\n", (void *) handle, flags);
  } else {
    char address_str[INET6_ADDRSTRLEN + 8]; // Enough space for IPv6 + port
    get_ip_str(addr, address_str, sizeof(address_str));
    // printf("Address: %s\n", address_str);

    fprintf(STDERR, "got udp packet! handle: %p ip: %s flags: %d bytes: %d\n", (void *) handle, address_str, flags,
            nread);
  }
  if (func_args == NULL) {
    func_args = collector_config->alloc(arena_collector, sizeof(parse_args_t));
    func_args->exporter = 0;
    func_args->len = 0;
    func_args->data = NULL;
    func_args->mutex = collector_config->alloc(arena_collector, sizeof(uv_mutex_t));
    uv_mutex_init(func_args->mutex);
  }

  /*
  for (int i = 0; i < nread; ++i) {
    fprintf(STDERR,"%x", buf->base[i]);
  }
  fprintf(STDERR,"\n");
  */
  NETFLOW_VERSION nf_version = collector_config->detect_version(buf->base);

  static void *tmp[1024] = {0};
  static uv_work_t *work_req[1024] = {0};
  uv_work_t *tmp_worker = NULL;
  static size_t data_counter = 0;
  if (tmp[data_counter] == NULL) {
    tmp[data_counter] = collector_config->alloc(arena_collector, 65536);
  }
  if (work_req[data_counter] == NULL) {
    tmp_worker = arena_alloc(arena_collector, sizeof(uv_work_t));
    work_req[data_counter] = tmp_worker;
  }
  switch (nf_version) {
    case NETFLOW_V5:
    case NETFLOW_V9:
    case NETFLOW_IPFIX:

      uv_mutex_lock((func_args->mutex));
      memset(tmp[data_counter], 0, 65536);
      if (nread > 65536) {
        fprintf(STDERR, "nread > 65536\n");
        return;
      }
      memcpy(tmp[data_counter], buf->base, nread);
      // collector_config->parse_v5(tmp,nread);
      uint32_t *exporter_ptr = NULL;
      exporter_ptr = &(addr->sa_data[2]);
      func_args->exporter = *(uint32_t *) exporter_ptr;
      //swap_endianness(&func_args->exporter, sizeof(uint32_t));
      //func_args->exporter = (uint32_t)(*(&(addr->sa_data[2])) | *(&(addr->sa_data[3]) ) << 8 | *(&(addr->sa_data[4])) << 16 | *(&(addr->sa_data[5])) << 24);
      //func_args->exporter = addr->sa_data[2] << 0 | addr->sa_data[3] << 8 | addr->sa_data[4] << 16 | addr->sa_data[5] << 24;
      func_args->data = tmp[data_counter];
      func_args->len = nread;
      // uv_thread_create(&threads[thread_counter], (void*)collector_config->parse_v5, func_args);

      if (work_req == NULL) {
        signal_handler(SIGABRT);
      }
      uv_work_cb work_cb = (void *) collector_config->parse_v5;
      work_req[data_counter]->data = (parse_args_t *) func_args;

      uv_queue_work(loop_pool, work_req[data_counter], work_cb, NULL);

      //      collector_config->parse_v5(func_args);

      /*func_args->data = tmp;
      func_args->size = nread;
      */
      ///

      data_counter++;
      break;
    default:
      fprintf(STDERR, "unsupported nf version %d\n", nf_version);
      break;
  }
  // memset((void *) buf->base, 0, nread);
  // memset((void *) buf, 0, sizeof(uv_buf_t));
  if (data_counter >= 1024) {
    data_counter = 0;
  }
  thread_counter++;
  if (thread_counter > 7) {
    thread_counter = 0;
  }
}
