#include "metrics.h"

#ifdef ENABLE_METRICS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "log.h"

#ifdef USE_REDIS
#include "redis_handler.h"
#endif

// The single global metrics variable
cnetflow_metrics_t g_metrics;

// Rate Tracking Accumulators (Internal to metrics thread)
static uint64_t total_bytes_accum = 0;
static uint64_t total_pkts_accum = 0;
static uint64_t total_flowsets_accum = 0;

static uint64_t last_bytes = 0;
static uint64_t last_pkts = 0;
static uint64_t last_flowsets = 0;

// Sync accumulators for Redis
static uint64_t redis_packets_delta = 0;
static uint64_t redis_v5_parsed_delta = 0;
static uint64_t redis_v5_dropped_delta = 0;
static uint64_t redis_v9_templates_delta = 0;
static uint64_t redis_v9_templates_dropped_delta = 0;
static uint64_t redis_v9_records_delta = 0;
static uint64_t redis_v9_records_dropped_delta = 0;
static uint64_t redis_ipfix_templates_delta = 0;
static uint64_t redis_ipfix_templates_dropped_delta = 0;
static uint64_t redis_ipfix_records_delta = 0;
static uint64_t redis_ipfix_records_dropped_delta = 0;

static uint32_t *exporters_array = NULL;
static size_t exporters_count = 0;
static size_t exporters_capacity = 0;

// Store combined exporter IP (32 bits) and interface ID (16 bits)
static uint64_t *interfaces_array = NULL;
static size_t interfaces_count = 0;
static size_t interfaces_capacity = 0;

// Async update mechanism
typedef enum {
  METRIC_PACKET_RECEIVED,
  METRIC_V5_PARSED,
  METRIC_V5_DROPPED,
  METRIC_V9_TEMPLATE_RECEIVED,
  METRIC_V9_TEMPLATE_DROPPED,
  METRIC_V9_RECORD_RECEIVED,
  METRIC_V9_RECORD_DROPPED,
  METRIC_IPFIX_TEMPLATE_RECEIVED,
  METRIC_IPFIX_TEMPLATE_DROPPED,
  METRIC_IPFIX_RECORD_RECEIVED,
  METRIC_IPFIX_RECORD_DROPPED,
  METRIC_ADD_BYTES,
  METRIC_ADD_FLOWSETS,
  METRIC_TRACK_EXPORTER,
  METRIC_TRACK_INTERFACE,
  METRIC_START_TCP,
  METRIC_START_TIMER
} metric_type_t;

typedef struct {
  metric_type_t type;
  uint64_t value;
  uint32_t ip;
  uint16_t id;
} metric_update_t;

#define METRICS_RING_SIZE 65536
static metric_update_t metrics_ring[METRICS_RING_SIZE];
static size_t ring_head = 0;
static size_t ring_tail = 0;
static uv_mutex_t ring_mutex;

static uv_thread_t metrics_thread;
static uv_loop_t metrics_loop;
static uv_async_t metrics_async;
static uv_sem_t metrics_ready_sem;

static void push_update(metric_update_t *update) {
  uv_mutex_lock(&ring_mutex);
  size_t next_head = (ring_head + 1) % METRICS_RING_SIZE;
  if (next_head != ring_tail) {
    metrics_ring[ring_head] = *update;
    ring_head = next_head;
  }
  uv_mutex_unlock(&ring_mutex);
  uv_async_send(&metrics_async);
}

#ifdef USE_REDIS
static void redis_sync_counters(void) {
  redisContext *c = get_redis_conn();
  if (!c) return;

  if (redis_packets_delta > 0) {
    redisCommand(c, "INCRBY cnetflow:metrics:packets_received %llu", (unsigned long long) redis_packets_delta);
    redis_packets_delta = 0;
  }
  if (redis_v5_parsed_delta > 0) {
    redisCommand(c, "INCRBY cnetflow:metrics:v5:parsed %llu", (unsigned long long) redis_v5_parsed_delta);
    redis_v5_parsed_delta = 0;
  }
  if (redis_v5_dropped_delta > 0) {
    redisCommand(c, "INCRBY cnetflow:metrics:v5:dropped %llu", (unsigned long long) redis_v5_dropped_delta);
    redis_v5_dropped_delta = 0;
  }
  if (redis_v9_templates_delta > 0) {
    redisCommand(c, "INCRBY cnetflow:metrics:v9:templates_received %llu", (unsigned long long) redis_v9_templates_delta);
    redis_v9_templates_delta = 0;
  }
  if (redis_v9_templates_dropped_delta > 0) {
    redisCommand(c, "INCRBY cnetflow:metrics:v9:templates_dropped %llu", (unsigned long long) redis_v9_templates_dropped_delta);
    redis_v9_templates_dropped_delta = 0;
  }
  if (redis_v9_records_delta > 0) {
    redisCommand(c, "INCRBY cnetflow:metrics:v9:records_received %llu", (unsigned long long) redis_v9_records_delta);
    redis_v9_records_delta = 0;
  }
  if (redis_v9_records_dropped_delta > 0) {
    redisCommand(c, "INCRBY cnetflow:metrics:v9:records_dropped %llu", (unsigned long long) redis_v9_records_dropped_delta);
    redis_v9_records_dropped_delta = 0;
  }
  if (redis_ipfix_templates_delta > 0) {
    redisCommand(c, "INCRBY cnetflow:metrics:ipfix:templates_received %llu", (unsigned long long) redis_ipfix_templates_delta);
    redis_ipfix_templates_delta = 0;
  }
  if (redis_ipfix_templates_dropped_delta > 0) {
    redisCommand(c, "INCRBY cnetflow:metrics:ipfix:templates_dropped %llu", (unsigned long long) redis_ipfix_templates_dropped_delta);
    redis_ipfix_templates_dropped_delta = 0;
  }
  if (redis_ipfix_records_delta > 0) {
    redisCommand(c, "INCRBY cnetflow:metrics:ipfix:records_received %llu", (unsigned long long) redis_ipfix_records_delta);
    redis_ipfix_records_delta = 0;
  }
  if (redis_ipfix_records_dropped_delta > 0) {
    redisCommand(c, "INCRBY cnetflow:metrics:ipfix:records_dropped %llu", (unsigned long long) redis_ipfix_records_dropped_delta);
    redis_ipfix_records_dropped_delta = 0;
  }
}

static void load_from_redis(void) {
  redisContext *c = get_redis_conn();
  if (!c) return;

  redisReply *reply;
  uv_mutex_lock(&g_metrics.mutex);
  
  reply = redisCommand(c, "GET cnetflow:metrics:packets_received");
  if (reply && reply->type == REDIS_REPLY_STRING) g_metrics.packets_received = strtoull(reply->str, NULL, 10);
  if (reply) freeReplyObject(reply);

  reply = redisCommand(c, "GET cnetflow:metrics:v5:parsed");
  if (reply && reply->type == REDIS_REPLY_STRING) g_metrics.netflow_v5_parsed = strtoull(reply->str, NULL, 10);
  if (reply) freeReplyObject(reply);

  reply = redisCommand(c, "GET cnetflow:metrics:v5:dropped");
  if (reply && reply->type == REDIS_REPLY_STRING) g_metrics.netflow_v5_dropped = strtoull(reply->str, NULL, 10);
  if (reply) freeReplyObject(reply);

  reply = redisCommand(c, "GET cnetflow:metrics:v9:templates_received");
  if (reply && reply->type == REDIS_REPLY_STRING) g_metrics.v9_templates_received = strtoull(reply->str, NULL, 10);
  if (reply) freeReplyObject(reply);

  reply = redisCommand(c, "GET cnetflow:metrics:v9:templates_dropped");
  if (reply && reply->type == REDIS_REPLY_STRING) g_metrics.v9_templates_dropped = strtoull(reply->str, NULL, 10);
  if (reply) freeReplyObject(reply);

  reply = redisCommand(c, "GET cnetflow:metrics:v9:records_received");
  if (reply && reply->type == REDIS_REPLY_STRING) g_metrics.v9_records_received = strtoull(reply->str, NULL, 10);
  if (reply) freeReplyObject(reply);

  reply = redisCommand(c, "GET cnetflow:metrics:v9:records_dropped");
  if (reply && reply->type == REDIS_REPLY_STRING) g_metrics.v9_records_dropped = strtoull(reply->str, NULL, 10);
  if (reply) freeReplyObject(reply);

  reply = redisCommand(c, "GET cnetflow:metrics:ipfix:templates_received");
  if (reply && reply->type == REDIS_REPLY_STRING) g_metrics.ipfix_templates_received = strtoull(reply->str, NULL, 10);
  if (reply) freeReplyObject(reply);

  reply = redisCommand(c, "GET cnetflow:metrics:ipfix:templates_dropped");
  if (reply && reply->type == REDIS_REPLY_STRING) g_metrics.ipfix_templates_dropped = strtoull(reply->str, NULL, 10);
  if (reply) freeReplyObject(reply);

  reply = redisCommand(c, "GET cnetflow:metrics:ipfix:records_received");
  if (reply && reply->type == REDIS_REPLY_STRING) g_metrics.ipfix_records_received = strtoull(reply->str, NULL, 10);
  if (reply) freeReplyObject(reply);

  reply = redisCommand(c, "GET cnetflow:metrics:ipfix:records_dropped");
  if (reply && reply->type == REDIS_REPLY_STRING) g_metrics.ipfix_records_dropped = strtoull(reply->str, NULL, 10);
  if (reply) freeReplyObject(reply);

  reply = redisCommand(c, "SCARD cnetflow:metrics:exporters");
  if (reply && reply->type == REDIS_REPLY_INTEGER) g_metrics.collectors_detected = reply->integer;
  if (reply) freeReplyObject(reply);

  reply = redisCommand(c, "SCARD cnetflow:metrics:interfaces");
  if (reply && reply->type == REDIS_REPLY_INTEGER) g_metrics.interfaces_detected = reply->integer;
  if (reply) freeReplyObject(reply);

  uv_mutex_unlock(&g_metrics.mutex);
}
#endif

static void process_track_exporter(uint32_t exporter_ip) {
  for (size_t i = 0; i < exporters_count; i++) {
    if (exporters_array[i] == exporter_ip) return;
  }
  if (exporters_count == exporters_capacity) {
    size_t new_cap = exporters_capacity == 0 ? 16 : exporters_capacity * 2;
    void *new_ptr = realloc(exporters_array, new_cap * sizeof(uint32_t));
    if (!new_ptr) {
      return;
    }
    exporters_array = (uint32_t *) new_ptr;
    exporters_capacity = new_cap;
  }
  exporters_array[exporters_count++] = exporter_ip;
  uv_mutex_lock(&g_metrics.mutex);
  g_metrics.collectors_detected = exporters_count;
  uv_mutex_unlock(&g_metrics.mutex);
#ifdef USE_REDIS
  redisContext *c = get_redis_conn();
  if (c) redisCommand(c, "SADD cnetflow:metrics:exporters %u", exporter_ip);
#endif
}

static void process_track_interface(uint32_t exporter_ip, uint16_t interface_id) {
  uint64_t combined_key = ((uint64_t) exporter_ip << 32) | interface_id;
  for (size_t i = 0; i < interfaces_count; i++) {
    if (interfaces_array[i] == combined_key) return;
  }
  if (interfaces_count == interfaces_capacity) {
    size_t new_cap = interfaces_capacity == 0 ? 16 : interfaces_capacity * 2;
    void *new_ptr = realloc(interfaces_array, new_cap * sizeof(uint64_t));
    if (!new_ptr) {
      return;
    }
    interfaces_array = (uint64_t *) new_ptr;
    interfaces_capacity = new_cap;
  }
  interfaces_array[interfaces_count++] = combined_key;
  uv_mutex_lock(&g_metrics.mutex);
  g_metrics.interfaces_detected = interfaces_count;
  uv_mutex_unlock(&g_metrics.mutex);
#ifdef USE_REDIS
  redisContext *c = get_redis_conn();
  if (c) redisCommand(c, "SADD cnetflow:metrics:interfaces %llu", (unsigned long long) combined_key);
#endif
}

static void process_update(metric_update_t *update) {
  switch (update->type) {
    case METRIC_PACKET_RECEIVED:
      uv_mutex_lock(&g_metrics.mutex); g_metrics.packets_received++; uv_mutex_unlock(&g_metrics.mutex);
      redis_packets_delta++;
      break;
    case METRIC_V5_PARSED:
      uv_mutex_lock(&g_metrics.mutex); g_metrics.netflow_v5_parsed++; uv_mutex_unlock(&g_metrics.mutex);
      redis_v5_parsed_delta++;
      break;
    case METRIC_V5_DROPPED:
      uv_mutex_lock(&g_metrics.mutex); g_metrics.netflow_v5_dropped++; uv_mutex_unlock(&g_metrics.mutex);
      redis_v5_dropped_delta++;
      break;
    case METRIC_V9_TEMPLATE_RECEIVED:
      uv_mutex_lock(&g_metrics.mutex); g_metrics.v9_templates_received++; uv_mutex_unlock(&g_metrics.mutex);
      redis_v9_templates_delta++;
      break;
    case METRIC_V9_TEMPLATE_DROPPED:
      uv_mutex_lock(&g_metrics.mutex); g_metrics.v9_templates_dropped++; uv_mutex_unlock(&g_metrics.mutex);
      redis_v9_templates_dropped_delta++;
      break;
    case METRIC_V9_RECORD_RECEIVED:
      uv_mutex_lock(&g_metrics.mutex); g_metrics.v9_records_received += update->value; uv_mutex_unlock(&g_metrics.mutex);
      redis_v9_records_delta += update->value;
      break;
    case METRIC_V9_RECORD_DROPPED:
      uv_mutex_lock(&g_metrics.mutex); g_metrics.v9_records_dropped++; uv_mutex_unlock(&g_metrics.mutex);
      redis_v9_records_dropped_delta++;
      break;
    case METRIC_IPFIX_TEMPLATE_RECEIVED:
      uv_mutex_lock(&g_metrics.mutex); g_metrics.ipfix_templates_received++; uv_mutex_unlock(&g_metrics.mutex);
      redis_ipfix_templates_delta++;
      break;
    case METRIC_IPFIX_TEMPLATE_DROPPED:
      uv_mutex_lock(&g_metrics.mutex); g_metrics.ipfix_templates_dropped++; uv_mutex_unlock(&g_metrics.mutex);
      redis_ipfix_templates_dropped_delta++;
      break;
    case METRIC_IPFIX_RECORD_RECEIVED:
      uv_mutex_lock(&g_metrics.mutex); g_metrics.ipfix_records_received += update->value; uv_mutex_unlock(&g_metrics.mutex);
      redis_ipfix_records_delta += update->value;
      break;
    case METRIC_IPFIX_RECORD_DROPPED:
      uv_mutex_lock(&g_metrics.mutex); g_metrics.ipfix_records_dropped++; uv_mutex_unlock(&g_metrics.mutex);
      redis_ipfix_records_dropped_delta++;
      break;
    case METRIC_ADD_BYTES:
      total_bytes_accum += update->value;
      total_pkts_accum++;
      break;
    case METRIC_ADD_FLOWSETS:
      total_flowsets_accum += update->value;
      break;
    case METRIC_TRACK_EXPORTER:
      process_track_exporter(update->ip);
      break;
    case METRIC_TRACK_INTERFACE:
      process_track_interface(update->ip, update->id);
      break;
    case METRIC_START_TCP:
      metrics_tcp_start((int)update->value);
      break;
    case METRIC_START_TIMER:
      metrics_timer_start();
      break;
  }
}

static void on_metrics_async(uv_async_t *handle) {
  (void)handle;
  while (1) {
    metric_update_t update;
    int found = 0;
    uv_mutex_lock(&ring_mutex);
    if (ring_tail != ring_head) {
      update = metrics_ring[ring_tail];
      ring_tail = (ring_tail + 1) % METRICS_RING_SIZE;
      found = 1;
    }
    uv_mutex_unlock(&ring_mutex);
    if (!found) break;
    process_update(&update);
  }
}

static void on_metrics_timer(uv_timer_t *handle) {
  (void)handle;
  uv_mutex_lock(&g_metrics.mutex);
  g_metrics.bytes_per_sec = total_bytes_accum - last_bytes;
  g_metrics.pkts_per_sec = total_pkts_accum - last_pkts;
  g_metrics.flowsets_per_sec = total_flowsets_accum - last_flowsets;

  last_bytes = total_bytes_accum;
  last_pkts = total_pkts_accum;
  last_flowsets = total_flowsets_accum;
  uv_mutex_unlock(&g_metrics.mutex);

#ifdef USE_REDIS
  redis_sync_counters();
#endif
}

static void metrics_worker_thread(void *arg) {
  (void)arg;
  uv_loop_init(&metrics_loop);
  uv_async_init(&metrics_loop, &metrics_async, on_metrics_async);
  uv_sem_post(&metrics_ready_sem);

#ifdef USE_REDIS
  load_from_redis();
#endif

  uv_run(&metrics_loop, UV_RUN_DEFAULT);
}

void metrics_init(void) {
  memset(&g_metrics, 0, sizeof(g_metrics));
  uv_mutex_init(&g_metrics.mutex);
  uv_mutex_init(&ring_mutex);
  uv_sem_init(&metrics_ready_sem, 0);
  
  uv_thread_create(&metrics_thread, metrics_worker_thread, NULL);
  uv_sem_wait(&metrics_ready_sem);
  uv_sem_destroy(&metrics_ready_sem);
}

static void on_metrics_write(uv_write_t *req, int status) {
  if (status) {
    LOG_ERROR("Metrics write error %s\n", uv_strerror(status));
  }
  uv_close((uv_handle_t *) req->handle, (uv_close_cb) free);
  free(req->data);
  free(req);
}

static void on_metrics_alloc(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
  (void)handle;
  buf->base = malloc(suggested_size);
  buf->len = suggested_size;
}

static void on_metrics_connection(uv_stream_t *server, int status) {
  if (status < 0) {
    LOG_ERROR("Metrics new connection error %s\n", uv_strerror(status));
    return;
  }

  uv_tcp_t *client = (uv_tcp_t *) malloc(sizeof(uv_tcp_t));
  uv_tcp_init(server->loop, client);

  if (uv_accept(server, (uv_stream_t *) client) == 0) {
    char *json_buf = malloc(2048);
    if (!json_buf) {
      uv_close((uv_handle_t *) client, (uv_close_cb) free);
      return;
    }

    uv_mutex_lock(&g_metrics.mutex);
    snprintf(json_buf, 2048,
             "HTTP/1.1 200 OK\r\n"
             "Content-Type: application/json\r\n"
             "Connection: close\r\n"
             "\r\n"
             "{\n"
             "  \"packets_received\": %lu,\n"
             "  \"netflow_v5_parsed\": %lu,\n"
             "  \"netflow_v5_dropped\": %lu,\n"
             "  \"v9_templates_received\": %lu,\n"
             "  \"v9_templates_dropped\": %lu,\n"
             "  \"v9_records_received\": %lu,\n"
             "  \"v9_records_dropped\": %lu,\n"
             "  \"ipfix_templates_received\": %lu,\n"
             "  \"ipfix_templates_dropped\": %lu,\n"
             "  \"ipfix_records_received\": %lu,\n"
             "  \"ipfix_records_dropped\": %lu,\n"
             "  \"collectors_detected\": %lu,\n"
             "  \"interfaces_detected\": %lu,\n"
             "  \"bytes_per_sec\": %lu,\n"
             "  \"pkts_per_sec\": %lu,\n"
             "  \"flowsets_per_sec\": %lu\n"
             "}\n",
             g_metrics.packets_received, g_metrics.netflow_v5_parsed, g_metrics.netflow_v5_dropped,
             g_metrics.v9_templates_received, g_metrics.v9_templates_dropped, g_metrics.v9_records_received,
             g_metrics.v9_records_dropped, g_metrics.ipfix_templates_received, g_metrics.ipfix_templates_dropped,
             g_metrics.ipfix_records_received, g_metrics.ipfix_records_dropped, g_metrics.collectors_detected,
             g_metrics.interfaces_detected, g_metrics.bytes_per_sec, g_metrics.pkts_per_sec,
             g_metrics.flowsets_per_sec);
    uv_mutex_unlock(&g_metrics.mutex);

    uv_write_t *req = (uv_write_t *) malloc(sizeof(uv_write_t));
    if (!req) {
      free(json_buf);
      uv_close((uv_handle_t *) client, (uv_close_cb) free);
      return;
    }

    uv_buf_t wrbuf = uv_buf_init(json_buf, (unsigned int)strlen(json_buf));
    req->data = json_buf;

    int ret = uv_write(req, (uv_stream_t *) client, &wrbuf, 1, on_metrics_write);
    if (ret != 0) {
      LOG_ERROR("uv_write error %s\n", uv_strerror(ret));
      free(json_buf);
      free(req);
      uv_close((uv_handle_t *) client, (uv_close_cb) free);
    }
  } else {
    uv_close((uv_handle_t *) client, (uv_close_cb) free);
  }
}

void metrics_tcp_start(int port) {
  uv_thread_t self = uv_thread_self();
  if (!uv_thread_equal(&self, &metrics_thread)) {
    metric_update_t update = { .type = METRIC_START_TCP, .value = (uint64_t)port };
    push_update(&update);
    return;
  }
  
  uv_tcp_t *server = (uv_tcp_t *) malloc(sizeof(uv_tcp_t));
  uv_tcp_init(&metrics_loop, server);

  struct sockaddr_in addr;
  uv_ip4_addr("0.0.0.0", port, &addr);

  int r = uv_tcp_bind(server, (const struct sockaddr *) &addr, 0);
  if (r) {
    LOG_ERROR("Metrics TCP Bind error %s\n", uv_strerror(r));
    free(server);
    return;
  }

  r = uv_listen((uv_stream_t *) server, 128, on_metrics_connection);
  if (r) {
    LOG_ERROR("Metrics TCP Listen error %s\n", uv_strerror(r));
    free(server);
    return;
  }

  LOG_INFO("Metrics TCP API listening on 0.0.0.0:%d\n", port);
}

void metrics_timer_start(void) {
  uv_thread_t self = uv_thread_self();
  if (!uv_thread_equal(&self, &metrics_thread)) {
    metric_update_t update = { .type = METRIC_START_TIMER };
    push_update(&update);
    return;
  }
  uv_timer_t *timer = malloc(sizeof(uv_timer_t));
  uv_timer_init(&metrics_loop, timer);
  uv_timer_start(timer, on_metrics_timer, 1000, 1000);
}

void metrics_inc_packets(void) {
  metric_update_t update = { .type = METRIC_PACKET_RECEIVED };
  push_update(&update);
}

void metrics_inc_v5_parsed(void) {
  metric_update_t update = { .type = METRIC_V5_PARSED };
  push_update(&update);
}

void metrics_inc_v5_dropped(void) {
  metric_update_t update = { .type = METRIC_V5_DROPPED };
  push_update(&update);
}

void metrics_inc_v9_templates_received(void) {
  metric_update_t update = { .type = METRIC_V9_TEMPLATE_RECEIVED };
  push_update(&update);
}

void metrics_inc_v9_templates_dropped(void) {
  metric_update_t update = { .type = METRIC_V9_TEMPLATE_DROPPED };
  push_update(&update);
}

void metrics_inc_v9_records_received(void) {
  metric_update_t update = { .type = METRIC_V9_RECORD_RECEIVED, .value = 1 };
  push_update(&update);
}

void metrics_inc_v9_records_received_batch(uint64_t count) {
  metric_update_t update = { .type = METRIC_V9_RECORD_RECEIVED, .value = count };
  push_update(&update);
}

void metrics_inc_v9_records_dropped(void) {
  metric_update_t update = { .type = METRIC_V9_RECORD_DROPPED };
  push_update(&update);
}

void metrics_inc_ipfix_templates_received(void) {
  metric_update_t update = { .type = METRIC_IPFIX_TEMPLATE_RECEIVED };
  push_update(&update);
}

void metrics_inc_ipfix_templates_dropped(void) {
  metric_update_t update = { .type = METRIC_IPFIX_TEMPLATE_DROPPED };
  push_update(&update);
}

void metrics_inc_ipfix_records_received(void) {
  metric_update_t update = { .type = METRIC_IPFIX_RECORD_RECEIVED, .value = 1 };
  push_update(&update);
}

void metrics_inc_ipfix_records_received_batch(uint64_t count) {
  metric_update_t update = { .type = METRIC_IPFIX_RECORD_RECEIVED, .value = count };
  push_update(&update);
}

void metrics_inc_ipfix_records_dropped(void) {
  metric_update_t update = { .type = METRIC_IPFIX_RECORD_DROPPED };
  push_update(&update);
}

void metrics_inc_bytes(uint64_t bytes) {
  metric_update_t update = { .type = METRIC_ADD_BYTES, .value = bytes };
  push_update(&update);
}

void metrics_inc_flowsets(uint64_t flowsets) {
  metric_update_t update = { .type = METRIC_ADD_FLOWSETS, .value = flowsets };
  push_update(&update);
}

void metrics_track_exporter(uint32_t exporter_ip) {
  static THREAD_LOCAL uint32_t last_exporter = 0;
  if (unlikely(exporter_ip == last_exporter)) return;
  last_exporter = exporter_ip;

  metric_update_t update = { .type = METRIC_TRACK_EXPORTER, .ip = exporter_ip };
  push_update(&update);
}

void metrics_track_interface(uint32_t exporter_ip, uint16_t interface_id) {
  static THREAD_LOCAL uint64_t last_combined = 0;
  uint64_t combined = ((uint64_t) exporter_ip << 32) | interface_id;
  if (unlikely(combined == last_combined)) return;
  last_combined = combined;

  metric_update_t update = { .type = METRIC_TRACK_INTERFACE, .ip = exporter_ip, .id = interface_id };
  push_update(&update);
}

#endif // ENABLE_METRICS
