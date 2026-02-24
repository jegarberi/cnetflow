#include "metrics.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "log.h"

// The single global metrics variable
cnetflow_metrics_t g_metrics;

void metrics_init(void) {
  // Zero out the struct correctly
  g_metrics.packets_received = 0;

  g_metrics.netflow_v5_parsed = 0;
  g_metrics.netflow_v5_dropped = 0;

  g_metrics.v9_templates_received = 0;
  g_metrics.v9_templates_dropped = 0;
  g_metrics.v9_records_received = 0;
  g_metrics.v9_records_dropped = 0;

  g_metrics.ipfix_templates_received = 0;
  g_metrics.ipfix_templates_dropped = 0;
  g_metrics.ipfix_records_received = 0;
  g_metrics.ipfix_records_dropped = 0;

  g_metrics.collectors_detected = 0;
  g_metrics.interfaces_detected = 0;

  g_metrics.bytes_per_sec = 0;
  g_metrics.pkts_per_sec = 0;
  g_metrics.flowsets_per_sec = 0;

  // Initialize the mutex
  uv_mutex_init(&g_metrics.mutex);
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
  // We actually don't need to allocate memory for reading as we won't read from the socket,
  // we just write the metrics and close. But a dummy buffer is still required by libuv if we start reading.
  // Although we aren't calling uv_read_start, we will define this in case.
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

    uv_buf_t wrbuf = uv_buf_init(json_buf, strlen(json_buf));
    req->data = json_buf; // Store buffer so we can free it in callback

    // HTTP response wrapper so it works in curl/browsers implicitly (HTTP/0.9 behavior)
    // Send it raw, but with a basic JSON structure.
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

void metrics_tcp_start(uv_loop_t *loop, int port) {
  uv_tcp_t *server = (uv_tcp_t *) malloc(sizeof(uv_tcp_t));
  uv_tcp_init(loop, server);

  struct sockaddr_in addr;
  uv_ip4_addr("0.0.0.0", port, &addr);

  int r;
  r = uv_tcp_bind(server, (const struct sockaddr *) &addr, 0);
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
