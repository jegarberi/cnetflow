#ifndef CNETFLOW_METRICS_H
#define CNETFLOW_METRICS_H

#include <stdint.h>
#include <uv.h>

/**
 * @brief Global metrics structure to count various events across the system.
 */
typedef struct {
  // Basic network stats
  uint64_t packets_received;

  // NetFlow v5
  uint64_t netflow_v5_parsed;
  uint64_t netflow_v5_dropped;

  // NetFlow v9
  uint64_t v9_templates_received;
  uint64_t v9_templates_dropped;
  uint64_t v9_records_received;
  uint64_t v9_records_dropped;

  // IPFIX
  uint64_t ipfix_templates_received;
  uint64_t ipfix_templates_dropped;
  uint64_t ipfix_records_received;
  uint64_t ipfix_records_dropped;

  // General runtime stats
  uint64_t collectors_detected;
  uint64_t interfaces_detected;

  // Rates (to be updated separately if needed, though typically rates are calculated
  // from totals over time intervals rather than accumulated here)
  uint64_t bytes_per_sec;
  uint64_t pkts_per_sec;
  uint64_t flowsets_per_sec;

  // Mutex to protect global writes from multiple threads
  uv_mutex_t mutex;
} cnetflow_metrics_t;

// The single global metrics instance
extern cnetflow_metrics_t g_metrics;

/**
 * @brief Initializes the global metrics structure and its mutex.
 */
void metrics_init(void);

/**
 * @brief Starts a TCP server to expose the metrics as JSON.
 *
 * @param loop The libuv loop to attach the TCP server to.
 * @param port The TCP port to listen on (e.g. 8080).
 */
void metrics_tcp_start(uv_loop_t *loop, int port);

#endif // CNETFLOW_METRICS_H
