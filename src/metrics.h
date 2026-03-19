#ifndef CNETFLOW_METRICS_H
#define CNETFLOW_METRICS_H

#include <stdint.h>
#include <uv.h>

#ifdef ENABLE_METRICS

/**
 * @brief Global metrics structure to count various events across the system.
 * Updated by the metrics thread.
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

  // Rates (to be updated separately)
  uint64_t bytes_per_sec;
  uint64_t pkts_per_sec;
  uint64_t flowsets_per_sec;

  // Mutex to protect global reads/writes
  uv_mutex_t mutex;
} cnetflow_metrics_t;

// The single global metrics instance
extern cnetflow_metrics_t g_metrics;

/**
 * @brief Initializes the global metrics structure and starts the metrics thread.
 */
void metrics_init(void);

/**
 * @brief Starts a TCP server to expose the metrics as JSON.
 * @param port The TCP port to listen on.
 */
void metrics_tcp_start(int port);

/**
 * @brief Starts the rate-calculation timer for metrics.
 */
void metrics_timer_start(void);

/**
 * @brief Asynchronous increment functions (Shoot and Forget)
 */
void metrics_inc_packets(void);
void metrics_inc_v5_parsed(void);
void metrics_inc_v5_dropped(void);
void metrics_inc_v9_templates_received(void);
void metrics_inc_v9_templates_dropped(void);
void metrics_inc_v9_records_received(void);
void metrics_inc_v9_records_dropped(void);
void metrics_inc_ipfix_templates_received(void);
void metrics_inc_ipfix_templates_dropped(void);
void metrics_inc_ipfix_records_received(void);
void metrics_inc_ipfix_records_dropped(void);

void metrics_inc_v9_records_received_batch(uint64_t count);
void metrics_inc_ipfix_records_received_batch(uint64_t count);

/**
 * @brief Increments processed byte count tracking for rate calculation.
 */
void metrics_inc_bytes(uint64_t bytes);

/**
 * @brief Increments processed flowsets count tracking for rate calculation.
 */
void metrics_inc_flowsets(uint64_t flowsets);

/**
 * @brief Tracks unique exporter IPs.
 */
void metrics_track_exporter(uint32_t exporter_ip);

/**
 * @brief Tracks unique interface IDs per exporter.
 */
void metrics_track_interface(uint32_t exporter_ip, uint16_t interface_id);

#else // ENABLE_METRICS

#define metrics_init() do {} while(0)
#define metrics_tcp_start(port) do {} while(0)
#define metrics_timer_start() do {} while(0)
#define metrics_inc_packets() do {} while(0)
#define metrics_inc_v5_parsed() do {} while(0)
#define metrics_inc_v5_dropped() do {} while(0)
#define metrics_inc_v9_templates_received() do {} while(0)
#define metrics_inc_v9_templates_dropped() do {} while(0)
#define metrics_inc_v9_records_received() do {} while(0)
#define metrics_inc_v9_records_dropped() do {} while(0)
#define metrics_inc_v9_records_received_batch(count) do {} while(0)
#define metrics_inc_ipfix_templates_received() do {} while(0)
#define metrics_inc_ipfix_templates_dropped() do {} while(0)
#define metrics_inc_ipfix_records_received() do {} while(0)
#define metrics_inc_ipfix_records_dropped() do {} while(0)
#define metrics_inc_ipfix_records_received_batch(count) do {} while(0)
#define metrics_inc_bytes(bytes) do {} while(0)
#define metrics_inc_flowsets(flowsets) do {} while(0)
#define metrics_track_exporter(ip) do {} while(0)
#define metrics_track_interface(ip, id) do {} while(0)

#endif // ENABLE_METRICS

#endif // CNETFLOW_METRICS_H
