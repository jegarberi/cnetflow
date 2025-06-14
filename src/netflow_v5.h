//
// Created by jon on 6/3/25.
//

#ifndef NETFLOW_V5_H
#define NETFLOW_V5_H
#include <stddef.h>
#include <stdint.h>
#include "collector.h"
#include <time.h>
#include "netflow.h"
#include "db_psql.h"
typedef struct {
  uint16_t version;
  uint16_t count;
  uint32_t SysUptime;
  uint32_t unix_secs;
  uint32_t unix_nsecs;
  uint32_t flow_sequence;
  uint8_t engine_type;
  uint8_t engine_id;
  uint16_t sampling_interval;

} netflow_v5_header_t;
typedef struct {
  uint32_t srcaddr;
  uint32_t dstaddr;
  uint32_t nexthop;
  uint16_t input;
  uint16_t output;
  uint32_t dPkts;
  uint32_t dOctets;
  uint32_t First;
  uint32_t Last;
  uint16_t srcport;
  uint16_t dstport;
  uint8_t pad1;
  uint8_t tcp_flags;
  uint8_t prot;
  uint8_t tos;
  uint16_t src_as;
  uint16_t dst_as;
  uint8_t src_mask;
  uint8_t dst_mask;
  uint16_t pad2;
} netflow_v5_record_t;

static void prepare_statement(PGconn *conn);
static void insert_v5(PGconn * conn,uint32_t exporter, const netflow_v5_record_t *flows, int count);
static void exit_nicely();
static void printf_v5(FILE *, const netflow_v5_record_t *);
void *parse_v5(const parse_args_t *);
#endif // NETFLOW_V5_H
