//
// Created by jon on 6/3/25.
//

#ifndef NETFLOW_H
#define NETFLOW_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

typedef __uint128_t uint128_t;

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
  uint16_t version;
  uint16_t count;
  uint32_t SysUptime;
  uint32_t unix_secs;
  uint32_t unix_nsecs;
  uint32_t flow_sequence;
  uint8_t engine_type;
  uint8_t engine_id;
  uint16_t sampling_interval;
} netflow_v9_header_insert_t;
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
typedef struct {
  uint32_t srcaddr;
  uint32_t dstaddr;
  uint32_t nexthop;
  uint128_t ipv6srcaddr;
  uint128_t ipv6dstaddr;
  uint128_t ipv6nexthop;
  uint16_t input;
  uint16_t output;
  uint64_t dPkts;
  uint64_t dOctets;
  uint32_t First;
  uint32_t Last;
  uint16_t srcport;
  uint16_t dstport;
  uint8_t tcp_flags;
  uint8_t prot;
  uint8_t tos;
  uint16_t src_as;
  uint16_t dst_as;
  uint8_t src_mask;
  uint8_t dst_mask;
  uint8_t ip_version;
} netflow_v9_record_insert_t;


typedef struct {
  uint128_t srcaddr;
  uint128_t dstaddr;
  uint128_t nexthop;
  uint16_t input;
  uint16_t output;
  uint64_t dPkts;
  uint64_t dOctets;
  uint32_t First;
  uint32_t Last;
  uint16_t srcport;
  uint16_t dstport;
  uint8_t tcp_flags;
  uint8_t prot;
  uint8_t tos;
  uint16_t src_as;
  uint16_t dst_as;
  uint8_t src_mask;
  uint8_t dst_mask;
  uint8_t ip_version;
} netflow_v9_record_insert_uint128_t;


typedef struct {
  netflow_v5_header_t header;
  netflow_v5_record_t records[60];
} netflow_v5_flowset_t;


typedef struct {
  netflow_v9_header_insert_t header;
  netflow_v9_record_insert_t records[60];
} netflow_v9_flowset_t;
typedef struct {
  netflow_v9_header_insert_t header;
  netflow_v9_record_insert_uint128_t records[60];
} netflow_v9_uint128_flowset_t;

typedef __uint128_t uint128_t;
typedef enum {
  NETFLOW_NO_ENDIAN = 0,
  NETFLOW_BIG_ENDIAN = 1,
  NETFLOW_LITTLE_ENDIAN = 2,
} endianness_e;

typedef enum {
  NETFLOW_NONE = 0,
  NETFLOW_UNKNOWN = 0,
  NETFLOW_V5 = 5,
  NETFLOW_V9 = 9,
  NETFLOW_IPFIX = 10
} NETFLOW_VERSION;

NETFLOW_VERSION detect_version(void *data);
endianness_e detect_endianness(void);
void swap_endianness(void *value, size_t len);
uint64_t swap_endian_64(uint64_t value);
uint32_t swap_endian_32(uint32_t value);
uint16_t swap_endian_16(uint16_t value);
uint128_t swap_endian_128(uint128_t value);
void *fix_endianness(void *buf, void *data, size_t len);
void printf_v5(FILE *, netflow_v5_flowset_t *, int);
void swap_src_dst_v5(netflow_v5_record_t *record);
void swap_src_dst_v9(netflow_v9_record_insert_t *record);
void printf_v9(FILE *file, netflow_v9_flowset_t *netflow_packet, int i);
static endianness_e endianness = 0;
#endif // NETFLOW_H
