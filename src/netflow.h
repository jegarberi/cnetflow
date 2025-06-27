//
// Created by jon on 6/3/25.
//

#ifndef NETFLOW_H
#define NETFLOW_H
#include <stddef.h>
#include <stdint.h>
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
static endianness_e endianness = 0;
#endif // NETFLOW_H
