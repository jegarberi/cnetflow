//
// Created by jon on 6/3/25.
//
#include "netflow.h"

#include <netinet/in.h>
#include <stdint.h>
#include <string.h>

NETFLOW_VERSION detect_version(void *data) {
  if (endianness == NETFLOW_NO_ENDIAN) {
    endianness = detect_endianness();
  }
  uint16_t version = 0;
  memcpy(&version, data, sizeof(uint16_t));
  if (endianness == NETFLOW_LITTLE_ENDIAN) {
    version = ntohs(version);
  }
  switch (version) {
    case NETFLOW_V5:
      return NETFLOW_V5;
    case NETFLOW_V9:
      return NETFLOW_V9;
    case NETFLOW_IPFIX:
      return NETFLOW_IPFIX;
    default:
      return NETFLOW_UNKNOWN;
  }
}
endianness_e detect_endianness(void) {
  uint64_t endianness_test = 65535;
  uint64_t *ptr = &endianness_test;
  uint16_t *b = (uint16_t *) ptr;
  if (*b == 0x0000) {
    return NETFLOW_BIG_ENDIAN;
  } else {
    return NETFLOW_LITTLE_ENDIAN;
  }
}

void swap_endianness(void *value, size_t len) {
  if (endianness == NETFLOW_NO_ENDIAN) {
    endianness = detect_endianness();
  }
  if (endianness == NETFLOW_BIG_ENDIAN) {
    return;
  }
  switch (len) {
    case 2:
      uint16_t tmp16 = *(uint16_t *) value;
      tmp16 = swap_endian_16(tmp16);
      memcpy(value, &tmp16, sizeof(uint16_t));
      break;
    case 4:
      uint32_t tmp32 = *(uint32_t *) value;
      tmp32 = swap_endian_32(tmp32);
      memcpy(value, &tmp32, sizeof(uint32_t));
      break;
    case 8:
      uint64_t tmp64 = *(uint64_t *) value;
      tmp64 = swap_endian_64(tmp64);
      memcpy(value, &tmp64, sizeof(uint64_t));
      break;
  }
}

uint64_t swap_endian_64(uint64_t value) {
  return ((value & 0xFF00000000000000ULL) >> 56) | ((value & 0x00FF000000000000ULL) >> 40) |
         ((value & 0x0000FF0000000000ULL) >> 24) | ((value & 0x000000FF00000000ULL) >> 8) |
         ((value & 0x00000000FF000000ULL) << 8) | ((value & 0x0000000000FF0000ULL) << 24) |
         ((value & 0x000000000000FF00ULL) << 40) | ((value & 0x00000000000000FFULL) << 56);
}

uint32_t swap_endian_32(uint32_t value) {
  return ((value & 0xFF000000) >> 24) | ((value & 0x00FF0000) >> 8) | ((value & 0x0000FF00) << 8) |
         ((value & 0x000000FF) << 24);
}

uint16_t swap_endian_16(uint16_t value) { return (value >> 8) | (value << 8); }

void *fix_endianness(void *buf, void *data, size_t len) {
  memset(buf, 0, len);
  if (endianness == NETFLOW_NO_ENDIAN) {
    endianness = detect_endianness();
  }
  if (endianness == NETFLOW_LITTLE_ENDIAN) {
    memcpy(buf, data, len);
    switch (len) {
      case 1:
        memcpy(buf, (uint8_t *) data, 2);
        break;
      case 2:
        int16_t *ptr16 = (uint16_t *) data;
        int16_t tmp16 = *ptr16;
        tmp16 = ntohs(tmp16);
        memcpy(buf, &tmp16, 2);
        break;
      case 4:
        int32_t *ptr32 = (uint32_t *) data;
        int32_t tmp32 = *ptr32;
        tmp32 = ntohs(tmp32);
        memcpy(buf, &tmp32, 2);
        break;
    }
  }
}
