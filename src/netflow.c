//
// Created by jon on 6/3/25.
//
#include "netflow.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <string.h>
#include "netflow_v5.h"
#include "log.h"

/**
 * Detects the NetFlow version from the provided data.
 *
 * This function analyzes the given raw data to determine the version of the
 * NetFlow protocol being used. It also handles byte-order conversion based
 * on the detected system endianness. Versions are returned as defined in the
 * NETFLOW_VERSION enum.
 *
 * @param data Pointer to the raw data that contains the NetFlow version information.
 * @return The detected NetFlow version as a value of type NETFLOW_VERSION.
 *         Returns NETFLOW_UNKNOWN if the version cannot be determined.
 */

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
/**
 * Detects the system's endianness.
 *
 * This function evaluates the system's endianness by analyzing the layout
 * of a test value in memory. It determines whether the system is big-endian
 * or little-endian and returns the corresponding value of the `endianness_e` enum.
 *
 * @return The system's endianness as a value of type `endianness_e`.
 *         Returns `NETFLOW_BIG_ENDIAN` for big-endian systems and `NETFLOW_LITTLE_ENDIAN`
 *         for little-endian systems.
 */
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

/**
 * Swaps the endianness of a value in memory based on the system's endianness.
 *
 * This function handles conversion of values from little-endian to big-endian
 * and vice versa. Before performing the conversion, the function detects the
 * system's endianness if it has not already been determined. If the system
 * endianness is big-endian, no swapping is performed. The function supports
 * swapping for 16-bit, 32-bit, and 64-bit values.
 *
 * @param value Pointer to the value in memory whose endianness is to be swapped.
 *              The value is modified in place.
 * @param len   The length of the value in bytes. Supported lengths are 2, 4, and 8 bytes.
 */
#if !CNETFLOW_BIG_ENDIAN_ARCH
void swap_endianness(void *value, size_t len) {
  if (endianness == NETFLOW_NO_ENDIAN) {
    endianness = detect_endianness();
  }
  if (endianness == NETFLOW_BIG_ENDIAN) {
    return;
  }
  switch (len) {
    case 2: {
      uint16_t tmp16 = *(uint16_t *) value;
      tmp16 = swap_endian_16(tmp16);
      memcpy(value, &tmp16, sizeof(uint16_t));
      break;
    }
    case 4: {
      uint32_t tmp32 = *(uint32_t *) value;
      tmp32 = swap_endian_32(tmp32);
      memcpy(value, &tmp32, sizeof(uint32_t));
      break;
    }
    case 8: {
      uint64_t tmp64 = *(uint64_t *) value;
      tmp64 = swap_endian_64(tmp64);
      memcpy(value, &tmp64, sizeof(uint64_t));
      break;
    }
    case 16: {
      uint128_t tmp128 = *(uint128_t *) value;
      tmp128 = swap_endian_128(tmp128);
      memcpy(value, &tmp128, sizeof(uint128_t));
      break;
    }
  }
}
#endif

/**
 * Swaps the byte order of a 64-bit unsigned integer.
 *
 * This function reverses the endianness of the provided 64-bit value,
 * converting it between big-endian and little-endian formats.
 *
 * @param value The 64-bit unsigned integer whose byte order is to be swapped.
 * @return The 64-bit unsigned integer with the byte order reversed.
 */
uint64_t swap_endian_64(uint64_t value) {
#if defined(__APPLE__)
  return OSSwapInt64(value);
#elif defined(__GNUC__)
  return __builtin_bswap64(value);
#else
  return ((uint64_t) swap_endian_32(value & 0xFFFFFFFFULL) << 32) | swap_endian_32((value >> 32) & 0xFFFFFFFFULL);
#endif
}
/*
uint64_t swap_endian_64(uint64_t value) {
  return ((value & 0xFF00000000000000ULL) >> 56) | ((value & 0x00FF000000000000ULL) >> 40) |
         ((value & 0x0000FF0000000000ULL) >> 24) | ((value & 0x000000FF00000000ULL) >> 8) |
         ((value & 0x00000000FF000000ULL) << 8) | ((value & 0x0000000000FF0000ULL) << 24) |
         ((value & 0x000000000000FF00ULL) << 40) | ((value & 0x00000000000000FFULL) << 56);
}
*/
uint128_t swap_endian_128(const uint128_t value) {
  // Extract the high and low 64-bit parts
  uint64_t high = (uint64_t) (value >> 64);
  uint64_t low = (uint64_t) (value & 0xFFFFFFFFFFFFFFFFULL);
  // Swap endianness of each 64 - bit part
  uint64_t swapped_high = ((high & 0xFF00000000000000ULL) >> 56) | ((high & 0x00FF000000000000ULL) >> 40) |
                          ((high & 0x0000FF0000000000ULL) >> 24) | ((high & 0x000000FF00000000ULL) >> 8) |
                          ((high & 0x00000000FF000000ULL) << 8) | ((high & 0x0000000000FF0000ULL) << 24) |
                          ((high & 0x000000000000FF00ULL) << 40) | ((high & 0x00000000000000FFULL) << 56);
  int64_t swapped_low = ((low & 0xFF00000000000000ULL) >> 56) | ((low & 0x00FF000000000000ULL) >> 40) |
                        ((low & 0x0000FF0000000000ULL) >> 24) | ((low & 0x000000FF00000000ULL) >> 8) |
                        ((low & 0x00000000FF000000ULL) << 8) | ((low & 0x0000000000FF0000ULL) << 24) |
                        ((low & 0x000000000000FF00ULL) << 40) | ((low & 0x00000000000000FFULL) << 56);

  // Combine the swapped parts (low becomes high, high becomes low)
  return ((uint128_t) swapped_low << 64) | swapped_high;
}


/**
 * Reverses the byte order of a 32-bit integer to swap endianness.
 *
 * This function takes a 32-bit unsigned integer and reverses its byte order,
 * effectively converting it from little-endian to big-endian or vice versa.
 *
 * @param value The 32-bit unsigned integer whose byte order is to be swapped.
 * @return The 32-bit unsigned integer with its byte order reversed.
 */
/*
uint32_t swap_endian_32(uint32_t value) {
  return ((value & 0xFF000000) >> 24) | ((value & 0x00FF0000) >> 8) | ((value & 0x0000FF00) << 8) |
         ((value & 0x000000FF) << 24);
}
*/
uint32_t swap_endian_32(uint32_t value) {
#if defined(__GNUC__) || defined(__clang__)
  return __builtin_bswap32(value);
#else
  return ((value & 0xFF000000) >> 24) | ((value & 0x00FF0000) >> 8) | ((value & 0x0000FF00) << 8) |
         ((value & 0x000000FF) << 24);
#endif
}

/**
 * Swaps the byte order of a 16-bit unsigned integer.
 *
 * This function reverses the byte order (endianness) of the provided 16-bit
 * value, effectively converting it between little-endian and big-endian formats.
 *
 * @param value The 16-bit unsigned integer to have its byte order swapped.
 * @return The 16-bit unsigned integer with the byte order reversed.
 */
/*uint16_t swap_endian_16(uint16_t value) { return (value >> 8) | (value << 8); }*/
uint16_t swap_endian_16(uint16_t value) {
#if defined(__GNUC__) || defined(__clang__)
  return __builtin_bswap16(value);
#else
  return (uint16_t) ((value >> 8) | (value << 8));
#endif
}


/**
 * Converts data into a consistent endianness format based on the system's detected endianness and the specified
 * conditions.
 *
 * This function processes raw data by first determining if the system endianness has been identified. If not, it
 * detects the endianness and adjusts the data accordingly. The function then ensures the data is in little-endian
 * format when required or keeps it unchanged if no conversion is needed. Note that the function supports conversions
 * for data lengths of 1, 2, or 4 bytes.
 *
 * @param buf Pointer to the buffer where the processed data should be stored.
 * @param data Pointer to the raw data that needs to be processed.
 * @param len Length of the data in bytes, which determines the type of conversion.
 *            Supported values are 1, 2, or 4 bytes.
 * @return A pointer to the buffer containing the converted data.
 *         If no conversion is needed, the data is directly copied to the buffer.
 */
void *fix_endianness(void *buf, void *data, size_t len) {
  memset(buf, 0, len);
  if (endianness == NETFLOW_NO_ENDIAN) {
    endianness = detect_endianness();
  }
  if (endianness == NETFLOW_LITTLE_ENDIAN) {
    memcpy(buf, data, len);
    switch (len) {
      case 1:
        memcpy(buf, (uint8_t *) data, 1);
        break;
      case 2: {
        int16_t *ptr16 = (uint16_t *) data;
        int16_t tmp16 = *ptr16;
        tmp16 = ntohs(tmp16);
        memcpy(buf, &tmp16, 2);
        break;
      }
      case 4: {
        int32_t *ptr32 = (uint32_t *) data;
        int32_t tmp32 = *ptr32;
        tmp32 = ntohs(tmp32);
        memcpy(buf, &tmp32, 2);
        break;
      }
    }
  }
}

int is_ipv4_private(const uint32_t ip) {
  if ((ip >= 167772160 && ip <= 184549375) || // CLASS A PRIVATE
      (ip >= 2886729728 && ip <= 2887843839) || // CLASS B PRIVATE
      (ip >= 3232235520 && ip <= 3232301055)) // CLASS C PRIVATE
  {
    return 1;
  }
  return 0;
}

void swap_src_dst_ipfix_ipv4(netflow_v9_record_insert_t *record) {

  /*
    char srcaddr[250];
    char dstaddr[250];
    memccpy(srcaddr, ip_int_to_str(record->srcaddr), '\0', 250);
    memccpy(dstaddr, ip_int_to_str(record->dstaddr), '\0', 250);
    LOG_ERROR("%lu %s %d %s: %s:%d  -> %s:%d \n", uv_thread_self(), __FILE__, __LINE__, __func__, srcaddr,
            record->srcport, dstaddr, record->dstport);
    */
  if (!is_ipv4_private(record->srcaddr) || (is_ipv4_private(record->dstaddr) && record->dstport > record->srcport)) {
    /*
    LOG_ERROR("%lu %s %d %s is_ipv4_private(record->srcaddr): %d\n", uv_thread_self(), __FILE__, __LINE__,
            __func__, is_ipv4_private(record->srcaddr));
    LOG_ERROR("%lu %s %d %s record->srcaddr %u\n", uv_thread_self(), __FILE__, __LINE__, __func__,
            record->srcaddr);
    LOG_ERROR("%lu %s %d %s is_ipv4_private(record->dstaddr): %d\n", uv_thread_self(), __FILE__, __LINE__,
            __func__, is_ipv4_private(record->dstaddr));
    LOG_ERROR("%lu %s %d %s record->dstaddr %u\n", uv_thread_self(), __FILE__, __LINE__, __func__,
            record->dstaddr);
    LOG_ERROR("%lu %s %d %s record->dstport > record->srcport: %d\n", uv_thread_self(), __FILE__, __LINE__,
            __func__, record->dstport > record->srcport);
    */
    //LOG_ERROR("%lu %s %d %s: swapping flow_v9 src and dst\n", uv_thread_self(), __FILE__, __LINE__, __func__);

    const uint16_t tmp_port = record->dstport;
    record->dstport = record->srcport;
    record->srcport = tmp_port;
    const uint32_t tmp_addr = record->dstaddr;
    record->dstaddr = record->srcaddr;
    record->srcaddr = tmp_addr;
    const uint16_t tmp_interface = record->input;
    record->input = record->output;
    record->output = tmp_interface;
  } else {
    //fprintf(stderr, "%s %d %s: NOT swapping flow_v9 src and dst\n", __FILE__, __LINE__, __func__);
  }
}


void swap_src_dst_v9_ipv4(netflow_v9_record_insert_t *record) {

  /*
    char srcaddr[250];
    char dstaddr[250];
    memccpy(srcaddr, ip_int_to_str(record->srcaddr), '\0', 250);
    memccpy(dstaddr, ip_int_to_str(record->dstaddr), '\0', 250);
    LOG_ERROR("%lu %s %d %s: %s:%d  -> %s:%d \n", uv_thread_self(), __FILE__, __LINE__, __func__, srcaddr,
            record->srcport, dstaddr, record->dstport);
    */
  if (!is_ipv4_private(record->srcaddr) || (is_ipv4_private(record->dstaddr) && record->dstport > record->srcport)) {
    /*
    LOG_ERROR("%lu %s %d %s is_ipv4_private(record->srcaddr): %d\n", uv_thread_self(), __FILE__, __LINE__,
            __func__, is_ipv4_private(record->srcaddr));
    LOG_ERROR("%lu %s %d %s record->srcaddr %u\n", uv_thread_self(), __FILE__, __LINE__, __func__,
            record->srcaddr);
    LOG_ERROR("%lu %s %d %s is_ipv4_private(record->dstaddr): %d\n", uv_thread_self(), __FILE__, __LINE__,
            __func__, is_ipv4_private(record->dstaddr));
    LOG_ERROR("%lu %s %d %s record->dstaddr %u\n", uv_thread_self(), __FILE__, __LINE__, __func__,
            record->dstaddr);
    LOG_ERROR("%lu %s %d %s record->dstport > record->srcport: %d\n", uv_thread_self(), __FILE__, __LINE__,
            __func__, record->dstport > record->srcport);
    */
    //LOG_ERROR("%lu %s %d %s: swapping flow_v9 src and dst\n", uv_thread_self(), __FILE__, __LINE__, __func__);

    const uint16_t tmp_port = record->dstport;
    record->dstport = record->srcport;
    record->srcport = tmp_port;
    const uint32_t tmp_addr = record->dstaddr;
    record->dstaddr = record->srcaddr;
    record->srcaddr = tmp_addr;
    const uint16_t tmp_interface = record->input;
    record->input = record->output;
    record->output = tmp_interface;
  } else {
    //fprintf(stderr, "%s %d %s: NOT swapping flow_v9 src and dst\n", __FILE__, __LINE__, __func__);
  }
}

void swap_src_dst_v5_ipv4(netflow_v5_record_t *record) {

  /*
    char srcaddr[250];
    char dstaddr[250];
    memccpy(srcaddr, ip_int_to_str(record->srcaddr), '\0', 250);
    memccpy(dstaddr, ip_int_to_str(record->dstaddr), '\0', 250);
    LOG_ERROR("%lu,%s %d %s: %s:%d  -> %s:%d \n", uv_thread_self(), __FILE__, __LINE__, __func__, srcaddr,
            record->srcport, dstaddr, record->dstport);
    */
  if (!is_ipv4_private(record->srcaddr) || (is_ipv4_private(record->dstaddr) && record->dstport > record->srcport)) {
    /*
    LOG_ERROR("%lu %s %d %s is_ipv4_private(record->srcaddr): %d\n", uv_thread_self(), __FILE__, __LINE__,
            __func__, is_ipv4_private(record->srcaddr));
    LOG_ERROR("%lu %s %d %s record->srcaddr %u\n", uv_thread_self(), __FILE__, __LINE__, __func__,
            record->srcaddr);
    LOG_ERROR("%lu %s %d %s is_ipv4_private(record->dstaddr): %d\n", uv_thread_self(), __FILE__, __LINE__,
            __func__, is_ipv4_private(record->dstaddr));
    LOG_ERROR("%lu %s %d %s record->dstaddr %u\n", uv_thread_self(), __FILE__, __LINE__, __func__,
            record->dstaddr);
    LOG_ERROR("%lu %s %d %s record->dstport > record->srcport: %d\n", uv_thread_self(), __FILE__, __LINE__,
            __func__, record->dstport > record->srcport);
    */
    LOG_ERROR("%lu %s %d %s: swapping flow_v5 src and dst\n", uv_thread_self(), __FILE__, __LINE__, __func__);

    const uint16_t tmp_port = record->dstport;
    record->dstport = record->srcport;
    record->srcport = tmp_port;
    const uint32_t tmp_addr = record->dstaddr;
    record->dstaddr = record->srcaddr;
    record->srcaddr = tmp_addr;
    const uint16_t tmp_interface = record->input;
    record->input = record->output;
    record->output = tmp_interface;
  } else {
    LOG_ERROR("%s %d %s: NOT swapping flow_v5 src and dst\n", __FILE__, __LINE__, __func__);
  }
}

void printf_v5(FILE *file, netflow_v5_flowset_t *netflow_packet, int i) {
  char ip_src_str[50] = {0};
  char ip_dst_str[50] = {0};

  char *tmp;
  tmp = ip_int_to_str(netflow_packet->records[i].srcaddr);
  strncpy(ip_src_str, tmp, strlen(tmp));
  uint16_t tmp_src_port = netflow_packet->records[i].srcport;
  uint16_t tmp_dst_port = netflow_packet->records[i].dstport;
  swap_endianness(&tmp_src_port, sizeof(tmp_src_port));
  swap_endianness(&tmp_dst_port, sizeof(tmp_dst_port));
  tmp = ip_int_to_str(netflow_packet->records[i].dstaddr);
  strncpy(ip_dst_str, tmp, strlen(tmp));
  fprintf(file, "%s:%u -> %s:%u %u\n", ip_src_str, tmp_src_port, ip_dst_str, tmp_dst_port,
          netflow_packet->records[i].prot);
}
void printf_v9(FILE *file, netflow_v9_flowset_t *netflow_packet, int i) {
  char ip_src_str[50] = {0};
  char ip_dst_str[50] = {0};

  char *tmp;
  uint32_t tmp_address = netflow_packet->records[i].srcaddr;
  swap_endianness(&tmp_address, sizeof(tmp_address));
  tmp = ip_int_to_str(tmp_address);
  strncpy(ip_src_str, tmp, strlen(tmp));
  uint16_t tmp_src_port = netflow_packet->records[i].srcport;
  uint16_t tmp_dst_port = netflow_packet->records[i].dstport;
  swap_endianness(&tmp_src_port, sizeof(tmp_src_port));
  swap_endianness(&tmp_dst_port, sizeof(tmp_dst_port));
  tmp_address = netflow_packet->records[i].dstaddr;
  swap_endianness(&tmp_address, sizeof(tmp_address));
  tmp = ip_int_to_str(tmp_address);
  strncpy(ip_dst_str, tmp, strlen(tmp));
  fprintf(file, "%s:%u -> %s:%u %u\n", ip_src_str, tmp_src_port, ip_dst_str, tmp_dst_port,
          netflow_packet->records[i].prot);
}
