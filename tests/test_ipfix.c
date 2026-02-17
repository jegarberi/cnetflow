#include <arpa/inet.h>
#include <criterion/criterion.h>
#include <stdint.h>
#include <string.h>
#include "../src/arena.h"
#include "../src/netflow_ipfix.h"

extern arena_struct_t *arena_collector;
extern arena_struct_t *arena_hashmap_ipfix;

Test(ipfix, parse_enterprise_field) {
  arena_collector = malloc(sizeof(arena_struct_t));
  arena_hashmap_ipfix = malloc(sizeof(arena_struct_t));
  arena_create(arena_collector, 1024 * 1024);
  arena_create(arena_hashmap_ipfix, 1024 * 1024);

  init_ipfix(arena_hashmap_ipfix, 100);

  // IPFIX packet with Template Set containing Enterprise Field
  uint8_t packet[] = {
      0x00, 0x0a, // Version 10
      0x00, 0x24, // Length (16 header + 20 template set)
      0x65, 0x81, 0x01, 0x01, // Export Time
      0x00, 0x00, 0x00, 0x01, // Sequence
      0x00, 0x00, 0x00, 0x00, // Domain ID

      // Template Set
      0x00, 0x02, // Set ID (Template Set)
      0x00, 0x14, // Length (4 set header + 16 template record)

      // Template Record
      0x01, 0x00, // Template ID 256
      0x00, 0x02, // Field Count 2

      // Field 1 (Enterprise)
      0x80, 0x01, // Type 1 (Enterprise bit set)
      0x00, 0x04, // Length 4
      0x00, 0x00, 0x00, 0x7b, // Enterprise 123

      // Field 2 (Normal)
      0x00, 0x02, // Type 2
      0x00, 0x04 // Length 4
  };

  parse_args_t args;
  args.data = packet;
  args.len = sizeof(packet);
  args.exporter = 0x01020304;
  args.status = 0;

  uv_work_t req;
  req.data = &args;

  // First call to parse template
  parse_ipfix(&req);

  // Now construct a Data Set using this template
  uint8_t data_packet[] = {0x00, 0x0a, // Version 10
                           0x00, 0x1c, // Length (16 header + 12 data set)
                           0x65, 0x81, 0x01, 0x01, // Export Time
                           0x00, 0x00, 0x00, 0x02, // Sequence
                           0x00, 0x00, 0x00, 0x00, // Domain ID

                           // Data Set
                           0x01, 0x00, // Set ID (256)
                           0x00, 0x0c, // Length (4 set header + 8 data)

                           // Data for Field 1 (4 bytes)
                           0x11, 0x22, 0x33, 0x44,
                           // Data for Field 2 (4 bytes)
                           0x55, 0x66, 0x77, 0x88};

  args.data = data_packet;
  args.len = sizeof(data_packet);
  parse_ipfix(&req);

  arena_destroy(arena_collector);
  arena_destroy(arena_hashmap_ipfix);
  free(arena_collector);
  free(arena_hashmap_ipfix);
}

Test(ipfix, template_field_count_oob) {
  arena_collector = malloc(sizeof(arena_struct_t));
  arena_hashmap_ipfix = malloc(sizeof(arena_struct_t));
  arena_create(arena_collector, 1024 * 1024);
  arena_create(arena_hashmap_ipfix, 1024 * 1024);

  init_ipfix(arena_hashmap_ipfix, 100);

  // IPFIX packet with Template Set where field_count is larger than available data
  uint8_t packet[] = {
      0x00,
      0x0a, // Version 10
      0x00,
      0x18, // Length 24
      0x65,
      0x81,
      0x01,
      0x01, // Export Time
      0x00,
      0x00,
      0x00,
      0x01, // Sequence
      0x00,
      0x00,
      0x00,
      0x00, // Domain ID

      // Template Set
      0x00,
      0x02, // Set ID (Template Set)
      0x00,
      0x08, // Length 8 (4 bytes set header + 4 bytes template record header)

      // Template Record Header (4 bytes)
      0x01,
      0x00, // Template ID 256
      0x00,
      0x05, // Field Count 5 (OOB because set length is only 8)
  };

  parse_args_t args;
  args.data = packet;
  args.len = sizeof(packet);
  args.exporter = 0x01020304;
  args.status = 0;

  uv_work_t req;
  req.data = &args;

  // This should NOT crash if bounds checking is implemented
  parse_ipfix(&req);

  arena_destroy(arena_collector);
  arena_destroy(arena_hashmap_ipfix);
  free(arena_collector);
  free(arena_hashmap_ipfix);
}

Test(ipfix, flowset_more_than_60_records) {
  arena_collector = malloc(sizeof(arena_struct_t));
  arena_hashmap_ipfix = malloc(sizeof(arena_struct_t));
  arena_create(arena_collector, 1024 * 1024);
  arena_create(arena_hashmap_ipfix, 1024 * 1024);

  init_ipfix(arena_hashmap_ipfix, 100);

  // 1. Template Set for a simple record (one 4-byte field)
  uint8_t template_packet[] = {
      0x00, 0x0a, 0x00, 0x1c, 0x65, 0x81, 0x01, 0x01, 0x00,
      0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, // Template Set ID
      0x00, 0x0c, // Length 12 (4 set header + 8 template record)
      0x01, 0x00, // Template ID 256
      0x00, 0x01, // Field Count 1
      0x00, 0x08, 0x00, 0x04 // Type 8 (sourceIPv4Address), length 4
  };

  parse_args_t args;
  args.data = template_packet;
  args.len = sizeof(template_packet);
  args.exporter = 0x01020304;
  args.status = 0;
  uv_work_t req;
  req.data = &args;
  parse_ipfix(&req);

  // 2. Data Set with 65 records (each 4 bytes)
  // 4 bytes set header + 65 * 4 bytes = 4 + 260 = 264 bytes (0x0108)
  uint16_t data_set_len = 4 + 65 * 4;
  uint16_t total_len = 16 + data_set_len;
  uint8_t *data_packet = calloc(1, total_len);

  data_packet[1] = 0x0a; // Version 10
  data_packet[2] = (total_len >> 8) & 0xFF;
  data_packet[3] = total_len & 0xFF;

  // Data Set Header
  data_packet[16] = 0x01;
  data_packet[17] = 0x00; // Set ID 256
  data_packet[18] = (data_set_len >> 8) & 0xFF;
  data_packet[19] = data_set_len & 0xFF;

  args.data = data_packet;
  args.len = total_len;

  // This should NOT crash/overflow if bounds checking is implemented
  parse_ipfix(&req);

  free(data_packet);
  arena_destroy(arena_collector);
  arena_destroy(arena_hashmap_ipfix);
  free(arena_collector);
  free(arena_hashmap_ipfix);
}

// Helper for ipv4 string to int
static uint32_t ipv4(const char *dotted) {
  struct in_addr a;
  inet_pton(AF_INET, dotted, &a);
  return ntohl(a.s_addr);
}

Test(ipfix, swap_src_dst_ipfix_logic) {
  netflow_v9_record_insert_t r = {0};
  r.srcaddr = ipv4("8.8.4.4"); // public
  r.dstaddr = ipv4("10.0.0.2"); // private
  r.srcport = htons(12345);
  r.dstport = htons(22);
  r.input = htons(5);
  r.output = htons(6);

  swap_src_dst_ipfix_ipv4(&r);
  cr_expect_eq(r.srcaddr, ipv4("10.0.0.2"));
  cr_expect_eq(r.dstaddr, ipv4("8.8.4.4"));
  cr_expect_eq(r.srcport, htons(22));
  cr_expect_eq(r.dstport, htons(12345));
  cr_expect_eq(r.input, htons(6));
  cr_expect_eq(r.output, htons(5));
}

Test(ipfix, copy_ipfix_to_flow_copies_fields) {
  netflow_v9_flowset_t in = {0};
  in.header.count = 1;
  in.records[0].srcaddr = ipv4("1.2.3.4");
  in.records[0].dstaddr = ipv4("5.6.7.8");
  in.records[0].srcport = htons(1111);
  in.records[0].dstport = htons(2222);
  in.records[0].dPkts = 42;
  in.records[0].dOctets = 1000;
  in.records[0].ip_version = 4;

  netflow_v9_uint128_flowset_t out = {0};
  // 3rd arg is likely is_ipv6, here 0
  copy_ipfix_to_flow(&in, &out, 0);

  // copy_ipfix_to_flow also swaps bytes if !BE
  uint32_t expected_src = ipv4("1.2.3.4");
  uint32_t expected_dst = ipv4("5.6.7.8");
  if (detect_endianness() == NETFLOW_LITTLE_ENDIAN) {
    expected_src = swap_endian_32(expected_src);
    expected_dst = swap_endian_32(expected_dst);
  }

  cr_expect_eq((uint32_t) out.records[0].srcaddr, expected_src);
  cr_expect_eq((uint32_t) out.records[0].dstaddr, expected_dst);
  // IPFIX might use 64-bit pkts/octets in input?
  // netflow_v9_record_insert_t in netflow.h has uint64_t dPkts.
  // So assigning 42 (host order) works.
  uint64_t expected_pkts = 42;
  uint64_t expected_octets = 1000;
  if (detect_endianness() == NETFLOW_LITTLE_ENDIAN) {
    expected_pkts = swap_endian_64(expected_pkts);
    expected_octets = swap_endian_64(expected_octets);
  }
  cr_expect_eq(out.records[0].dPkts, expected_pkts);
  cr_expect_eq(out.records[0].dOctets, expected_octets);
}
