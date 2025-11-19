#include <criterion/criterion.h>
#include <criterion/logging.h>
#include <criterion/new/assert.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdint.h>

#include "../src/netflow.h"
#include "../src/netflow_v5.h"

// --- Linkage stubs for external dependencies referenced by libnetflow and libnetflow_v5 ---
// Provide minimal implementations to avoid bringing database or collector modules into the test binary.
#include <netinet/in.h>
static char ip_str_buf[INET_ADDRSTRLEN];
char *ip_int_to_str(const unsigned int addr) {
    struct in_addr a; a.s_addr = htonl(addr);
    inet_ntop(AF_INET, &a, ip_str_buf, sizeof(ip_str_buf));
    return ip_str_buf;
}
void insert_flows(uint32_t exporter, netflow_v9_uint128_flowset_t *flows) {
    (void)exporter; (void)flows; // no-op stub
}

// Suite: netflow

Test(netflow, detect_version_basic) {
    uint8_t buf[4] = {0};
    uint16_t v5 = htons(5);
    memcpy(buf, &v5, sizeof(v5));
    cr_expect_eq(detect_version(buf), NETFLOW_V5);

    uint16_t v9 = htons(9);
    memcpy(buf, &v9, sizeof(v9));
    cr_expect_eq(detect_version(buf), NETFLOW_V9);

    uint16_t v10 = htons(10);
    memcpy(buf, &v10, sizeof(v10));
    cr_expect_eq(detect_version(buf), NETFLOW_IPFIX);
}

Test(netflow, endianness_and_swaps) {
    endianness_e e = detect_endianness();
    cr_expect_neq(e, NETFLOW_NO_ENDIAN);

    uint16_t u16 = 0x1234;
    uint16_t s16 = swap_endian_16(u16);
    cr_expect_eq(s16, (uint16_t)0x3412);

    uint32_t u32 = 0x12345678u;
    uint32_t s32 = swap_endian_32(u32);
    cr_expect_eq(s32, (uint32_t)0x78563412u);

    uint64_t u64 = 0x0123456789abcdefULL;
    uint64_t s64 = swap_endian_64(u64);
    cr_expect_eq(s64, (uint64_t)0xefcdab8967452301ULL);

    __uint128_t u128 = (((__uint128_t)0x0123456789abcdefULL) << 64) | 0xfedcba9876543210ULL;
    __uint128_t s128 = swap_endian_128(u128);
    __uint128_t expect128 = (((__uint128_t)0x1032547698badcfeULL) << 64) | 0xefcdab8967452301ULL;
    // Validate by splitting to 64-bit halves
    uint64_t s128_hi = (uint64_t)(s128 >> 64);
    uint64_t s128_lo = (uint64_t)(s128 & 0xFFFFFFFFFFFFFFFFULL);
    cr_expect_eq(s128_hi, (uint64_t)0x1032547698badcfeULL);
    cr_expect_eq(s128_lo, (uint64_t)0xefcdab8967452301ULL);
}

static uint32_t ipv4(const char *dotted) {
    struct in_addr a; inet_pton(AF_INET, dotted, &a); return ntohl(a.s_addr);
}

Test(netflow, swap_src_dst_v5_logic) {
    netflow_v5_record_t r = {0};
    r.srcaddr = ipv4("8.8.8.8"); // public
    r.dstaddr = ipv4("192.168.1.10"); // private
    r.srcport = htons(5555);
    r.dstport = htons(80);
    r.input = htons(1);
    r.output = htons(2);

    swap_src_dst_v5(&r);
    // Since src is public and dst is private, condition !is_private(src) is true => swap occurs
    cr_expect_eq(r.srcaddr, ipv4("192.168.1.10"));
    cr_expect_eq(r.dstaddr, ipv4("8.8.8.8"));
    cr_expect_eq(r.srcport, htons(80));
    cr_expect_eq(r.dstport, htons(5555));
    cr_expect_eq(r.input, htons(2));
    cr_expect_eq(r.output, htons(1));
}

Test(netflow, swap_src_dst_v9_logic) {
    netflow_v9_record_insert_t r = {0};
    r.srcaddr = ipv4("8.8.4.4"); // public
    r.dstaddr = ipv4("10.0.0.2"); // private
    r.srcport = htons(12345);
    r.dstport = htons(22);
    r.input = htons(5);
    r.output = htons(6);

    swap_src_dst_v9(&r);
    cr_expect_eq(r.srcaddr, ipv4("10.0.0.2"));
    cr_expect_eq(r.dstaddr, ipv4("8.8.4.4"));
    cr_expect_eq(r.srcport, htons(22));
    cr_expect_eq(r.dstport, htons(12345));
    cr_expect_eq(r.input, htons(6));
    cr_expect_eq(r.output, htons(5));
}

Test(netflow, copy_v5_to_flow_copies_fields) {
    netflow_v5_flowset_t in = {0};
    in.header.count = 1;
    in.records[0].srcaddr = ipv4("1.2.3.4");
    in.records[0].dstaddr = ipv4("5.6.7.8");
    in.records[0].srcport = htons(1111);
    in.records[0].dstport = htons(2222);
    in.records[0].dPkts = 42;
    in.records[0].dOctets = 1000;

    netflow_v9_uint128_flowset_t out = {0};
    copy_v5_to_flow(&in, &out);

    cr_expect_eq(out.header.count, 1);
    cr_expect_eq((uint32_t)out.records[0].srcaddr, ipv4("1.2.3.4"));
    cr_expect_eq((uint32_t)out.records[0].dstaddr, ipv4("5.6.7.8"));
    cr_expect_eq(out.records[0].srcport, htons(1111));
    cr_expect_eq(out.records[0].dstport, htons(2222));
    cr_expect_eq(out.records[0].dPkts, (uint64_t)42);
    cr_expect_eq(out.records[0].dOctets, (uint64_t)1000);
    cr_expect_eq(out.records[0].ip_version, (uint8_t)4);
}
