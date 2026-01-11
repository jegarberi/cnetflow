#include <criterion/criterion.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include "../src/netflow_ipfix.h"
#include "../src/arena.h"

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
        0x00, 0x04  // Length 4
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
    uint8_t data_packet[] = {
        0x00, 0x0a, // Version 10
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
        0x55, 0x66, 0x77, 0x88
    };

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
        0x00, 0x0a, // Version 10
        0x00, 0x18, // Length 24
        0x65, 0x81, 0x01, 0x01, // Export Time
        0x00, 0x00, 0x00, 0x01, // Sequence
        0x00, 0x00, 0x00, 0x00, // Domain ID
        
        // Template Set
        0x00, 0x02, // Set ID (Template Set)
        0x00, 0x08, // Length 8 (4 bytes set header + 4 bytes template record header)
        
        // Template Record Header (4 bytes)
        0x01, 0x00, // Template ID 256
        0x00, 0x05, // Field Count 5 (OOB because set length is only 8)
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
        0x00, 0x0a, 0x00, 0x1c, 0x65, 0x81, 0x01, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x02, // Template Set ID
        0x00, 0x0c, // Length 12 (4 set header + 8 template record)
        0x01, 0x00, // Template ID 256
        0x00, 0x01, // Field Count 1
        0x00, 0x08, 0x00, 0x04  // Type 8 (sourceIPv4Address), length 4
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
    data_packet[16] = 0x01; data_packet[17] = 0x00; // Set ID 256
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
