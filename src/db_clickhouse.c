//
// Created for cnetflow - ClickHouse TCP Native Protocol Client
//

#include "db_clickhouse.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "arena.h"

#if defined(__STDC_NO_THREADS__) || !defined(__STDC_VERSION__) || __STDC_VERSION__ < 201112L
#if defined(__GNUC__) || defined(__clang__)
#define THREAD_LOCAL __thread
#else
#define THREAD_LOCAL
#endif
#else
#include <threads.h>
#define THREAD_LOCAL thread_local
#endif

// External arena from collector
extern arena_struct_t *arena_collector;

// Buffer size for packet assembly
#define CH_BUFFER_SIZE 6553600

// Varint encoding/decoding functions
void ch_write_varint(uint64_t value, uint8_t *buffer, size_t *offset) {
    while (value >= 0x80) {
        buffer[(*offset)++] = (uint8_t)(value | 0x80);
        value >>= 7;
    }
    buffer[(*offset)++] = (uint8_t)value;
}

uint64_t ch_read_varint(const uint8_t *buffer, size_t *offset) {
    uint64_t result = 0;
    int shift = 0;
    uint8_t byte;

    do {
        byte = buffer[(*offset)++];
        result |= ((uint64_t)(byte & 0x7F)) << shift;
        shift += 7;
    } while (byte & 0x80);

    return result;
}

void ch_write_string(const char *str, uint8_t *buffer, size_t *offset) {
    size_t len = str ? strlen(str) : 0;
    ch_write_varint(len, buffer, offset);
    if (len > 0) {
        memcpy(buffer + *offset, str, len);
        *offset += len;
    }
}

char *ch_read_string(const uint8_t *buffer, size_t *offset) {
    uint64_t len = ch_read_varint(buffer, offset);
    if (len == 0) {
        return strdup("");
    }
    char *str = (char *)malloc(len + 1);
    if (!str) return NULL;
    memcpy(str, buffer + *offset, len);
    str[len] = '\0';
    *offset += len;
    return str;
}

// Write fixed-size integers
static void write_uint8(uint8_t value, uint8_t *buffer, size_t *offset) {
    buffer[(*offset)++] = value;
}

static void write_uint16(uint16_t value, uint8_t *buffer, size_t *offset) {
    memcpy(buffer + *offset, &value, sizeof(value));
    *offset += sizeof(value);
}

static void write_uint32(uint32_t value, uint8_t *buffer, size_t *offset) {
    memcpy(buffer + *offset, &value, sizeof(value));
    *offset += sizeof(value);
}

static void write_uint64(uint64_t value, uint8_t *buffer, size_t *offset) {
    memcpy(buffer + *offset, &value, sizeof(value));
    *offset += sizeof(value);
}

char *ch_ip_uint128_to_string(uint128_t value, uint8_t ip_version) {
#define _MAX_LEN 50
    static THREAD_LOCAL char ret_string[_MAX_LEN] = {0};

    if (ip_version == 4) {
        uint32_t ip = (uint32_t)value;
        snprintf(ret_string, _MAX_LEN, "%u.%u.%u.%u",
                 (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
                 (ip >> 8) & 0xFF, ip & 0xFF);
    } else if (ip_version == 6) {
        uint16_t parts[8];
        uint128_t v = value;
        for (int i = 0; i < 8; i++) {
            parts[7 - i] = (uint16_t)(v & 0xFFFF);
            v >>= 16;
        }
        snprintf(ret_string, _MAX_LEN, "%x:%x:%x:%x:%x:%x:%x:%x",
                 parts[0], parts[1], parts[2], parts[3],
                 parts[4], parts[5], parts[6], parts[7]);
    } else {
        snprintf(ret_string, _MAX_LEN, "INVALID_IP_VERSION");
    }
    return ret_string;
#undef _MAX_LEN
}

ch_conn_t *ch_connect(const char *host, uint16_t port, const char *database,
                      const char *user, const char *password) {
    ch_conn_t *conn = (ch_conn_t *)calloc(1, sizeof(ch_conn_t));
    if (!conn) {
        fprintf(stderr, "%s %d %s: Failed to allocate connection structure\n",
                __FILE__, __LINE__, __func__);
        return NULL;
    }

    conn->host = strdup(host);
    conn->port = port;
    conn->database = strdup(database ? database : "default");
    conn->user = strdup(user ? user : "default");
    conn->password = strdup(password ? password : "");
    conn->connected = false;

    // Create socket
    conn->sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (conn->sockfd < 0) {
        fprintf(stderr, "%s %d %s: Failed to create socket: %s\n",
                __FILE__, __LINE__, __func__, strerror(errno));
        goto error;
    }

    // Resolve hostname
    struct hostent *server = gethostbyname(host);
    if (!server) {
        fprintf(stderr, "%s %d %s: Failed to resolve host: %s\n",
                __FILE__, __LINE__, __func__, host);
        goto error;
    }

    // Connect to server
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    memcpy(&serv_addr.sin_addr.s_addr, server->h_addr, server->h_length);
    serv_addr.sin_port = htons(port);

    if (connect(conn->sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        fprintf(stderr, "%s %d %s: Failed to connect to %s:%d: %s\n",
                __FILE__, __LINE__, __func__, host, port, strerror(errno));
        goto error;
    }

    // Send and receive hello packets
    if (ch_send_hello(conn) < 0) {
        fprintf(stderr, "%s %d %s: Failed to send hello\n",
                __FILE__, __LINE__, __func__);
        goto error;
    }

    if (ch_receive_hello(conn) < 0) {
        fprintf(stderr, "%s %d %s: Failed to receive hello\n",
                __FILE__, __LINE__, __func__);
        goto error;
    }

    conn->connected = true;
    fprintf(stderr, "Connected to ClickHouse %s at %s:%d\n",
            conn->server_version ? conn->server_version : "unknown", host, port);
    return conn;

error:
    if (conn->sockfd >= 0) close(conn->sockfd);
    if (conn->host) free(conn->host);
    if (conn->database) free(conn->database);
    if (conn->user) free(conn->user);
    if (conn->password) free(conn->password);
    free(conn);
    return NULL;
}

void ch_db_connect(ch_conn_t **conn) {
    if (*conn != NULL && (*conn)->connected) {
        return;
    }

    const char *conn_string = getenv("CH_CONN_STRING");
    if (!conn_string) {
        fprintf(stderr, "Environment variable CH_CONN_STRING is not set.\n");
        fprintf(stderr, "Format: host:port:database:user:password\n");
        fprintf(stderr, "%s %d %s\n", __FILE__, __LINE__, __func__);
        exit(EXIT_FAILURE);
    }

    // Parse connection string: host:port:database:user:password
    char *conn_str_copy = strdup(conn_string);
    char *host = strtok(conn_str_copy, ":");
    char *port_str = strtok(NULL, ":");
    char *database = strtok(NULL, ":");
    char *user = strtok(NULL, ":");
    char *password = strtok(NULL, ":");

    if (!host || !port_str) {
        fprintf(stderr, "Invalid CH_CONN_STRING format\n");
        free(conn_str_copy);
        exit(EXIT_FAILURE);
    }

    uint16_t port = atoi(port_str);
    *conn = ch_connect(host, port, database, user, password);
    free(conn_str_copy);

    if (!*conn) {
        fprintf(stderr, "Failed to connect to ClickHouse\n");
        exit(EXIT_FAILURE);
    }
}

void ch_disconnect(ch_conn_t *conn) {
    if (!conn) return;

    if (conn->sockfd >= 0) {
        close(conn->sockfd);
    }
    if (conn->host) free(conn->host);
    if (conn->database) free(conn->database);
    if (conn->user) free(conn->user);
    if (conn->password) free(conn->password);
    if (conn->server_name) free(conn->server_name);
    if (conn->server_version) free(conn->server_version);
    if (conn->server_timezone) free(conn->server_timezone);
    free(conn);
}

int ch_send_hello(ch_conn_t *conn) {
    uint8_t buffer[CH_BUFFER_SIZE];
    size_t offset = 0;

    // Packet type: Hello
    write_uint8(CH_CLIENT_HELLO, buffer, &offset);

    // Client name
    ch_write_string("cnetflow", buffer, &offset);

    // Client version
    ch_write_varint(CH_CLIENT_VERSION_MAJOR, buffer, &offset);
    ch_write_varint(CH_CLIENT_VERSION_MINOR, buffer, &offset);
    ch_write_varint(CH_CLIENT_REVISION, buffer, &offset);

    // Database name
    ch_write_string(conn->database, buffer, &offset);

    // Username
    ch_write_string(conn->user, buffer, &offset);

    // Password
    ch_write_string(conn->password, buffer, &offset);

    ssize_t sent = send(conn->sockfd, buffer, offset, 0);
    if (sent != (ssize_t)offset) {
        fprintf(stderr, "%s %d %s: Failed to send hello packet\n",
                __FILE__, __LINE__, __func__);
        return -1;
    }

    return 0;
}

int ch_receive_hello(ch_conn_t *conn) {
    uint8_t buffer[CH_BUFFER_SIZE];
    size_t offset = 0;

    // Receive packet type
    ssize_t received = recv(conn->sockfd, buffer, sizeof(buffer), 0);
    if (received <= 0) {
        fprintf(stderr, "%s %d %s: Failed to receive hello response\n",
                __FILE__, __LINE__, __func__);
        return -1;
    }

    uint8_t packet_type = buffer[offset++];

    if (packet_type == CH_EXCEPTION) {
        uint32_t code = *(uint32_t *)(buffer + offset);
        offset += sizeof(uint32_t);
        char *name = ch_read_string(buffer, &offset);
        char *message = ch_read_string(buffer, &offset);
        fprintf(stderr, "%s %d %s: Server exception [%u]: %s - %s\n",
                __FILE__, __LINE__, __func__, code, name, message);
        free(name);
        free(message);
        return -1;
    }

    if (packet_type != CH_HELLO) {
        fprintf(stderr, "%s %d %s: Expected HELLO packet, got %d\n",
                __FILE__, __LINE__, __func__, packet_type);
        return -1;
    }

    // Read server info
    conn->server_name = ch_read_string(buffer, &offset);
    uint64_t major = ch_read_varint(buffer, &offset);
    uint64_t minor = ch_read_varint(buffer, &offset);
    conn->server_revision = ch_read_varint(buffer, &offset);

    // Read timezone if supported
    if (conn->server_revision >= CH_DBMS_MIN_REVISION_WITH_SERVER_TIMEZONE) {
        conn->server_timezone = ch_read_string(buffer, &offset);
    }

    // Build version string
    char version_str[64];
    snprintf(version_str, sizeof(version_str), "%lu.%lu", major, minor);
    conn->server_version = strdup(version_str);

    return 0;
}

int ch_send_query(ch_conn_t *conn, const char *query_id, const char *query) {
    size_t query_len = strlen(query);
    // Allocate buffer: fixed overhead (~200 bytes) + query length + varint overhead
    size_t buffer_size = 1024 + query_len + 100;
    uint8_t *buffer = (uint8_t *)arena_alloc(arena_collector, buffer_size);
    if (!buffer) {
        fprintf(stderr, "%s %d %s: Failed to allocate buffer from arena\n",
                __FILE__, __LINE__, __func__);
        return -1;
    }

    size_t offset = 0;

    // Packet type: Query
    write_uint8(CH_CLIENT_QUERY, buffer, &offset);

    // Query ID
    ch_write_string(query_id, buffer, &offset);

    // Client info (minimal)
    if (conn->server_revision >= CH_DBMS_MIN_REVISION_WITH_CLIENT_INFO) {
        write_uint8(1, buffer, &offset); // query_kind: Initial query
        ch_write_string("", buffer, &offset); // initial_user
        ch_write_string("", buffer, &offset); // initial_query_id
        ch_write_string("0.0.0.0:0", buffer, &offset); // initial_address
        write_uint8(1, buffer, &offset); // interface: TCP
        ch_write_string("", buffer, &offset); // os_user
        ch_write_string("", buffer, &offset); // client_hostname
        ch_write_string("cnetflow", buffer, &offset); // client_name
        ch_write_varint(CH_CLIENT_VERSION_MAJOR, buffer, &offset);
        ch_write_varint(CH_CLIENT_VERSION_MINOR, buffer, &offset);
        ch_write_varint(CH_CLIENT_REVISION, buffer, &offset);

        if (conn->server_revision >= CH_DBMS_MIN_REVISION_WITH_QUOTA_KEY_IN_CLIENT_INFO) {
            ch_write_string("", buffer, &offset); // quota_key
        }
    }

    // Settings (empty)
    ch_write_string("", buffer, &offset);

    // Stage: Complete
    ch_write_varint(2, buffer, &offset);

    // Compression: disabled
    write_uint8(0, buffer, &offset);

    // Query text
    size_t query_start_offset = offset;
    ch_write_string(query, buffer, &offset);
    size_t query_bytes_written = offset - query_start_offset;

    fprintf(stderr, "%s %d %s: Query string length=%zu, encoded bytes=%zu, total packet=%zu\n",
            __FILE__, __LINE__, __func__, query_len, query_bytes_written, offset);

    // Check if we exceeded buffer
    if (offset > buffer_size) {
        fprintf(stderr, "%s %d %s: Query packet overflow (%zu > %zu)\n",
                __FILE__, __LINE__, __func__, offset, buffer_size);
        arena_free(arena_collector, buffer);
        return -1;
    }

    // Use MSG_NOSIGNAL to avoid SIGPIPE if connection closes
    ssize_t sent = send(conn->sockfd, buffer, offset, MSG_NOSIGNAL);

    fprintf(stderr, "%s %d %s: Sent %zd of %zu bytes\n",
            __FILE__, __LINE__, __func__, sent, offset);

    // Free arena memory after sending
    arena_free(arena_collector, buffer);

    if (sent != (ssize_t)offset) {
        fprintf(stderr, "%s %d %s: Failed to send query packet (sent %zd of %zu bytes)\n",
                __FILE__, __LINE__, __func__, sent, offset);
        return -1;
    }

    return 0;
}

int ch_send_data_block(ch_conn_t *conn, const char *table_name,
                       uint32_t exporter, netflow_v9_uint128_flowset_t *flows) {
    uint8_t buffer[CH_BUFFER_SIZE];
    size_t offset = 0;

    // Packet type: Data
    write_uint8(CH_CLIENT_DATA, buffer, &offset);

    // Temporary table name (empty for regular inserts)
    ch_write_string("", buffer, &offset);

    // Block info
    write_uint8(1, buffer, &offset); // is_overflows
    write_uint8(2, buffer, &offset); // bucket_num
    write_uint32(0, buffer, &offset); // reserved (was is_overflows)

    // Number of columns
    ch_write_varint(19, buffer, &offset);

    // Number of rows
    int valid_rows = 0;
    for (int i = 0; i < flows->header.count; i++) {
        if (flows->records[i].dOctets > 0 && flows->records[i].dPkts > 0) {
            valid_rows++;
        }
    }
    ch_write_varint(valid_rows, buffer, &offset);

    // Column definitions and data
    // Column 1: exporter (UInt32)
    ch_write_string("exporter", buffer, &offset);
    ch_write_string("UInt32", buffer, &offset);
    for (int i = 0; i < flows->header.count; i++) {
        if (flows->records[i].dOctets > 0 && flows->records[i].dPkts > 0) {
            write_uint32(exporter, buffer, &offset);
        }
    }

    // Column 2: srcaddr (String for IPv4/IPv6)
    ch_write_string("srcaddr", buffer, &offset);
    ch_write_string("String", buffer, &offset);
    for (int i = 0; i < flows->header.count; i++) {
        if (flows->records[i].dOctets > 0 && flows->records[i].dPkts > 0) {
            char *ip_str = ch_ip_uint128_to_string(flows->records[i].srcaddr,
                                                   flows->records[i].ip_version);
            ch_write_string(ip_str, buffer, &offset);
        }
    }

    // Column 3: srcport (UInt16)
    ch_write_string("srcport", buffer, &offset);
    ch_write_string("UInt16", buffer, &offset);
    for (int i = 0; i < flows->header.count; i++) {
        if (flows->records[i].dOctets > 0 && flows->records[i].dPkts > 0) {
            write_uint16(flows->records[i].srcport, buffer, &offset);
        }
    }

    // Column 4: dstaddr (String)
    ch_write_string("dstaddr", buffer, &offset);
    ch_write_string("String", buffer, &offset);
    for (int i = 0; i < flows->header.count; i++) {
        if (flows->records[i].dOctets > 0 && flows->records[i].dPkts > 0) {
            char *ip_str = ch_ip_uint128_to_string(flows->records[i].dstaddr,
                                                   flows->records[i].ip_version);
            ch_write_string(ip_str, buffer, &offset);
        }
    }

    // Column 5: dstport (UInt16)
    ch_write_string("dstport", buffer, &offset);
    ch_write_string("UInt16", buffer, &offset);
    for (int i = 0; i < flows->header.count; i++) {
        if (flows->records[i].dOctets > 0 && flows->records[i].dPkts > 0) {
            write_uint16(flows->records[i].dstport, buffer, &offset);
        }
    }

    // Column 6: first (DateTime - UInt32 Unix timestamp)
    ch_write_string("first", buffer, &offset);
    ch_write_string("DateTime", buffer, &offset);
    for (int i = 0; i < flows->header.count; i++) {
        if (flows->records[i].dOctets > 0 && flows->records[i].dPkts > 0) {
            write_uint32(flows->records[i].First, buffer, &offset);
        }
    }

    // Column 7: last (DateTime)
    ch_write_string("last", buffer, &offset);
    ch_write_string("DateTime", buffer, &offset);
    for (int i = 0; i < flows->header.count; i++) {
        if (flows->records[i].dOctets > 0 && flows->records[i].dPkts > 0) {
            write_uint32(flows->records[i].Last, buffer, &offset);
        }
    }

    // Column 8: dpkts (UInt64)
    ch_write_string("dpkts", buffer, &offset);
    ch_write_string("UInt64", buffer, &offset);
    for (int i = 0; i < flows->header.count; i++) {
        if (flows->records[i].dOctets > 0 && flows->records[i].dPkts > 0) {
            write_uint64(flows->records[i].dPkts, buffer, &offset);
        }
    }

    // Column 9: doctets (UInt64)
    ch_write_string("doctets", buffer, &offset);
    ch_write_string("UInt64", buffer, &offset);
    for (int i = 0; i < flows->header.count; i++) {
        if (flows->records[i].dOctets > 0 && flows->records[i].dPkts > 0) {
            write_uint64(flows->records[i].dOctets, buffer, &offset);
        }
    }

    // Column 10: input (UInt16)
    ch_write_string("input", buffer, &offset);
    ch_write_string("UInt16", buffer, &offset);
    for (int i = 0; i < flows->header.count; i++) {
        if (flows->records[i].dOctets > 0 && flows->records[i].dPkts > 0) {
            write_uint16(flows->records[i].input, buffer, &offset);
        }
    }

    // Column 11: output (UInt16)
    ch_write_string("output", buffer, &offset);
    ch_write_string("UInt16", buffer, &offset);
    for (int i = 0; i < flows->header.count; i++) {
        if (flows->records[i].dOctets > 0 && flows->records[i].dPkts > 0) {
            write_uint16(flows->records[i].output, buffer, &offset);
        }
    }

    // Column 12: protocol (UInt8)
    ch_write_string("protocol", buffer, &offset);
    ch_write_string("UInt8", buffer, &offset);
    for (int i = 0; i < flows->header.count; i++) {
        if (flows->records[i].dOctets > 0 && flows->records[i].dPkts > 0) {
            write_uint8(flows->records[i].prot, buffer, &offset);
        }
    }

    // Column 13: tos (UInt8)
    ch_write_string("tos", buffer, &offset);
    ch_write_string("UInt8", buffer, &offset);
    for (int i = 0; i < flows->header.count; i++) {
        if (flows->records[i].dOctets > 0 && flows->records[i].dPkts > 0) {
            write_uint8(flows->records[i].tos, buffer, &offset);
        }
    }

    // Column 14: src_as (UInt16)
    ch_write_string("src_as", buffer, &offset);
    ch_write_string("UInt16", buffer, &offset);
    for (int i = 0; i < flows->header.count; i++) {
        if (flows->records[i].dOctets > 0 && flows->records[i].dPkts > 0) {
            write_uint16(flows->records[i].src_as, buffer, &offset);
        }
    }

    // Column 15: dst_as (UInt16)
    ch_write_string("dst_as", buffer, &offset);
    ch_write_string("UInt16", buffer, &offset);
    for (int i = 0; i < flows->header.count; i++) {
        if (flows->records[i].dOctets > 0 && flows->records[i].dPkts > 0) {
            write_uint16(flows->records[i].dst_as, buffer, &offset);
        }
    }

    // Column 16: src_mask (UInt8)
    ch_write_string("src_mask", buffer, &offset);
    ch_write_string("UInt8", buffer, &offset);
    for (int i = 0; i < flows->header.count; i++) {
        if (flows->records[i].dOctets > 0 && flows->records[i].dPkts > 0) {
            write_uint8(flows->records[i].src_mask, buffer, &offset);
        }
    }

    // Column 17: dst_mask (UInt8)
    ch_write_string("dst_mask", buffer, &offset);
    ch_write_string("UInt8", buffer, &offset);
    for (int i = 0; i < flows->header.count; i++) {
        if (flows->records[i].dOctets > 0 && flows->records[i].dPkts > 0) {
            write_uint8(flows->records[i].dst_mask, buffer, &offset);
        }
    }

    // Column 18: tcp_flags (UInt8)
    ch_write_string("tcp_flags", buffer, &offset);
    ch_write_string("UInt8", buffer, &offset);
    for (int i = 0; i < flows->header.count; i++) {
        if (flows->records[i].dOctets > 0 && flows->records[i].dPkts > 0) {
            write_uint8(flows->records[i].tcp_flags, buffer, &offset);
        }
    }

    // Column 19: ip_version (UInt8)
    ch_write_string("ip_version", buffer, &offset);
    ch_write_string("UInt8", buffer, &offset);
    for (int i = 0; i < flows->header.count; i++) {
        if (flows->records[i].dOctets > 0 && flows->records[i].dPkts > 0) {
            write_uint8(flows->records[i].ip_version, buffer, &offset);
        }
    }

    ssize_t sent = send(conn->sockfd, buffer, offset, 0);
    if (sent != (ssize_t)offset) {
        fprintf(stderr, "%s %d %s: Failed to send data block\n",
                __FILE__, __LINE__, __func__);
        return -1;
    }

    return 0;
}

int ch_receive_response(ch_conn_t *conn) {
    uint8_t buffer[CH_BUFFER_SIZE];
    int packets_received = 0;

    while (1) {
        size_t offset = 0;
        ssize_t received = recv(conn->sockfd, buffer, sizeof(buffer), 0);

        if (received <= 0) {
            // If we received at least one packet before connection closed, consider it success
            // This happens with INSERT queries where server closes after processing
            if (packets_received > 0) {
                return 0;
            }
            fprintf(stderr, "%s %d %s: Connection closed or error (packets_received=%d)\n",
                    __FILE__, __LINE__, __func__, packets_received);
            return -1;
        }

        packets_received++;
        uint8_t packet_type = buffer[offset++];

        switch (packet_type) {
            case CH_END_OF_STREAM:
                return 0;

            case CH_EXCEPTION: {
                uint32_t code = *(uint32_t *)(buffer + offset);
                offset += sizeof(uint32_t);
                char *name = ch_read_string(buffer, &offset);
                char *message = ch_read_string(buffer, &offset);
                fprintf(stderr, "%s %d %s: Server exception [%u]: %s - %s\n",
                        __FILE__, __LINE__, __func__, code, name, message);
                free(name);
                free(message);
                return -1;
            }

            case CH_PROGRESS:
            case CH_PROFILE_INFO:
            case CH_LOG:
                // Skip these informational packets
                continue;

            case CH_DATA:
                // Data packet received (for SELECT queries)
                continue;

            default:
                fprintf(stderr, "%s %d %s: Unknown packet type: %d\n",
                        __FILE__, __LINE__, __func__, packet_type);
                continue;
        }
    }
}

int ch_execute_with_data(ch_conn_t *conn, const char *query, const char *data) {
    if (!conn || !conn->connected) {
        fprintf(stderr, "%s %d %s: Not connected\n",
                __FILE__, __LINE__, __func__);
        return -1;
    }

    // Generate query ID
    char query_id[64];
    snprintf(query_id, sizeof(query_id), "query_%ld_%d", time(NULL), rand());

    // Send query
    if (ch_send_query(conn, query_id, query) < 0) {
        conn->connected = false;
        return -1;
    }

    // Send the VALUES data as raw input if provided (ClickHouse will parse it)
    if (data && data[0] != '\0') {
        size_t data_len = strlen(data);
        ssize_t sent = send(conn->sockfd, data, data_len, MSG_NOSIGNAL);
        if (sent != (ssize_t)data_len) {
            fprintf(stderr, "%s %d %s: Failed to send data (%zd of %zu bytes)\n",
                    __FILE__, __LINE__, __func__, sent, data_len);
            conn->connected = false;
            return -1;
        }
    }

    // Send empty data block to signal end of input
    uint8_t buffer[256];
    size_t offset = 0;
    write_uint8(CH_CLIENT_DATA, buffer, &offset);
    ch_write_string("", buffer, &offset); // temp table name
    write_uint8(1, buffer, &offset); // is_overflows
    write_uint8(2, buffer, &offset); // bucket_num
    write_uint32(0, buffer, &offset); // reserved
    ch_write_varint(0, buffer, &offset); // num columns
    ch_write_varint(0, buffer, &offset); // num rows

    size_t sent = send(conn->sockfd, buffer, offset, MSG_NOSIGNAL);
    if (sent < 0) {
        fprintf(stderr, "%s %d %s: Note: Could not send empty block (connection closed by server)\n",
                __FILE__, __LINE__, __func__);
    }

    // Receive response
    int result = ch_receive_response(conn);

    // ClickHouse closes connection after INSERT queries, mark as disconnected
    conn->connected = false;
    close(conn->sockfd);
    conn->sockfd = -1;

    return result;
}

int ch_execute(ch_conn_t *conn, const char *query) {
    return ch_execute_with_data(conn, query, NULL);
}

int ch_create_flows_table(ch_conn_t *conn) {
    const char *create_table_query =
        "CREATE TABLE IF NOT EXISTS flows ("
        "    exporter UInt32,"
        "    srcaddr String,"
        "    srcport UInt16,"
        "    dstaddr String,"
        "    dstport UInt16,"
        "    first DateTime,"
        "    last DateTime,"
        "    dpkts UInt64,"
        "    doctets UInt64,"
        "    input UInt16,"
        "    output UInt16,"
        "    protocol UInt8,"
        "    tos UInt8,"
        "    src_as UInt16,"
        "    dst_as UInt16,"
        "    src_mask UInt8,"
        "    dst_mask UInt8,"
        "    tcp_flags UInt8,"
        "    ip_version UInt8"
        ") ENGINE = MergeTree()"
        " PARTITION BY toYYYYMMDD(first)"
        " ORDER BY (exporter, first, srcaddr, dstaddr)";

    return ch_execute(conn, create_table_query);
}

int ch_insert_flows(uint32_t exporter, netflow_v9_uint128_flowset_t *flows) {
    static THREAD_LOCAL ch_conn_t *conn = NULL;

    ch_db_connect(&conn);
    if (!conn || !conn->connected) {
        fprintf(stderr, "%s %d %s: Failed to connect\n",
                __FILE__, __LINE__, __func__);
        return -1;
    }

    if (!flows || flows->header.count == 0) {
        return 0;
    }

    // Insert flows one at a time to avoid query size limits
    int inserted = 0;
    for (int i = 0; i < flows->header.count; i++) {
        if (flows->records[i].dOctets == 0 || flows->records[i].dPkts == 0) {
            continue;
        }

        char *srcaddr = ch_ip_uint128_to_string(flows->records[i].srcaddr,
                                                flows->records[i].ip_version);
        char *dstaddr = ch_ip_uint128_to_string(flows->records[i].dstaddr,
                                                flows->records[i].ip_version);

        // For ClickHouse native protocol with single VALUES row,
        // we need to build complete INSERT statement
        char query[2048];
        int written = snprintf(query, sizeof(query),
            "INSERT INTO flows (exporter,srcaddr,srcport,dstaddr,dstport,"
            "first,last,dpkts,doctets,input,output,protocol,tos,"
            "src_as,dst_as,src_mask,dst_mask,tcp_flags,ip_version) "
            "FORMAT Values (%u,'%s',%u,'%s',%u,%u,%u,%lu,%lu,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u)",
            exporter,
            srcaddr,
            flows->records[i].srcport,
            dstaddr,
            flows->records[i].dstport,
            flows->records[i].First,
            flows->records[i].Last,
            flows->records[i].dPkts,
            flows->records[i].dOctets,
            flows->records[i].input,
            flows->records[i].output,
            flows->records[i].prot,
            flows->records[i].tos,
            flows->records[i].src_as,
            flows->records[i].dst_as,
            flows->records[i].src_mask,
            flows->records[i].dst_mask,
            flows->records[i].tcp_flags,
            flows->records[i].ip_version
        );

        // Check for truncation
        if (written >= (int)sizeof(query)) {
            fprintf(stderr, "%s %d %s: Query truncated (needed %d bytes, have %zu)\n",
                    __FILE__, __LINE__, __func__, written, sizeof(query));
            continue;
        }

        if (ch_execute(conn, query) < 0) {
            fprintf(stderr, "%s %d %s: Failed to insert record %d\n",
                    __FILE__, __LINE__, __func__, i);
            // Continue with next record instead of failing completely
            continue;
        }

        inserted++;
    }

    fprintf(stderr, "%s %d %s: Successfully inserted %d of %d flows\n",
            __FILE__, __LINE__, __func__, inserted, flows->header.count);

    return inserted > 0 ? 0 : -1;
}
