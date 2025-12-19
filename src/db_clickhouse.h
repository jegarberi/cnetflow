//
// Created for cnetflow - ClickHouse TCP Native Protocol Client
//

#ifndef DB_CLICKHOUSE_H
#define DB_CLICKHOUSE_H

#include "netflow.h"
#include <stdint.h>
#include <time.h>
#include <stdbool.h>

// ClickHouse Native Protocol Packet Types
#define CH_HELLO 0
#define CH_DATA 1
#define CH_EXCEPTION 2
#define CH_PROGRESS 3
#define CH_PONG 4
#define CH_END_OF_STREAM 5
#define CH_PROFILE_INFO 6
#define CH_TOTALS 7
#define CH_EXTREMES 8
#define CH_TABLES_STATUS_RESPONSE 9
#define CH_LOG 10
#define CH_TABLE_COLUMNS 11
#define CH_PART_UUIDS 12
#define CH_READ_TASK_REQUEST 13

// Client packet types
#define CH_CLIENT_HELLO 0
#define CH_CLIENT_QUERY 1
#define CH_CLIENT_DATA 2
#define CH_CLIENT_CANCEL 3
#define CH_CLIENT_PING 4
#define CH_CLIENT_TABLES_STATUS_REQUEST 5

// Protocol versions
#define CH_DBMS_MIN_REVISION_WITH_CLIENT_INFO 54032
#define CH_DBMS_MIN_REVISION_WITH_SERVER_TIMEZONE 54058
#define CH_DBMS_MIN_REVISION_WITH_QUOTA_KEY_IN_CLIENT_INFO 54060
#define CH_DBMS_MIN_REVISION_WITH_SERVER_DISPLAY_NAME 54372
#define CH_DBMS_MIN_REVISION_WITH_VERSION_PATCH 54401
#define CH_DBMS_MIN_REVISION_WITH_CLIENT_WRITE_INFO 54420

#define CH_CLIENT_VERSION_MAJOR 21
#define CH_CLIENT_VERSION_MINOR 8
#define CH_CLIENT_VERSION_PATCH 0
#define CH_CLIENT_REVISION 54449

// Data types
#define CH_TYPE_UINT8 0
#define CH_TYPE_UINT16 1
#define CH_TYPE_UINT32 2
#define CH_TYPE_UINT64 3
#define CH_TYPE_INT8 4
#define CH_TYPE_INT16 5
#define CH_TYPE_INT32 6
#define CH_TYPE_INT64 7
#define CH_TYPE_STRING 8
#define CH_TYPE_IPV4 9
#define CH_TYPE_IPV6 10
#define CH_TYPE_DATETIME 11

// Connection structure
typedef struct {
    int sockfd;
    char *host;
    uint16_t port;
    char *database;
    char *user;
    char *password;
    bool connected;
    uint64_t server_revision;
    char *server_name;
    char *server_version;
    char *server_timezone;
} ch_conn_t;

// Function declarations

/**
 * Creates a new ClickHouse connection structure
 * @param host ClickHouse server hostname or IP
 * @param port ClickHouse native protocol port (default: 9000)
 * @param database Database name
 * @param user Username
 * @param password Password
 * @return Pointer to ch_conn_t structure or NULL on failure
 */
ch_conn_t *ch_connect(const char *host, uint16_t port, const char *database,
                      const char *user, const char *password);

/**
 * Connects to ClickHouse using environment variable CH_CONN_STRING
 * Format: host:port:database:user:password
 * @param conn Pointer to connection pointer
 */
void ch_db_connect(ch_conn_t **conn);

/**
 * Closes the connection and frees resources
 * @param conn Connection to close
 */
void ch_disconnect(ch_conn_t *conn);

/**
 * Executes a query without expecting results
 * @param conn Active connection
 * @param query SQL query string
 * @return 0 on success, -1 on failure
 */
int ch_execute(ch_conn_t *conn, const char *query);

/**
 * Executes a query with data payload (for FORMAT Values inserts)
 * @param conn Active connection
 * @param query SQL query string
 * @param data Data payload to send after query
 * @return 0 on success, -1 on failure
 */
int ch_execute_with_data(ch_conn_t *conn, const char *query, const char *data);

/**
 * Creates the flows table if it doesn't exist
 * @param conn Active connection
 * @return 0 on success, -1 on failure
 */
int ch_create_flows_table(ch_conn_t *conn);

/**
 * Inserts NetFlow records into ClickHouse using native protocol
 * @param exporter Exporter IP address
 * @param flows NetFlow v9 flowset to insert
 * @return 0 on success, -1 on failure
 */
int ch_insert_flows(uint32_t exporter, netflow_v9_uint128_flowset_t *flows);

/**
 * Converts IP address to string representation
 * @param value IP address as uint128_t
 * @param ip_version 4 for IPv4, 6 for IPv6
 * @return String representation (thread-local storage)
 */
char *ch_ip_uint128_to_string(uint128_t value, uint8_t ip_version);

// Low-level protocol functions

/**
 * Sends client hello packet
 * @param conn Active connection
 * @return 0 on success, -1 on failure
 */
int ch_send_hello(ch_conn_t *conn);

/**
 * Receives server hello packet
 * @param conn Active connection
 * @return 0 on success, -1 on failure
 */
int ch_receive_hello(ch_conn_t *conn);

/**
 * Sends a query packet
 * @param conn Active connection
 * @param query_id Unique query identifier
 * @param query SQL query string
 * @return 0 on success, -1 on failure
 */
int ch_send_query(ch_conn_t *conn, const char *query_id, const char *query);

/**
 * Sends a data block
 * @param conn Active connection
 * @param table_name Table name
 * @param exporter Exporter IP
 * @param flows Flow records to send
 * @return 0 on success, -1 on failure
 */
int ch_send_data_block(ch_conn_t *conn, const char *table_name,
                       uint32_t exporter, netflow_v9_uint128_flowset_t *flows);

/**
 * Receives server response packets until end of stream
 * @param conn Active connection
 * @return 0 on success, -1 on failure
 */
int ch_receive_response(ch_conn_t *conn);

// Utility functions for varint encoding
void ch_write_varint(uint64_t value, uint8_t *buffer, size_t *offset);
uint64_t ch_read_varint(const uint8_t *buffer, size_t *offset);
void ch_write_string(const char *str, uint8_t *buffer, size_t *offset);
char *ch_read_string(const uint8_t *buffer, size_t *offset);

#endif // DB_CLICKHOUSE_H
