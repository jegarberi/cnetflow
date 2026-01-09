//
// Created for cnetflow - ClickHouse HTTP Interface Client
//

#ifndef DB_CLICKHOUSE_H
#define DB_CLICKHOUSE_H
#define _MAX_OCTETS_TO_CONSIDER_WRONG 10737418240 //10G
#define _MAX_PACKETS_TO_CONSIDER_WRONG 10737418240
#include <curl/curl.h>
#include "netflow.h"
#include <stdint.h>
#include <time.h>
#include <stdbool.h>

// Connection structure
typedef struct {
    CURL *curl;
    char *host;
    uint16_t port;
    char *database;
    char *user;
    char *password;
    bool connected;
    char userpwd[256];
} ch_conn_t;

// Function declarations

/**
 * Creates a new ClickHouse connection structure
 * @param host ClickHouse server hostname or IP
 * @param port ClickHouse HTTP port (default: 8123)
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
 * Creates the flows table if it doesn't exist
 * @param conn Active connection
 * @return 0 on success, -1 on failure
 */
int ch_create_flows_table(ch_conn_t *conn);

/**
 * Inserts NetFlow records into ClickHouse using HTTP interface
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


int ch_insert_template(uint32_t exporter, char * template_key,const uint8_t * dump, const size_t dump_size);
int ch_insert_dump(uint32_t exporter, char * template_key,const uint8_t * dump, const size_t dump_size) ;
int insert_template(uint32_t exporter, char * template_key,const uint8_t * dump, const size_t dump_size);
int insert_dump(uint32_t exporter, char * template_key,const uint8_t * dump, const size_t dump_size);
#endif // DB_CLICKHOUSE_H
