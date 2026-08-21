//
// Created for cnetflow - Unified Database Interface
//
#ifndef DB_H
#define DB_H

#include "netflow.h"
#include "log.h"

// Forward declaration of ClickHouse connection type
typedef struct ch_conn_t* db_conn_t;

// Backend declarations (from db_clickhouse.h)
/**
 * @brief TODO: Document ch_db_connect
 *
 * @param conn TODO
 * @return TODO
 */
void ch_db_connect(db_conn_t *conn);
/**
 * @brief TODO: Document ch_disconnect
 *
 * @param conn TODO
 * @return TODO
 */
void ch_disconnect(db_conn_t conn);
/**
 * @brief TODO: Document ch_insert_flows
 *
 * @param exporter TODO
 * @param flows TODO
 * @return TODO
 */
int ch_insert_flows(uint32_t exporter, netflow_v9_uint128_flowset_t *flows);
/**
 * @brief TODO: Document ch_insert_dump
 *
 * @param exporter TODO
 * @param template_key TODO
 * @param dump TODO
 * @param dump_size TODO
 * @return TODO
 */
int ch_insert_dump(uint32_t exporter, char *template_key, const uint8_t *dump, const size_t dump_size);
/**
 * @brief TODO: Document ch_insert_template
 *
 * @param exporter TODO
 * @param template_key TODO
 * @param dump TODO
 * @param dump_size TODO
 * @return TODO
 */
int ch_insert_template(uint32_t exporter, char *template_key, const uint8_t *dump, const size_t dump_size);
/**
 * @brief TODO: Document ch_create_flows_table
 *
 * @param conn TODO
 * @return TODO
 */
int ch_create_flows_table(db_conn_t conn);
/**
 * @brief TODO: Document ch_ip_uint128_to_string
 *
 * @param value TODO
 * @param ip_version TODO
 * @return TODO
 */
char *ch_ip_uint128_to_string(uint128_t value, uint8_t ip_version);

// Function aliases for unified API
#define db_connect(conn) ch_db_connect(conn)
#define db_disconnect(conn) do { if(*(conn)) ch_disconnect(*(conn)); *(conn) = NULL; } while(0)
#define insert_flows(exporter, flows) ch_insert_flows(exporter, flows)
#define insert_dump(exporter, template_key, dump, dump_size) ch_insert_dump(exporter, template_key, dump, dump_size)
#define insert_template(exporter, template_key, dump, dump_size) ch_insert_template(exporter, template_key, dump, dump_size)
#define db_create_flows_table(conn) ch_create_flows_table(*(conn))
#define ip_uint128_to_string(value, version) ch_ip_uint128_to_string(value, version)

// Backend identifier
#define DB_BACKEND_NAME "ClickHouse"
#define DB_BACKEND_CLICKHOUSE 1

// Common interface functions that work with the backend
// These are the functions that application code should use

/**
 * Initialize database connection using environment variables
 * ClickHouse: Uses CH_CONN_STRING (via ch_db_connect from db_clickhouse.h)
 */
static inline void db_init_connection(db_conn_t *conn) {
    ch_db_connect(conn);
}

/**
 * Insert NetFlow records into the database
 */
static inline int db_insert_flows(uint32_t exporter, netflow_v9_uint128_flowset_t *flows) {
    return ch_insert_flows(exporter, flows);
}

/**
 * Get the name of the current database backend
 */
static inline const char* db_get_backend_name(void) {
    return DB_BACKEND_NAME;
}

/**
 * Print database backend information
 */
static inline void db_print_info(void) {
    LOG_ERROR("Database Backend: %s\n", DB_BACKEND_NAME);
    LOG_ERROR("Connection String Variable: CH_CONN_STRING\n");
    LOG_ERROR("Format: host:port:database:user:password\n");
}

/**
 * @brief TODO: Document insert_template
 *
 * @param exporter TODO
 * @param template_key TODO
 * @param dump TODO
 * @param dump_size TODO
 * @return TODO
 */
int insert_template(uint32_t exporter, char * template_key,const uint8_t * dump, const size_t dump_size);
/**
 * @brief TODO: Document insert_dump
 *
 * @param exporter TODO
 * @param template_key TODO
 * @param dump TODO
 * @param dump_size TODO
 * @return TODO
 */
int insert_dump(uint32_t exporter, char * template_key,const uint8_t * dump, const size_t dump_size);

#endif // DB_H
