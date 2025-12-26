//
// Created for cnetflow - Unified Database Interface
// Compile-time selection between PostgreSQL and ClickHouse
//

#ifndef DB_H
#define DB_H

#include "netflow.h"
#include "log.h"

// Compile-time database backend selection
// Use -DUSE_CLICKHOUSE to enable ClickHouse, otherwise defaults to PostgreSQL
#ifdef USE_CLICKHOUSE
    #include "db_clickhouse.h"

    // Type aliases for unified API
    typedef ch_conn_t* db_conn_t;

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

#else
    #include "db_psql.h"

    // Type aliases for unified API - PGconn is defined in libpq-fe.h (included by db_psql.h)
    typedef PGconn* db_conn_t;

    // PostgreSQL uses the functions directly from db_psql.h
    // No macros needed - functions are already defined with correct names

    // Backend identifier
    #define DB_BACKEND_NAME "PostgreSQL"
    #define DB_BACKEND_POSTGRESQL 1

#endif

// Common interface functions that work with both backends
// These are the functions that application code should use

/**
 * Initialize database connection using environment variables
 * PostgreSQL: Uses PG_CONN_STRING (via db_connect from db_psql.h)
 * ClickHouse: Uses CH_CONN_STRING (via ch_db_connect from db_clickhouse.h)
 */
static inline void db_init_connection(db_conn_t *conn) {
#ifdef USE_CLICKHOUSE
    ch_db_connect(conn);
#else
    db_connect(conn);
#endif
}

/**
 * Insert NetFlow records into the database
 * Works with both PostgreSQL and ClickHouse backends
 */
static inline int db_insert_flows(uint32_t exporter, netflow_v9_uint128_flowset_t *flows) {
#ifdef USE_CLICKHOUSE
    return ch_insert_flows(exporter, flows);
#else
    insert_flows(exporter, flows);
    return 0;
#endif
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
#ifdef USE_CLICKHOUSE
    LOG_ERROR("Connection String Variable: CH_CONN_STRING\n");
    LOG_ERROR("Format: host:port:database:user:password\n");
#else
    LOG_ERROR("Connection String Variable: PG_CONN_STRING\n");
    LOG_ERROR("Format: postgresql://user:password@host:port/database\n");
#endif
}
int insert_template(uint32_t exporter, char * template_key,const uint8_t * dump, const size_t dump_size);
int insert_dump(uint32_t exporter, char * template_key,const uint8_t * dump, const size_t dump_size);
#endif // DB_H
