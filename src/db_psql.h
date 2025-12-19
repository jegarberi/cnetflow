//
// Created by jon on 6/6/25.
//

#ifndef DB_PSQL_H
#define DB_PSQL_H
#ifdef __has_include
#  if __has_include(<postgresql/libpq-fe.h>)
#    include <postgresql/libpq-fe.h>
#  else
#    include <libpq-fe.h>
#  endif
#else
#  include <libpq-fe.h>
#endif
#include "netflow.h"
#define BOOLOID 16 // boolean
#define BYTEAOID 17 // binary data ("byte array")
#define CHAROID 18 // single character
#define NAMEOID 19 // name (63-byte type for storing system identifiers)
#define INT8OID 20 // ~18 digit integer (8 bytes), "bigint"
#define INT2OID 21 // -32k to 32k, 2-byte storage, "smallint"
#define INT4OID 23 // -2b to 2b integer, 4-byte storage, "integer"
#define TEXTOID 25 // variable-length string, no limit specified
#define OIDOID 26 // object identifier
#define FLOAT4OID 700 // single-precision floating point number, 4-byte storage, "real"
#define FLOAT8OID 701 // double-precision floating point number, 8-byte storage, "double precision"
#define BPCHAROID 1042 // char(length), blank-padded string, fixed storage length
#define VARCHAROID 1043 // varchar(length), non-blank-padded string, variable storage length
#define DATEOID 1082 // date
#define TIMEOID 1083 // time of day
#define TIMESTAMPOID 1114 // date and time
#define TIMESTAMPTZOID 1184 // date and time with time zone
#define INTERVALOID 1186 // time interval
#define NUMERICOID 1700 // numeric(precision, decimal), arbitrary precision number
#define UUIDOID 2950 // UUID datatype
#define INETOID 869 // IP address/netmask, host address
#define CIDROID 650 // network IP address/netmask, network address
#define JSONOID 114 // JSON data
#define JSONBOID 3802 // Binary JSON data

static void exit_nicely();

void db_connect(PGconn **conn);
// void prepare_statement_v5(PGconn *conn);
// void prepare_statement_v9(PGconn *conn);
// void insert_v5(uint32_t exporter, netflow_v5_flowset_t *flows);
// void insert_v9(uint32_t exporter, netflow_v9_flowset_t *flows);

void prepare_statement_insert_flows(PGconn *conn);
void insert_flows(uint32_t, netflow_v9_uint128_flowset_t *);
char *ip_uint128_to_string(uint128_t value, uint8_t ip_version);
void swap_src_dst(netflow_v9_uint128_flowset_t *);
#endif // DB_PSQL_H
