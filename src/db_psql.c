//
// Created by jon on 6/6/25.
//

#include "db_psql.h"
#include "log.h"
#include <stdlib.h>
#include <string.h>
#if defined(__STDC_NO_THREADS__) || !defined(__STDC_VERSION__) || __STDC_VERSION__ < 201112L
// If <threads.h> is missing (C11), some compilers support __thread, or _Thread_local, or nothing.
#if defined(__GNUC__) || defined(__clang__)
#define THREAD_LOCAL __thread
#else
#define THREAD_LOCAL
#endif
#else
#include <threads.h>
#define THREAD_LOCAL thread_local
#endif
#include "arena.h"
#define BUFFLEN 10000
char *read_snmp_config(PGconn *conn, arena_struct_t *arena) {
  char *config;
  if (conn == NULL || PQstatus(conn) != CONNECTION_OK) {
    LOG_ERROR("Connection to database failed: %s\n", conn ? PQerrorMessage(conn) : "NULL connection");
    goto read_snmp_config_exit_nicely;
  }
  config = (char *) arena_alloc(arena, BUFFLEN + 1);
  memset(config, 0, BUFFLEN + 1);
  char *query = "select * from config";
  return config;
read_snmp_config_exit_nicely:
  if (conn != NULL) {
    LOG_ERROR("%s %d %s PQerrorMessage: %s", __FILE__, __LINE__, __func__, PQerrorMessage(conn));
    PQfinish(conn);
  }
  LOG_ERROR("%s %d %s", __FILE__, __LINE__, __func__);
  fprintf(stderr,"%s %d %s This should not happen...\n", __FILE__, __LINE__, __func__);
  exit(-1);
}

/**
 * Prepares a PostgreSQL prepared statement named "insert_flows" for inserting NetFlow data
 * into the "public.flows" table. The statement includes 12 parameters to support the necessary
 * columns in the table and checks for any errors during the preparation process.
 *
 * @param conn   A pointer to the PostgreSQL connection object. Must be an open and valid connection.
 */
/*
 void prepare_statement_v5(PGconn *conn) {
  if (conn == NULL || PQstatus(conn) != CONNECTION_OK) {
    LOG_ERROR("Connection to database failed: %s\n", conn ? PQerrorMessage(conn) : "NULL connection");
    goto prepare_statement_v5_exit_nicely;
  }

  PGresult *res;
  char stmtName[] = "insert_flows_v5";
  const int nParams = 18;
  char query[] = "insert into public.flows_v5 "
                 "(exporter,srcaddr,srcport,dstaddr,dstport,first,last,dpkts,doctets,input,output,prot,tos,src_as,dst_"
                 "as,src_mask,dst_mask,tcp_flags) values($1, $2, "
                 "$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)";

  const Oid paramTypes[18] = {
      INT4OID, // 1 INT4OID for exporter (integer)
      INT4OID, // 2 INT4OID for srcaddr (integer)
      INT2OID, // 3 INT2OID for srcport (smallint)
      INT4OID, // 4 INT4OID for dstaddr (integer)
      INT2OID, // 5 INT2OID for dstport (smallint)
      INT4OID, // 6 INT4OID for First (integer)
      INT4OID, // 7 INT4OID for Last (integer)
      INT4OID, // 8 INT4OID for dPkts (integer)
      INT4OID, // 9 INT4OID for dOctets (integer)
      INT2OID, // 10 INT2OID for input (smallint)
      INT2OID, // 11 INT2OID for output (smallint)
      CHAROID, // 12 CHAROID for prot (byte)
      CHAROID, // 13 CHAROID for tos (byte)
      INT2OID, // 14 INT2OID for srcas (smallint)
      INT2OID, // 15 INT2OID for dstas (smallint)
      CHAROID, // 16 CHAROID for src_mask (byte)
      CHAROID, // 17 CHAROID for dst_mask (byte)
      CHAROID, // 18 CHAROID for tcp_flags (byte)
  };


  res = PQprepare(conn, stmtName, query, nParams, paramTypes);
  if (PQresultStatus(res) != PGRES_COMMAND_OK) {

    LOG_ERROR("%s %d %s PQprepare failed: %s", __FILE__, __LINE__, __func__, PQerrorMessage(conn));
    char *prepare_failed_stmtName = "ERROR:  prepared statement \"insert_flows_v5\" already exists\n";
    char *err_msg = PQerrorMessage(conn);
    if (strcmp(prepare_failed_stmtName, err_msg) != 0) {
      PQclear(res);
      goto prepare_statement_v5_exit_nicely;
    }
  }
  PQclear(res);
  return;
prepare_statement_v5_exit_nicely:
  if (conn != NULL) {
    LOG_ERROR("%s %d %s PQerrorMessage: %s", __FILE__, __LINE__, __func__, PQerrorMessage(conn));
    PQfinish(conn);
  }
  LOG_ERROR("%s %d %s", __FILE__, __LINE__, __func__);
  exit(-1);
}
*/

void prepare_statement_insert_flows(PGconn *conn) {
  if (conn == NULL || PQstatus(conn) != CONNECTION_OK) {
    LOG_ERROR("%s %d %s: Connection to database failed: %s\n", __FILE__, __LINE__, __func__,
            conn ? PQerrorMessage(conn) : "NULL connection");
    goto prepare_statement_insert_flows_exit_nicely;
  }

  PGresult *res;
  char stmtName[] = "insert_flows";
#define _N_PARAMS 19
  char query[] = "insert into public.flows "
                 "(exporter,srcaddr,srcport,dstaddr,dstport,first,last,dpkts,doctets,input,"
                 "output,protocol,tos,src_as,dst_"
                 "as,src_mask,dst_mask,tcp_flags,ip_version) values($1, $2, "
                 "$3,$4,$5,TO_TIMESTAMP($6),TO_TIMESTAMP($7),$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)";

  const Oid paramTypes[_N_PARAMS] = {
      INT4OID, // 1 INT4OID for exporter (integer)
      INT4OID, // 2 INT4OID for srcaddr (integer)
      INT2OID, // 3 INT2OID for srcport (smallint)
      INT4OID, // 4 INT4OID for dstaddr (integer)
      INT2OID, // 5 INT2OID for dstport (smallint)
      INT4OID, // 6 INT4OID for First (integer)
      INT4OID, // 7 INT4OID for Last (integer)
      INT8OID, // 8 INT4OID for dPkts (bigint)
      INT8OID, // 9 INT4OID for dOctets (bigint)
      INT2OID, // 10 INT2OID for input (smallint)
      INT2OID, // 11 INT2OID for output (smallint)
      CHAROID, // 12 CHAROID for prot (byte)
      CHAROID, // 13 CHAROID for tos (byte)
      INT2OID, // 14 INT2OID for srcas (smallint)
      INT2OID, // 15 INT2OID for dstas (smallint)
      CHAROID, // 16 CHAROID for src_mask (byte)
      CHAROID, // 17 CHAROID for dst_mask (byte)
      CHAROID, // 18 CHAROID for tcp_flags (byte)
      CHAROID, // 19 CHAROID for tcp_flags (byte)
  };


  res = PQprepare(conn, stmtName, query, _N_PARAMS, NULL);
  if (PQresultStatus(res) != PGRES_COMMAND_OK) {

    LOG_ERROR("%s %d %s PQprepare failed: %s", __FILE__, __LINE__, __func__, PQerrorMessage(conn));
    char *prepare_failed_stmtName = "ERROR:  prepared statement \"insert_flows\" already exists\n";
    char *err_msg = PQerrorMessage(conn);
    if (strcmp(prepare_failed_stmtName, err_msg) != 0) {
      PQclear(res);
      goto prepare_statement_insert_flows_exit_nicely;
    }
  }
  PQclear(res);
  return;
prepare_statement_insert_flows_exit_nicely:
  if (conn != NULL) {
    LOG_ERROR("%s %d %s PQerrorMessage: %s", __FILE__, __LINE__, __func__, PQerrorMessage(conn));
    PQfinish(conn);
  }
  LOG_ERROR("%s %d %s", __FILE__, __LINE__, __func__);
  // exit(-1);
#undef _N_PARAMS
}
/*

void prepare_statement_v9(PGconn *conn) {
  if (conn == NULL || PQstatus(conn) != CONNECTION_OK) {
    LOG_ERROR("Connection to database failed: %s\n", conn ? PQerrorMessage(conn) : "NULL connection");
    goto prepare_statement_v9_exit_nicely;
  }

  PGresult *res;
  char stmtName[] = "insert_flows_v9";
  const int nParams = 19;
  char query[] = "insert into public.flows_v9 "
                 "(exporter,srcaddr,srcport,dstaddr,dstport,first,last,dpkts,doctets,input,output,prot,tos,src_as,dst_"
                 "as,src_mask,dst_mask,tcp_flags,ip_version) values($1, $2, "
                 "$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)";

  const Oid paramTypes[19] = {
      INT4OID, // 1 INT4OID for exporter (integer)
      INT4OID, // 2 INT4OID for srcaddr (integer)
      INT2OID, // 3 INT2OID for srcport (smallint)
      INT4OID, // 4 INT4OID for dstaddr (integer)
      INT2OID, // 5 INT2OID for dstport (smallint)
      INT4OID, // 6 INT4OID for First (integer)
      INT4OID, // 7 INT4OID for Last (integer)
      INT8OID, // 8 INT4OID for dPkts (bigint)
      INT8OID, // 9 INT4OID for dOctets (bigint)
      INT2OID, // 10 INT2OID for input (smallint)
      INT2OID, // 11 INT2OID for output (smallint)
      CHAROID, // 12 CHAROID for prot (byte)
      CHAROID, // 13 CHAROID for tos (byte)
      INT2OID, // 14 INT2OID for srcas (smallint)
      INT2OID, // 15 INT2OID for dstas (smallint)
      CHAROID, // 16 CHAROID for src_mask (byte)
      CHAROID, // 17 CHAROID for dst_mask (byte)
      CHAROID, // 18 CHAROID for tcp_flags (byte)
      CHAROID, // 18 CHAROID for ip_version (byte)
  };


  res = PQprepare(conn, stmtName, query, nParams, paramTypes);
  if (PQresultStatus(res) != PGRES_COMMAND_OK) {

    LOG_ERROR("%s %d %s PQprepare failed: %s", __FILE__, __LINE__, __func__, PQerrorMessage(conn));
    char *prepare_failed_stmtName = "ERROR:  prepared statement \"insert_flows_v9\" already exists\n";
    char *err_msg = PQerrorMessage(conn);
    if (strcmp(prepare_failed_stmtName, err_msg) != 0) {
      PQclear(res);
      goto prepare_statement_v9_exit_nicely;
    }
  }
  PQclear(res);
  return;
prepare_statement_v9_exit_nicely:
  if (conn != NULL) {
    LOG_ERROR("%s %d %s PQerrorMessage: %s", __FILE__, __LINE__, __func__, PQerrorMessage(conn));
    PQfinish(conn);
  }
  LOG_ERROR("%s %d %s", __FILE__, __LINE__, __func__);
  // exit(-1);
}
*/
/**
 * Inserts a batch of NetFlow v5 records into a PostgreSQL database.
 *
 * @param conn       A pointer to the PostgreSQL connection object. Must be an open and valid connection.
 * @param exporter   A unique identifier for the exporter sending the flow data. Must be non-zero.
 * @param flows      A pointer to an array of NetFlow v5 records to be inserted into the database.
 * @param count      The number of records in the `flows` array. Must be greater than zero.
 */
/*
void insert_v5(uint32_t exporter, netflow_v5_flowset_t *flows) {
  static THREAD_LOCAL PGconn *conn = NULL;
  db_connect(&conn);
  if (conn == NULL || exporter == 0) {
    fprintf(stderr, "%s %d %s", __FILE__, __LINE__, __func__);
    exit(-1);
  }
  PGresult *res;
  prepare_statement_v5(conn);

  res = PQexec(conn, "BEGIN");
  if (PQresultStatus(res) != PGRES_COMMAND_OK) {
    LOG_ERROR("%s[%d]: PQexecPrepared failed: %s\n", __FILE__, __LINE__, PQresultErrorMessage(res));
    PQclear(res);
    goto insert_v5_exit_nicely;
  }
  PQclear(res);


  for (int i = 0; i < flows->header.count; i++) {
    int nParams = 18;
    const char *const paramValues[18] = {
        // exporter,srcaddr,srcport,dstport,dstaddr,first,last,dpkts,doctets,input,output,prot
        (char *) &exporter,
        (char *) &(flows->records[i].srcaddr),
        (char *) &(flows->records[i].srcport),
        (char *) &(flows->records[i].dstaddr),
        (char *) &(flows->records[i].dstport),
        (char *) &(flows->records[i].First),
        (char *) &(flows->records[i].Last),
        (char *) &(flows->records[i].dPkts),
        (char *) &(flows->records[i].dOctets),
        (char *) &(flows->records[i].input),
        (char *) &(flows->records[i].output),
        (char *) &(flows->records[i].prot),
        (char *) &(flows->records[i].tos),
        (char *) &(flows->records[i].src_as),
        (char *) &(flows->records[i].dst_as),
        (char *) &(flows->records[i].src_mask),
        (char *) &(flows->records[i].dst_mask),
        (char *) &(flows->records[i].tcp_flags)};
    const int paramLengths[18] = {
        // exporter,srcaddr,srcport,dstport,dstaddr,first,last,dpkts,doctets,input,output
        sizeof(exporter), // 1
        sizeof(flows->records[i].srcaddr), // 2
        sizeof(flows->records[i].srcport), // 3
        sizeof(flows->records[i].dstaddr), // 4
        sizeof(flows->records[i].dstport), // 5
        sizeof(flows->records[i].First), // 6
        sizeof(flows->records[i].Last), // 7
        sizeof(flows->records[i].dPkts), // 8
        sizeof(flows->records[i].dOctets), // 9
        sizeof(flows->records[i].input), // 10
        sizeof(flows->records[i].output), // 11
        sizeof(flows->records[i].prot), // 12
        sizeof(flows->records[i].tos), // 13
        sizeof(flows->records[i].src_as), // 14
        sizeof(flows->records[i].dst_as), // 15
        sizeof(flows->records[i].src_mask), // 16
        sizeof(flows->records[i].dst_mask), // 17
        sizeof(flows->records[i].tcp_flags), // 17
    };
    const int paramFormats[18] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
    const int resultFormat = 0;

    res = PQexecPrepared(conn, "insert_flows_v5", nParams, paramValues, paramLengths, paramFormats, resultFormat);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
      fprintf(stderr, "%s[%d]: PQexecPrepared failed: %s\n", __FILE__, __LINE__, PQresultErrorMessage(res));
      PQclear(res);
      prepare_statement_v5(conn);
      res = PQexecPrepared(conn, "insert_flows_v5", nParams, paramValues, paramLengths, paramFormats, resultFormat);
      if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        PQclear(res);
        fprintf(stderr, "%s[%d]: PQexecPrepared failed: %s\n", __FILE__, __LINE__, PQresultErrorMessage(res));
        goto insert_v5_exit_nicely;
      } else {
        PQclear(res);
      }
    } else {
      PQclear(res);
    }
  }
  // PQfinish(conn);
  /* end the transaction */
/*
res = PQexec(conn, "END");
if (PQresultStatus(res) != PGRES_COMMAND_OK) {
  LOG_ERROR("%s[%d]: PQexec failed: %s\n", __FILE__, __LINE__, PQresultErrorMessage(res));
  PQclear(res);
  goto insert_v5_exit_nicely;
}
PQclear(res);

insert_v5_return : return;
insert_v5_exit_nicely : if (conn != NULL) {
  LOG_ERROR("%s %d %s PQerrorMessage: %s", __FILE__, __LINE__, __func__, PQerrorMessage(conn));
  PQfinish(conn);
}
LOG_ERROR("%s %d %s", __FILE__, __LINE__, __func__);
exit(-1);
}
*/
char *ip_uint128_to_string(uint128_t value, uint8_t ip_version) {
  // NOTE: Make the output buffer STATIC so it's not invalid after returning!
  // This makes this function NOT thread-safe. (Can be improved.)
#define _MAX_LEN 50
  static THREAD_LOCAL char ret_string[_MAX_LEN] = {0};

  if (ip_version == 4) {
    // IPv4 is in 32 bits of value, print as dotted quad
    uint32_t ip = (uint32_t) value;
    snprintf(ret_string, _MAX_LEN, "%u.%u.%u.%u", (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
  } else if (ip_version == 6) {
    // IPv6: print as canonical x:x:x:x:x:x:x:x (eight 16-bit hex groups)
    uint16_t parts[8];
    uint128_t v = value;
    for (int i = 0; i < 8; i++) {
      // Big-endian: first group is highest-order bits
      parts[7 - i] = (uint16_t) (v & 0xFFFF);
      v >>= 16;
    }
    // Print groups as hex, compact representation with leading zeros, not handling ::
    snprintf(ret_string, _MAX_LEN, "%x:%x:%x:%x:%x:%x:%x:%x", parts[0], parts[1], parts[2], parts[3], parts[4],
             parts[5], parts[6], parts[7]);
  } else {
    snprintf(ret_string, _MAX_LEN, "INVALID_IP_VERSION");
  }
  return ret_string;
#undef _MAX_LEN
}

#define _N_PARAMS 19
#define _MAX_LEN 50
void fill_param_values(char (*values)[_N_PARAMS][_MAX_LEN], uint128_t exporter,
                       netflow_v9_record_insert_uint128_t *flow) {
  /* char query[] = "insert into public.flows "
  "(exporter,srcaddr,srcport,dstaddr,dstport,first,last,dpkts,doctets,input,output,prot,tos,src_as,dst_"
  "as,src_mask,dst_mask,tcp_flags,ip_version) values($1, $2, "
  "$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)";
  */
#define _EXPORTER 0
#define _SRCADDR 1
#define _SRCPORT 2
#define _DSTADDR 3
#define _DSTPORT 4
#define _FIRST 5
#define _LAST 6
#define _DPKTS 7
#define _DOCTETS 8
#define _INPUT 9
#define _OUTPUT 10
#define _PROTOCOL 11
#define _TOS 12
#define _SRC_AS 13
#define _DST_AS 14
#define _SRC_MASK 15
#define _DST_MASK 16
#define _TCP_FLAGS 17
#define _IP_VERSION 18

  // char values[_N_PARAMS][_MAX_LEN] = {0};
  char temp_values[_N_PARAMS][_MAX_LEN] = {0};
  snprintf(temp_values[_IP_VERSION], _MAX_LEN, "%d", flow->ip_version);
  snprintf(temp_values[_EXPORTER], _MAX_LEN, "%s", ip_uint128_to_string(exporter, 4));
  snprintf(temp_values[_SRCADDR], _MAX_LEN, "%s", ip_uint128_to_string(flow->srcaddr, flow->ip_version));
  snprintf(temp_values[_SRCPORT], _MAX_LEN, "%u", flow->srcport);
  snprintf(temp_values[_DSTADDR], _MAX_LEN, "%s", ip_uint128_to_string(flow->dstaddr, flow->ip_version));
  snprintf(temp_values[_DSTPORT], _MAX_LEN, "%u", flow->dstport);
  snprintf(temp_values[_FIRST], _MAX_LEN, "%u", flow->First);
  snprintf(temp_values[_LAST], _MAX_LEN, "%u", flow->Last);

  // swap_endianness(&flow->dPkts, sizeof(flow->dPkts));
  if (flow->dPkts > 1000000) {
    fprintf(stderr, "%s %d %s flow->dPkts = %lu\n", __FILE__, __LINE__, __func__, flow->dPkts);
  }
  snprintf(temp_values[_DPKTS], _MAX_LEN, "%lu", flow->dPkts);
  // swap_endianness(&flow->dOctets, sizeof(flow->dOctets));
  snprintf(temp_values[_DOCTETS], _MAX_LEN, "%lu", flow->dOctets);

  snprintf(temp_values[_INPUT], _MAX_LEN, "%u", flow->input);
  snprintf(temp_values[_OUTPUT], _MAX_LEN, "%u", flow->output);

  snprintf(temp_values[_PROTOCOL], _MAX_LEN, "%u", flow->prot);
  snprintf(temp_values[_TOS], _MAX_LEN, "%u", flow->tos);
  snprintf(temp_values[_SRC_AS], _MAX_LEN, "%u", flow->src_as);
  snprintf(temp_values[_DST_AS], _MAX_LEN, "%u", flow->dst_as);
  snprintf(temp_values[_SRC_MASK], _MAX_LEN, "%u", flow->src_mask);
  snprintf(temp_values[_DST_MASK], _MAX_LEN, "%u", flow->dst_mask);
  snprintf(temp_values[_TCP_FLAGS], _MAX_LEN, "%u", flow->tcp_flags);

  memcpy(values, temp_values, sizeof(char[_N_PARAMS][_MAX_LEN]));

  /*
  *&exporter,
        &(flows->records[i].srcaddr),
        &(flows->records[i].srcport),
        &(flows->records[i].dstaddr),
        &(flows->records[i].dstport),
        &(flows->records[i].First),
        &(flows->records[i].Last),
        &(flows->records[i].dPkts),
        &(flows->records[i].dOctets),
        &(flows->records[i].input),
        &(flows->records[i].output),
        &(flows->records[i].prot),
        &(flows->records[i].tos),
        &(flows->records[i].src_as),
        &(flows->records[i].dst_as),
        &(flows->records[i].src_mask),
        &(flows->records[i].dst_mask),
        &(flows->records[i].tcp_flags),
        &(flows->records[i].ip_version)}
   *
   */
}
#undef _MAX_LEN
#undef _N_PARAMS
/**
 * Inserts a batch of NetFlow v9 records into a PostgreSQL database.
 *
 * @param conn       A pointer to the PostgreSQL connection object. Must be an open and valid connection.
 * @param exporter   A unique identifier for the exporter sending the flow data. Must be non-zero.
 * @param flows      A pointer to an array of NetFlow v5 records to be inserted into the database.
 * @param count      The number of records in the `flows` array. Must be greater than zero.
 */
void insert_flows(uint32_t exporter, netflow_v9_uint128_flowset_t *flows) {
  static THREAD_LOCAL PGconn *conn = NULL;

  db_connect(&conn);
  if (conn == NULL || exporter == 0) {
    LOG_ERROR("%s %d %s", __FILE__, __LINE__, __func__);
    fprintf(stderr,"%s %d %s This should not happen...\n", __FILE__, __LINE__, __func__);
    exit(-1);
  }
  PGresult *res;
  prepare_statement_insert_flows(conn);

  res = PQexec(conn, "BEGIN");
  if (PQresultStatus(res) != PGRES_COMMAND_OK) {
    LOG_ERROR("%s[%d] %s: BEGIN failed: %s\n", __FILE__, __LINE__, __func__, PQresultErrorMessage(res));
    PQclear(res);
    goto insert_flows_exit_nicely;
  }
  PQclear(res);
#define _N_PARAMS 19
#define _MAX_LEN 50
  char paramValuesAsString[_N_PARAMS][_MAX_LEN] = {0};

  for (int i = 0; i < flows->header.count; i++) {
    int nParams = _N_PARAMS;
    if (flows->records[i].dOctets == 0) {
      fprintf(stderr, "%s[%d] %s: flow->dOctets = 0\n", __FILE__, __LINE__, __func__);
      continue;
    }
    if (flows->records[i].dPkts == 0) {
      fprintf(stderr, "%s[%d] %s: flow->dOctets = 0\n", __FILE__, __LINE__, __func__);
      continue;
    }
    fill_param_values(&paramValuesAsString, (uint128_t) exporter, &(flows->records[i]));
    const char *paramValues[_N_PARAMS];
    for (int k = 0; k < _N_PARAMS; k++) {
      paramValues[k] = paramValuesAsString[k];
    }
    /*const char *const paramValues[_N_PARAMS] = {
        // exporter,srcaddr,srcport,dstport,dstaddr,first,last,dpkts,doctets,input,output,prot
        (char *) &exporter,
        (char *) &(flows->records[i].srcaddr),
        (char *) &(flows->records[i].srcport),
        (char *) &(flows->records[i].dstaddr),
        (char *) &(flows->records[i].dstport),
        (char *) &(flows->records[i].First),
        (char *) &(flows->records[i].Last),
        (char *) &(flows->records[i].dPkts),
        (char *) &(flows->records[i].dOctets),
        (char *) &(flows->records[i].input),
        (char *) &(flows->records[i].output),
        (char *) &(flows->records[i].prot),
        (char *) &(flows->records[i].tos),
        (char *) &(flows->records[i].src_as),
        (char *) &(flows->records[i].dst_as),
        (char *) &(flows->records[i].src_mask),
        (char *) &(flows->records[i].dst_mask),
        (char *) &(flows->records[i].tcp_flags),
        (char *) &(flows->records[i].ip_version)};*/
    // https:// www.postgresql.org/docs/current/libpq-exec.html#LIBPQ-EXEC-MAIN
    const int paramLengths[_N_PARAMS] = {0}; // IGNORED IF TEXT FORMAT
    const int paramFormats[_N_PARAMS] = {0}; // ALL TEXT FORMAT
    const int resultFormat = 0;
    const char *const *ptr_values = (const char *const *) &paramValuesAsString;
    res = PQexecPrepared(conn, "insert_flows", nParams, (const char *const *) paramValues, NULL, NULL, resultFormat);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
      LOG_ERROR("%s[%d] %s: PQexecPrepared failed: %s\n", __FILE__, __LINE__, __func__,
              PQresultErrorMessage(res));
      for (int k = 0; k < _N_PARAMS; k++) {
        LOG_ERROR("%s[%d] %s: paramValues[%d] = %s\n", __FILE__, __LINE__, __func__, k, paramValuesAsString[k]);
      }
      PQclear(res);
      prepare_statement_insert_flows(conn);
      res = PQexecPrepared(conn, "insert_flows", nParams, (const char *const *) paramValues, NULL, NULL, resultFormat);
      if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        PQclear(res);
        LOG_ERROR("%s[%d] %s: PQexecPrepared failed: %s\n", __FILE__, __LINE__, __func__,
                PQresultErrorMessage(res));
        goto insert_flows_exit_nicely;
      } else {
        PQclear(res);
      }
    } else {
      PQclear(res);
    }
  }
  // PQfinish(conn);
  /* end the transaction */

  res = PQexec(conn, "END");
  if (PQresultStatus(res) != PGRES_COMMAND_OK) {
    LOG_ERROR("%s[%d] %s: END failed: %s\n", __FILE__, __LINE__, __func__, PQresultErrorMessage(res));
    PQclear(res);
    goto insert_flows_exit_nicely;
  }
  PQclear(res);

insert_flows_return:

  return;
insert_flows_exit_nicely:
  if (conn != NULL) {
    LOG_ERROR("%s %d %s PQerrorMessage: %s", __FILE__, __LINE__, __func__, PQerrorMessage(conn));
    PQfinish(conn);
  }
  LOG_ERROR("%s %d %s", __FILE__, __LINE__, __func__);
  fprintf(stderr,"%s %d %s This should not happen...\n", __FILE__, __LINE__, __func__);
  exit(-1);
#undef _N_PARAMS
#undef _MAX_LEN
}


/**
 * Inserts a batch of NetFlow v9 records into a PostgreSQL database.
 *
 * @param conn       A pointer to the PostgreSQL connection object. Must be an open and valid connection.
 * @param exporter   A unique identifier for the exporter sending the flow data. Must be non-zero.
 * @param flows      A pointer to an array of NetFlow v5 records to be inserted into the database.
 * @param count      The number of records in the `flows` array. Must be greater than zero.
 */
/*
void insert_v9(uint32_t exporter, netflow_v9_flowset_t *flows) {

  static THREAD_LOCAL PGconn *conn = NULL;
  db_connect(&conn);
  if (conn == NULL || exporter == 0) {
    fprintf(stderr, "%s %d %s", __FILE__, __LINE__, __func__);
    exit(-1);
  }
  PGresult *res;
  prepare_statement_v9(conn);

  res = PQexec(conn, "BEGIN");
  if (PQresultStatus(res) != PGRES_COMMAND_OK) {
    LOG_ERROR("BEGIN command failed: %s", PQerrorMessage(conn));
    PQclear(res);
    goto insert_v9_exit_nicely;
  }
  PQclear(res);


  for (int i = 0; i < flows->header.count; i++) {
    int nParams = 19;
    const char *const paramValues[19] = {
        // exporter,srcaddr,srcport,dstport,dstaddr,first,last,dpkts,doctets,input,output,prot
        (char *) &exporter,
        (char *) &(flows->records[i].srcaddr),
        (char *) &(flows->records[i].srcport),
        (char *) &(flows->records[i].dstaddr),
        (char *) &(flows->records[i].dstport),
        (char *) &(flows->records[i].First),
        (char *) &(flows->records[i].Last),
        (char *) &(flows->records[i].dPkts),
        (char *) &(flows->records[i].dOctets),
        (char *) &(flows->records[i].input),
        (char *) &(flows->records[i].output),
        (char *) &(flows->records[i].prot),
        (char *) &(flows->records[i].tos),
        (char *) &(flows->records[i].src_as),
        (char *) &(flows->records[i].dst_as),
        (char *) &(flows->records[i].src_mask),
        (char *) &(flows->records[i].dst_mask),
        (char *) &(flows->records[i].tcp_flags),
        (char *) &(flows->records[i].ip_version)};
    const int paramLengths[19] = {
        // exporter,srcaddr,srcport,dstport,dstaddr,first,last,dpkts,doctets,input,output
        sizeof(exporter), // 1
        sizeof(flows->records[i].srcaddr), // 2
        sizeof(flows->records[i].srcport), // 3
        sizeof(flows->records[i].dstaddr), // 4
        sizeof(flows->records[i].dstport), // 5
        sizeof(flows->records[i].First), // 6
        sizeof(flows->records[i].Last), // 7
        sizeof(flows->records[i].dPkts), // 8
        sizeof(flows->records[i].dOctets), // 9
        sizeof(flows->records[i].input), // 10
        sizeof(flows->records[i].output), // 11
        sizeof(flows->records[i].prot), // 12
        sizeof(flows->records[i].tos), // 13
        sizeof(flows->records[i].src_as), // 14
        sizeof(flows->records[i].dst_as), // 15
        sizeof(flows->records[i].src_mask), // 16
        sizeof(flows->records[i].dst_mask), // 17
        sizeof(flows->records[i].tcp_flags), // 18
        sizeof(flows->records[i].ip_version), // 19
    };
    const int paramFormats[19] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
    const int resultFormat = 0;

    res = PQexecPrepared(conn, "insert_flows_v9", nParams, paramValues, paramLengths, paramFormats, resultFormat);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
      fprintf(stderr, "%s[%d]: PQexecPrepared failed: %s\n", __FILE__, __LINE__, PQresultErrorMessage(res));
      PQclear(res);
      prepare_statement_v9(conn);
      res = PQexecPrepared(conn, "insert_flows_v9", nParams, paramValues, paramLengths, paramFormats, resultFormat);
      if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        PQclear(res);
        fprintf(stderr, "%s[%d]: PQexecPrepared failed: %s\n", __FILE__, __LINE__, PQresultErrorMessage(res));
        goto insert_v9_exit_nicely;
      } else {
        PQclear(res);
      }
    } else {
      PQclear(res);
    }
  }
  // PQfinish(conn);
  /* end the transaction */
/*
res = PQexec(conn, "END");
if (PQresultStatus(res) != PGRES_COMMAND_OK) {
  fprintf(stderr, "%s[%d]: PQexec failed: %s\n", __FILE__, __LINE__, PQresultErrorMessage(res));

  goto insert_v9_exit_nicely;
}

insert_v9_return : PQclear(res);
return;
insert_v9_exit_nicely : PQclear(res);
if (conn != NULL) {
  fprintf(stderr, "%s %d %s PQerrorMessage: %s", __FILE__, __LINE__, __func__, PQerrorMessage(conn));
  PQfinish(conn);
}
fprintf(stderr, "%s %d %s", __FILE__, __LINE__, __func__);
exit(-1);
}
*/

/**
 * Establishes a connection to a PostgreSQL database using the connection string
 * obtained from the environment variable "PG_CONN_STRING". If a connection is
 * already present, it returns without taking any action. On a successful connection,
 * it sets a secure search path and validates the connection status.
 *
 * @param conn A pointer to a `PGconn` pointer. If the connection is not already
 *             established, this function will populate it with a valid connection
 *             object. If the connection fails, the application will terminate.
 */
void db_connect(PGconn **conn) {
  if (*conn != NULL) {
    return;
  }
  /*static char *static_conn_string =
      "postgresql://postgres.your-tenant-id:your-super-secret-and-long-postgres-password@192.168.100.78:5432/postgres";*/
  const char *static_conn_string = getenv("PG_CONN_STRING");
  if (static_conn_string == NULL) {
    LOG_ERROR("Environment variable PG_CONN_STRING is not set.\n");
    LOG_ERROR("%s %d %s", __FILE__, __LINE__, __func__);
    exit(EXIT_FAILURE);
  }

  /* Make a connection to the database */
  PGconn *conn_ptr;
  conn_ptr = PQconnectdb(static_conn_string);
  *conn = conn_ptr;
  /* Check to see that the backend connection was successfully made */
  if (PQstatus(*conn) != CONNECTION_OK) {
    LOG_ERROR("%s", PQerrorMessage(*conn));
    goto db_connect_exit_nicely;
  }
  /* Set always-secure search path, so malicious users can't take control. */

  PGresult *res;

  res = PQexec(*conn, "SELECT pg_catalog.set_config('search_path', '', false)");
  if (PQresultStatus(res) != PGRES_TUPLES_OK) {
    LOG_ERROR("SELECT pg_catalog.set_config('search_path', '', false) failed: %s\n", PQerrorMessage(*conn));
    PQclear(res);
    goto db_connect_exit_nicely;
  }
  PQclear(res);
  LOG_DEBUG("SELECT pg_catalog.set_config('search_path', '', false) succesfull: %s\n", PQerrorMessage(*conn));

  /*
  res = PQexec(*conn, "DEALLOCATE ALL");
  if (PQresultStatus(res) != PGRES_COMMAND_OK) {
    LOG_ERROR("DEALLOCATE ALL UNsuccessfull: %s\n", PQerrorMessage(*conn));
    PQclear(res);
    exit_nicely(*conn);
  }
  PQclear(res);
  LOG_DEBUG("DEALLOCATE ALL successfull\n");
  */

  // return conn;
  /*
   * Fetch rows from pg_database, the system catalog of databases
   */
  /*
  res = PQexec(conn, "DECLARE myportal CURSOR FOR select * from pg_database");
  if (PQresultStatus(res) != PGRES_COMMAND_OK) {
    LOG_ERROR("DECLARE CURSOR failed: %s", PQerrorMessage(conn));
    PQclear(res);
    exit_nicely(conn);
  }
  PQclear(res);

  res = PQexec(conn, "FETCH ALL in myportal");
  if (PQresultStatus(res) != PGRES_TUPLES_OK) {
    LOG_ERROR("FETCH ALL failed: %s", PQerrorMessage(conn));
    PQclear(res);
    exit_nicely(conn);
  }
  */
  /* first, print out the attribute names */
  /*
  nFields = PQnfields(res);
  for (i = 0; i < nFields; i++)
    printf("%-15s", PQfname(res, i));
  printf("\n\n");
  */
  /* next, print out the rows */
  /*
  for (i = 0; i < PQntuples(res); i++) {
    for (j = 0; j < nFields; j++)
      printf("%-15s", PQgetvalue(res, i, j));
    printf("\n");
  }

  PQclear(res);
  */
  /* close the portal ... we don't bother to check for errors ... */
  /*
  res = PQexec(conn, "CLOSE myportal");
  PQclear(res);
  */
  /* end the transaction */
  /*
  res = PQexec(conn, "END");
  PQclear(res);
  */
  /* close the connection to the database and cleanup */

  //  PQfinish(conn);
  // prepare_statement_v5(*conn);
  // prepare_statement_v9(*conn);
  prepare_statement_insert_flows(*conn);
  return;
db_connect_exit_nicely:
  if (*conn != NULL) {
    LOG_ERROR("%s %d %s %s",__FILE__, __LINE__, __func__,PQerrorMessage(*conn));
    PQfinish(*conn);
  }
  LOG_ERROR("%s %d %s exit -1", __FILE__, __LINE__, __func__);
  exit(-1);
}


void swap_src_dst(netflow_v9_uint128_flowset_t *flows) {
  for (int i = 0; i < flows->header.count; ++i) {
    if (flows->records[i].dstport > flows->records[i].srcport) {
    }
  }
}
