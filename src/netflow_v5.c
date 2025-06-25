//
// Created by jon on 6/3/25.
//
#include "netflow_v5.h"
#include <stdlib.h>
#include <string.h>

#include "arena.h"
#include "collector.h"
#include "db_psql.h"

arena_struct_t *arena_collector;
static void exit_nicely(PGconn *conn) {
  if (conn != NULL) {
    fprintf(stderr, PQerrorMessage(conn));
    PQfinish(conn);
    exit(-1);
  }
}

/**
 * Inserts a batch of NetFlow v5 records into a PostgreSQL database.
 *
 * @param conn       A pointer to the PostgreSQL connection object. Must be an open and valid connection.
 * @param exporter   A unique identifier for the exporter sending the flow data. Must be non-zero.
 * @param flows      A pointer to an array of NetFlow v5 records to be inserted into the database.
 * @param count      The number of records in the `flows` array. Must be greater than zero.
 */
static void insert_v5(uint32_t exporter, netflow_v5_flowset_t *flows) {
  PGconn *conn = NULL;
  db_connect(&conn);
  if (conn == NULL || exporter == 0) {
    exit(-1);
  }
  PGresult *res;
  prepare_statement(conn);
  /*
  res = PQexec(conn, "BEGIN");
  if (PQresultStatus(res) != PGRES_COMMAND_OK)
  {
    fprintf(stderr, "BEGIN command failed: %s", PQerrorMessage(conn));
    PQclear(res);
    exit_nicely(conn);
  }
  PQclear(res);
  */

  for (int i = 0; i < flows->header.count; i++) {
    int nParams = 18;
    const char *const paramValues[18] = {
        // exporter,srcaddr,srcport,dstport,dstaddr,first,last,dpkts,doctets,input,output,prot
        &exporter,
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
        &(flows->records[i].tcp_flags)};
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

    res = PQexecPrepared(conn, "insert_flows", nParams, paramValues, paramLengths, paramFormats, resultFormat);
    /*if (PQresultStatus(res) != PGRES_COMMAND_OK) {
      fprintf(stderr, "%s[%d]: PQexecPrepared failed: %s\n", __FILE__, __LINE__, PQresultErrorMessage(res));
      PQclear(res);
      prepare_statement(conn);
      res = PQexecPrepared(conn, "insert_flows", nParams, paramValues, paramLengths, paramFormats, resultFormat);
      if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        PQclear(res);
        exit_nicely(conn);
      }
      PQclear(res);
    }*/
    PQclear(res);
  }
  PQfinish(conn);
  /* end the transaction */
  /*
  res = PQexec(conn, "END");
  if (PQresultStatus(res) != PGRES_COMMAND_OK) {
    fprintf(stderr, "%s[%d]: PQexec failed: %s\n", __FILE__, __LINE__, PQresultErrorMessage(res));
    PQclear(res);
    exit_nicely();
  }
  PQclear(res);
  */
}


static void printf_v5(FILE *file, netflow_v5_flowset_t *netflow_packet, int i) {
  char ip_src_str[50] = {0};
  char ip_dst_str[50] = {0};

  char *tmp;
  tmp = ip_int_to_str(netflow_packet->records[i].srcaddr);
  strncpy(ip_src_str, tmp, strlen(tmp));
  tmp = ip_int_to_str(netflow_packet->records[i].dstaddr);
  strncpy(ip_dst_str, tmp, strlen(tmp));
  fprintf(file, "%s:%u -> %s:%u %u\n", ip_src_str, netflow_packet->records[i].srcport, ip_dst_str,
          netflow_packet->records[i].dstport, netflow_packet->records[i].prot);
}

/**
 * Prepares a PostgreSQL prepared statement named "insert_flows" for inserting NetFlow data
 * into the "public.flows" table. The statement includes 12 parameters to support the necessary
 * columns in the table and checks for any errors during the preparation process.
 *
 * @param conn   A pointer to the PostgreSQL connection object. Must be an open and valid connection.
 */
static void prepare_statement(PGconn *conn) {
  if (conn == NULL || PQstatus(conn) != CONNECTION_OK) {
    fprintf(stderr, "Connection to database failed: %s\n", conn ? PQerrorMessage(conn) : "NULL connection");
    exit_nicely(conn);
  }

  PGresult *res;
  char stmtName[] = "insert_flows";
  const int nParams = 18;
  char query[] = "insert into public.flows "
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

    fprintf(stderr, "PQprepare failed: %s", PQerrorMessage(conn));
    char *prepare_failed_stmtName = "ERROR:  prepared statement \"insert_flows\" already exists\n";
    char *err_msg = PQerrorMessage(conn);
    if (strcmp(prepare_failed_stmtName, err_msg) != 0) {
      PQclear(res);
      exit_nicely(conn);
    }
  }
  PQclear(res);
}


/**
 * Parses and processes NetFlow v5 data from the provided arguments structure,
 * updating flow timestamps, swapping endianness where necessary, and inserting
 * the parsed records into a database. This function also manages concurrency
 * using a mutex lock during processing.
 *
 * @param args_data   A pointer to a `parse_args_t` structure containing NetFlow
 *                    v5 data to be parsed and processed. Must include a valid
 *                    data buffer and mutex for synchronization.
 * @return            A pointer to result or data processed (depends on the
 *                    function usage; typically NULL if no return object is needed).
 */
void *parse_v5(uv_work_t *req) {
  parse_args_t *args = (parse_args_t *) req->data;
  args->status = collector_data_status_processing;
  netflow_v5_flowset_t *netflow_packet;
  netflow_packet = (netflow_v5_flowset_t *) args->data;
  swap_endianness((void *) &(netflow_packet->header.version), sizeof(netflow_packet->header.version));
  if (netflow_packet->header.version != 5) {
    fprintf(stderr, "%s %d %s This should not happen...\n", __FILE__, __LINE__, __func__);
    exit(-1);
    goto unlock_mutex_parse_v5;
  }
  swap_endianness((void *) &(netflow_packet->header.count), sizeof(netflow_packet->header.count));
  if (netflow_packet->header.count > 30) {
    fprintf(stderr, "Too many flows...\n");
    goto unlock_mutex_parse_v5;
  }
  swap_endianness((void *) &(netflow_packet->header.SysUptime), sizeof(netflow_packet->header.SysUptime));
  swap_endianness((void *) &(netflow_packet->header.unix_secs), sizeof(netflow_packet->header.unix_secs));
  swap_endianness((void *) &(netflow_packet->header.unix_nsecs), sizeof(netflow_packet->header.unix_nsecs));
  swap_endianness((void *) &(netflow_packet->header.flow_sequence), sizeof(netflow_packet->header.flow_sequence));
  swap_endianness((void *) &(netflow_packet->header.sampling_interval),
                  sizeof(netflow_packet->header.sampling_interval));

  uint32_t now = (uint32_t) time(NULL);
  uint32_t diff = now - (uint32_t) (netflow_packet->header.SysUptime / 1000);

  // memcpy(records, args->data + sizeof(netflow_v5_header_t), args->len - (sizeof(netflow_v5_header_t)));
  // memcpy(&netflow_packet, args->data, args->len);
  for (int i = 0; i < netflow_packet->header.count; i++) {
    /*
    swap_endianness((void*)&(records[i].srcaddr), sizeof((records[i].srcaddr)));
    swap_endianness((void*)&(records[i].dstaddr), sizeof((records[i].dstaddr)));
    swap_endianness((void *) &(records[i].nexthop), sizeof((records[i].nexthop)));
    swap_endianness((void *) &(records[i].input), sizeof((records[i].input)));
    swap_endianness((void *) &(records[i].output), sizeof((records[i].output)));
    swap_endianness((void *) &(records[i].dPkts), sizeof((records[i].dPkts)));
    swap_endianness((void *) &(records[i].dOctets), sizeof((records[i].dOctets)));
    */
    swap_endianness((void *) &(netflow_packet->records[i].First), sizeof((netflow_packet->records[i].First)));
    swap_endianness((void *) &(netflow_packet->records[i].Last), sizeof((netflow_packet->records[i].Last)));
    netflow_packet->records[i].First = netflow_packet->records[i].First / 1000 + diff;
    netflow_packet->records[i].Last = netflow_packet->records[i].Last / 1000 + diff;
    swap_endianness((void *) &(netflow_packet->records[i].First), sizeof((netflow_packet->records[i].First)));
    swap_endianness((void *) &(netflow_packet->records[i].Last), sizeof((netflow_packet->records[i].Last)));
    /*
    swap_endianness((void *) &(records[i].srcport), sizeof((records[i].srcport)));
    swap_endianness((void *) &(records[i].dstport), sizeof((records[i].dstport)));
    // pad1
    // tcp_flags
    // prot
    // tos
    swap_endianness((void *) &(records[i].src_as), sizeof((records[i].src_as)));
    swap_endianness((void *) &(records[i].dst_as), sizeof((records[i].dst_as)));
    swap_endianness((void *) &(records[i].src_mask), sizeof((records[i].src_mask)));
    swap_endianness((void *) &(records[i].dst_mask), sizeof((records[i].dst_mask)));
    */
    swap_endianness((void *) &(netflow_packet->records[i].srcport), sizeof((netflow_packet->records[i].srcport)));
    swap_endianness((void *) &(netflow_packet->records[i].dstport), sizeof((netflow_packet->records[i].dstport)));
    if (netflow_packet->records[i].dstport > netflow_packet->records[i].srcport) {
      uint16_t tmp_port = netflow_packet->records[i].dstport;
      netflow_packet->records[i].dstport = netflow_packet->records[i].srcport;
      netflow_packet->records[i].srcport = tmp_port;
      uint32_t tmp_addr = netflow_packet->records[i].dstaddr;
      netflow_packet->records[i].dstaddr = netflow_packet->records[i].srcaddr;
      netflow_packet->records[i].srcaddr = tmp_addr;
    }
    swap_endianness((void *) &(netflow_packet->records[i].srcport), sizeof((netflow_packet->records[i].srcport)));
    swap_endianness((void *) &(netflow_packet->records[i].dstport), sizeof((netflow_packet->records[i].dstport)));
    printf_v5(stdout, netflow_packet, i);
  }
  // swap_endianness((void *) &args->exporter, sizeof(args->exporter));
  insert_v5(args->exporter, netflow_packet);
unlock_mutex_parse_v5:
  // uv_mutex_unlock(lock);
  args->status = collector_data_status_done;

  return NULL;
}
