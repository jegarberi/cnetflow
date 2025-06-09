//
// Created by jon on 6/3/25.
//
#include "netflow_v5.h"
#include <stdlib.h>
#include <string.h>

#include "collector.h"
#include "db_psql.h"

static PGconn *conn;

static void exit_nicely() {
  if (conn != NULL) {
    fprintf(stderr, PQerrorMessage(conn));

    PQfinish(conn);
    exit(-1);
  }
}

static void insert_v5(PGconn * conn,uint32_t exporter, const netflow_v5_record_t *flows, int count) {
  prepare_statement(conn);
  if (conn == NULL || PQstatus(conn) != CONNECTION_OK || exporter == 0 || count == 0) {
    exit(-1);
  }
  PGresult *res;
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
  for (int i = 0; i < count; i++) {
    int nParams = 12;
    const char *const paramValues[12] = {
        // exporter,srcaddr,srcport,dstport,dstaddr,first,last,dpkts,doctets,input,output,prot
        &exporter,           &(flows[i].srcaddr), &(flows[i].srcport), &(flows[i].dstaddr),
        &(flows[i].dstport), &(flows[i].First),   &(flows[i].Last),    &(flows[i].dPkts),
        &(flows[i].dOctets), &(flows[i].input),   &(flows[i].output),  &(flows[i].prot),
    };
    const int paramLengths[12] = {
        // exporter,srcaddr,srcport,dstport,dstaddr,first,last,dpkts,doctets,input,output
        sizeof(exporter), // 1
        sizeof(flows[i].srcaddr), // 2
        sizeof(flows[i].srcport), // 3
        sizeof(flows[i].dstaddr), // 4
        sizeof(flows[i].dstport), // 5
        sizeof(flows[i].First), // 6
        sizeof(flows[i].Last), // 7
        sizeof(flows[i].dPkts), // 8
        sizeof(flows[i].dOctets), // 9
        sizeof(flows[i].input), // 10
        sizeof(flows[i].output), // 11
        sizeof(flows[i].prot), // 12
    };
    const int paramFormats[12] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
    const int resultFormat = 0;

    res = PQexecPrepared(conn, "insert_flows", nParams, paramValues, paramLengths, paramFormats, resultFormat);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
      fprintf(stderr, "%s[%d]: PQexecPrepared failed: %s\n", __FILE__, __LINE__, PQresultErrorMessage(res));
      PQclear(res);
      prepare_statement(conn);
      res = PQexecPrepared(conn, "insert_flows", nParams, paramValues, paramLengths, paramFormats, resultFormat);
      if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        PQclear(res);
        exit_nicely();
      }
      PQclear(res);
    }
    PQclear(res);
  }

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


static void printf_v5(FILE *file, const netflow_v5_record_t *flow) {
  char ip_src_str[50] = {0};
  char ip_dst_str[50] = {0};
  char *tmp;
  tmp = ip_int_to_str(flow->srcaddr);
  strncpy(ip_src_str, tmp, strlen(tmp));
  tmp = ip_int_to_str(flow->dstaddr);
  strncpy(ip_dst_str, tmp, strlen(tmp));
  fprintf(file, "%s:%u -> %s:%u %u\n", ip_src_str, flow->srcport, ip_dst_str, flow->dstport, flow->prot);
}

static void prepare_statement(PGconn *conn) {
  if (conn == NULL) {
    db_connect(conn);
    if (conn == NULL || PQstatus(conn) != CONNECTION_OK) {
      fprintf(stderr, "Connection to database failed: %s", conn ? PQerrorMessage(conn) : "NULL connection");
      exit_nicely();
    }
  }
  PGresult *res;
  char stmtName[] = "insert_flows";
  const int nParams = 12;
  char query[] = "insert into public.flows "
                 "(exporter,srcaddr,srcport,dstaddr,dstport,first,last,dpkts,doctets,input,output,prot) values($1, $2, "
                 "$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)";

  const Oid paramTypes[12] = {
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
      CHAROID, // 12 INT2OID for prot (byte)
  };

  res = PQprepare(conn, stmtName, query, nParams, paramTypes);
  if (PQresultStatus(res) != PGRES_COMMAND_OK) {

    fprintf(stderr, "PQprepare failed: %s", PQerrorMessage(conn));
    char *prepare_failed_stmtName = "ERROR:  prepared statement \"insert_flows\" already exists\n";
    char *err_msg = PQerrorMessage(conn);
    if (strcmp(prepare_failed_stmtName, err_msg) != 0) {
      PQclear(res);
      exit_nicely();
    }
  }
  PQclear(res);
}


void *parse_v5(parse_args_t *args_data) {

  db_connect(&conn);
  parse_args_t args_copy;
  parse_args_t *args;
  args = &args_copy;
  memcpy(args, args_data->data, sizeof(parse_args_t));
  uv_mutex_t *lock = args->mutex;
  //__attribute__((cleanup(uv_mutex_unlock))) uv_mutex_t * lock = &(args->mutex);
  netflow_v5_header_t *header = (netflow_v5_header_t *) (args->data);
  netflow_v5_record_t records[30] = {0};
  swap_endianness((void *) &(header->version), sizeof(header->version));
  if (header->version != 5) {
    goto unlock_mutex_parse_v5;
  }
  swap_endianness((void *) &(header->count), sizeof(header->count));

  swap_endianness((void *) &(header->SysUptime), sizeof(header->SysUptime));
  swap_endianness((void *) &(header->unix_secs), sizeof(header->unix_secs));
  swap_endianness((void *) &(header->unix_nsecs), sizeof(header->unix_nsecs));
  swap_endianness((void *) &(header->flow_sequence), sizeof(header->flow_sequence));
  swap_endianness((void *) &(header->sampling_interval), sizeof(header->sampling_interval));
  uint32_t now = (uint32_t) time(NULL);
  uint32_t diff = now - (uint32_t) (header->SysUptime / 1000);

  memcpy(records, args->data + sizeof(netflow_v5_header_t), args->len - (sizeof(netflow_v5_header_t)));
  for (int i = 0; i < header->count; i++) {
    /*
    swap_endianness((void*)&(records[i].srcaddr), sizeof((records[i].srcaddr)));
    swap_endianness((void*)&(records[i].dstaddr), sizeof((records[i].dstaddr)));
    swap_endianness((void *) &(records[i].nexthop), sizeof((records[i].nexthop)));
    swap_endianness((void *) &(records[i].input), sizeof((records[i].input)));
    swap_endianness((void *) &(records[i].output), sizeof((records[i].output)));
    swap_endianness((void *) &(records[i].dPkts), sizeof((records[i].dPkts)));
    swap_endianness((void *) &(records[i].dOctets), sizeof((records[i].dOctets)));
    */
    swap_endianness((void *) &(records[i].First), sizeof((records[i].First)));
    swap_endianness((void *) &(records[i].Last), sizeof((records[i].Last)));
    records[i].First = records[i].First/1000 + diff;
    records[i].Last = records[i].Last/1000 + diff;
    swap_endianness((void *) &(records[i].First), sizeof((records[i].First)));
    swap_endianness((void *) &(records[i].Last), sizeof((records[i].Last)));
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
    swap_endianness((void *) &(records[i].srcport), sizeof((records[i].srcport)));
    swap_endianness((void *) &(records[i].dstport), sizeof((records[i].dstport)));
    if (records[i].dstport > records[i].srcport) {
      uint16_t tmp_port = records[i].dstport;
      records[i].dstport = records[i].srcport;
      records[i].srcport = tmp_port;
      uint32_t tmp_addr = records[i].dstaddr;
      records[i].dstaddr = records[i].srcaddr;
      records[i].srcaddr = tmp_addr;
    }
    swap_endianness((void *) &(records[i].srcport), sizeof((records[i].srcport)));
    swap_endianness((void *) &(records[i].dstport), sizeof((records[i].dstport)));
    printf_v5(stdout, &records[i]);
  }
  // swap_endianness((void *) &args->exporter, sizeof(args->exporter));
  insert_v5(conn,args->exporter, records, header->count);
unlock_mutex_parse_v5:
  uv_mutex_unlock(lock);
}
