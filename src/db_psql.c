//
// Created by jon on 6/6/25.
//

#include "db_psql.h"
#include <stdlib.h>
#include <string.h>
#if defined(__STDC_NO_THREADS__)
// If <threads.h> is missing, some compilers support __thread, or _Thread_local, or nothing.
#if defined(__GNUC__) || defined(__clang__)
#define THREAD_LOCAL __thread
#else
#define THREAD_LOCAL
#endif
#else
#define THREAD_LOCAL thread_local
#endif
#include <threads.h>
#include "arena.h"
#define BUFFLEN 10000
char *read_snmp_config(PGconn *conn, arena_struct_t *arena) {
  char *config;
  if (conn == NULL || PQstatus(conn) != CONNECTION_OK) {
    fprintf(stderr, "Connection to database failed: %s\n", conn ? PQerrorMessage(conn) : "NULL connection");
    goto read_snmp_config_exit_nicely;
  }
  config = (char *) arena_alloc(arena, BUFFLEN + 1);
  memset(config, 0, BUFFLEN + 1);
  char *query = "select * from config";
  return config;
read_snmp_config_exit_nicely:
  if (conn != NULL) {
    fprintf(stderr, PQerrorMessage(conn));
    PQfinish(conn);
  }
  fprintf(stderr, "%s %d %s", __FILE__, __LINE__, __func__);
  exit(-1);
}

/**
 * Prepares a PostgreSQL prepared statement named "insert_flows" for inserting NetFlow data
 * into the "public.flows" table. The statement includes 12 parameters to support the necessary
 * columns in the table and checks for any errors during the preparation process.
 *
 * @param conn   A pointer to the PostgreSQL connection object. Must be an open and valid connection.
 */
void prepare_statement_v5(PGconn *conn) {
  if (conn == NULL || PQstatus(conn) != CONNECTION_OK) {
    fprintf(stderr, "Connection to database failed: %s\n", conn ? PQerrorMessage(conn) : "NULL connection");
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

    fprintf(stderr, "PQprepare failed: %s", PQerrorMessage(conn));
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
    fprintf(stderr, PQerrorMessage(conn));
    PQfinish(conn);
  }
  fprintf(stderr, "%s %d %s", __FILE__, __LINE__, __func__);
  exit(-1);
}
void prepare_statement_v9(PGconn *conn) {
  if (conn == NULL || PQstatus(conn) != CONNECTION_OK) {
    fprintf(stderr, "Connection to database failed: %s\n", conn ? PQerrorMessage(conn) : "NULL connection");
    goto prepare_statement_v9_exit_nicely;
  }

  PGresult *res;
  char stmtName[] = "insert_flows_v9";
  const int nParams = 18;
  char query[] = "insert into public.flows_v9 "
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
  };


  res = PQprepare(conn, stmtName, query, nParams, paramTypes);
  if (PQresultStatus(res) != PGRES_COMMAND_OK) {

    fprintf(stderr, "PQprepare failed: %s", PQerrorMessage(conn));
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
    fprintf(stderr, PQerrorMessage(conn));
    PQfinish(conn);
  }
  fprintf(stderr, "%s %d %s", __FILE__, __LINE__, __func__);
  exit(-1);
}
/**
 * Inserts a batch of NetFlow v5 records into a PostgreSQL database.
 *
 * @param conn       A pointer to the PostgreSQL connection object. Must be an open and valid connection.
 * @param exporter   A unique identifier for the exporter sending the flow data. Must be non-zero.
 * @param flows      A pointer to an array of NetFlow v5 records to be inserted into the database.
 * @param count      The number of records in the `flows` array. Must be greater than zero.
 */
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
    fprintf(stderr, "BEGIN command failed: %s", PQerrorMessage(conn));
    PQclear(res);
    goto insert_v5_exit_nicely;
  }
  PQclear(res);


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

  res = PQexec(conn, "END");
  if (PQresultStatus(res) != PGRES_COMMAND_OK) {
    fprintf(stderr, "%s[%d]: PQexec failed: %s\n", __FILE__, __LINE__, PQresultErrorMessage(res));
    PQclear(res);
    goto insert_v5_exit_nicely;
  }
  PQclear(res);

insert_v5_return:
  return;
insert_v5_exit_nicely:
  if (conn != NULL) {
    fprintf(stderr, PQerrorMessage(conn));
    PQfinish(conn);
  }
  fprintf(stderr, "%s %d %s", __FILE__, __LINE__, __func__);
  exit(-1);
}


/**
 * Inserts a batch of NetFlow v9 records into a PostgreSQL database.
 *
 * @param conn       A pointer to the PostgreSQL connection object. Must be an open and valid connection.
 * @param exporter   A unique identifier for the exporter sending the flow data. Must be non-zero.
 * @param flows      A pointer to an array of NetFlow v5 records to be inserted into the database.
 * @param count      The number of records in the `flows` array. Must be greater than zero.
 */
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
    fprintf(stderr, "BEGIN command failed: %s", PQerrorMessage(conn));
    PQclear(res);
    goto insert_v9_exit_nicely;
  }
  PQclear(res);


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

  res = PQexec(conn, "END");
  if (PQresultStatus(res) != PGRES_COMMAND_OK) {
    fprintf(stderr, "%s[%d]: PQexec failed: %s\n", __FILE__, __LINE__, PQresultErrorMessage(res));
    PQclear(res);
    goto insert_v9_exit_nicely;
  }
  PQclear(res);

insert_v9_return:
  return;
insert_v9_exit_nicely:
  if (conn != NULL) {
    fprintf(stderr, PQerrorMessage(conn));
    PQfinish(conn);
  }
  fprintf(stderr, "%s %d %s", __FILE__, __LINE__, __func__);
  exit(-1);
}


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
    fprintf(stderr, "Environment variable PG_CONN_STRING is not set.\n");
    fprintf(stderr, "%s %d %s", __FILE__, __LINE__, __func__);
    exit(EXIT_FAILURE);
  }

  /* Make a connection to the database */
  PGconn *conn_ptr;
  conn_ptr = PQconnectdb(static_conn_string);
  *conn = conn_ptr;
  /* Check to see that the backend connection was successfully made */
  if (PQstatus(*conn) != CONNECTION_OK) {
    fprintf(stderr, "%s", PQerrorMessage(*conn));
    goto db_connect_exit_nicely;
  }
  /* Set always-secure search path, so malicious users can't take control. */

  PGresult *res;

  res = PQexec(*conn, "SELECT pg_catalog.set_config('search_path', '', false)");
  if (PQresultStatus(res) != PGRES_TUPLES_OK) {
    fprintf(stderr, "SELECT pg_catalog.set_config('search_path', '', false) failed: %s\n", PQerrorMessage(*conn));
    PQclear(res);
    goto db_connect_exit_nicely;
  }
  PQclear(res);
  fprintf(stderr, "SELECT pg_catalog.set_config('search_path', '', false) succesfull: %s\n", PQerrorMessage(*conn));

  /*
  res = PQexec(*conn, "DEALLOCATE ALL");
  if (PQresultStatus(res) != PGRES_COMMAND_OK) {
    fprintf(stderr, "DEALLOCATE ALL UNsuccessfull: %s\n", PQerrorMessage(*conn));
    PQclear(res);
    exit_nicely(*conn);
  }
  PQclear(res);
  fprintf(stderr, "DEALLOCATE ALL successfull\n");
  */

  // return conn;
  /*
   * Fetch rows from pg_database, the system catalog of databases
   */
  /*
  res = PQexec(conn, "DECLARE myportal CURSOR FOR select * from pg_database");
  if (PQresultStatus(res) != PGRES_COMMAND_OK) {
    fprintf(stderr, "DECLARE CURSOR failed: %s", PQerrorMessage(conn));
    PQclear(res);
    exit_nicely(conn);
  }
  PQclear(res);

  res = PQexec(conn, "FETCH ALL in myportal");
  if (PQresultStatus(res) != PGRES_TUPLES_OK) {
    fprintf(stderr, "FETCH ALL failed: %s", PQerrorMessage(conn));
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
  prepare_statement_v5(*conn);
  prepare_statement_v9(*conn);
  return;
db_connect_exit_nicely:
  if (*conn != NULL) {
    fprintf(stderr, PQerrorMessage(*conn));
    PQfinish(*conn);
  }
  fprintf(stderr, "%s %d %s", __FILE__, __LINE__, __func__);
  exit(-1);
}
