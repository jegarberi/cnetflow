//
// Created by jon on 6/6/25.
//

#include "db_psql.h"
#include <stdlib.h>


static void exit_nicely(PGconn *conn) {
  PQfinish(conn);
  exit(1);
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
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
      fprintf(stderr, "%s[%d]: PQexecPrepared failed: %s\n", __FILE__, __LINE__, PQresultErrorMessage(res));
      PQclear(res);
      prepare_statement(conn);
      res = PQexecPrepared(conn, "insert_flows", nParams, paramValues, paramLengths, paramFormats, resultFormat);
      if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        PQclear(res);
        exit_nicely(conn);
      } else {
        PQclear(res);
      }
    } else {
      PQclear(res);
    }
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
    exit(EXIT_FAILURE);
  }

  /* Make a connection to the database */
  PGconn *conn_ptr;
  conn_ptr = PQconnectdb(static_conn_string);
  *conn = conn_ptr;
  /* Check to see that the backend connection was successfully made */
  if (PQstatus(*conn) != CONNECTION_OK) {
    fprintf(stderr, "%s", PQerrorMessage(*conn));
    exit_nicely(*conn);
  }
  /* Set always-secure search path, so malicious users can't take control. */

  PGresult *res;

  res = PQexec(*conn, "SELECT pg_catalog.set_config('search_path', '', false)");
  if (PQresultStatus(res) != PGRES_TUPLES_OK) {
    fprintf(stderr, "SELECT pg_catalog.set_config('search_path', '', false) failed: %s\n", PQerrorMessage(*conn));
    PQclear(res);
    exit_nicely(*conn);
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
}
