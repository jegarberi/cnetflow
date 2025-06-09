//
// Created by jon on 6/6/25.
//

#include "db_psql.h"
#include <stdlib.h>


static void exit_nicely(PGconn *conn) {
  PQfinish(conn);
  exit(1);
}

void db_connect(PGconn ** conn) {
  if (*conn != NULL) {
    return;
  }
  int nFields = 0, i = 0, j = 0;
  //PGconn *conn;
  /*static char *static_conn_string =
      "postgresql://postgres.your-tenant-id:your-super-secret-and-long-postgres-password@192.168.100.78:5432/postgres";*/
  static char *static_conn_string;
  static_conn_string = getenv("PG_CONN_STRING");
  /* Make a connection to the database */
  *conn = PQconnectdb(static_conn_string);
  /* Check to see that the backend connection was successfully made */
  if (PQstatus(*conn) != CONNECTION_OK) {
    fprintf(stderr, "%s", PQerrorMessage(*conn));
    exit_nicely(*conn);
  }
  /* Set always-secure search path, so malicious users can't take control. */
  PGresult *res;
  res = PQexec(*conn, "SELECT pg_catalog.set_config('search_path', '', false)");
  if (PQresultStatus(res) != PGRES_TUPLES_OK) {
    fprintf(stderr, "SET failed: %s", PQerrorMessage(*conn));
    PQclear(res);
    exit_nicely(*conn);
  }
  //return conn;
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
  /*
  PQfinish(conn);
  */
  // return 0;
}
