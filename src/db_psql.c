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
  /*
  PQfinish(conn);
  */
  // return 0;
}
