//
// Created for cnetflow - ClickHouse HTTP Interface Client
//

#include "db_clickhouse.h"
#include <arpa/inet.h>
#include <curl/curl.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <uv.h>
#include "arena.h"
#include "log.h"
#include "netflow.h"

// Compatibility macros for old logging names
#define CH_LOG_ERROR LOG_ERROR
#define CH_LOG_INFO LOG_INFO
#define CH_LOG_DEBUG LOG_DEBUG

// External arena from collector
extern arena_struct_t *arena_collector;

// Response buffer for CURL
typedef struct {
  char data[4096];
  size_t size;
} curl_response_t;

/**
 * @brief TODO: Document ch_curl_write_callback
 *
 * @param contents TODO
 * @param size TODO
 * @param nmemb TODO
 * @param userp TODO
 * @return TODO
 */
static size_t ch_curl_write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
  size_t realsize = size * nmemb;
  curl_response_t *mem = (curl_response_t *) userp;

  size_t available = sizeof(mem->data) - mem->size - 1;
  size_t to_copy = realsize < available ? realsize : available;
  if (to_copy > 0) {
    memcpy(mem->data + mem->size, contents, to_copy);
    mem->size += to_copy;
    mem->data[mem->size] = '\0';
  }
  /* Returning the complete input length tells libcurl the response was
   * consumed even when the diagnostic buffer has been truncated. */
  return realsize;
}

// Global cleanup tracking for thread locals
static uv_mutex_t cleanup_mutex;
static uv_once_t cleanup_mutex_once = UV_ONCE_INIT;

/**
 * @brief TODO: Document init_cleanup_mutex
 *
 * @return TODO
 */
static void init_cleanup_mutex(void) {
  uv_mutex_init(&cleanup_mutex);
}

static ch_conn_t ***ch_conns_ptrs = NULL;
static int ch_conns_count = 0;
static int ch_conns_capacity = 0;

static char ***ch_queries_ptrs = NULL;
static int ch_queries_count = 0;
static int ch_queries_capacity = 0;

typedef struct {
  ch_conn_t **conn;
  char **query;
  int *offset;
  size_t *inserted;
} ch_flush_ctx_t;

static ch_flush_ctx_t *ch_flush_ctxs = NULL;
static int ch_flush_ctx_count = 0;
static int ch_flush_ctx_capacity = 0;

/**
 * @brief TODO: Document register_ch_flush_ctx
 *
 * @param conn TODO
 * @param query TODO
 * @param offset TODO
 * @param inserted TODO
 * @return TODO
 */
void register_ch_flush_ctx(ch_conn_t **conn, char **query, int *offset, size_t *inserted) {
  uv_once(&cleanup_mutex_once, init_cleanup_mutex);
  uv_mutex_lock(&cleanup_mutex);
  if (ch_flush_ctx_count == ch_flush_ctx_capacity) {
    int new_cap = ch_flush_ctx_capacity == 0 ? 16 : ch_flush_ctx_capacity * 2;
    ch_flush_ctx_t *new_arr = realloc(ch_flush_ctxs, new_cap * sizeof(ch_flush_ctx_t));
    if (new_arr) {
      ch_flush_ctxs = new_arr;
      ch_flush_ctx_capacity = new_cap;
    }
  }
  if (ch_flush_ctx_count < ch_flush_ctx_capacity) {
    ch_flush_ctxs[ch_flush_ctx_count].conn = conn;
    ch_flush_ctxs[ch_flush_ctx_count].query = query;
    ch_flush_ctxs[ch_flush_ctx_count].offset = offset;
    ch_flush_ctxs[ch_flush_ctx_count].inserted = inserted;
    ch_flush_ctx_count++;
  }
  uv_mutex_unlock(&cleanup_mutex);
}

/**
 * @brief TODO: Document register_ch_cleanup
 *
 * @param conn_ptr TODO
 * @param query_ptr TODO
 * @return TODO
 */
void register_ch_cleanup(ch_conn_t **conn_ptr, char **query_ptr) {
  uv_once(&cleanup_mutex_once, init_cleanup_mutex);
  uv_mutex_lock(&cleanup_mutex);
  if (conn_ptr) {
    if (ch_conns_count == ch_conns_capacity) {
      int new_cap = ch_conns_capacity == 0 ? 16 : ch_conns_capacity * 2;
      ch_conn_t ***new_arr = realloc(ch_conns_ptrs, new_cap * sizeof(ch_conn_t**));
      if (new_arr) {
        ch_conns_ptrs = new_arr;
        ch_conns_capacity = new_cap;
      }
    }
    if (ch_conns_count < ch_conns_capacity) {
      ch_conns_ptrs[ch_conns_count++] = conn_ptr;
    }
  }
  if (query_ptr) {
    if (ch_queries_count == ch_queries_capacity) {
      int new_cap = ch_queries_capacity == 0 ? 16 : ch_queries_capacity * 2;
      char ***new_arr = realloc(ch_queries_ptrs, new_cap * sizeof(char**));
      if (new_arr) {
        ch_queries_ptrs = new_arr;
        ch_queries_capacity = new_cap;
      }
    }
    if (ch_queries_count < ch_queries_capacity) {
      ch_queries_ptrs[ch_queries_count++] = query_ptr;
    }
  }
  uv_mutex_unlock(&cleanup_mutex);
}

/**
 * @brief TODO: Document ch_db_cleanup_all
 *
 * @return TODO
 */
void ch_db_cleanup_all(void) {
  uv_mutex_lock(&cleanup_mutex);

  for (int i = 0; i < ch_flush_ctx_count; i++) {
    if (ch_flush_ctxs[i].inserted && *ch_flush_ctxs[i].inserted > 0 &&
        ch_flush_ctxs[i].conn && *ch_flush_ctxs[i].conn && (*ch_flush_ctxs[i].conn)->connected &&
        ch_flush_ctxs[i].query && *ch_flush_ctxs[i].query &&
        ch_flush_ctxs[i].offset && *ch_flush_ctxs[i].offset > 0) {
      ch_execute(*ch_flush_ctxs[i].conn, *ch_flush_ctxs[i].query, *ch_flush_ctxs[i].offset);
      *ch_flush_ctxs[i].inserted = 0;
      *ch_flush_ctxs[i].offset = 0;
    }
  }
  free(ch_flush_ctxs);
  ch_flush_ctxs = NULL;
  ch_flush_ctx_count = 0;
  ch_flush_ctx_capacity = 0;

  for (int i = 0; i < ch_conns_count; i++) {
    if (ch_conns_ptrs[i] && *ch_conns_ptrs[i]) {
      ch_disconnect(*ch_conns_ptrs[i]);
      *ch_conns_ptrs[i] = NULL;
    }
  }
  free(ch_conns_ptrs);
  ch_conns_ptrs = NULL;
  ch_conns_count = 0;
  ch_conns_capacity = 0;

  for (int i = 0; i < ch_queries_count; i++) {
    if (ch_queries_ptrs[i] && *ch_queries_ptrs[i]) {
      free(*ch_queries_ptrs[i]);
      *ch_queries_ptrs[i] = NULL;
    }
  }
  free(ch_queries_ptrs);
  ch_queries_ptrs = NULL;
  ch_queries_count = 0;
  ch_queries_capacity = 0;
  uv_mutex_unlock(&cleanup_mutex);
}

/**
 * @brief TODO: Document ch_ip_uint128_to_string
 *
 * @param value TODO
 * @param ip_version TODO
 * @return TODO
 */
char *ch_ip_uint128_to_string(uint128_t value, uint8_t ip_version) {
  static THREAD_LOCAL char ret_string[4][INET6_ADDRSTRLEN];
  static THREAD_LOCAL int buffer_idx = 0;
  char *buf = ret_string[buffer_idx];
  buffer_idx = (buffer_idx + 1) % 4;

  if (ip_version == 4) {
    struct in_addr addr;
    uint32_t ip_host = (uint32_t) value;
    addr.s_addr = htonl(ip_host);
    if (inet_ntop(AF_INET, &addr, buf, INET6_ADDRSTRLEN) == NULL) {
      snprintf(buf, INET6_ADDRSTRLEN, "unknown");
    }
  } else if (ip_version == 6) {
    struct in6_addr addr;
    memcpy(&addr, &value, 16);
    if (inet_ntop(AF_INET6, &addr, buf, INET6_ADDRSTRLEN) == NULL) {
      snprintf(buf, INET6_ADDRSTRLEN, "unknown");
    }
  } else {
    snprintf(buf, INET6_ADDRSTRLEN, "unknown");
  }
  return buf;
}

/**
 * @brief TODO: Document ch_connect
 *
 * @param host TODO
 * @param port TODO
 * @param database TODO
 * @param user TODO
 * @param password TODO
 * @param params TODO
 * @return TODO
 */
ch_conn_t *ch_connect(const char *host, uint16_t port, const char *database, const char *user, const char *password, const char *params) {
  ch_conn_t *conn = (ch_conn_t *) calloc(1, sizeof(ch_conn_t));
  if (!conn) {
    CH_LOG_ERROR("%s %d %s: Failed to allocate connection structure\n", __FILE__, __LINE__, __func__);
    return NULL;
  }

  conn->host = strdup(host);
  conn->port = port;
  conn->database = strdup(database ? database : "default");
  conn->user = strdup(user ? user : "default");
  conn->password = strdup(password ? password : "");
  conn->params = params ? strdup(params) : NULL;

  if (!conn->host || !conn->database || !conn->user || !conn->password) {
    CH_LOG_ERROR("%s %d %s: Failed to duplicate connection strings\n", __FILE__, __LINE__, __func__);
    goto error;
  }
  conn->connected = false;

  // Initialize CURL
  conn->curl = curl_easy_init();
  if (!conn->curl) {
    CH_LOG_ERROR("%s %d %s: Failed to initialize CURL\n", __FILE__, __LINE__, __func__);
    goto error;
  }

  // Test connection with a simple query
  char test_url[512];
  if (conn->params && conn->params[0] != '\0') {
    snprintf(test_url, sizeof(test_url), "http://%s:%u/?query=SELECT%%201&%s", host, port, conn->params);
  } else {
    snprintf(test_url, sizeof(test_url), "http://%s:%u/?query=SELECT%%201", host, port);
  }

  curl_easy_setopt(conn->curl, CURLOPT_URL, test_url);
  curl_easy_setopt(conn->curl, CURLOPT_TIMEOUT, 5L);

  if (user && user[0] != '\0') {
    char userpwd[256];
    snprintf(userpwd, sizeof(userpwd), "%s:%s", user, password ? password : "");
    curl_easy_setopt(conn->curl, CURLOPT_USERPWD, userpwd);
    curl_easy_setopt(conn->curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
  }

  curl_response_t response = {0};
  curl_easy_setopt(conn->curl, CURLOPT_WRITEFUNCTION, ch_curl_write_callback);
  curl_easy_setopt(conn->curl, CURLOPT_WRITEDATA, (void *) &response);

  CURLcode res = curl_easy_perform(conn->curl);

  if (res != CURLE_OK) {
    CH_LOG_ERROR("%s %d %s: ClickHouse connection test failed: %s\n", __FILE__, __LINE__, __func__,
                 curl_easy_strerror(res));
    goto error;
  }

  long http_code = 0;
  curl_easy_getinfo(conn->curl, CURLINFO_RESPONSE_CODE, &http_code);
  if (http_code != 200) {
    CH_LOG_ERROR("%s %d %s: ClickHouse returned HTTP %ld\n", __FILE__, __LINE__, __func__, http_code);
    goto error;
  }

  conn->connected = true;
  CH_LOG_INFO("Connected to ClickHouse HTTP interface at %s:%d\n", host, port);
  return conn;

error:
  if (conn->curl)
    curl_easy_cleanup(conn->curl);
  if (conn->host)
    free(conn->host);
  if (conn->database)
    free(conn->database);
  if (conn->user)
    free(conn->user);
  if (conn->password)
    free(conn->password);
  if (conn->params)
    free(conn->params);
  free(conn);
  return NULL;
}

/**
 * @brief TODO: Document ch_db_connect
 *
 * @param conn TODO
 * @return TODO
 */
WEAK void ch_db_connect(ch_conn_t **conn) {
  if (*conn != NULL) {
    if ((*conn)->connected) {
      return;
    }
    // Connection object exists but is disconnected. Free it before reconnecting to prevent leaks.
    ch_disconnect(*conn);
    *conn = NULL;
  }

  const char *conn_string = getenv("CH_CONN_STRING");
  if (!conn_string) {
    CH_LOG_ERROR("Environment variable CH_CONN_STRING is not set.\n");
    CH_LOG_ERROR("Format: host:port:database:user:password\n");
    EXIT_WITH_MSG(EXIT_FAILURE, "%s %d %s This should not happen...\n", __FILE__, __LINE__, __func__);
  }

  // Extract params first if present
  char *conn_str_copy = strdup(conn_string);
  char *params_ptr = strchr(conn_str_copy, '?');
  if (params_ptr) {
    *params_ptr = '\0';
    params_ptr++; // Points to params
  }

  // Parse connection string: host:port:database:user:password
  char *saveptr;
  char *host = strtok_r(conn_str_copy, ":", &saveptr);
  char *port_str = strtok_r(NULL, ":", &saveptr);
  char *database = strtok_r(NULL, ":", &saveptr);
  char *user = strtok_r(NULL, ":", &saveptr);
  char *password = strtok_r(NULL, ":", &saveptr);

  if (!host || !port_str) {
    CH_LOG_ERROR("Invalid CH_CONN_STRING format\n");
    free(conn_str_copy);
    EXIT_WITH_MSG(EXIT_FAILURE, "%s %d %s This should not happen...\n", __FILE__, __LINE__, __func__);
  }

  uint16_t port = atoi(port_str);
  *conn = ch_connect(host, port, database, user, password, params_ptr);
  free(conn_str_copy);

  static THREAD_LOCAL bool registered = false;
  if (!registered && *conn) {
    register_ch_cleanup(conn, NULL);
    registered = true;
  }

  if (!*conn) {
    CH_LOG_ERROR("Failed to connect to ClickHouse\n");
    EXIT_WITH_MSG(EXIT_FAILURE, "%s %d %s This should not happen...\n", __FILE__, __LINE__, __func__);
  }
}

/**
 * @brief TODO: Document ch_disconnect
 *
 * @param conn TODO
 * @return TODO
 */
void ch_disconnect(ch_conn_t *conn) {
  if (!conn)
    return;

  if (conn->curl) {
    curl_easy_cleanup(conn->curl);
  }
  if (conn->host)
    free(conn->host);
  if (conn->database)
    free(conn->database);
  if (conn->user)
    free(conn->user);
  if (conn->password)
    free(conn->password);
  if (conn->params)
    free(conn->params);
  free(conn);
}

/**
 * @brief TODO: Document ch_execute
 *
 * @param conn TODO
 * @param query TODO
 * @param query_len TODO
 * @return TODO
 */
int ch_execute(ch_conn_t *conn, const char *query, size_t query_len) {
  if (!conn || !conn->curl)
    return -1;
  if (query_len == 0)
    return -1;
  char url[512];
  if (conn->params && conn->params[0] != '\0') {
    snprintf(url, sizeof(url), "http://%s:%u/?database=%s&%s", conn->host, conn->port, conn->database, conn->params);
  } else {
    snprintf(url, sizeof(url), "http://%s:%u/?database=%s", conn->host, conn->port, conn->database);
  }

  curl_easy_setopt(conn->curl, CURLOPT_URL, url);
  curl_easy_setopt(conn->curl, CURLOPT_POSTFIELDS, query);
  curl_easy_setopt(conn->curl, CURLOPT_POSTFIELDSIZE, (long) query_len);
  curl_easy_setopt(conn->curl, CURLOPT_TIMEOUT, 10L);

  if (conn->user && conn->user[0] != '\0') {
    // char userpwd[256];
    snprintf(conn->userpwd, sizeof(conn->userpwd), "%s:%s", conn->user, conn->password ? conn->password : "");
    curl_easy_setopt(conn->curl, CURLOPT_USERPWD, conn->userpwd);
    curl_easy_setopt(conn->curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
  }

  curl_response_t response = {0};
  curl_easy_setopt(conn->curl, CURLOPT_WRITEFUNCTION, ch_curl_write_callback);
  curl_easy_setopt(conn->curl, CURLOPT_WRITEDATA, (void *) &response);

  CURLcode res = curl_easy_perform(conn->curl);

  if (res != CURLE_OK) {
    CH_LOG_ERROR("%s %d %s: Query failed: %s\n", __FILE__, __LINE__, __func__, curl_easy_strerror(res));
    return -1;
  }

  long http_code = 0;
  curl_easy_getinfo(conn->curl, CURLINFO_RESPONSE_CODE, &http_code);

  if (http_code != 200) {
    CH_LOG_ERROR("%s %d %s: Query failed with HTTP %ld: %s\n", __FILE__, __LINE__, __func__, http_code,
                 response.size ? response.data : "no response");
    return -1;
  }
  return 0;
}

/**
 * @brief TODO: Document ch_create_flows_table
 *
 * @param conn TODO
 * @return TODO
 */
int ch_create_flows_table(ch_conn_t *conn) {
  const char *create_table_query = "CREATE TABLE IF NOT EXISTS flows ("
                                   "    inserted_at DateTime DEFAULT now(),"
                                   "    exporter String,"
                                   "    srcaddr String,"
                                   "    dstaddr String,"
                                   "    srcport UInt16,"
                                   "    dstport UInt16,"
                                   "    protocol UInt8,"
                                   "    input UInt16,"
                                   "    output UInt16,"
                                   "    dpkts UInt64,"
                                   "    doctets UInt64,"
                                   "    first DateTime,"
                                   "    last DateTime,"
                                   "    tcp_flags UInt8,"
                                   "    tos UInt8,"
                                   "    src_as UInt16,"
                                   "    dst_as UInt16,"
                                   "    src_mask UInt8,"
                                   "    dst_mask UInt8,"
                                   "    ip_version UInt8,"
                                   "    flow_hash String DEFAULT ''"
                                   ") ENGINE = MergeTree()"
                                   " PARTITION BY toYYYYMMDD(first)"
                                   " ORDER BY (exporter, first, srcaddr, dstaddr, srcport, dstport, protocol)"
                                   " TTL first + INTERVAL 7 DAY"
                                   " SETTINGS index_granularity = 8192, storage_policy = 'default'";

  return ch_execute(conn, create_table_query, strlen(create_table_query));
}


static int ch_insert_binary_record(ch_conn_t **conn, uint32_t exporter, const char *table,
                                   const char *key_column, const char *data_column, const char *template_key,
                                   const uint8_t *dump, size_t dump_size) {
  ch_db_connect(conn);
  if (!*conn || !(*conn)->connected) {
    CH_LOG_ERROR("%s %d %s: Failed to connect\n", __FILE__, __LINE__, __func__);
    return -1;
  }

  swap_endianness(&exporter, sizeof(exporter));
  char exporter_str[INET_ADDRSTRLEN];
  struct in_addr addr = {.s_addr = htonl(exporter)};
  if (inet_ntop(AF_INET, &addr, exporter_str, sizeof(exporter_str)) == NULL) {
    snprintf(exporter_str, sizeof(exporter_str), "unknown");
  }

  const size_t encoded_len = 2 + (dump_size ? dump_size * 3 - 1 : 0) + 1;
  if (encoded_len > (size_t) (1 << 20)) {
    CH_LOG_ERROR("%s %d %s: dump too large (%zu bytes), refusing to build query\n", __FILE__, __LINE__, __func__,
                 encoded_len);
    return -1;
  }

  char *encoded = malloc(encoded_len);
  if (!encoded) {
    CH_LOG_ERROR("%s %d %s: Failed to allocate dump string buffer (%zu bytes)\n", __FILE__, __LINE__, __func__,
                 encoded_len);
    return -1;
  }

  char *cursor = encoded;
  *cursor++ = '{';
  for (size_t i = 0; i < dump_size; i++) {
    cursor += snprintf(cursor, 3, "%02x", dump[i]);
    if (i + 1 < dump_size) {
      *cursor++ = ',';
    }
  }
  *cursor++ = '}';
  *cursor = '\0';

  const char *format = "INSERT INTO %s (exporter,%s,%s) VALUES ('%s','%s','%s')";
  const int required = snprintf(NULL, 0, format, table, key_column, data_column, exporter_str, template_key, encoded);
  if (required < 0) {
    free(encoded);
    return -1;
  }

  const size_t query_size = (size_t) required + 1;
  char *query = malloc(query_size);
  if (!query) {
    CH_LOG_ERROR("%s %d %s: Failed to allocate query buffer (%zu bytes)\n", __FILE__, __LINE__, __func__, query_size);
    free(encoded);
    return -1;
  }

  const int written = snprintf(query, query_size, format, table, key_column, data_column, exporter_str, template_key,
                               encoded);
  if (written != required) {
    CH_LOG_ERROR("%s %d %s: snprintf failed while building query\n", __FILE__, __LINE__, __func__);
    free(encoded);
    free(query);
    return -1;
  }

  const int result = ch_execute(*conn, query, (size_t) written);
  CH_LOG_INFO("%s\n", query);
  free(encoded);
  free(query);

  if (result < 0) {
    CH_LOG_ERROR("%s %d %s: Failed to insert record into %s\n", __FILE__, __LINE__, __func__, table);
    return -1;
  }
  return 0;
}

WEAK int ch_insert_template(uint32_t exporter, char *template_key, const uint8_t *dump, const size_t dump_size) {
  static THREAD_LOCAL ch_conn_t *conn = NULL;
  return ch_insert_binary_record(&conn, exporter, "templates", "template_key", "template", template_key, dump,
                                 dump_size);
}

WEAK int ch_insert_dump(uint32_t exporter, char *template_key, const uint8_t *dump, const size_t dump_size) {
  static THREAD_LOCAL ch_conn_t *conn = NULL;
  return ch_insert_binary_record(&conn, exporter, "dumps", "template", "dump", template_key, dump, dump_size);
}


extern int g_max_flows;
extern int g_max_diff;

/**
 * @brief TODO: Document ch_insert_flows
 *
 * @param exporter TODO
 * @param flows TODO
 * @return TODO
 */
WEAK int ch_insert_flows(uint32_t exporter, netflow_v9_uint128_flowset_t *flows) {
  static THREAD_LOCAL ch_conn_t *conn = NULL;
  static THREAD_LOCAL char *query = NULL;
  static THREAD_LOCAL int offset = 0;
  static THREAD_LOCAL int query_size = 0;
  static THREAD_LOCAL size_t inserted = 0;
  static THREAD_LOCAL uint32_t last = 0;
  static THREAD_LOCAL char exporter_str[INET_ADDRSTRLEN] = {0};
  static THREAD_LOCAL uint32_t last_exporter = 0;

  if (unlikely(last == 0)) {
    last = (uint32_t) time(NULL);
  }
  uint32_t now = (uint32_t) time(NULL);

  ch_db_connect(&conn);
  if (unlikely(!conn || !conn->connected)) {
    CH_LOG_ERROR("%s %d %s: Failed to connect\n", __FILE__, __LINE__, __func__);
    return -1;
  }

  if (unlikely(!flows || flows->header.count == 0)) {
    return 0;
  }

  // Cache exporter IP string
  if (unlikely(exporter != last_exporter || exporter_str[0] == '\0')) {
    struct in_addr addr;
    addr.s_addr = htonl(exporter);
    if (inet_ntop(AF_INET, &addr, exporter_str, sizeof(exporter_str)) == NULL) {
      snprintf(exporter_str, sizeof(exporter_str), "unknown");
    }
    last_exporter = exporter;
  }

  // Build bulk insert query for better performance
  if (unlikely(query_size == 0)) {
    query_size = 1024 * 1024; // Start with 1MB for TSV
  }
  if (unlikely(query == NULL)) {
    query = calloc(query_size, 1);
    static THREAD_LOCAL bool query_registered = false;
    if (!query_registered) {
      register_ch_cleanup(NULL, &query);
      register_ch_flush_ctx(&conn, &query, &offset, &inserted);
      query_registered = true;
    }
  }
  if (unlikely(!query)) {
    CH_LOG_ERROR("%s %d %s: Failed to allocate query buffer\n", __FILE__, __LINE__, __func__);
    return -1;
  }

  if (offset == 0) {
    offset = snprintf(query, query_size,
                      "INSERT INTO flows (exporter,srcaddr,dstaddr,srcport,dstport,"
                      "protocol,input,output,dpkts,doctets,first,last,"
                      "tcp_flags,tos,src_as,dst_as,src_mask,dst_mask,ip_version) FORMAT TabSeparated\n");
  }

  for (int i = 0; i < flows->header.count; i++) {
    if (flows->records[i].dOctets == 0 || flows->records[i].dPkts == 0 ||
        flows->records[i].First > flows->records[i].Last || flows->records[i].First == 0 ||
        flows->records[i].Last == 0 ||
        (flows->records[i].prot == 6 && flows->records[i].srcport == 0 && flows->records[i].dstport == 0) ||
        (flows->records[i].prot == 17 && flows->records[i].srcport == 0 && flows->records[i].dstport == 0)
    ) {
      continue;
    }

    uint32_t dur = flows->records[i].Last - flows->records[i].First;
    if (dur > 0 && (flows->records[i].dOctets / dur > _MAX_OCTETS_TO_CONSIDER_WRONG ||
                    flows->records[i].dPkts / dur > _MAX_PACKETS_TO_CONSIDER_WRONG)) {
      continue;
    }
    if (dur == 0 && (flows->records[i].dOctets > _MAX_OCTETS_TO_CONSIDER_WRONG ||
                     flows->records[i].dPkts > _MAX_PACKETS_TO_CONSIDER_WRONG)) {
      continue;
    }

    if (unlikely(flows->records[i].srcaddr < 16777216 || flows->records[i].dstaddr < 16777216)) {
      continue;
    }

    char *srcaddr = ch_ip_uint128_to_string(flows->records[i].srcaddr, flows->records[i].ip_version);
    // Note: ch_ip_uint128_to_string uses a ring of 4 buffers, so we can call it again for dstaddr safely
    char *dstaddr = ch_ip_uint128_to_string(flows->records[i].dstaddr, flows->records[i].ip_version);

    uint32_t start_time = flows->records[i].First;
    uint32_t total_dur = dur;
    uint64_t total_pkts = flows->records[i].dPkts;
    uint64_t total_octets = flows->records[i].dOctets;

    int num_splits = (total_dur > 300) ? ((total_dur + 299) / 300) : 1;
    uint32_t remaining_dur = total_dur;
    uint64_t remaining_pkts = total_pkts;
    uint64_t remaining_octets = total_octets;
    uint32_t current_start = start_time;

    while (remaining_dur > 0 || num_splits == 1) {
      uint32_t current_dur = (remaining_dur > 300) ? 300 : remaining_dur;

      uint64_t current_pkts = (total_dur > 0) ? ((total_pkts * current_dur) / total_dur) : total_pkts;
      uint64_t current_octets = (total_dur > 0) ? ((total_octets * current_dur) / total_dur) : total_octets;

      if (current_dur == remaining_dur) {
        current_pkts = remaining_pkts;
        current_octets = remaining_octets;
      }

      uint32_t current_last = current_start + current_dur;

      /* Format directly into the reusable batch.  A row is well below 512
       * bytes, including two IPv6 strings, so reserve that much up front and
       * avoid a temporary 1 KiB stack buffer plus memcpy for every row. */
      const size_t row_reserve = 512;
      if (unlikely((size_t) query_size - (size_t) offset < row_reserve)) {
        size_t new_query_size = (size_t) query_size * 2;
        while (new_query_size - (size_t) offset < row_reserve) {
          new_query_size *= 2;
        }
        char *new_query = realloc(query, new_query_size);
        if (!new_query) {
          CH_LOG_ERROR("%s %d %s: Failed to reallocate query buffer\n", __FILE__, __LINE__, __func__);
          return -1;
        }
        query = new_query;
        query_size = (int) new_query_size;
      }

      int written =
          snprintf(query + offset, (size_t) query_size - (size_t) offset,
                   "%s\t%s\t%s\t%u\t%u\t%u\t%u\t%u\t%llu\t%llu\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\n",
                   exporter_str, srcaddr, dstaddr, flows->records[i].srcport,
                   flows->records[i].dstport, flows->records[i].prot, flows->records[i].input, flows->records[i].output,
                   (unsigned long long) current_pkts, (unsigned long long) current_octets,
                   current_start, current_last,
                   flows->records[i].tcp_flags, flows->records[i].tos, flows->records[i].src_as, flows->records[i].dst_as,
                   flows->records[i].src_mask, flows->records[i].dst_mask, flows->records[i].ip_version);

      if (unlikely(written < 0 || (size_t) written >= (size_t) query_size - (size_t) offset)) {
        CH_LOG_ERROR("%s %d %s: Failed to format flow row\n", __FILE__, __LINE__, __func__);
        return -1;
      }

      offset += written;
      inserted++;

      if (num_splits == 1) break;

      remaining_dur -= current_dur;
      remaining_pkts -= current_pkts;
      remaining_octets -= current_octets;
      current_start += current_dur;
    }
  }

  if (inserted > 0 && (inserted >= (size_t) g_max_flows || (now - last) > (uint32_t) g_max_diff)) {
    last = now;
    int result = ch_execute(conn, query, (size_t) offset);

    if (unlikely(result < 0)) {
      CH_LOG_ERROR("%s %d %s: Failed to insert %zu flows\n", __FILE__, __LINE__, __func__, inserted);
    } else {
      CH_LOG_INFO("%s %d %s: Successfully inserted %zu flows\n", __FILE__, __LINE__, __func__, inserted);
    }

    inserted = 0;
    offset = 0;
    // We don't free query here, we keep it for reuse in next batch
  }
  return 0;
}


/**
 * @brief TODO: Document ch_insert_flows2
 *
 * @param exporter TODO
 * @param flows TODO
 * @return TODO
 */
int ch_insert_flows2(uint32_t exporter, netflow_v9_uint128_flowset_t *flows) {
  return ch_insert_flows(exporter, flows);
}
