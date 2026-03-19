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
  char *data;
  size_t size;
} curl_response_t;

static size_t ch_curl_write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
  size_t realsize = size * nmemb;
  curl_response_t *mem = (curl_response_t *) userp;

  char *ptr = realloc(mem->data, mem->size + realsize + 1);
  if (!ptr) {
    CH_LOG_ERROR("Not enough memory for CURL response\n");
    return 0;
  }

  mem->data = ptr;
  memcpy(&(mem->data[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->data[mem->size] = 0;

  return realsize;
}

// Global cleanup tracking for thread locals
static uv_mutex_t cleanup_mutex;
static uv_once_t cleanup_mutex_once = UV_ONCE_INIT;

static void init_cleanup_mutex(void) {
  uv_mutex_init(&cleanup_mutex);
}

#define MAX_THREADS 128
static ch_conn_t **ch_conns_ptrs[MAX_THREADS] = {0};
static int ch_conns_count = 0;

static char **ch_queries_ptrs[MAX_THREADS] = {0};
static int ch_queries_count = 0;

void register_ch_cleanup(ch_conn_t **conn_ptr, char **query_ptr) {
  uv_once(&cleanup_mutex_once, init_cleanup_mutex);
  uv_mutex_lock(&cleanup_mutex);
  if (conn_ptr && ch_conns_count < MAX_THREADS) {
    ch_conns_ptrs[ch_conns_count++] = conn_ptr;
  }
  if (query_ptr && ch_queries_count < MAX_THREADS) {
    ch_queries_ptrs[ch_queries_count++] = query_ptr;
  }
  uv_mutex_unlock(&cleanup_mutex);
}

void ch_db_cleanup_all(void) {
  uv_mutex_lock(&cleanup_mutex);
  for (int i = 0; i < ch_conns_count; i++) {
    if (ch_conns_ptrs[i] && *ch_conns_ptrs[i]) {
      ch_disconnect(*ch_conns_ptrs[i]);
      *ch_conns_ptrs[i] = NULL;
    }
  }
  ch_conns_count = 0;

  for (int i = 0; i < ch_queries_count; i++) {
    if (ch_queries_ptrs[i] && *ch_queries_ptrs[i]) {
      free(*ch_queries_ptrs[i]);
      *ch_queries_ptrs[i] = NULL;
    }
  }
  ch_queries_count = 0;
  uv_mutex_unlock(&cleanup_mutex);
}

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

ch_conn_t *ch_connect(const char *host, uint16_t port, const char *database, const char *user, const char *password) {
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
  snprintf(test_url, sizeof(test_url), "http://%s:%u/?query=SELECT%%201", host, port);

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

  if (response.data) {
    free(response.data);
  }

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
  free(conn);
  return NULL;
}

void ch_db_connect(ch_conn_t **conn) {
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

  // Parse connection string: host:port:database:user:password
  char *conn_str_copy = strdup(conn_string);
  char *saveptr;
  char *host = strtok_r(conn_str_copy, ":", &saveptr);
  char *port_str = strtok_r(NULL, ":", &saveptr);
  char *database = strtok_r(NULL, ":", &saveptr);
  char *user = strtok_r(NULL, ":", &saveptr);
  char *password = strtok_r(NULL, "?", &saveptr);

  if (!host || !port_str) {
    CH_LOG_ERROR("Invalid CH_CONN_STRING format\n");
    free(conn_str_copy);
    EXIT_WITH_MSG(EXIT_FAILURE, "%s %d %s This should not happen...\n", __FILE__, __LINE__, __func__);
  }

  uint16_t port = atoi(port_str);
  *conn = ch_connect(host, port, database, user, password);
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
  free(conn);
}

int ch_execute(ch_conn_t *conn, const char *query) {
  if (!conn || !conn->curl)
    return -1;
  if (strlen(query) == 0)
    return -1;
  char url[512];
  snprintf(url, sizeof(url), "http://%s:%u/?database=%s", conn->host, conn->port, conn->database);

  curl_easy_setopt(conn->curl, CURLOPT_URL, url);
  curl_easy_setopt(conn->curl, CURLOPT_POSTFIELDS, query);
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
    if (response.data)
      free(response.data);
    return -1;
  }

  long http_code = 0;
  curl_easy_getinfo(conn->curl, CURLINFO_RESPONSE_CODE, &http_code);

  if (http_code != 200) {
    CH_LOG_ERROR("%s %d %s: Query failed with HTTP %ld: %s\n", __FILE__, __LINE__, __func__, http_code,
                 response.data ? response.data : "no response");
    if (response.data)
      free(response.data);
    return -1;
  }

  if (response.data)
    free(response.data);
  return 0;
}

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

  return ch_execute(conn, create_table_query);
}


int ch_insert_template(uint32_t exporter, char *template_key, const uint8_t *dump, const size_t dump_size) {
  static THREAD_LOCAL ch_conn_t *conn = NULL;

  ch_db_connect(&conn);
  if (!conn || !conn->connected) {
    CH_LOG_ERROR("%s %d %s: Failed to connect\n", __FILE__, __LINE__, __func__);
    return -1;
  }

  // Convert exporter IP to string format
  swap_endianness(&exporter, sizeof(exporter));
  char exporter_str[INET_ADDRSTRLEN];
  struct in_addr addr;
  addr.s_addr = htonl(exporter);
  if (inet_ntop(AF_INET, &addr, exporter_str, sizeof(exporter_str)) == NULL) {
    snprintf(exporter_str, sizeof(exporter_str), "unknown");
  }

  // Build dump string safely: {aa,bb,...}
  size_t needed_dump_len = 2 + (dump_size ? (dump_size * 2 + (dump_size - 1)) : 0) + 1; // {} + hex+commas + NUL
  // Put a soft cap to avoid excessive memory usage
  if (needed_dump_len > (size_t) (1 << 20)) { // >1MB string for a single row is suspicious
    CH_LOG_ERROR("%s %d %s: dump too large (%zu bytes), refusing to build query\n", __FILE__, __LINE__, __func__,
                 needed_dump_len);
    return -1;
  }
  char *str_dump = (char *) malloc(needed_dump_len);
  if (!str_dump) {
    CH_LOG_ERROR("%s %d %s: Failed to allocate dump string buffer (%zu bytes)\n", __FILE__, __LINE__, __func__,
                 needed_dump_len);
    return -1;
  }
  char *p = str_dump;
  *p++ = '{';
  for (size_t i = 0; i < dump_size; i++) {
    int n = snprintf(p, 3, "%02x", dump[i]);
    p += n;
    if (i + 1 < dump_size) {
      *p++ = ',';
    }
  }
  *p++ = '}';
  *p = '\0';

  const char *prefix = "INSERT INTO templates (exporter,template_key,template) VALUES ";
  size_t query_cap = strlen(prefix) + strlen(exporter_str) + strlen(template_key) + strlen(str_dump) + 32;
  char *query = (char *) malloc(query_cap);
  if (!query) {
    CH_LOG_ERROR("%s %d %s: Failed to allocate query buffer (%zu bytes)\n", __FILE__, __LINE__, __func__, query_cap);
    free(str_dump);
    return -1;
  }
  int written = snprintf(query, query_cap, "%s('%s','%s','%s')", prefix, exporter_str, template_key, str_dump);
  if (written < 0 || (size_t) written >= query_cap) {
    CH_LOG_ERROR("%s %d %s: snprintf truncated while building query\n", __FILE__, __LINE__, __func__);
    free(str_dump);
    free(query);
    return -1;
  }

  int result = ch_execute(conn, query);
  CH_LOG_INFO("%s\n", query);

  free(str_dump);
  free(query);

  if (result < 0) {
    CH_LOG_ERROR("%s %d %s: Failed to insert dump\n", __FILE__, __LINE__, __func__);
    return -1;
  }

  CH_LOG_INFO("%s %d %s: Successfully inserted dump for template %s\n", __FILE__, __LINE__, __func__, template_key);
  return 0;
}

int ch_insert_dump(uint32_t exporter, char *template_key, const uint8_t *dump, const size_t dump_size) {
  static THREAD_LOCAL ch_conn_t *conn = NULL;

  ch_db_connect(&conn);
  if (!conn || !conn->connected) {
    CH_LOG_ERROR("%s %d %s: Failed to connect\n", __FILE__, __LINE__, __func__);
    return -1;
  }

  // Convert exporter IP to string format
  swap_endianness(&exporter, sizeof(exporter));
  char exporter_str[INET_ADDRSTRLEN];
  struct in_addr addr;
  addr.s_addr = htonl(exporter);
  if (inet_ntop(AF_INET, &addr, exporter_str, sizeof(exporter_str)) == NULL) {
    snprintf(exporter_str, sizeof(exporter_str), "unknown");
  }

  // Build dump string safely: {aa,bb,...}
  size_t needed_dump_len = 2 + (dump_size ? (dump_size * 2 + (dump_size - 1)) : 0) + 1; // {} + hex+commas + NUL
  if (needed_dump_len > (size_t) (1 << 20)) {
    CH_LOG_ERROR("%s %d %s: dump too large (%zu bytes), refusing to build query\n", __FILE__, __LINE__, __func__,
                 needed_dump_len);
    return -1;
  }
  char *str_dump = (char *) malloc(needed_dump_len);
  if (!str_dump) {
    CH_LOG_ERROR("%s %d %s: Failed to allocate dump string buffer (%zu bytes)\n", __FILE__, __LINE__, __func__,
                 needed_dump_len);
    return -1;
  }
  char *p = str_dump;
  *p++ = '{';
  for (size_t i = 0; i < dump_size; i++) {
    int n = snprintf(p, 3, "%02x", dump[i]);
    p += n;
    if (i + 1 < dump_size) {
      *p++ = ',';
    }
  }
  *p++ = '}';
  *p = '\0';

  const char *prefix = "INSERT INTO dumps (exporter,template,dump) VALUES ";
  size_t query_cap = strlen(prefix) + strlen(exporter_str) + strlen(template_key) + strlen(str_dump) + 32;
  char *query = (char *) malloc(query_cap);
  if (!query) {
    CH_LOG_ERROR("%s %d %s: Failed to allocate query buffer (%zu bytes)\n", __FILE__, __LINE__, __func__, query_cap);
    free(str_dump);
    return -1;
  }
  int written = snprintf(query, query_cap, "%s('%s','%s','%s')", prefix, exporter_str, template_key, str_dump);
  if (written < 0 || (size_t) written >= query_cap) {
    CH_LOG_ERROR("%s %d %s: snprintf truncated while building query\n", __FILE__, __LINE__, __func__);
    free(str_dump);
    free(query);
    return -1;
  }

  int result = ch_execute(conn, query);
  CH_LOG_INFO("%s\n", query);

  free(str_dump);
  free(query);

  if (result < 0) {
    CH_LOG_ERROR("%s %d %s: Failed to insert dump\n", __FILE__, __LINE__, __func__);
    return -1;
  }

  CH_LOG_INFO("%s %d %s: Successfully inserted dump for dump %s\n", __FILE__, __LINE__, __func__, template_key);
  return 0;
}


extern int g_max_flows;
extern int g_max_diff;

int ch_insert_flows(uint32_t exporter, netflow_v9_uint128_flowset_t *flows) {
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

    if (unlikely(flows->records[i].srcaddr == 0 || flows->records[i].dstaddr == 0)) {
      continue;
    }

    char *srcaddr = ch_ip_uint128_to_string(flows->records[i].srcaddr, flows->records[i].ip_version);
    // Note: ch_ip_uint128_to_string uses a ring of 4 buffers, so we can call it again for dstaddr safely
    char *dstaddr = ch_ip_uint128_to_string(flows->records[i].dstaddr, flows->records[i].ip_version);

    char value_str[1024];
    int written =
        snprintf(value_str, sizeof(value_str),
                 "%s\t%s\t%s\t%u\t%u\t%u\t%u\t%u\t%llu\t%llu\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\n",
                 exporter_str, srcaddr, dstaddr, flows->records[i].srcport,
                 flows->records[i].dstport, flows->records[i].prot, flows->records[i].input, flows->records[i].output,
                 (unsigned long long) flows->records[i].dPkts, (unsigned long long) flows->records[i].dOctets,
                 flows->records[i].First, flows->records[i].Last,
                 flows->records[i].tcp_flags, flows->records[i].tos, flows->records[i].src_as, flows->records[i].dst_as,
                 flows->records[i].src_mask, flows->records[i].dst_mask, flows->records[i].ip_version);

    if (unlikely(offset + written + 1 >= query_size)) {
      size_t new_query_size = query_size * 2;
      char *new_query = realloc(query, new_query_size);
      if (!new_query) {
        CH_LOG_ERROR("%s %d %s: Failed to reallocate query buffer\n", __FILE__, __LINE__, __func__);
        return -1;
      }
      query = new_query;
      query_size = (int) new_query_size;
    }

    memcpy(query + offset, value_str, written);
    offset += written;
    inserted++;
  }

  if (inserted > 0 && (inserted >= (size_t) g_max_flows || (now - last) > (uint32_t) g_max_diff)) {
    last = now;
    int result = ch_execute(conn, query);

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


int ch_insert_flows2(uint32_t exporter, netflow_v9_uint128_flowset_t *flows) {
  return ch_insert_flows(exporter, flows);
}
