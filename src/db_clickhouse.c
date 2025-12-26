//
// Created for cnetflow - ClickHouse HTTP Interface Client
//

#include "db_clickhouse.h"
#include "log.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <curl/curl.h>
#include "arena.h"

#if defined(__STDC_NO_THREADS__) || !defined(__STDC_VERSION__) || __STDC_VERSION__ < 201112L
#if defined(__GNUC__) || defined(__clang__)
#define THREAD_LOCAL __thread
#else
#define THREAD_LOCAL
#endif
#else
#include <threads.h>
#define THREAD_LOCAL thread_local
#endif

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
    curl_response_t *mem = (curl_response_t *)userp;

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

char *ch_ip_uint128_to_string(uint128_t value, uint8_t ip_version) {
    static THREAD_LOCAL char ret_string[INET6_ADDRSTRLEN] = {0};

    if (ip_version == 4) {
        struct in_addr addr;
        uint32_t ip_host = (uint32_t)value;
        addr.s_addr = htonl(ip_host);
        if (inet_ntop(AF_INET, &addr, ret_string, sizeof(ret_string)) == NULL) {
            snprintf(ret_string, sizeof(ret_string), "unknown");
        }
    } else if (ip_version == 6) {
        struct in6_addr addr;
        memcpy(&addr, &value, 16);
        if (inet_ntop(AF_INET6, &addr, ret_string, sizeof(ret_string)) == NULL) {
            snprintf(ret_string, sizeof(ret_string), "unknown");
        }
    } else {
        snprintf(ret_string, sizeof(ret_string), "unknown");
    }
    return ret_string;
}

ch_conn_t *ch_connect(const char *host, uint16_t port, const char *database,
                      const char *user, const char *password) {
    ch_conn_t *conn = (ch_conn_t *)calloc(1, sizeof(ch_conn_t));
    if (!conn) {
        CH_LOG_ERROR("%s %d %s: Failed to allocate connection structure\n",
                     __FILE__, __LINE__, __func__);
        return NULL;
    }

    conn->host = strdup(host);
    conn->port = port;
    conn->database = strdup(database ? database : "default");
    conn->user = strdup(user ? user : "default");
    conn->password = strdup(password ? password : "");
    conn->connected = false;

    // Initialize CURL
    conn->curl = curl_easy_init();
    if (!conn->curl) {
        CH_LOG_ERROR("%s %d %s: Failed to initialize CURL\n",
                     __FILE__, __LINE__, __func__);
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
    curl_easy_setopt(conn->curl, CURLOPT_WRITEDATA, (void *)&response);

    CURLcode res = curl_easy_perform(conn->curl);

    if (response.data) {
        free(response.data);
    }

    if (res != CURLE_OK) {
        CH_LOG_ERROR("%s %d %s: ClickHouse connection test failed: %s\n",
                     __FILE__, __LINE__, __func__, curl_easy_strerror(res));
        goto error;
    }

    long http_code = 0;
    curl_easy_getinfo(conn->curl, CURLINFO_RESPONSE_CODE, &http_code);
    if (http_code != 200) {
        CH_LOG_ERROR("%s %d %s: ClickHouse returned HTTP %ld\n",
                     __FILE__, __LINE__, __func__, http_code);
        goto error;
    }

    conn->connected = true;
    CH_LOG_INFO("Connected to ClickHouse HTTP interface at %s:%d\n", host, port);
    return conn;

error:
    if (conn->curl) curl_easy_cleanup(conn->curl);
    if (conn->host) free(conn->host);
    if (conn->database) free(conn->database);
    if (conn->user) free(conn->user);
    if (conn->password) free(conn->password);
    free(conn);
    return NULL;
}

void ch_db_connect(ch_conn_t **conn) {
    if (*conn != NULL && (*conn)->connected) {
        return;
    }

    const char *conn_string = getenv("CH_CONN_STRING");
    if (!conn_string) {
        CH_LOG_ERROR("Environment variable CH_CONN_STRING is not set.\n");
        CH_LOG_ERROR("Format: host:port:database:user:password\n");
        EXIT_WITH_MSG(EXIT_FAILURE, "%s %d %s This should not happen...\n", __FILE__, __LINE__, __func__);
    }

    // Parse connection string: host:port:database:user:password
    char *conn_str_copy = strdup(conn_string);
    char *host = strtok(conn_str_copy, ":");
    char *port_str = strtok(NULL, ":");
    char *database = strtok(NULL, ":");
    char *user = strtok(NULL, ":");
    char *password = strtok(NULL, "?");

    if (!host || !port_str) {
        CH_LOG_ERROR("Invalid CH_CONN_STRING format\n");
        free(conn_str_copy);
        EXIT_WITH_MSG(EXIT_FAILURE, "%s %d %s This should not happen...\n", __FILE__, __LINE__, __func__);
    }

    uint16_t port = atoi(port_str);
    *conn = ch_connect(host, port, database, user, password);
    free(conn_str_copy);

    if (!*conn) {
        CH_LOG_ERROR("Failed to connect to ClickHouse\n");
        EXIT_WITH_MSG(EXIT_FAILURE, "%s %d %s This should not happen...\n", __FILE__, __LINE__, __func__);
    }
}

void ch_disconnect(ch_conn_t *conn) {
    if (!conn) return;

    if (conn->curl) {
        curl_easy_cleanup(conn->curl);
    }
    if (conn->host) free(conn->host);
    if (conn->database) free(conn->database);
    if (conn->user) free(conn->user);
    if (conn->password) free(conn->password);
    free(conn);
}

int ch_execute(ch_conn_t *conn, const char *query) {
    if (!conn || !conn->curl) return -1;

    char url[512];
    snprintf(url, sizeof(url), "http://%s:%u/?database=%s", conn->host, conn->port,conn->database);

    curl_easy_setopt(conn->curl, CURLOPT_URL, url);
    curl_easy_setopt(conn->curl, CURLOPT_POSTFIELDS, query);
    curl_easy_setopt(conn->curl, CURLOPT_TIMEOUT, 10L);

    if (conn->user && conn->user[0] != '\0') {
        //char userpwd[256];
        snprintf(conn->userpwd, sizeof(conn->userpwd), "%s:%s", conn->user, conn->password ? conn->password : "");
        curl_easy_setopt(conn->curl, CURLOPT_USERPWD, conn->userpwd);
        curl_easy_setopt(conn->curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
    }

    curl_response_t response = {0};
    curl_easy_setopt(conn->curl, CURLOPT_WRITEFUNCTION, ch_curl_write_callback);
    curl_easy_setopt(conn->curl, CURLOPT_WRITEDATA, (void *)&response);

    CURLcode res = curl_easy_perform(conn->curl);

    if (res != CURLE_OK) {
        CH_LOG_ERROR("%s %d %s: Query failed: %s\n",
                     __FILE__, __LINE__, __func__, curl_easy_strerror(res));
        if (response.data) free(response.data);
        return -1;
    }

    long http_code = 0;
    curl_easy_getinfo(conn->curl, CURLINFO_RESPONSE_CODE, &http_code);

    if (http_code != 200) {
        CH_LOG_ERROR("%s %d %s: Query failed with HTTP %ld: %s\n",
                     __FILE__, __LINE__, __func__, http_code,
                     response.data ? response.data : "no response");
        if (response.data) free(response.data);
        return -1;
    }

    if (response.data) free(response.data);
    return 0;
}

int ch_create_flows_table(ch_conn_t *conn) {
    const char *create_table_query =
        "CREATE TABLE IF NOT EXISTS flows ("
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



int ch_insert_template(uint32_t exporter, char * template_key,const uint8_t * dump, const size_t dump_size) {
  static THREAD_LOCAL ch_conn_t *conn = NULL;

  ch_db_connect(&conn);
  if (!conn || !conn->connected) {
    CH_LOG_ERROR("%s %d %s: Failed to connect\n",
                 __FILE__, __LINE__, __func__);
    return -1;
  }
  // Build bulk insert query for better performance

  char query[65536] = {0} ;
  char pre_query[250] = {0};
  if (!query) {
    CH_LOG_ERROR("%s %d %s: Failed to allocate query buffer\n",
                 __FILE__, __LINE__, __func__);
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

  int offset = snprintf(pre_query, sizeof(pre_query),
                        "INSERT INTO templates (exporter,template_key,template) VALUES ");
  char str_dump[10000] = {0};
  int dump_offset = 0;
  dump_offset = snprintf(str_dump, 2,"{");
  for (size_t i = 0; i < dump_size; i++) {
    uint8_t pkt = *(dump+i);
    dump_offset += snprintf(str_dump+dump_offset, 5,"%02x", pkt);
    if (i < dump_size - 1) {
      dump_offset +=snprintf(str_dump+dump_offset, 3,",");
    }
  }
  dump_offset +=snprintf(str_dump+dump_offset, 2,"}");
  char value_str[1024];
  int written = snprintf((char*)query, sizeof(query) + sizeof(pre_query),
                         "%s ('%s','%s','%s')",
                         pre_query,
                         exporter_str,
                         template_key,
                         str_dump
  );


  int result = ch_execute(conn, query);
  CH_LOG_INFO("%s\n", query);


  if (result < 0) {
    CH_LOG_ERROR("%s %d %s: Failed to insert dump\n", __FILE__, __LINE__, __func__);
    return -1;
  }

  CH_LOG_INFO("%s %d %s: Successfully inserted dump for template %s\n", __FILE__, __LINE__, __func__, template_key);

  return 0;
}

int ch_insert_dump(uint32_t exporter, char * template_key,const uint8_t * dump, const size_t dump_size) {
  static THREAD_LOCAL ch_conn_t *conn = NULL;

  ch_db_connect(&conn);
  if (!conn || !conn->connected) {
    CH_LOG_ERROR("%s %d %s: Failed to connect\n",
                 __FILE__, __LINE__, __func__);
    return -1;
  }
  // Build bulk insert query for better performance
  size_t query_size = 65536; // Start with 64KB
  char *query = malloc(query_size);
  if (!query) {
    CH_LOG_ERROR("%s %d %s: Failed to allocate query buffer\n",
                 __FILE__, __LINE__, __func__);
    return -1;
  }
  // Convert exporter IP to string format
  swap_endianness(&exporter, sizeof(exporter));
  char exporter_str[INET_ADDRSTRLEN];
  struct in_addr addr;
  //addr.s_addr = htonl(exporter);
  if (inet_ntop(AF_INET, &addr, exporter_str, sizeof(exporter_str)) == NULL) {
    snprintf(exporter_str, sizeof(exporter_str), "unknown");
  }

  int offset = snprintf(query, query_size,
                        "INSERT INTO dumps (exporter,template,dump) VALUES ");
  char str_dump[10000] = {0};
  int dump_offset = 0;
  dump_offset = snprintf(str_dump, 2,"{");
  for (size_t i = 0; i < dump_size; i++) {
    uint8_t pkt = *(dump+i);
    dump_offset += snprintf(str_dump+dump_offset, 5,"%02x", pkt);
    if (i < dump_size - 1) {
      dump_offset +=snprintf(str_dump+dump_offset, 3,",");
    }
  }
  dump_offset +=snprintf(str_dump+dump_offset, 2,"}");
  char value_str[1024];
  int written = snprintf(value_str, sizeof(value_str),
                         "('%s','%s','%s')",
                         exporter_str,
                         template_key,
                         str_dump
  );


  int result = ch_execute(conn, query);
  CH_LOG_INFO("%s\n", query);
  free(query);

  if (result < 0) {
    CH_LOG_ERROR("%s %d %s: Failed to insert dump\n", __FILE__, __LINE__, __func__);
    return -1;
  }

  CH_LOG_INFO("%s %d %s: Successfully inserted dump for template %s\n", __FILE__, __LINE__, __func__, template_key);

  return 0;
}

int ch_insert_flows(uint32_t exporter, netflow_v9_uint128_flowset_t *flows) {
    static THREAD_LOCAL ch_conn_t *conn = NULL;

    ch_db_connect(&conn);
    if (!conn || !conn->connected) {
        CH_LOG_ERROR("%s %d %s: Failed to connect\n",
                     __FILE__, __LINE__, __func__);
        return -1;
    }

    if (!flows || flows->header.count == 0) {
        return 0;
    }

    // Build bulk insert query for better performance
    size_t query_size = 65536; // Start with 64KB
    char *query = malloc(query_size);
    if (!query) {
        CH_LOG_ERROR("%s %d %s: Failed to allocate query buffer\n",
                     __FILE__, __LINE__, __func__);
        return -1;
    }

    int offset = snprintf(query, query_size,
        "INSERT INTO flows (exporter,srcaddr,dstaddr,srcport,dstport,"
        "protocol,input,output,dpkts,doctets,first,last,"
        "tcp_flags,tos,src_as,dst_as,src_mask,dst_mask,ip_version) VALUES ");

    int inserted = 0;
    for (int i = 0; i < flows->header.count; i++) {
        if (flows->records[i].dOctets == 0 || flows->records[i].dPkts == 0 || flows->records[i].First > flows->records[i].Last || flows->records[i].First == 0 || flows->records[i].Last == 0 ||
          flows->records[i].dPkts >= 50000 || flows->records[i].dOctets >= 50000000 ) {

            continue;
        }

        // Convert exporter IP to string format
        char exporter_str[INET_ADDRSTRLEN];
        struct in_addr addr;
        addr.s_addr = htonl(exporter);
        if (inet_ntop(AF_INET, &addr, exporter_str, sizeof(exporter_str)) == NULL) {
            snprintf(exporter_str, sizeof(exporter_str), "unknown");
        }

        char srcaddr[250];
        char dstaddr[250];

        char *nfaddr = ch_ip_uint128_to_string(flows->records[i].srcaddr,
                                                flows->records[i].ip_version);
        memccpy(srcaddr, nfaddr, '\0', 250);
        nfaddr = ch_ip_uint128_to_string(flows->records[i].dstaddr,
                                                flows->records[i].ip_version);
        memccpy(dstaddr, nfaddr, '\0', 250);
        char value_str[1024];
        int written = snprintf(value_str, sizeof(value_str),
            "%s('%s','%s','%s',%u,%u,%u,%u,%u,%lu,%lu,toDateTime(%u),toDateTime(%u),%u,%u,%u,%u,%u,%u,%u)",
            inserted > 0 ? "," : "",
            exporter_str,
            srcaddr,
            dstaddr,
            flows->records[i].srcport,
            flows->records[i].dstport,
            flows->records[i].prot,
            flows->records[i].input,
            flows->records[i].output,
            flows->records[i].dPkts,
            flows->records[i].dOctets,
            flows->records[i].First,
            flows->records[i].Last,
            flows->records[i].tcp_flags,
            flows->records[i].tos,
            flows->records[i].src_as,
            flows->records[i].dst_as,
            flows->records[i].src_mask,
            flows->records[i].dst_mask,
            flows->records[i].ip_version
        );

        // Check if we need to resize the buffer
        if (offset + written + 1 >= query_size) {
            query_size *= 2;
            char *new_query = realloc(query, query_size);
            if (!new_query) {
                CH_LOG_ERROR("%s %d %s: Failed to reallocate query buffer\n",
                             __FILE__, __LINE__, __func__);
                free(query);
                return -1;
            }
            query = new_query;
        }

        memcpy(query + offset, value_str, written);
        offset += written;
        inserted++;
    }

    if (inserted == 0) {
        free(query);
        return 0;
    }

    query[offset] = '\0';

    int result = ch_execute(conn, query);
    CH_LOG_INFO("%s\n", query);
    free(query);

    if (result < 0) {
        CH_LOG_ERROR("%s %d %s: Failed to insert flows\n",
                     __FILE__, __LINE__, __func__);
        return -1;
    }

    CH_LOG_INFO("%s %d %s: Successfully inserted %d of %d flows\n",
                __FILE__, __LINE__, __func__, inserted, flows->header.count);

    return 0;
}
