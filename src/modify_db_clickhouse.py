import re
import sys

with open('db_clickhouse.c', 'r') as f:
    content = f.read()

# 1. Add background thread structs and init
thread_code = """
// Background thread for ClickHouse insertions
typedef struct ch_job {
  char *query;
  size_t length;
  struct ch_job *next;
} ch_job_t;

static ch_job_t *ch_job_head = NULL;
static ch_job_t *ch_job_tail = NULL;
static uv_mutex_t ch_job_mutex;
static uv_cond_t ch_job_cond;
static uv_thread_t ch_worker_thread;
static volatile int ch_worker_running = 0;
static uv_once_t ch_worker_once = UV_ONCE_INIT;

static void ch_background_worker(void *arg) {
  ch_conn_t *conn = NULL;
  while (ch_worker_running) {
    uv_mutex_lock(&ch_job_mutex);
    while (ch_job_head == NULL && ch_worker_running) {
      uv_cond_wait(&ch_job_cond, &ch_job_mutex);
    }
    
    if (!ch_worker_running && ch_job_head == NULL) {
      uv_mutex_unlock(&ch_job_mutex);
      break;
    }
    
    ch_job_t *job = ch_job_head;
    if (job != NULL) {
      ch_job_head = job->next;
      if (ch_job_head == NULL) {
        ch_job_tail = NULL;
      }
    }
    uv_mutex_unlock(&ch_job_mutex);
    
    if (job != NULL) {
      if (!conn || !conn->connected) {
        ch_db_connect(&conn);
      }
      if (conn && conn->connected) {
        ch_execute(conn, job->query, job->length);
      }
      free(job->query);
      free(job);
    }
  }
  if (conn) {
    ch_disconnect(conn);
  }
}

static void init_ch_worker(void) {
  uv_mutex_init(&ch_job_mutex);
  uv_cond_init(&ch_job_cond);
  ch_worker_running = 1;
  uv_thread_create(&ch_worker_thread, ch_background_worker, NULL);
}

"""
content = content.replace('// External arena from collector\nextern arena_struct_t *arena_collector;\n', 
                          '// External arena from collector\nextern arena_struct_t *arena_collector;\n' + thread_code)

# 2. Add fast append functions before ch_insert_flows
fast_append_code = """
static inline int fast_append_uint64(char *buf, uint64_t val) {
  char temp[24];
  int len = 0;
  if (val == 0) {
    buf[0] = '0';
    return 1;
  }
  while (val > 0) {
    temp[len++] = '0' + (val % 10);
    val /= 10;
  }
  for (int i = 0; i < len; i++) {
    buf[i] = temp[len - 1 - i];
  }
  return len;
}

static inline int fast_append_uint32(char *buf, uint32_t val) {
  char temp[12];
  int len = 0;
  if (val == 0) {
    buf[0] = '0';
    return 1;
  }
  while (val > 0) {
    temp[len++] = '0' + (val % 10);
    val /= 10;
  }
  for (int i = 0; i < len; i++) {
    buf[i] = temp[len - 1 - i];
  }
  return len;
}

static inline int fast_append_str(char *buf, const char *str) {
  int len = 0;
  while (*str) {
    buf[len++] = *str++;
  }
  return len;
}

"""
content = content.replace('WEAK int ch_insert_flows(uint32_t exporter, netflow_v9_uint128_flowset_t *flows) {',
                          fast_append_code + 'WEAK int ch_insert_flows(uint32_t exporter, netflow_v9_uint128_flowset_t *flows) {')


# 3. Modify ch_insert_flows
# Remove sync connect
sync_conn_code = """  ch_db_connect(&conn);
  if (unlikely(!conn || !conn->connected)) {
    CH_LOG_ERROR("%s %d %s: Failed to connect\\n", __FILE__, __LINE__, __func__);
    return -1;
  }"""
content = content.replace(sync_conn_code, "  // Database connection is handled by the background thread")

# Remove static conn
content = content.replace('static THREAD_LOCAL ch_conn_t *conn = NULL;', '// static THREAD_LOCAL ch_conn_t *conn = NULL;')

# Replace snprintf with fast append
snprintf_code = """    char value_str[1024];
    int written =
        snprintf(value_str, sizeof(value_str),
                 "%s\\t%s\\t%s\\t%u\\t%u\\t%u\\t%u\\t%u\\t%llu\\t%llu\\t%u\\t%u\\t%u\\t%u\\t%u\\t%u\\t%u\\t%u\\t%u\\n",
                 exporter_str, srcaddr, dstaddr, flows->records[i].srcport,
                 flows->records[i].dstport, flows->records[i].prot, flows->records[i].input, flows->records[i].output,
                 (unsigned long long) flows->records[i].dPkts, (unsigned long long) flows->records[i].dOctets,
                 flows->records[i].First, flows->records[i].Last,
                 flows->records[i].tcp_flags, flows->records[i].tos, flows->records[i].src_as, flows->records[i].dst_as,
                 flows->records[i].src_mask, flows->records[i].dst_mask, flows->records[i].ip_version);"""

fast_append_impl = """    char value_str[1024];
    int written = 0;
    written += fast_append_str(value_str + written, exporter_str);
    value_str[written++] = '\\t';
    written += fast_append_str(value_str + written, srcaddr);
    value_str[written++] = '\\t';
    written += fast_append_str(value_str + written, dstaddr);
    value_str[written++] = '\\t';
    written += fast_append_uint32(value_str + written, flows->records[i].srcport);
    value_str[written++] = '\\t';
    written += fast_append_uint32(value_str + written, flows->records[i].dstport);
    value_str[written++] = '\\t';
    written += fast_append_uint32(value_str + written, flows->records[i].prot);
    value_str[written++] = '\\t';
    written += fast_append_uint32(value_str + written, flows->records[i].input);
    value_str[written++] = '\\t';
    written += fast_append_uint32(value_str + written, flows->records[i].output);
    value_str[written++] = '\\t';
    written += fast_append_uint64(value_str + written, flows->records[i].dPkts);
    value_str[written++] = '\\t';
    written += fast_append_uint64(value_str + written, flows->records[i].dOctets);
    value_str[written++] = '\\t';
    written += fast_append_uint32(value_str + written, flows->records[i].First);
    value_str[written++] = '\\t';
    written += fast_append_uint32(value_str + written, flows->records[i].Last);
    value_str[written++] = '\\t';
    written += fast_append_uint32(value_str + written, flows->records[i].tcp_flags);
    value_str[written++] = '\\t';
    written += fast_append_uint32(value_str + written, flows->records[i].tos);
    value_str[written++] = '\\t';
    written += fast_append_uint32(value_str + written, flows->records[i].src_as);
    value_str[written++] = '\\t';
    written += fast_append_uint32(value_str + written, flows->records[i].dst_as);
    value_str[written++] = '\\t';
    written += fast_append_uint32(value_str + written, flows->records[i].src_mask);
    value_str[written++] = '\\t';
    written += fast_append_uint32(value_str + written, flows->records[i].dst_mask);
    value_str[written++] = '\\t';
    written += fast_append_uint32(value_str + written, flows->records[i].ip_version);
    value_str[written++] = '\\n';"""

content = content.replace(snprintf_code, fast_append_impl)

# Replace ch_execute logic with queueing
execute_code = """  if (inserted > 0 && (inserted >= (size_t) g_max_flows || (now - last) > (uint32_t) g_max_diff)) {
    last = now;
    int result = ch_execute(conn, query, (size_t) offset);

    if (unlikely(result < 0)) {
      CH_LOG_ERROR("%s %d %s: Failed to insert %zu flows\\n", __FILE__, __LINE__, __func__, inserted);
    } else {
      CH_LOG_INFO("%s %d %s: Successfully inserted %zu flows\\n", __FILE__, __LINE__, __func__, inserted);
    }

    inserted = 0;
    offset = 0;
    // We don't free query here, we keep it for reuse in next batch
  }"""

queue_code = """  if (inserted > 0 && (inserted >= (size_t) g_max_flows || (now - last) > (uint32_t) g_max_diff)) {
    last = now;
    uv_once(&ch_worker_once, init_ch_worker);
    
    char *job_query = malloc(offset + 1);
    if (job_query) {
      memcpy(job_query, query, offset);
      job_query[offset] = '\\0';
      
      ch_job_t *job = malloc(sizeof(ch_job_t));
      if (job) {
        job->query = job_query;
        job->length = offset;
        job->next = NULL;
        
        uv_mutex_lock(&ch_job_mutex);
        if (ch_job_tail == NULL) {
          ch_job_head = job;
          ch_job_tail = job;
        } else {
          ch_job_tail->next = job;
          ch_job_tail = job;
        }
        uv_cond_signal(&ch_job_cond);
        uv_mutex_unlock(&ch_job_mutex);
      } else {
        free(job_query);
      }
    }

    inserted = 0;
    offset = 0;
  }"""

content = content.replace(execute_code, queue_code)

with open('db_clickhouse.c', 'w') as f:
    f.write(content)

print("db_clickhouse.c modified successfully.")

