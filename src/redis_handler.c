#include "redis_handler.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "log.h"
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

// Thread-local connection
static THREAD_LOCAL redisContext *redis_conn = NULL;

// Global configuration
static char g_redis_host[256] = "127.0.0.1";
static int g_redis_port = 6379;
static char g_redis_user[128] = {0};
static char g_redis_password[128] = {0};

// Template cache structure
typedef struct template_cache_entry {
  char *key;
  size_t key_len;
  void *data;
  size_t data_len;
  time_t expiry;
  struct template_cache_entry *next;
} template_cache_entry_t;

#define TEMPLATE_CACHE_SIZE 256
#define TEMPLATE_CACHE_EXPIRY 300 // 5 minutes

static THREAD_LOCAL template_cache_entry_t *g_template_cache[TEMPLATE_CACHE_SIZE] = {NULL};

static unsigned int template_cache_hash(const char *key, size_t len) {
  const uint32_t FNV_OFFSET_BASIS = 2166136261u;
  const uint32_t FNV_PRIME = 16777619u;
  uint32_t hash = FNV_OFFSET_BASIS;
  const unsigned char *bytes = (const unsigned char *) key;

  for (size_t i = 0; i < len; i++) {
    hash ^= bytes[i];
    hash *= FNV_PRIME;
  }
  return hash % TEMPLATE_CACHE_SIZE;
}

static void clear_template_cache(void) {
  for (int i = 0; i < TEMPLATE_CACHE_SIZE; i++) {
    template_cache_entry_t *entry = g_template_cache[i];
    while (entry) {
      template_cache_entry_t *next = entry->next;
      free(entry->key);
      free(entry->data);
      free(entry);
      entry = next;
    }
    g_template_cache[i] = NULL;
  }
}

int init_redis(const char *hostname, int port, const char *user, const char *password) {
  // Store configuration for lazy connection by threads
  if (hostname) {
    strncpy(g_redis_host, hostname, sizeof(g_redis_host) - 1);
  }
  g_redis_port = port;

  if (user) {
    strncpy(g_redis_user, user, sizeof(g_redis_user) - 1);
  } else {
    g_redis_user[0] = '\0';
  }

  if (password) {
    strncpy(g_redis_password, password, sizeof(g_redis_password) - 1);
  } else {
    g_redis_password[0] = '\0';
  }

  return 0;
}

static int connect_thread_local_redis(void) {
  if (redis_conn != NULL) {
    redisFree(redis_conn);
    redis_conn = NULL;
  }

  struct timeval timeout = {1, 500000}; // 1.5 seconds

  // Use globals
  const char *hostname = g_redis_host;
  int port = g_redis_port;
  const char *user = g_redis_user[0] ? g_redis_user : NULL;
  const char *password = g_redis_password[0] ? g_redis_password : NULL;

  redis_conn = (hostname && hostname[0] == '/') ? redisConnectUnixWithTimeout(hostname, timeout)
                                                : redisConnectWithTimeout(hostname, port, timeout);

  if (redis_conn == NULL || redis_conn->err) {
    if (redis_conn) {
      LOG_ERROR("Redis connection error: %s\n", redis_conn->errstr);
      redisFree(redis_conn);
      redis_conn = NULL;
    } else {
      LOG_ERROR("Connection error: can't allocate redis context\n");
    }
    return -1;
  }

  if (user && password) {
    // ACL style: AUTH user password
    redisReply *reply = redisCommand(redis_conn, "AUTH %s %s", user, password);
    if (reply == NULL || reply->type == REDIS_REPLY_ERROR) {
      LOG_ERROR("Redis authentication failed (user+pass): %s\n", reply ? reply->str : redis_conn->errstr);
      if (reply)
        freeReplyObject(reply);
      redisFree(redis_conn);
      redis_conn = NULL;
      return -1;
    }
    freeReplyObject(reply);
  } else if (password) {
    // Legacy style: AUTH password
    redisReply *reply = redisCommand(redis_conn, "AUTH %s", password);
    if (reply == NULL || reply->type == REDIS_REPLY_ERROR) {
      LOG_ERROR("Redis authentication failed (pass only): %s\n", reply ? reply->str : redis_conn->errstr);
      if (reply)
        freeReplyObject(reply);
      redisFree(redis_conn);
      redis_conn = NULL;
      return -1;
    }
    freeReplyObject(reply);
  }

  if (hostname && hostname[0] == '/') {
    LOG_INFO("Connected to Redis via Unix socket %s (Thread Local)\n", hostname);
  } else {
    LOG_INFO("Connected to Redis at %s:%d (Thread Local)\n", hostname, port);
  }
  return 0;
}

redisContext *get_redis_conn(void) {
  if (!redis_conn) {
    if (connect_thread_local_redis() != 0) {
      return NULL;
    }
  }
  return redis_conn;
}

void close_redis(void) {
  if (redis_conn != NULL) {
    redisFree(redis_conn);
    redis_conn = NULL;
  }
  clear_template_cache();
}

void *redis_get_template(const char *key, size_t key_len, size_t *out_len) {
  time_t now = time(NULL);
  unsigned int h = template_cache_hash(key, key_len);

  // Check thread-local cache first
  template_cache_entry_t *entry = g_template_cache[h];
  while (entry) {
    if (entry->key_len == key_len && memcmp(entry->key, key, key_len) == 0) {
      if (now < entry->expiry) {
        // Cache hit and not expired
        void *copy = malloc(entry->data_len);
        if (copy) {
          memcpy(copy, entry->data, entry->data_len);
          if (out_len)
            *out_len = entry->data_len;
          return copy;
        }
      }
      break; // Found but expired, or malloc failed
    }
    entry = entry->next;
  }

  if (!redis_conn) {
    if (connect_thread_local_redis() != 0) {
      return NULL;
    }
  }

  redisReply *reply = redisCommand(redis_conn, "GET %b", key, key_len);
  if (!reply) {
    LOG_ERROR("Redis error: %s\n", redis_conn->errstr);
    if (redis_conn->err) {
      redisFree(redis_conn);
      redis_conn = NULL;
    }
    return NULL;
  }

  void *result = NULL;
  if (reply->type == REDIS_REPLY_STRING) {
    result = malloc(reply->len);
    if (result) {
      memcpy(result, reply->str, reply->len);
      if (out_len)
        *out_len = reply->len;

      // Update local cache
      entry = g_template_cache[h];
      while (entry) {
        if (entry->key_len == key_len && memcmp(entry->key, key, key_len) == 0) {
          // Update existing entry
          void *new_data = malloc(reply->len);
          if (new_data) {
            free(entry->data);
            entry->data = new_data;
            memcpy(entry->data, reply->str, reply->len);
            entry->data_len = reply->len;
            entry->expiry = now + TEMPLATE_CACHE_EXPIRY;
          }
          break;
        }
        entry = entry->next;
      }

      if (!entry) {
        // Create new entry
        entry = malloc(sizeof(template_cache_entry_t));
        if (entry) {
          entry->key = malloc(key_len);
          entry->data = malloc(reply->len);
          if (entry->key && entry->data) {
            memcpy(entry->key, key, key_len);
            entry->key_len = key_len;
            memcpy(entry->data, reply->str, reply->len);
            entry->data_len = reply->len;
            entry->expiry = now + TEMPLATE_CACHE_EXPIRY;
            entry->next = g_template_cache[h];
            g_template_cache[h] = entry;
          } else {
            if (entry->key)
              free(entry->key);
            if (entry->data)
              free(entry->data);
            free(entry);
          }
        }
      }
    }
  }

  freeReplyObject(reply);
  return result;
}

int redis_set_template(const char *key, size_t key_len, void *data, size_t len) {
  if (!redis_conn) {
    if (connect_thread_local_redis() != 0) {
      return -1;
    }
  }

  // Set in Redis with 5 minute expiration
  redisReply *reply = redisCommand(redis_conn, "SET %b %b EX %d", key, key_len, data, len, TEMPLATE_CACHE_EXPIRY);
  if (!reply) {
    LOG_ERROR("Redis error: %s\n", redis_conn->errstr);
    if (redis_conn->err) {
      redisFree(redis_conn);
      redis_conn = NULL;
    }
    return -1;
  }

  int ret = -1;
  if (reply->type != REDIS_REPLY_ERROR) {
    ret = 0;
    // Update local cache as well
    time_t now = time(NULL);
    unsigned int h = template_cache_hash(key, key_len);
    template_cache_entry_t *entry = g_template_cache[h];
    while (entry) {
      if (entry->key_len == key_len && memcmp(entry->key, key, key_len) == 0) {
        void *new_data = malloc(len);
        if (new_data) {
          free(entry->data);
          entry->data = new_data;
          memcpy(entry->data, data, len);
          entry->data_len = len;
          entry->expiry = now + TEMPLATE_CACHE_EXPIRY;
        }
        break;
      }
      entry = entry->next;
    }
    if (!entry) {
      entry = malloc(sizeof(template_cache_entry_t));
      if (entry) {
        entry->key = malloc(key_len);
        entry->data = malloc(len);
        if (entry->key && entry->data) {
          memcpy(entry->key, key, key_len);
          entry->key_len = key_len;
          memcpy(entry->data, data, len);
          entry->data_len = len;
          entry->expiry = now + TEMPLATE_CACHE_EXPIRY;
          entry->next = g_template_cache[h];
          g_template_cache[h] = entry;
        } else {
          if (entry->key)
            free(entry->key);
          if (entry->data)
            free(entry->data);
          free(entry);
        }
      }
    }
  } else {
    LOG_ERROR("Redis SET error: %s\n", reply->str);
  }

  freeReplyObject(reply);
  return ret;
}
