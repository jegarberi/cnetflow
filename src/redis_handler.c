#include "redis_handler.h"
#include <stdlib.h>
#include <string.h>
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

  redis_conn = redisConnectWithTimeout(hostname, port, timeout);

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

  LOG_INFO("Connected to Redis at %s:%d (Thread Local)\n", hostname, port);
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
}

void *redis_get_template(const char *key, size_t key_len, size_t *out_len) {
  if (!redis_conn) {
    if (connect_thread_local_redis() != 0) {
      return NULL;
    }
  }

  redisReply *reply = redisCommand(redis_conn, "GET %b", key, key_len);
  if (!reply) {
    LOG_ERROR("Redis error: %s\n", redis_conn->errstr);
    // Attempt reconnect on next call by implementation logic if needed,
    // or we could force a reconnect here. For now, just return NULL.
    // If connection is dead, hiredis usually sets context err.
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

  redisReply *reply = redisCommand(redis_conn, "SET %b %b", key, key_len, data, len);
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
  } else {
    LOG_ERROR("Redis SET error: %s\n", reply->str);
  }

  freeReplyObject(reply);
  return ret;
}
