#include "redis_handler.h"
#include <stdlib.h>
#include <string.h>
#include "log.h"

static redisContext *redis_conn = NULL;

int init_redis(const char *hostname, int port, const char *user, const char *password) {
  if (redis_conn != NULL) {
    redisFree(redis_conn);
  }

  struct timeval timeout = {1, 500000}; // 1.5 seconds

  if (user || password) {
    redisOptions options = {0};
    REDIS_OPTIONS_SET_TCP(&options, hostname, port);
    options.connect_timeout = &timeout;
    if (user) {
      // hiredis < 1.0.0 might not have options.user.
      // But we are on 1.2.0 according to conanfile.
      // However, to be safe and simple, let's use redisConnectWithTimeout and then AUTH.
      // Actually, redisConnectWithOptions is cleaner if available.
      // Let's stick to redisConnectWithTimeout + manual AUTH for maximum compatibility if we are unsure about hiredis
      // version details in code, but conan says 1.2.0 which definitely has ACL support. Let's use
      // redisConnectWithOptions? No, let's keep it simple first. If we use redisConnectWithOptions we need to init
      // options properly.
    }
  }

  // Revised approach: Connect first, then AUTH. This is standard and works everywhere.
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

  LOG_INFO("Connected to Redis at %s:%d\n", hostname, port);
  return 0;
}

redisContext *get_redis_conn(void) { return redis_conn; }

void close_redis(void) {
  if (redis_conn != NULL) {
    redisFree(redis_conn);
    redis_conn = NULL;
  }
}

void *redis_get_template(const char *key, size_t key_len, size_t *out_len) {
  if (!redis_conn)
    return NULL;

  redisReply *reply = redisCommand(redis_conn, "GET %b", key, key_len);
  if (!reply) {
    LOG_ERROR("Redis error: %s\n", redis_conn->errstr);
    // Attempt reconnect?
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
  if (!redis_conn)
    return -1;

  redisReply *reply = redisCommand(redis_conn, "SET %b %b", key, key_len, data, len);
  if (!reply) {
    LOG_ERROR("Redis error: %s\n", redis_conn->errstr);
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
