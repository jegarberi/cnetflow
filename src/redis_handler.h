#ifndef REDIS_HANDLER_H
#define REDIS_HANDLER_H

#include <hiredis/hiredis.h>
#include <stddef.h>

/**
 * Initialize Redis connection
 * @param hostname Redis host
 * @param port Redis port
 * @param user Redis user (optional, can be NULL)
 * @param password Redis password (optional, can be NULL)
 * @return 0 on success, -1 on failure
 */
int init_redis(const char *hostname, int port, const char *user, const char *password);

/**
 * Get internal Redis context
 * @return pointer to redisContext or NULL if not connected
 */
redisContext *get_redis_conn(void);

/**
 * Close Redis connection
 */
void close_redis(void);

/**
 * Get template from Redis
 * @param key Key buffer
 * @param key_len Length of key
 * @param out_len Pointer to store result length
 * @return Pointer to allocated data (must be freed) or NULL if not found/error
 */
void *redis_get_template(const char *key, size_t key_len, size_t *out_len);

/**
 * Set template in Redis
 * @param key Key buffer
 * @param key_len Length of key
 * @param data Data buffer
 * @param len Length of data
 * @return 0 on success, -1 on failure
 */
int redis_set_template(const char *key, size_t key_len, void *data, size_t len);

/**
 * Get all keys matching a pattern
 * @param pattern Glob pattern for keys
 * @param keys Pointer to store array of keys (must be freed with redis_free_keys)
 * @param count Pointer to store key count
 * @return 0 on success, -1 on failure
 */
int redis_get_keys(const char *pattern, char ***keys, size_t *count);

/**
 * Free keys returned by redis_get_keys
 * @param keys Array of keys
 * @param count Key count
 */
void redis_free_keys(char **keys, size_t count);

#endif // REDIS_HANDLER_H
