#include <criterion/criterion.h>
#include <criterion/redirect.h>
#include "../src/redis_handler.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void redirect_all_std(void) {
    cr_redirect_stdout();
    cr_redirect_stderr();
}

Test(redis, unix_socket_init, .init = redirect_all_std) {
    // We don't need a real redis for this, just check if it attempts to connect
    const char *socket_path = "/tmp/non_existent_redis.sock";
    init_redis(socket_path, 0, NULL, NULL);

    redisContext *ctx = get_redis_conn();

    // It should be NULL because the socket doesn't exist
    cr_assert_null(ctx);

    // Verify error message in stderr if logging is enabled
#ifdef ENABLE_LOGGING
    FILE *f_stderr = cr_get_redirected_stderr();
    char buf[1024];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f_stderr);
    buf[n] = '\0';
    cr_assert(strstr(buf, "Redis connection error") != NULL);
    cr_assert(strstr(buf, "/tmp/non_existent_redis.sock") == NULL); // errstr doesn't contain the path usually
#endif
}

Test(redis, tcp_init, .init = redirect_all_std) {
    // We don't need a real redis for this, just check if it attempts to connect
    const char *host = "127.0.0.1";
    int port = 6378; // different from default to avoid any potential running redis
    init_redis(host, port, NULL, NULL);

    redisContext *ctx = get_redis_conn();

    // It should be NULL because there is no redis running there
    cr_assert_null(ctx);

#ifdef ENABLE_LOGGING
    FILE *f_stderr = cr_get_redirected_stderr();
    char buf[1024];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f_stderr);
    buf[n] = '\0';
    cr_assert(strstr(buf, "Redis connection error") != NULL);
#endif
}

Test(redis, auth_init_acl, .init = redirect_all_std) {
    // Test that init_redis accepts user and password
    init_redis("127.0.0.1", 6378, "user", "pass");

    redisContext *ctx = get_redis_conn();
    cr_assert_null(ctx);
    // Even though it fails at connection, we verified the API call
}

Test(redis, auth_init_legacy, .init = redirect_all_std) {
    // Test that init_redis accepts only password
    init_redis("127.0.0.1", 6378, NULL, "pass");

    redisContext *ctx = get_redis_conn();
    cr_assert_null(ctx);
}

Test(redis, templates_disconnected, .init = redirect_all_std) {
    // Ensure get_redis_conn returns NULL first
    init_redis("127.0.0.1", 6378, NULL, NULL);
    close_redis();

    size_t out_len = 0;
    void *data = redis_get_template("key", 3, &out_len);
    cr_assert_null(data);

    int ret = redis_set_template("key", 3, "val", 3);
    cr_assert_eq(ret, -1);
}

Test(redis, config_truncation, .init = redirect_all_std) {
    // Test that very long configuration parameters are handled safely
    char long_str[512];
    memset(long_str, 'A', sizeof(long_str) - 1);
    long_str[sizeof(long_str) - 1] = '\0';

    // This should not crash even if the internal buffers are smaller (they are 256 and 128)
    init_redis(long_str, 6379, long_str, long_str);
    
    // get_redis_conn will try to connect using the truncated hostname
    redisContext *ctx = get_redis_conn();
    cr_assert_null(ctx);
}

Test(redis, close_redis_twice) {
    close_redis();
    close_redis();
    // Should not crash
}

Test(redis, init_null_hostname) {
    // Initializing with non-default hostname
    init_redis("localhost", 6379, NULL, NULL);
    
    // Calling with NULL hostname should keep the old one (localhost)
    init_redis(NULL, 6380, NULL, NULL);
    
    // We can't check g_redis_host directly, but we can check if it tries to connect to localhost:6380
    // If it was NULL, it might have reset to 127.0.0.1, but implementation doesn't do that.
    
    // This is more of a documentation of current behavior
}
