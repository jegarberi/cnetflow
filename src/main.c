
#include <stdio.h>
#include "collector.h"
#include "log.h"
#include <string.h>

void print_compile_options(void) {
    printf("cnetflow compile options:\n");
#ifdef USE_CLICKHOUSE
    printf("  Database: ClickHouse\n");
#else
    printf("  Database: PostgreSQL\n");
#endif

#ifdef USE_REDIS
    printf("  Redis: ON\n");
#else
    printf("  Redis: OFF\n");
#endif

#ifdef USE_ARENA_ALLOCATOR
    printf("  Arena Allocator: ON\n");
#else
    printf("  Arena Allocator: OFF\n");
#endif

#ifdef ENABLE_LOGGING
    printf("  Logging: ON\n");
#else
    printf("  Logging: OFF\n");
#endif

#ifdef ENABLE_METRICS
    printf("  Metrics: ON\n");
#else
    printf("  Metrics: OFF\n");
#endif

#ifdef BUILD_STATIC
    printf("  Build type: STATIC\n");
#else
    printf("  Build type: DYNAMIC\n");
#endif

#ifdef COMPAT_CENTOS6
    printf("  CentOS 6 Compatibility: ON\n");
#endif

#ifdef CNETFLOW_DEBUG_BUILD
    printf("  Configuration: Debug\n");
#elif defined(CNETFLOW_RELEASE_BUILD)
    printf("  Configuration: Release\n");
#endif
}

/**
 * The main entry point for the program.
 * Initializes the system, starts the collector, and performs its operations.
 *
 * The function initializes logging to indicate the start and end of its process.
 * It sets up the collector configuration, applies default settings using the `collector_default`
 * function, and starts the collector using the `collector_start` method.
 *
 * @return Returns 0 if the program completes successfully.
 */
int main(int argc, char *argv[]) {
  if (argc > 1) {
    if (strcmp(argv[1], "--options") == 0 || strcmp(argv[1], "-o") == 0) {
      print_compile_options();
      return 0;
    } else {
      printf("Usage: %s [--options|-o]\n", argv[0]);
      return 1;
    }
  }
  fprintf(stderr, "Starting main...\n");
  fprintf(stdout, "Starting main...\n");
  //fflush(stderr);
  //fflush(stdout);
  LOG_INFO("%s %d %s Init main...\n", __FILE__, __LINE__, __func__);
  LOG_ERROR("%s %d %s Init main...\n", __FILE__, __LINE__, __func__);
  LOG_ERROR("%s %d %s Starting collector...\n", __FILE__, __LINE__, __func__);
  collector_t col_config;
  collector_default(&col_config);
  collector_start(&col_config);
  LOG_ERROR("%s %d %s Exit main...\n", __FILE__, __LINE__, __func__);
  LOG_INFO("%s %d %s Exit main...\n", __FILE__, __LINE__, __func__);
  fprintf(stderr, "Exiting main...\n");
  fprintf(stdout, "Exiting main...\n");
  //fflush(stderr);
  //fflush(stdout);
  EXIT_WITH_MSG(0, "Exiting...\n");

}
