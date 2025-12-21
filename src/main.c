
#include <stdio.h>
#include "collector.h"
#include "log.h"


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
int main(void) {
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
