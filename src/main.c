
#include <stdio.h>
#include "collector.h"


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
  fprintf(stderr, "Init main...\n");
  fprintf(stderr, "Starting collector...\n");
  collector_t col_config;
  collector_default(&col_config);
  collector_start(&col_config);
  fprintf(stderr, "Exit main...\n");
}
