#define CNETFLOW_THREADS 1
#include <stdio.h>
#include "collector.h"


int main(void) {
  fprintf(stderr, "Init main...\n");
  fprintf(stderr, "Starting collector...\n");
  collector_t col_config;
  collector_default(&col_config);
  collector_start(&col_config);
  fprintf(stderr, "Exit main...\n");
}
