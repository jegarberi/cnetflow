//
// Created by jon on 6/3/25.
//

#ifndef NETFLOW_V5_H
#define NETFLOW_V5_H
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include "collector.h"
#include "netflow.h"

void *parse_v5(uv_work_t *);

void copy_v5_to_flow(const netflow_v5_flowset_t * restrict, netflow_v9_uint128_flowset_t * restrict);

#endif // NETFLOW_V5_H
