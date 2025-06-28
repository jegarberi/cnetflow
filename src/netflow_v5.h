//
// Created by jon on 6/3/25.
//

#ifndef NETFLOW_V5_H
#define NETFLOW_V5_H
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include "collector.h"
#include "db_psql.h"
#include "netflow.h"


static void exit_nicely(PGconn *conn);

void *parse_v5(uv_work_t *req);
#endif // NETFLOW_V5_H
