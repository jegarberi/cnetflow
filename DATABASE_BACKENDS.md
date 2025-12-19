 sele# Database Backend Configuration

cnetflow supports two database backends that can be selected at compile-time:
- **PostgreSQL** (default)
- **ClickHouse** (native TCP protocol)

## Building with Different Backends

### PostgreSQL (Default)

```bash
mkdir build && cd build
cmake ..
make
```

Or explicitly:

```bash
cmake -DUSE_CLICKHOUSE=OFF ..
make
```

### ClickHouse

```bash
mkdir build && cd build
cmake -DUSE_CLICKHOUSE=ON ..
make
```

## Runtime Configuration

### PostgreSQL Configuration

Set the `PG_CONN_STRING` environment variable with a PostgreSQL connection string:

```bash
export PG_CONN_STRING="postgresql://user:password@host:port/database"
```

Example:
```bash
export PG_CONN_STRING="postgresql://netflow:secret@192.168.1.10:5432/netflow"
```

### ClickHouse Configuration

Set the `CH_CONN_STRING` environment variable with colon-separated values:

```bash
export CH_CONN_STRING="host:port:database:user:password"
```

Example:
```bash
export CH_CONN_STRING="192.168.1.20:9000:default:default:"
```

Format breakdown:
- **host**: ClickHouse server hostname or IP
- **port**: Native protocol port (default: 9000, NOT the HTTP port 8123)
- **database**: Database name (use "default" if unsure)
- **user**: Username (typically "default")
- **password**: Password (leave empty for no password)

## Code Usage

Your application code uses the unified `db.h` interface, which automatically adapts to the compiled backend:

```c
#include "db.h"

// Connect to database (uses appropriate env var)
db_conn_t conn = NULL;
db_init_connection(&conn);

// Insert flows (same API for both backends)
db_insert_flows(exporter_ip, flows);

// Get backend info
printf("Using: %s\n", db_get_backend_name());
```

## Backend Differences

### PostgreSQL
- **Protocol**: PostgreSQL wire protocol via libpq
- **Port**: 5432 (default)
- **Dependencies**: libpq-dev
- **Data Format**: Row-oriented
- **Best For**: OLTP workloads, complex queries, ACID requirements

### ClickHouse
- **Protocol**: Native TCP binary protocol (custom implementation)
- **Port**: 9000 (native protocol, NOT 8123 HTTP)
- **Dependencies**: None (uses standard sockets)
- **Data Format**: Columnar (Native format)
- **Best For**: OLAP workloads, time-series data, high insert rates

## Table Schema

Both backends create compatible schemas optimized for NetFlow data:

### PostgreSQL
```sql
CREATE TABLE flows (
    exporter integer,
    srcaddr inet,
    srcport smallint,
    dstaddr inet,
    dstport smallint,
    first timestamp,
    last timestamp,
    dpkts bigint,
    doctets bigint,
    input smallint,
    output smallint,
    protocol smallint,
    tos smallint,
    src_as smallint,
    dst_as smallint,
    src_mask smallint,
    dst_mask smallint,
    tcp_flags smallint,
    ip_version smallint
);
```

### ClickHouse
```sql
CREATE TABLE flows (
    exporter UInt32,
    srcaddr String,
    srcport UInt16,
    dstaddr String,
    dstport UInt16,
    first DateTime,
    last DateTime,
    dpkts UInt64,
    doctets UInt64,
    input UInt16,
    output UInt16,
    protocol UInt8,
    tos UInt8,
    src_as UInt16,
    dst_as UInt16,
    src_mask UInt8,
    dst_mask UInt8,
    tcp_flags UInt8,
    ip_version UInt8
) ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(first)
ORDER BY (exporter, first, srcaddr, dstaddr);
```

## Build Options Summary

| Option | Default | Description |
|--------|---------|-------------|
| `USE_CLICKHOUSE` | OFF | Use ClickHouse instead of PostgreSQL |
| `BUILD_FOR_RHEL7` | OFF | Build for RHEL7/CentOS7 compatibility |
| `CMAKE_BUILD_TYPE` | - | Debug, Release, RelWithDebInfo, MinSizeRel |

## Package Dependencies

### DEB Packages
- **PostgreSQL build**: `libpq-dev, libuv1-dev`
- **ClickHouse build**: `libuv1-dev`

### RPM Packages
- **PostgreSQL build**: `postgresql-devel, libuv-devel`
- **ClickHouse build**: `libuv-devel`

## Performance Considerations

### PostgreSQL
- Good all-around performance
- Prepare statements for efficiency
- Use connection pooling for high concurrency
- Consider partitioning by time for large datasets

### ClickHouse
- Exceptional write performance (columnar storage)
- Optimized for analytical queries on time-series data
- Automatic partitioning by date
- Compression reduces storage requirements
- Best for append-only workloads

## Troubleshooting

### PostgreSQL
```bash
# Test connection
psql "$PG_CONN_STRING"

# Check if table exists
psql "$PG_CONN_STRING" -c "\dt flows"
```

### ClickHouse
```bash
# Test connection (using clickhouse-client)
clickhouse-client --host=192.168.1.20 --port=9000

# Check if table exists
echo "SHOW TABLES" | clickhouse-client --host=192.168.1.20 --port=9000

# View data
echo "SELECT count() FROM flows" | clickhouse-client --host=192.168.1.20 --port=9000
```

### Common Issues

**ClickHouse: "Connection refused"**
- Ensure you're using port 9000 (native protocol), not 8123 (HTTP)
- Check ClickHouse is listening on the correct interface
- Verify firewall rules

**PostgreSQL: "libpq not found"**
- Install development package: `apt install libpq-dev` or `yum install postgresql-devel`

**Runtime: "Environment variable not set"**
- Set appropriate connection string before running cnetflow
- Use `export` to make it available to the process
