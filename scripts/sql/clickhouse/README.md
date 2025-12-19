# ClickHouse Database Setup for NetFlow Collector

This directory contains SQL scripts to set up the ClickHouse database schema for the cnetflow NetFlow collector.

## Prerequisites

- ClickHouse Server installed and running
- ClickHouse Client (`clickhouse-client`) installed
- Network access to ClickHouse server (default port 9000 for native protocol)
- Appropriate permissions to create databases and tables

## Installation

### 1. Install ClickHouse

#### Ubuntu/Debian
```bash
sudo apt-get install -y apt-transport-https ca-certificates dirmngr
sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv 8919F6BD2B48D754

echo "deb https://packages.clickhouse.com/deb stable main" | sudo tee \
    /etc/apt/sources.list.d/clickhouse.list
sudo apt-get update

sudo apt-get install -y clickhouse-server clickhouse-client

sudo service clickhouse-server start
```

#### RHEL/CentOS
```bash
sudo yum install -y yum-utils
sudo yum-config-manager --add-repo https://packages.clickhouse.com/rpm/clickhouse.repo
sudo yum install -y clickhouse-server clickhouse-client

sudo systemctl start clickhouse-server
sudo systemctl enable clickhouse-server
```

### 2. Configure ClickHouse

Edit `/etc/clickhouse-server/config.xml` to allow network connections:

```xml
<listen_host>0.0.0.0</listen_host>
```

Or for specific IP:
```xml
<listen_host>192.168.1.10</listen_host>
```

Restart ClickHouse:
```bash
sudo systemctl restart clickhouse-server
```

### 3. Create Database

```bash
clickhouse-client --query "CREATE DATABASE IF NOT EXISTS netflow"
```

Or connect interactively:
```bash
clickhouse-client
```

Then execute:
```sql
CREATE DATABASE IF NOT EXISTS netflow;
USE netflow;
```

### 4. Run Setup Scripts

Execute the scripts in order:

```bash
# Create tables
clickhouse-client --database=netflow < 001-tables.sql

# Create materialized views
clickhouse-client --database=netflow < 002-materialized-views.sql
```

Or execute all at once:
```bash
cat 001-tables.sql 002-materialized-views.sql | clickhouse-client --database=netflow
```

## Files Description

### 001-tables.sql
Creates the main tables:
- **flows**: Main NetFlow records table with automatic partitioning by date
- **exporters**: NetFlow exporter devices configuration
- **interfaces**: Network interface information
- **interface_metrics**: SNMP interface metrics

### 002-materialized-views.sql
Creates materialized views for pre-aggregated data:
- **flows_5minute_mv**: 5-minute aggregations (7-day retention)
- **flows_hourly_mv**: Hourly aggregations (30-day retention)
- **flows_daily_mv**: Daily aggregations (1-year retention)
- **flows_top_talkers_hourly_mv**: Top traffic sources/destinations
- **flows_protocol_hourly_mv**: Protocol distribution
- **flows_dstport_hourly_mv**: Destination port statistics
- **flows_as_hourly_mv**: Autonomous System pair analysis

## Configuration for cnetflow

Set the connection string environment variable:

```bash
export CH_CONN_STRING="localhost:9000:netflow:default:"
```

Format: `host:port:database:user:password`

For remote server:
```bash
export CH_CONN_STRING="192.168.1.20:9000:netflow:cnetflow:mypassword"
```

## User Management

### Create a dedicated user for cnetflow

```sql
CREATE USER IF NOT EXISTS cnetflow IDENTIFIED BY 'your_password';

-- Grant permissions
GRANT SELECT, INSERT, CREATE TABLE ON netflow.* TO cnetflow;

-- Or for full access
GRANT ALL ON netflow.* TO cnetflow;
```

### Set user in connection string
```bash
export CH_CONN_STRING="localhost:9000:netflow:cnetflow:your_password"
```

## Verification

### Check tables were created
```bash
clickhouse-client --database=netflow --query "SHOW TABLES"
```

Expected output:
```
exporters
flows
flows_5minute_mv
flows_as_hourly_mv
flows_daily_mv
flows_dstport_hourly_mv
flows_hourly_mv
flows_protocol_hourly_mv
flows_top_talkers_hourly_mv
interface_metrics
interfaces
```

### Check table structure
```bash
clickhouse-client --database=netflow --query "DESCRIBE flows"
```

### Insert test data
```sql
INSERT INTO flows (exporter, srcaddr, dstaddr, srcport, dstport, protocol,
                   dpkts, doctets, first, last, ip_version)
VALUES (3232235777, '192.168.1.100', '8.8.8.8', 54321, 443, 6,
        100, 50000, now(), now(), 4);
```

### Query test data
```bash
clickhouse-client --database=netflow --query "SELECT count() FROM flows"
clickhouse-client --database=netflow --query "SELECT * FROM flows LIMIT 5"
```

## Maintenance

### View table sizes
```sql
SELECT
    table,
    formatReadableSize(sum(bytes)) AS size,
    sum(rows) AS rows,
    max(modification_time) AS latest_modification
FROM system.parts
WHERE active AND database = 'netflow'
GROUP BY table
ORDER BY sum(bytes) DESC;
```

### View partition information
```sql
SELECT
    partition,
    count() AS parts,
    formatReadableSize(sum(bytes_on_disk)) AS size,
    sum(rows) AS rows,
    min(min_date) AS min_date,
    max(max_date) AS max_date
FROM system.parts
WHERE table = 'flows' AND database = 'netflow' AND active
GROUP BY partition
ORDER BY partition DESC
LIMIT 10;
```

### Optimize tables (merge small parts)
```sql
OPTIMIZE TABLE flows FINAL;
OPTIMIZE TABLE flows_hourly_mv FINAL;
```

### Drop old partitions manually
```sql
-- Drop flows data from specific date
ALTER TABLE flows DROP PARTITION '20250101';

-- Drop all partitions older than 30 days
ALTER TABLE flows DROP PARTITION WHERE toDate(partition) < today() - 30;
```

### Check compression ratio
```sql
SELECT
    table,
    sum(data_compressed_bytes) AS compressed,
    sum(data_uncompressed_bytes) AS uncompressed,
    round(sum(data_uncompressed_bytes) / sum(data_compressed_bytes), 2) AS ratio
FROM system.columns
WHERE database = 'netflow' AND table = 'flows'
GROUP BY table;
```

## Performance Tuning

### Increase memory for aggregations (in config.xml)
```xml
<max_memory_usage>10000000000</max_memory_usage>
```

### Adjust merge settings
```xml
<background_pool_size>16</background_pool_size>
<background_merges_mutations_concurrency_ratio>2</background_merges_mutations_concurrency_ratio>
```

### Enable query log
```bash
clickhouse-client --query "SET log_queries = 1"
```

## Backup and Restore

### Backup to file
```bash
clickhouse-client --database=netflow --query "SELECT * FROM flows FORMAT Native" > flows_backup.native
```

### Restore from file
```bash
cat flows_backup.native | clickhouse-client --database=netflow --query "INSERT INTO flows FORMAT Native"
```

### Backup using clickhouse-backup tool
```bash
# Install clickhouse-backup
wget https://github.com/AlexAkulov/clickhouse-backup/releases/latest/download/clickhouse-backup.tar.gz
tar -xzf clickhouse-backup.tar.gz
sudo mv clickhouse-backup /usr/local/bin/

# Create backup
clickhouse-backup create netflow_backup

# List backups
clickhouse-backup list

# Restore backup
clickhouse-backup restore netflow_backup
```

## Troubleshooting

### Cannot connect to ClickHouse
1. Check if service is running: `sudo systemctl status clickhouse-server`
2. Check port is listening: `sudo netstat -tlnp | grep 9000`
3. Check firewall: `sudo ufw allow 9000/tcp` (if using UFW)
4. Verify configuration: `/etc/clickhouse-server/config.xml`

### Permission denied
```sql
GRANT ALL ON netflow.* TO cnetflow;
```

### Table already exists error
Comment out or remove the `DROP TABLE` statements at the beginning of scripts if you want to preserve existing data.

### Out of memory
- Reduce batch size in cnetflow collector
- Increase ClickHouse memory limits
- Add more RAM to server
- Enable compression earlier

### Slow queries
- Check if indexes are being used: `EXPLAIN` query
- Ensure queries filter by partition key (date)
- Consider adding more skip indexes
- Increase `max_threads` for parallel execution

## Example Queries

### Top 10 talkers in last hour
```sql
SELECT
    srcaddr,
    formatReadableSize(sum(total_bytes_sent)) AS bytes
FROM flows_top_talkers_hourly_mv
WHERE bucket >= now() - INTERVAL 1 HOUR
GROUP BY srcaddr
ORDER BY sum(total_bytes_sent) DESC
LIMIT 10;
```

### Protocol distribution today
```sql
SELECT
    protocol,
    count() AS flows,
    formatReadableSize(sum(doctets)) AS bytes
FROM flows
WHERE toDate(first) = today()
GROUP BY protocol
ORDER BY sum(doctets) DESC;
```

### Traffic by hour for last 24 hours
```sql
SELECT
    toStartOfHour(first) AS hour,
    formatReadableSize(sum(doctets)) AS bytes,
    count() AS flows
FROM flows
WHERE first >= now() - INTERVAL 24 HOUR
GROUP BY hour
ORDER BY hour;
```

## Additional Resources

- [ClickHouse Documentation](https://clickhouse.com/docs/)
- [MergeTree Engine](https://clickhouse.com/docs/en/engines/table-engines/mergetree-family/mergetree/)
- [Materialized Views](https://clickhouse.com/docs/en/guides/developer/cascading-materialized-views/)
- [Data Types](https://clickhouse.com/docs/en/sql-reference/data-types/)
