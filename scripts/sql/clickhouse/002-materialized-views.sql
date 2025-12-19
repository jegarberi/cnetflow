-- ============================================================
-- CLICKHOUSE MATERIALIZED VIEWS FOR NETFLOW AGGREGATIONS
-- ============================================================
-- These materialized views pre-aggregate NetFlow data at different
-- time intervals for faster analytical queries
-- ============================================================

-- Drop existing materialized views if they exist
-- DROP TABLE IF EXISTS flows_5minute_mv;
-- DROP TABLE IF EXISTS flows_hourly_mv;
-- DROP TABLE IF EXISTS flows_daily_mv;
-- DROP TABLE IF EXISTS flows_top_talkers_hourly_mv;

-- ============================================================
-- 1. FIVE-MINUTE AGGREGATION
-- ============================================================
-- Aggregates flows into 5-minute buckets for recent data analysis

CREATE MATERIALIZED VIEW IF NOT EXISTS flows_5minute_mv
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMMDD(bucket)
ORDER BY (bucket, exporter, srcaddr, dstaddr, srcport, dstport, protocol, input, output)
TTL bucket + INTERVAL 7 DAY  -- Keep 5-minute data for 7 days
POPULATE
AS SELECT
    toStartOfFiveMinutes(first) AS bucket,
    exporter,
    srcaddr,
    dstaddr,
    srcport,
    dstport,
    protocol,
    input,
    output,
    count() AS flow_count,
    sum(dpkts) AS total_packets,
    sum(doctets) AS total_bytes,
    min(first) AS earliest_flow,
    max(last) AS latest_flow
FROM flows
GROUP BY
    bucket,
    exporter,
    srcaddr,
    dstaddr,
    srcport,
    dstport,
    protocol,
    input,
    output;

-- ============================================================
-- 2. HOURLY AGGREGATION
-- ============================================================
-- Aggregates flows into hourly buckets for mid-term analysis

CREATE MATERIALIZED VIEW IF NOT EXISTS flows_hourly_mv
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(bucket)
ORDER BY (bucket, exporter, srcaddr, dstaddr, srcport, dstport, protocol, input, output)
TTL bucket + INTERVAL 30 DAY  -- Keep hourly data for 30 days
POPULATE
AS SELECT
    toStartOfHour(first) AS bucket,
    exporter,
    srcaddr,
    dstaddr,
    srcport,
    dstport,
    protocol,
    input,
    output,
    count() AS flow_count,
    sum(dpkts) AS total_packets,
    sum(doctets) AS total_bytes,
    min(first) AS earliest_flow,
    max(last) AS latest_flow
FROM flows
GROUP BY
    bucket,
    exporter,
    srcaddr,
    dstaddr,
    srcport,
    dstport,
    protocol,
    input,
    output;

-- ============================================================
-- 3. DAILY AGGREGATION
-- ============================================================
-- Aggregates flows into daily buckets for long-term trends

CREATE MATERIALIZED VIEW IF NOT EXISTS flows_daily_mv
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(bucket)
ORDER BY (bucket, exporter, srcaddr, dstaddr, protocol, input, output)
TTL bucket + INTERVAL 365 DAY  -- Keep daily data for 1 year
POPULATE
AS SELECT
    toStartOfDay(first) AS bucket,
    exporter,
    srcaddr,
    dstaddr,
    protocol,
    input,
    output,
    count() AS flow_count,
    sum(dpkts) AS total_packets,
    sum(doctets) AS total_bytes
FROM flows
GROUP BY
    bucket,
    exporter,
    srcaddr,
    dstaddr,
    protocol,
    input,
    output;

-- ============================================================
-- 4. TOP TALKERS HOURLY
-- ============================================================
-- Tracks top traffic generators by bytes per hour

CREATE MATERIALIZED VIEW IF NOT EXISTS flows_top_talkers_hourly_mv
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(bucket)
ORDER BY (bucket, exporter, srcaddr, dstaddr, input, output)
TTL bucket + INTERVAL 30 DAY  -- Keep top talkers for 30 days
POPULATE
AS SELECT
    toStartOfHour(first) AS bucket,
    exporter,
    srcaddr,
    dstaddr,
    input,
    output,
    sum(doctets) AS total_bytes_sent,
    count() AS flow_count
FROM flows
GROUP BY
    bucket,
    exporter,
    srcaddr,
    dstaddr,
    input,
    output;

-- ============================================================
-- 5. PROTOCOL DISTRIBUTION (OPTIONAL)
-- ============================================================
-- Hourly protocol distribution for traffic analysis

CREATE MATERIALIZED VIEW IF NOT EXISTS flows_protocol_hourly_mv
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(bucket)
ORDER BY (bucket, exporter, protocol)
TTL bucket + INTERVAL 30 DAY
POPULATE
AS SELECT
    toStartOfHour(first) AS bucket,
    exporter,
    protocol,
    count() AS flow_count,
    sum(dpkts) AS total_packets,
    sum(doctets) AS total_bytes
FROM flows
GROUP BY
    bucket,
    exporter,
    protocol;

-- ============================================================
-- 6. PORT ANALYSIS (OPTIONAL)
-- ============================================================
-- Hourly destination port statistics for service analysis

CREATE MATERIALIZED VIEW IF NOT EXISTS flows_dstport_hourly_mv
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(bucket)
ORDER BY (bucket, exporter, dstport, protocol)
TTL bucket + INTERVAL 30 DAY
POPULATE
AS SELECT
    toStartOfHour(first) AS bucket,
    exporter,
    dstport,
    protocol,
    count() AS flow_count,
    sum(dpkts) AS total_packets,
    sum(doctets) AS total_bytes,
    uniq(srcaddr) AS unique_sources
FROM flows
WHERE dstport > 0
GROUP BY
    bucket,
    exporter,
    dstport,
    protocol;

-- ============================================================
-- 7. AS (AUTONOMOUS SYSTEM) ANALYSIS (OPTIONAL)
-- ============================================================
-- Hourly AS pair analysis for peering statistics

CREATE MATERIALIZED VIEW IF NOT EXISTS flows_as_hourly_mv
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(bucket)
ORDER BY (bucket, exporter, src_as, dst_as)
TTL bucket + INTERVAL 30 DAY
POPULATE
AS SELECT
    toStartOfHour(first) AS bucket,
    exporter,
    src_as,
    dst_as,
    count() AS flow_count,
    sum(dpkts) AS total_packets,
    sum(doctets) AS total_bytes
FROM flows
WHERE src_as > 0 OR dst_as > 0
GROUP BY
    bucket,
    exporter,
    src_as,
    dst_as;

-- ============================================================
-- EXAMPLE QUERIES FOR MATERIALIZED VIEWS
-- ============================================================

-- Query 5-minute aggregated data
-- SELECT
--     bucket,
--     srcaddr,
--     dstaddr,
--     sum(total_bytes) AS bytes,
--     sum(flow_count) AS flows
-- FROM flows_5minute_mv
-- WHERE bucket >= now() - INTERVAL 1 HOUR
-- GROUP BY bucket, srcaddr, dstaddr
-- ORDER BY bytes DESC
-- LIMIT 10;

-- Query top talkers in the last 24 hours
-- SELECT
--     srcaddr,
--     sum(total_bytes_sent) AS total_bytes,
--     sum(flow_count) AS flows
-- FROM flows_top_talkers_hourly_mv
-- WHERE bucket >= now() - INTERVAL 24 HOUR
-- GROUP BY srcaddr
-- ORDER BY total_bytes DESC
-- LIMIT 20;

-- Query protocol distribution
-- SELECT
--     protocol,
--     sum(total_bytes) AS bytes,
--     sum(flow_count) AS flows,
--     formatReadableSize(sum(total_bytes)) AS readable_size
-- FROM flows_protocol_hourly_mv
-- WHERE bucket >= now() - INTERVAL 24 HOUR
-- GROUP BY protocol
-- ORDER BY bytes DESC;

-- Query popular destination ports
-- SELECT
--     dstport,
--     protocol,
--     sum(total_bytes) AS bytes,
--     sum(flow_count) AS flows,
--     sum(unique_sources) AS unique_sources
-- FROM flows_dstport_hourly_mv
-- WHERE bucket >= now() - INTERVAL 24 HOUR
-- GROUP BY dstport, protocol
-- ORDER BY bytes DESC
-- LIMIT 20;

-- ============================================================
-- MAINTENANCE NOTES
-- ============================================================

-- Materialized views are automatically updated as new data arrives
-- in the base flows table. No manual refresh is needed.

-- To manually refresh a materialized view (if data was deleted/updated):
-- This is rarely needed as ClickHouse MV updates are automatic
-- SYSTEM STOP VIEW flows_5minute_mv;
-- SYSTEM START VIEW flows_5minute_mv;

-- To check materialized view data size:
-- SELECT
--     table,
--     formatReadableSize(sum(bytes)) AS size,
--     sum(rows) AS rows
-- FROM system.parts
-- WHERE database = currentDatabase() AND table LIKE '%_mv'
-- GROUP BY table
-- ORDER BY sum(bytes) DESC;
