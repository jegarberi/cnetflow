-- ============================================================
-- CLICKHOUSE DATABASE SCHEMA FOR NETFLOW COLLECTOR
-- ============================================================
-- This script creates the necessary tables and structures for
-- storing NetFlow data in ClickHouse
-- ============================================================

-- Drop existing tables if they exist (BE CAREFUL IN PRODUCTION!)
-- DROP TABLE IF EXISTS flows;
-- DROP TABLE IF EXISTS exporters;
-- DROP TABLE IF EXISTS interfaces;
-- DROP TABLE IF EXISTS interface_metrics;

-- ============================================================
-- 1. MAIN FLOWS TABLE
-- ============================================================
-- Stores individual NetFlow records with columnar compression
-- Uses MergeTree engine optimized for time-series data

CREATE TABLE IF NOT EXISTS flows
(

    inserted_at DateTime DEFAULT now(),

    exporter    String,
    srcaddr     String,
    dstaddr     String,
    srcport     UInt16,
    dstport     UInt16,
    protocol    UInt8,


    input       UInt16,
    output      UInt16,

    -- Traffic metrics
    dpkts       UInt64,
    doctets     UInt64,

    -- Timing
    first       DateTime,
    last        DateTime,

    -- Additional flow attributes
    tcp_flags   UInt8,
    tos         UInt8,
    src_as      UInt16,
    dst_as      UInt16,
    src_mask    UInt8,
    dst_mask    UInt8,
    ip_version  UInt8,

    -- Flow hash for deduplication (optional)
    flow_hash   String DEFAULT ''
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(first)
ORDER BY (exporter, first, srcaddr, dstaddr, srcport, dstport, protocol)
TTL first + INTERVAL 7 DAY  -- Automatically delete data older than 7 days
SETTINGS
    index_granularity = 8192,
    storage_policy = 'default';

-- ============================================================
-- 2. EXPORTERS TABLE
-- ============================================================
-- Stores information about NetFlow exporters (routers/switches)

CREATE TABLE IF NOT EXISTS exporters
(
    id                UInt64,
    created_at        DateTime DEFAULT now(),
    ip_bin            UInt32,
    ip_inet           String,
    name              String,
    snmp_version      UInt8 DEFAULT 0,
    snmp_community    String DEFAULT '',
    snmpv3_username   String DEFAULT '',
    snmpv3_level      String DEFAULT '',
    snmpv3_auth_proto String DEFAULT '',
    snmpv3_auth_pass  String DEFAULT '',
    snmpv3_priv_proto String DEFAULT '',
    snmpv3_priv_pass  String DEFAULT '',
    data              String DEFAULT '{}'  -- JSON as String in ClickHouse
)
ENGINE = ReplacingMergeTree(created_at)
ORDER BY (id, ip_bin)
SETTINGS index_granularity = 8192;

-- ============================================================
-- 3. INTERFACES TABLE
-- ============================================================
-- Stores interface information from exporters

CREATE TABLE IF NOT EXISTS interfaces
(
    id          UInt64,
    created_at  DateTime DEFAULT now(),
    exporter    UInt64,
    snmp_index  UInt64,
    name        String,
    description String,
    alias       String,
    speed       UInt64 DEFAULT 0,
    enabled     UInt8 DEFAULT 1,
    bandwidth   UInt64 DEFAULT 0
)
ENGINE = ReplacingMergeTree(created_at)
ORDER BY (exporter, snmp_index, id)
SETTINGS index_granularity = 8192;

-- ============================================================
-- 4. INTERFACE METRICS TABLE
-- ============================================================
-- Stores SNMP metrics collected from interfaces

CREATE TABLE IF NOT EXISTS interface_metrics
(
    inserted_at   DateTime DEFAULT now(),
    exporter      UInt64,
    snmp_index    UInt64,
    octets_in     UInt64 DEFAULT 0,
    octets_out    UInt64 DEFAULT 0,
    packets_in    UInt64 DEFAULT 0,
    packets_out   UInt64 DEFAULT 0,
    errors_in     UInt64 DEFAULT 0,
    errors_out    UInt64 DEFAULT 0,
    discards_in   UInt64 DEFAULT 0,
    discards_out  UInt64 DEFAULT 0
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(inserted_at)
ORDER BY (exporter, snmp_index, inserted_at)
TTL inserted_at + INTERVAL 30 DAY
SETTINGS index_granularity = 8192;

-- ============================================================
-- 5. INDEXES FOR QUERY OPTIMIZATION
-- ============================================================

-- Skip indexes for better filtering performance on flows table
ALTER TABLE flows ADD INDEX idx_srcaddr srcaddr TYPE set(1000) GRANULARITY 4;
ALTER TABLE flows ADD INDEX idx_dstaddr dstaddr TYPE set(1000) GRANULARITY 4;
ALTER TABLE flows ADD INDEX idx_protocol protocol TYPE set(100) GRANULARITY 4;
ALTER TABLE flows ADD INDEX idx_srcport srcport TYPE set(1000) GRANULARITY 4;
ALTER TABLE flows ADD INDEX idx_dstport dstport TYPE set(1000) GRANULARITY 4;

-- ============================================================
-- 6. USEFUL QUERIES FOR TABLE MANAGEMENT
-- ============================================================

-- View table size and compression
-- SELECT
--     table,
--     formatReadableSize(sum(bytes)) AS size,
--     sum(rows) AS rows,
--     max(modification_time) AS latest_modification
-- FROM system.parts
-- WHERE active AND database = currentDatabase()
-- GROUP BY table
-- ORDER BY sum(bytes) DESC;

-- View partition information
-- SELECT
--     partition,
--     count() AS parts,
--     formatReadableSize(sum(bytes_on_disk)) AS size,
--     sum(rows) AS rows,
--     min(min_date) AS min_date,
--     max(max_date) AS max_date
-- FROM system.parts
-- WHERE (table = 'flows') AND active
-- GROUP BY partition
-- ORDER BY partition;

-- Optimize table (merge small parts)
-- OPTIMIZE TABLE flows FINAL;

-- Drop old partitions manually if needed
-- ALTER TABLE flows DROP PARTITION '20250101';
