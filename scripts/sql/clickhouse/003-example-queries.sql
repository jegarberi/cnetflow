-- ============================================================
-- CLICKHOUSE EXAMPLE QUERIES FOR NETFLOW ANALYSIS
-- ============================================================
-- This file contains useful queries for analyzing NetFlow data
-- in ClickHouse
-- ============================================================

-- ============================================================
-- BASIC STATISTICS
-- ============================================================

-- Total flows in database
SELECT count() AS total_flows FROM flows;

-- Total bytes and packets
SELECT
    formatReadableSize(sum(doctets)) AS total_bytes,
    formatReadableQuantity(sum(dpkts)) AS total_packets
FROM flows;

-- Data range
SELECT
    min(first) AS earliest_flow,
    max(last) AS latest_flow,
    dateDiff('day', min(first), max(last)) AS days_of_data
FROM flows;

-- Flows per day
SELECT
    toDate(first) AS date,
    count() AS flows,
    formatReadableSize(sum(doctets)) AS bytes
FROM flows
GROUP BY date
ORDER BY date DESC
LIMIT 30;

-- ============================================================
-- TOP TALKERS
-- ============================================================

-- Top 20 source IPs by bytes (last 24 hours)
SELECT
    srcaddr,
    count() AS flows,
    formatReadableSize(sum(doctets)) AS total_bytes,
    formatReadableQuantity(sum(dpkts)) AS total_packets
FROM flows
WHERE first >= now() - INTERVAL 24 HOUR
GROUP BY srcaddr
ORDER BY sum(doctets) DESC
LIMIT 20;

-- Top 20 destination IPs by bytes (last 24 hours)
SELECT
    dstaddr,
    count() AS flows,
    formatReadableSize(sum(doctets)) AS total_bytes,
    formatReadableQuantity(sum(dpkts)) AS total_packets
FROM flows
WHERE first >= now() - INTERVAL 24 HOUR
GROUP BY dstaddr
ORDER BY sum(doctets) DESC
LIMIT 20;

-- Top conversations (src->dst pairs)
SELECT
    srcaddr,
    dstaddr,
    count() AS flows,
    formatReadableSize(sum(doctets)) AS total_bytes
FROM flows
WHERE first >= now() - INTERVAL 24 HOUR
GROUP BY srcaddr, dstaddr
ORDER BY sum(doctets) DESC
LIMIT 20;

-- Using materialized view for better performance
SELECT
    srcaddr,
    formatReadableSize(sum(total_bytes_sent)) AS bytes,
    sum(flow_count) AS flows
FROM flows_top_talkers_hourly_mv
WHERE bucket >= now() - INTERVAL 24 HOUR
GROUP BY srcaddr
ORDER BY sum(total_bytes_sent) DESC
LIMIT 20;

-- ============================================================
-- PROTOCOL ANALYSIS
-- ============================================================

-- Traffic by protocol (last 24 hours)
SELECT
    protocol,
    CASE protocol
        WHEN 1 THEN 'ICMP'
        WHEN 6 THEN 'TCP'
        WHEN 17 THEN 'UDP'
        WHEN 47 THEN 'GRE'
        WHEN 50 THEN 'ESP'
        WHEN 51 THEN 'AH'
        ELSE toString(protocol)
    END AS protocol_name,
    count() AS flows,
    formatReadableSize(sum(doctets)) AS total_bytes,
    round(sum(doctets) * 100.0 / (SELECT sum(doctets) FROM flows WHERE first >= now() - INTERVAL 24 HOUR), 2) AS percent
FROM flows
WHERE first >= now() - INTERVAL 24 HOUR
GROUP BY protocol
ORDER BY sum(doctets) DESC;

-- Using materialized view
SELECT
    protocol,
    sum(flow_count) AS flows,
    formatReadableSize(sum(total_bytes)) AS bytes
FROM flows_protocol_hourly_mv
WHERE bucket >= now() - INTERVAL 24 HOUR
GROUP BY protocol
ORDER BY sum(total_bytes) DESC;

-- ============================================================
-- PORT ANALYSIS
-- ============================================================

-- Top destination ports by traffic
SELECT
    dstport,
    protocol,
    count() AS flows,
    formatReadableSize(sum(doctets)) AS total_bytes,
    uniq(srcaddr) AS unique_sources,
    uniq(dstaddr) AS unique_destinations
FROM flows
WHERE first >= now() - INTERVAL 24 HOUR
  AND dstport > 0
GROUP BY dstport, protocol
ORDER BY sum(doctets) DESC
LIMIT 30;

-- Well-known services
SELECT
    dstport,
    CASE dstport
        WHEN 20 THEN 'FTP-DATA'
        WHEN 21 THEN 'FTP'
        WHEN 22 THEN 'SSH'
        WHEN 23 THEN 'TELNET'
        WHEN 25 THEN 'SMTP'
        WHEN 53 THEN 'DNS'
        WHEN 80 THEN 'HTTP'
        WHEN 110 THEN 'POP3'
        WHEN 143 THEN 'IMAP'
        WHEN 443 THEN 'HTTPS'
        WHEN 3389 THEN 'RDP'
        WHEN 3306 THEN 'MySQL'
        WHEN 5432 THEN 'PostgreSQL'
        WHEN 6379 THEN 'Redis'
        WHEN 27017 THEN 'MongoDB'
        ELSE 'OTHER'
    END AS service,
    count() AS flows,
    formatReadableSize(sum(doctets)) AS bytes
FROM flows
WHERE first >= now() - INTERVAL 24 HOUR
  AND dstport IN (20,21,22,23,25,53,80,110,143,443,3389,3306,5432,6379,27017)
GROUP BY dstport
ORDER BY sum(doctets) DESC;

-- Using materialized view
SELECT
    dstport,
    sum(flow_count) AS flows,
    formatReadableSize(sum(total_bytes)) AS bytes,
    sum(unique_sources) AS unique_sources
FROM flows_dstport_hourly_mv
WHERE bucket >= now() - INTERVAL 24 HOUR
GROUP BY dstport
ORDER BY sum(total_bytes) DESC
LIMIT 30;

-- ============================================================
-- TIME-BASED ANALYSIS
-- ============================================================

-- Traffic by hour (last 24 hours)
SELECT
    toStartOfHour(first) AS hour,
    count() AS flows,
    formatReadableSize(sum(doctets)) AS bytes,
    formatReadableQuantity(sum(dpkts)) AS packets
FROM flows
WHERE first >= now() - INTERVAL 24 HOUR
GROUP BY hour
ORDER BY hour;

-- Traffic by 5-minute intervals (last 2 hours)
SELECT
    toStartOfFiveMinutes(first) AS interval,
    count() AS flows,
    formatReadableSize(sum(doctets)) AS bytes
FROM flows
WHERE first >= now() - INTERVAL 2 HOUR
GROUP BY interval
ORDER BY interval;

-- Peak traffic time
SELECT
    toStartOfHour(first) AS hour,
    sum(doctets) AS bytes
FROM flows
WHERE first >= now() - INTERVAL 7 DAY
GROUP BY hour
ORDER BY bytes DESC
LIMIT 10;

-- ============================================================
-- INTERFACE ANALYSIS
-- ============================================================

-- Traffic by input interface
SELECT
    input AS interface,
    count() AS flows,
    formatReadableSize(sum(doctets)) AS bytes_in
FROM flows
WHERE first >= now() - INTERVAL 24 HOUR
GROUP BY interface
ORDER BY sum(doctets) DESC
LIMIT 20;

-- Traffic by output interface
SELECT
    output AS interface,
    count() AS flows,
    formatReadableSize(sum(doctets)) AS bytes_out
FROM flows
WHERE first >= now() - INTERVAL 24 HOUR
GROUP BY interface
ORDER BY sum(doctets) DESC
LIMIT 20;

-- Interface traffic matrix (in vs out)
SELECT
    input,
    output,
    count() AS flows,
    formatReadableSize(sum(doctets)) AS bytes
FROM flows
WHERE first >= now() - INTERVAL 24 HOUR
GROUP BY input, output
ORDER BY sum(doctets) DESC
LIMIT 30;

-- ============================================================
-- AUTONOMOUS SYSTEM (AS) ANALYSIS
-- ============================================================

-- Traffic by source AS
SELECT
    src_as,
    count() AS flows,
    formatReadableSize(sum(doctets)) AS bytes
FROM flows
WHERE first >= now() - INTERVAL 24 HOUR
  AND src_as > 0
GROUP BY src_as
ORDER BY sum(doctets) DESC
LIMIT 20;

-- Traffic by destination AS
SELECT
    dst_as,
    count() AS flows,
    formatReadableSize(sum(doctets)) AS bytes
FROM flows
WHERE first >= now() - INTERVAL 24 HOUR
  AND dst_as > 0
GROUP BY dst_as
ORDER BY sum(doctets) DESC
LIMIT 20;

-- AS pair traffic matrix
SELECT
    src_as,
    dst_as,
    count() AS flows,
    formatReadableSize(sum(doctets)) AS bytes
FROM flows
WHERE first >= now() - INTERVAL 24 HOUR
  AND (src_as > 0 OR dst_as > 0)
GROUP BY src_as, dst_as
ORDER BY sum(doctets) DESC
LIMIT 30;

-- Using materialized view
SELECT
    src_as,
    dst_as,
    sum(flow_count) AS flows,
    formatReadableSize(sum(total_bytes)) AS bytes
FROM flows_as_hourly_mv
WHERE bucket >= now() - INTERVAL 24 HOUR
GROUP BY src_as, dst_as
ORDER BY sum(total_bytes) DESC
LIMIT 30;

-- ============================================================
-- TRAFFIC PATTERN ANALYSIS
-- ============================================================

-- Small packets (potential DoS/scanning)
SELECT
    srcaddr,
    dstaddr,
    count() AS flows,
    sum(dpkts) AS packets,
    sum(doctets) AS bytes,
    round(sum(doctets) / sum(dpkts), 2) AS avg_packet_size
FROM flows
WHERE first >= now() - INTERVAL 1 HOUR
  AND dpkts > 0
GROUP BY srcaddr, dstaddr
HAVING avg_packet_size < 100
ORDER BY flows DESC
LIMIT 20;

-- Long-duration flows
SELECT
    srcaddr,
    dstaddr,
    srcport,
    dstport,
    first,
    last,
    dateDiff('second', first, last) AS duration_seconds,
    formatReadableSize(doctets) AS bytes
FROM flows
WHERE first >= now() - INTERVAL 24 HOUR
  AND dateDiff('second', first, last) > 3600  -- flows longer than 1 hour
ORDER BY duration_seconds DESC
LIMIT 20;

-- High packet rate flows
SELECT
    srcaddr,
    dstaddr,
    protocol,
    dpkts AS packets,
    dateDiff('second', first, last) AS duration_seconds,
    CASE
        WHEN duration_seconds > 0 THEN dpkts / duration_seconds
        ELSE 0
    END AS packets_per_second
FROM flows
WHERE first >= now() - INTERVAL 1 HOUR
  AND dateDiff('second', first, last) > 0
ORDER BY packets_per_second DESC
LIMIT 20;

-- ============================================================
-- SECURITY ANALYSIS
-- ============================================================

-- Potential port scanning (many dst ports, few packets each)
SELECT
    srcaddr,
    count(DISTINCT dstport) AS unique_ports,
    count() AS flows,
    sum(dpkts) AS total_packets,
    round(sum(dpkts) / count(), 2) AS avg_packets_per_flow
FROM flows
WHERE first >= now() - INTERVAL 1 HOUR
GROUP BY srcaddr
HAVING unique_ports > 50 AND avg_packets_per_flow < 10
ORDER BY unique_ports DESC
LIMIT 20;

-- Unusual high ports (potential backdoors)
SELECT
    dstport,
    count() AS flows,
    uniq(srcaddr) AS unique_sources,
    formatReadableSize(sum(doctets)) AS bytes
FROM flows
WHERE first >= now() - INTERVAL 24 HOUR
  AND dstport > 40000
GROUP BY dstport
ORDER BY flows DESC
LIMIT 20;

-- TCP SYN flood detection (SYN flag without ACK)
SELECT
    srcaddr,
    dstaddr,
    count() AS syn_count
FROM flows
WHERE first >= now() - INTERVAL 1 HOUR
  AND protocol = 6  -- TCP
  AND bitAnd(tcp_flags, 2) != 0  -- SYN flag set
  AND bitAnd(tcp_flags, 16) = 0  -- ACK flag not set
GROUP BY srcaddr, dstaddr
HAVING syn_count > 100
ORDER BY syn_count DESC
LIMIT 20;

-- ============================================================
-- EXPORTER ANALYSIS
-- ============================================================

-- Traffic by exporter
SELECT
    IPv4NumToString(exporter) AS exporter_ip,
    count() AS flows,
    formatReadableSize(sum(doctets)) AS bytes
FROM flows
WHERE first >= now() - INTERVAL 24 HOUR
GROUP BY exporter
ORDER BY sum(doctets) DESC;

-- Flows per exporter per hour
SELECT
    toStartOfHour(first) AS hour,
    IPv4NumToString(exporter) AS exporter_ip,
    count() AS flows
FROM flows
WHERE first >= now() - INTERVAL 24 HOUR
GROUP BY hour, exporter
ORDER BY hour, flows DESC;

-- ============================================================
-- COMPARISON QUERIES
-- ============================================================

-- Compare traffic today vs yesterday
WITH
    today AS (
        SELECT sum(doctets) AS bytes
        FROM flows
        WHERE toDate(first) = today()
    ),
    yesterday AS (
        SELECT sum(doctets) AS bytes
        FROM flows
        WHERE toDate(first) = yesterday()
    )
SELECT
    formatReadableSize(today.bytes) AS today_bytes,
    formatReadableSize(yesterday.bytes) AS yesterday_bytes,
    round((today.bytes - yesterday.bytes) * 100.0 / yesterday.bytes, 2) AS percent_change
FROM today, yesterday;

-- Top talkers comparison (last hour vs previous hour)
WITH
    last_hour AS (
        SELECT srcaddr, sum(doctets) AS bytes
        FROM flows
        WHERE first >= now() - INTERVAL 1 HOUR
        GROUP BY srcaddr
    ),
    prev_hour AS (
        SELECT srcaddr, sum(doctets) AS bytes
        FROM flows
        WHERE first >= now() - INTERVAL 2 HOUR
          AND first < now() - INTERVAL 1 HOUR
        GROUP BY srcaddr
    )
SELECT
    coalesce(last_hour.srcaddr, prev_hour.srcaddr) AS srcaddr,
    formatReadableSize(coalesce(last_hour.bytes, 0)) AS last_hour_bytes,
    formatReadableSize(coalesce(prev_hour.bytes, 0)) AS prev_hour_bytes,
    round((coalesce(last_hour.bytes, 0) - coalesce(prev_hour.bytes, 0)) * 100.0 / greatest(prev_hour.bytes, 1), 2) AS percent_change
FROM last_hour
FULL OUTER JOIN prev_hour ON last_hour.srcaddr = prev_hour.srcaddr
ORDER BY coalesce(last_hour.bytes, 0) DESC
LIMIT 20;

-- ============================================================
-- AGGREGATED VIEWS EXAMPLES
-- ============================================================

-- Query 5-minute aggregated data for better performance
SELECT
    bucket,
    srcaddr,
    dstaddr,
    sum(total_bytes) AS bytes,
    sum(flow_count) AS flows
FROM flows_5minute_mv
WHERE bucket >= now() - INTERVAL 2 HOUR
GROUP BY bucket, srcaddr, dstaddr
ORDER BY bytes DESC
LIMIT 20;

-- Hourly traffic trend (last 7 days)
SELECT
    toStartOfHour(bucket) AS hour,
    sum(total_bytes) AS bytes,
    sum(flow_count) AS flows
FROM flows_hourly_mv
WHERE bucket >= now() - INTERVAL 7 DAY
GROUP BY hour
ORDER BY hour;

-- Daily traffic summary (last 30 days)
SELECT
    toDate(bucket) AS date,
    formatReadableSize(sum(total_bytes)) AS bytes,
    sum(flow_count) AS flows
FROM flows_daily_mv
WHERE bucket >= now() - INTERVAL 30 DAY
GROUP BY date
ORDER BY date DESC;
