-- ============================================================
-- TIMESCALEDB OPTIMIZATION POLICIES FOR FLOWS TABLE
-- ============================================================

-- 1. COMPRESSION POLICY: Automatically compress chunks older than 1 day
-- This significantly reduces storage while maintaining query performance
--SELECT add_compression_policy('flows', INTERVAL '10 minute');

-- 2. RETENTION POLICY: Automatically drop chunks older than 90 days
-- Adjust the retention period based on your requirements
SELECT add_retention_policy('flows', INTERVAL '30 days');

-- 3. Add useful indexes for common query patterns
CREATE INDEX idx_flows_first_exporter ON flows (first DESC, exporter);
CREATE INDEX idx_flows_srcaddr ON flows (srcaddr) WHERE srcaddr IS NOT NULL;
CREATE INDEX idx_flows_dstaddr ON flows (dstaddr) WHERE dstaddr IS NOT NULL;
CREATE INDEX idx_flows_prot ON flows (prot) WHERE prot IS NOT NULL;
CREATE INDEX idx_flows_srcport ON flows (srcport) WHERE srcport IS NOT NULL;
CREATE INDEX idx_flows_dstport ON flows (dstport) WHERE dstport IS NOT NULL;

-- 4. CONTINUOUS AGGREGATES for faster analytics queries
-- Hourly aggregation for recent data analysis
CREATE MATERIALIZED VIEW flows_hourly
            WITH (
            timescaledb.continuous = true
            )
AS
SELECT time_bucket('1 hour', first) AS bucket,
       exporter,
       srcaddr,
       dstaddr,
       srcport,
       dstport,
       prot,
       input,
       output,
       COUNT(*)                     as flow_count,
       SUM(dpkts)                   as total_packets,
       SUM(doctets)                 as total_bytes,
       MIN(first)                   as earliest_flow,
       MAX(last)                    as latest_flow
FROM flows
GROUP BY bucket, exporter, srcaddr, dstaddr, srcport, dstport, prot, input, output
WITH NO DATA;
ALTER MATERIALIZED VIEW flows_hourly SET (timescaledb.materialized_only = false);
ALTER MATERIALIZED VIEW flows_hourly SET ( timescaledb.enable_columnstore = true,timescaledb.compress_orderby = 'bucket DESC, flow_count DESC');

-- Daily aggregation for long-term trends
CREATE MATERIALIZED VIEW flows_daily
            WITH (
            timescaledb.continuous = true
            )
AS
SELECT time_bucket('1 day', first) AS bucket,
       exporter,
       srcaddr,
       dstaddr,
       prot,
       input,
       output,
       COUNT(*)                    as flow_count,
       SUM(dpkts)                  as total_packets,
       SUM(doctets)                as total_bytes
FROM flows
GROUP BY bucket, exporter, srcaddr, dstaddr, prot, input, output
WITH NO DATA;
ALTER MATERIALIZED VIEW flows_daily SET (timescaledb.materialized_only = false);
ALTER MATERIALIZED VIEW flows_daily SET ( timescaledb.enable_columnstore = true,timescaledb.compress_orderby = 'bucket DESC, flow_count DESC');
-- Top talkers by bytes - useful for traffic analysis
CREATE MATERIALIZED VIEW flows_top_talkers_hourly
            WITH (
            timescaledb.continuous = true
            )
AS
SELECT time_bucket('1 hour', first) AS bucket,
       exporter,
       srcaddr,
       dstaddr,
       input,
       output,
       SUM(doctets)                 as total_bytes_sent,
       COUNT(*)                     as flow_count
FROM flows
GROUP BY bucket, exporter, srcaddr, dstaddr, input, output
WITH NO DATA;
ALTER MATERIALIZED VIEW flows_top_talkers_hourly SET (timescaledb.materialized_only = false);
ALTER MATERIALIZED VIEW flows_top_talkers_hourly SET ( timescaledb.enable_columnstore = true,timescaledb.compress_orderby = 'bucket DESC, flow_count DESC');
-- 5. REFRESH POLICIES for continuous aggregates
-- Refresh hourly view every 15 minutes for recent data
SELECT add_continuous_aggregate_policy('flows_hourly',
                                       start_offset => INTERVAL '3 hours',
                                       end_offset => INTERVAL '5 minutes',
                                       schedule_interval => INTERVAL '15 minutes');
SELECT add_compression_policy('flows_hourly', INTERVAL '7 days');
-- Refresh daily view once per hour
SELECT add_continuous_aggregate_policy('flows_daily',
                                       start_offset => INTERVAL '7 days',
                                       end_offset => INTERVAL '1 hour',
                                       schedule_interval => INTERVAL '1 hour');

-- Refresh top talkers every 10 minutes
SELECT add_continuous_aggregate_policy('flows_top_talkers_hourly',
                                       start_offset => INTERVAL '5 hours',
                                       end_offset => INTERVAL '5 minutes',
                                       schedule_interval => INTERVAL '30 minutes');

-- 6. COMPRESSION POLICY for continuous aggregates
--SELECT add_compression_policy('flows_hourly', INTERVAL '7 days');
--SELECT add_compression_policy('flows_daily', INTERVAL '30 days');
--SELECT add_compression_policy('flows_top_talkers_hourly', INTERVAL '7 days');

-- 7. RETENTION POLICY for continuous aggregates (optional)
-- Keep hourly data for 30 days
SELECT add_retention_policy('flows_hourly', INTERVAL '30 days');
-- Keep daily data for 1 year
SELECT add_retention_policy('flows_daily', INTERVAL '365 days');
-- Keep top talkers for 30 days
SELECT add_retention_policy('flows_top_talkers_hourly', INTERVAL '30 days');

-- ============================================================
-- OPTIMIZATION FOR flows_agg_5min TABLE
-- ============================================================

-- Add compression policy for 5-minute aggregates
--SELECT add_compression_policy('flows_agg_5min', INTERVAL '1 day');

-- Add retention policy (adjust as needed)
--SELECT add_retention_policy('flows_agg_5min', INTERVAL '30 days');


create function int2inet(integer) returns inet
    immutable
    strict
    language plpgsql
as
$$
declare
    oct1 int;
    oct2
         int;
    oct3
         int;
    oct4
         int;
begin
    oct1
        := ((($1 >> 24) % 256) + 256) % 256;
    oct2
        := ((($1 >> 16) % 256) + 256) % 256;
    oct3
        := ((($1 >> 8) % 256) + 256) % 256;
    oct4
        := ((($1) % 256) + 256) % 256;
    return oct1 || '.' || oct2 || '.' || oct3 || '.' || oct4;
end
$$;

create function int2port(port smallint) returns numeric
    language plpgsql
as
$$
declare
    oct1 int;
    oct2
         int;
BEGIN
    oct1
        := ((($1 >> 8) % 256) + 256) % 256 * 256;
    oct2
        := ((($1) % 256) + 256) % 256;
    return oct1 + oct2;
END;
$$;

create function int4touint4(int_in integer) returns bigint
    language plpgsql
as
$$
declare
    oct1 int8;
    oct2
         int8;
    oct3
         int8;
    oct4
         int8;
begin
    oct1
        := ((($1 >> 24) % 256) + 256) * (256 * 256 * 256);
    oct2
        := ((($1 >> 16) % 256) + 256) * (256 * 256);
    oct3
        := ((($1 >> 8) % 256) + 256) * (256);
    oct4
        := ((($1) % 256) + 256);
    return oct1 + oct2 + oct3 + oct4;
end
$$;



CREATE OR REPLACE PROCEDURE extract_and_insert_unique_interfaces()
    LANGUAGE plpgsql
AS
$$
BEGIN
    -- Batch insert for both input and output interfaces
    INSERT INTO interfaces (created_at, exporter, snmp_index)
    SELECT DISTINCT now(), e.id, f.input
    FROM flows f
             JOIN exporters e ON e.ip_inet = f.exporter
    WHERE f.input IS NOT NULL
      AND f.input > 0
      AND f.inserted_at > NOW() - INTERVAL '1 day'
    UNION
    SELECT DISTINCT now(), e.id, f.output
    FROM flows f
             JOIN exporters e ON e.ip_inet = f.exporter
    WHERE f.output IS NOT NULL
      AND f.output > 0
      AND f.inserted_at > NOW() - INTERVAL '1 day'
    ON CONFLICT (exporter, snmp_index) DO NOTHING;
END;
$$;



create procedure import_exporters()
    language plpgsql
as
$$
BEGIN
    insert into exporters (name, ip_bin, ip_inet)
    select exporter, 0, exporter
    FROM (select distinct exporter
          from flows) flows
    WHERE NOT EXISTS (SELECT 1
                      FROM exporters e
                      WHERE e.ip_inet = flows.exporter);

    -- insert into importers (name, ip, port);
END;
$$;


--SELECT cron.schedule('*/4 * * * *', $$call import_exporters()$$);
--SELECT cron.schedule('*/1 * * * *', $$call import_flows_agg_5min()$$);
--SELECT cron.schedule('*/1 * * * *', $$call import_flows_agg_5min_segmented()$$);
--SELECT cron.schedule('*/5 * * * *', $$call extract_and_insert_unique_interfaces_5min()$$);

