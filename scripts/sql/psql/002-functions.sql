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


create function get_flows() returns record
    language plpgsql
as
$$
BEGIN
    select int2inet(srcaddr)                                                                              as srcaddr,
           int2port(srcport)                                                                              as srcport,
           int2inet(dstaddr)                                                                              as dstaddr,
           int2port(dstport)                                                                              as dstport,
           ascii(prot),
           input,
           output,
           sum(doctets)                                                                                   as octets,
           sum(dpkts)                                                                                     as dpkts,
           (CASE when first < 0 then (cast(first as bigint) + (4294967296::bigint)) / 100 else first end) as first,
           (CASE when last < 0 then (cast(last as bigint) + (4294967296::bigint)) / 100 else last end)    as last
    from flows
    group by srcaddr, srcport, dstaddr, dstport, prot, first, last, input, output
    order by first desc, dstaddr, dstport, prot;
END;
$$;

create function get_flow() returns record
    language plpgsql
as
$$
DECLARE
    ret RECORD;
BEGIN
    select int2inet(srcaddr)                                                                              as srcaddr,
           int2port(srcport)                                                                              as srcport,
           int2inet(dstaddr)                                                                              as dstaddr,
           int2port(dstport)                                                                              as dstport,
           ascii(prot)                                                                                    as prot,
           input,
           output,
           sum(doctets)                                                                                   as octets,
           sum(dpkts)                                                                                     as dpkts,
           (CASE when first < 0 then (cast(first as bigint) + (4294967296::bigint)) / 100 else first end) as first,
           (CASE when last < 0 then (cast(last as bigint) + (4294967296::bigint)) / 100 else last end)    as last
    from flows
    group by srcaddr, srcport, dstaddr, dstport, prot, first, last, input, output
    order by first desc, dstaddr, dstport, prot
    limit 1
    into ret;
    RETURN ret;
END;
$$;



CREATE OR REPLACE PROCEDURE extract_and_insert_unique_interfaces_5min()
    LANGUAGE plpgsql
AS
$$
DECLARE
    iface_record RECORD;
    exporter_id  BIGINT;
BEGIN
    -- For each unique exporter::input
    FOR iface_record IN
        SELECT DISTINCT e.id    AS exporter_id,
                        f.input AS snmp_index
        FROM flows_agg_5min f
                 JOIN exporters e ON e.ip_inet = f.exporter
        WHERE f.input IS NOT NULL
          AND f.input > 0
        LOOP
            -- Insert if it doesn't exist
            INSERT INTO interfaces (created_at, exporter, snmp_index)
            SELECT now(), iface_record.exporter_id, iface_record.snmp_index
            WHERE NOT EXISTS (SELECT 1
                              FROM interfaces
                              WHERE exporter = iface_record.exporter_id
                                AND snmp_index = iface_record.snmp_index);
        END LOOP;

    -- For each unique exporter::output
    FOR iface_record IN
        SELECT DISTINCT e.id     AS exporter_id,
                        f.output AS snmp_index
        FROM flows_agg_5min f
                 JOIN exporters e ON e.ip_inet = f.exporter
        WHERE f.output IS NOT NULL
          AND f.output > 0
        LOOP
            -- Insert if it doesn't exist
            INSERT INTO interfaces (created_at, exporter, snmp_index)
            SELECT now(), iface_record.exporter_id, iface_record.snmp_index
            WHERE NOT EXISTS (SELECT 1
                              FROM interfaces
                              WHERE exporter = iface_record.exporter_id
                                AND snmp_index = iface_record.snmp_index);
        END LOOP;
END;
$$;



CREATE OR REPLACE PROCEDURE import_flows_agg_5min()
    LANGUAGE plpgsql
AS
$$
DECLARE
    min_first_time  timestamp;
    v_error_state   TEXT;
    v_error_msg     TEXT;
    v_error_detail  TEXT;
    v_error_hint    TEXT;
    v_error_context TEXT;
BEGIN
    -- Get the oldest timestamp to process (limit scope to avoid full table scan)
    SELECT MIN(first)
    INTO min_first_time
    FROM flows
    -- WHERE first < NOW() - INTERVAL '5 days'
    LIMIT 1;

    -- Exit early if nothing to process
    IF min_first_time IS NULL THEN
        RETURN;
    END IF;

    -- Process in small batches: aggregate only the oldest 5-minute bucket
    WITH to_process AS (SELECT *
                        FROM flows
                        WHERE first >= min_first_time
                          AND first < min_first_time + INTERVAL '30 minutes'
                          AND (last - first) <= INTERVAL '5 minutes'),
         aggregated AS (SELECT time_bucket('5 minutes', first) AS bucket_5min,
                               exporter,
                               srcaddr,
                               dstaddr,
                               srcport,
                               dstport,
                               prot,
                               src_as,
                               dst_as,
                               input,
                               output,
                               SUM(dpkts)::bigint              AS total_packets,
                               SUM(doctets)::bigint            AS total_octets,
                               ip_version,
                               tos,
                               ENCODE(
                                       SHA256(
                                               (
                                                   time_bucket('5 minutes', first)::TEXT || '|' ||
                                                   COALESCE(exporter::TEXT, '~~NULL_EXP~~') || '|' ||
                                                   COALESCE(srcaddr::TEXT, '~~NULL_SRC_ADDR~~') || '|' ||
                                                   COALESCE(dstaddr::TEXT, '~~NULL_DST_ADDR~~') || '|' ||
                                                   COALESCE(srcport::TEXT, '~~NULL_SRCPORT~~') || '|' ||
                                                   COALESCE(dstport::TEXT, '~~NULL_DSTPORT~~') || '|' ||
                                                   COALESCE(prot::TEXT, '~~NULL_PROT~~') || '|' ||
                                                   COALESCE(src_as::TEXT, '~~NULL_SRC_AS~~') || '|' ||
                                                   COALESCE(dst_as::TEXT, '~~NULL_DST_AS~~') || '|' ||
                                                   COALESCE(input::TEXT, '~~NULL_INPUT~~') || '|' ||
                                                   COALESCE(output::TEXT, '~~NULL_OUTPUT~~') || '|' ||
                                                   COALESCE(ip_version::TEXT, '~~NULL_IPVER~~') || '|' ||
                                                   COALESCE(tos::TEXT, '~~NULL_TOS~~')
                                                   )::BYTEA
                                       ),
                                       'hex'
                               )                               AS flow_hash,
                               array_agg(id)                   AS ids
                        FROM to_process
                        GROUP BY bucket_5min, exporter, srcaddr, dstaddr, srcport, dstport, prot,
                                 src_as, dst_as, input, output, ip_version, tos),
         inserted AS (
             INSERT INTO flows_agg_5min (bucket_5min, exporter, srcaddr, dstaddr,
                                         srcport, dstport, prot, src_as, dst_as, input, output,
                                         ip_version, total_packets, total_octets, tos, flow_hash)
                 SELECT bucket_5min,
                        exporter,
                        srcaddr,
                        dstaddr,
                        srcport,
                        dstport,
                        prot,
                        src_as,
                        dst_as,
                        input,
                        output,
                        ip_version,
                        total_packets,
                        total_octets,
                        tos,
                        flow_hash
                 FROM aggregated
                 ON CONFLICT (bucket_5min, exporter,flow_hash)
                     DO UPDATE SET total_packets = flows_agg_5min.total_packets + EXCLUDED.total_packets,
                         total_octets = flows_agg_5min.total_octets + EXCLUDED.total_octets
                 RETURNING 1),
         ids_to_delete AS (SELECT DISTINCT unnest(ids) AS id
                           FROM aggregated)
    DELETE
    FROM flows
    WHERE id IN (SELECT id FROM ids_to_delete);

EXCEPTION
    WHEN OTHERS THEN
        GET STACKED DIAGNOSTICS
            v_error_state = RETURNED_SQLSTATE,
            v_error_msg = MESSAGE_TEXT,
            v_error_detail = PG_EXCEPTION_DETAIL,
            v_error_hint = PG_EXCEPTION_HINT,
            v_error_context = PG_EXCEPTION_CONTEXT;

        RAISE WARNING 'ROLLBACK in import_flows_agg_5min() - SQLSTATE: %, Message: %, Detail: %, Hint: %, Context: %',
            v_error_state, v_error_msg, v_error_detail, v_error_hint, v_error_context;

        RAISE;
END;
$$;

CREATE OR REPLACE PROCEDURE import_flows_agg_5min_segmented()
    LANGUAGE plpgsql
AS
$$
DECLARE
    min_first_time  timestamp;
    v_error_state   TEXT;
    v_error_msg     TEXT;
    v_error_detail  TEXT;
    v_error_hint    TEXT;
    v_error_context TEXT;
BEGIN
    -- Get the oldest timestamp to process (limit scope to avoid full table scan)
    SELECT MIN(first)
    INTO min_first_time
    FROM flows
    WHERE (last - first) > INTERVAL '5 minutes'
    LIMIT 1;

    -- Exit early if nothing to process
    IF min_first_time IS NULL THEN
        RETURN;
    END IF;

    -- Process flows that span multiple 5-minute buckets
    WITH to_process AS (SELECT *
                        FROM flows
                        WHERE first >= min_first_time
                          AND first < min_first_time + INTERVAL '30 minutes'
                          AND (last - first) > INTERVAL '5 minutes'),
         -- Generate all 5-minute buckets that each flow spans
         flow_buckets AS (SELECT f.*,
                                 time_bucket('5 minutes', bucket_start)                                 AS bucket_5min,
                                 -- Calculate the overlap between this bucket and the flow
                                 GREATEST(bucket_start, f.first)                                        AS segment_start,
                                 LEAST(bucket_end, f.last)                                              AS segment_end,
                                 -- Calculate the total flow duration in seconds
                                 EXTRACT(EPOCH FROM (f.last - f.first))                                 AS total_duration_sec,
                                 -- Calculate this segment's duration in seconds
                                 EXTRACT(EPOCH FROM
                                         (LEAST(bucket_end, f.last) - GREATEST(bucket_start, f.first))) AS segment_duration_sec
                          FROM to_process f
                                   CROSS JOIN LATERAL (
                              SELECT generate_series(
                                             time_bucket('5 minutes', f.first),
                                             time_bucket('5 minutes', f.last),
                                             INTERVAL '5 minutes'
                                     ) AS bucket_start
                              ) buckets
                                   CROSS JOIN LATERAL (
                              SELECT bucket_start + INTERVAL '5 minutes' AS bucket_end
                              ) bucket_bounds
                          WHERE GREATEST(bucket_start, f.first) < LEAST(bucket_end, f.last)),
         -- Distribute octets and packets proportionally across segments
         segmented AS (SELECT bucket_5min,
                              exporter,
                              srcaddr,
                              dstaddr,
                              srcport,
                              dstport,
                              prot,
                              src_as,
                              dst_as,
                              input,
                              output,
                              ip_version,
                              tos,
                              -- Proportionally allocate packets (ensure sum equals original)
                              CASE
                                  WHEN total_duration_sec > 0 THEN
                                      ROUND((dpkts * segment_duration_sec / total_duration_sec)::numeric, 0)::bigint
                                  ELSE dpkts
                                  END                                                       AS allocated_packets,
                              -- Proportionally allocate octets (ensure sum equals original)
                              CASE
                                  WHEN total_duration_sec > 0 THEN
                                      ROUND((doctets * segment_duration_sec / total_duration_sec)::numeric, 0)::bigint
                                  ELSE doctets
                                  END                                                       AS allocated_octets,
                              id,
                              ROW_NUMBER() OVER (PARTITION BY id ORDER BY bucket_5min DESC) as segment_num,
                              COUNT(*) OVER (PARTITION BY id)                               as total_segments,
                              dpkts                                                         as original_packets,
                              doctets                                                       as original_octets
                       FROM flow_buckets),
         -- Adjust the first segment to account for rounding errors
         adjusted_segments AS (SELECT bucket_5min,
                                      exporter,
                                      srcaddr,
                                      dstaddr,
                                      srcport,
                                      dstport,
                                      prot,
                                      src_as,
                                      dst_as,
                                      input,
                                      output,
                                      ip_version,
                                      tos,
                                      -- Adjust last segment to ensure exact sum
                                      CASE
                                          WHEN segment_num = 1 THEN
                                              original_packets -
                                              (SUM(allocated_packets) OVER (PARTITION BY id) - allocated_packets)
                                          ELSE allocated_packets
                                          END AS final_packets,
                                      CASE
                                          WHEN segment_num = 1 THEN
                                              original_octets -
                                              (SUM(allocated_octets) OVER (PARTITION BY id) - allocated_octets)
                                          ELSE allocated_octets
                                          END AS final_octets,
                                      id
                               FROM segmented),
         aggregated AS (SELECT bucket_5min,
                               exporter,
                               srcaddr,
                               dstaddr,
                               srcport,
                               dstport,
                               prot,
                               src_as,
                               dst_as,
                               input,
                               output,
                               ip_version,
                               tos,
                               SUM(final_packets)::bigint AS total_packets,
                               SUM(final_octets)::bigint  AS total_octets,
                               ENCODE(
                                       SHA256(
                                               (
                                                   bucket_5min::TEXT || '|' ||
                                                   COALESCE(exporter::TEXT, '~~NULL_EXP~~') || '|' ||
                                                   COALESCE(srcaddr::TEXT, '~~NULL_SRC_ADDR~~') || '|' ||
                                                   COALESCE(dstaddr::TEXT, '~~NULL_DST_ADDR~~') || '|' ||
                                                   COALESCE(srcport::TEXT, '~~NULL_SRCPORT~~') || '|' ||
                                                   COALESCE(dstport::TEXT, '~~NULL_DSTPORT~~') || '|' ||
                                                   COALESCE(prot::TEXT, '~~NULL_PROT~~') || '|' ||
                                                   COALESCE(src_as::TEXT, '~~NULL_SRC_AS~~') || '|' ||
                                                   COALESCE(dst_as::TEXT, '~~NULL_DST_AS~~') || '|' ||
                                                   COALESCE(input::TEXT, '~~NULL_INPUT~~') || '|' ||
                                                   COALESCE(output::TEXT, '~~NULL_OUTPUT~~') || '|' ||
                                                   COALESCE(ip_version::TEXT, '~~NULL_IPVER~~') || '|' ||
                                                   COALESCE(tos::TEXT, '~~NULL_TOS~~')
                                                   )::BYTEA
                                       ),
                                       'hex'
                               )                          AS flow_hash,
                               array_agg(id)              AS ids
                        FROM adjusted_segments
                        GROUP BY bucket_5min, exporter, srcaddr, dstaddr, srcport, dstport, prot,
                                 src_as, dst_as, input, output, ip_version, tos),
         inserted AS (
             INSERT INTO flows_agg_5min (bucket_5min, exporter, srcaddr, dstaddr,
                                         srcport, dstport, prot, src_as, dst_as, input, output,
                                         ip_version, total_packets, total_octets, tos, flow_hash)
                 SELECT bucket_5min,
                        exporter,
                        srcaddr,
                        dstaddr,
                        srcport,
                        dstport,
                        prot,
                        src_as,
                        dst_as,
                        input,
                        output,
                        ip_version,
                        total_packets,
                        total_octets,
                        tos,
                        flow_hash
                 FROM aggregated
                 ON CONFLICT (bucket_5min, exporter, flow_hash)
                     DO UPDATE SET total_packets = flows_agg_5min.total_packets + EXCLUDED.total_packets,
                         total_octets = flows_agg_5min.total_octets + EXCLUDED.total_octets
                 RETURNING 1),
         ids_to_delete AS (SELECT DISTINCT unnest(ids) AS id
                           FROM aggregated)
    DELETE
    FROM flows
    WHERE id IN (SELECT id FROM ids_to_delete);

EXCEPTION
    WHEN OTHERS THEN
        GET STACKED DIAGNOSTICS
            v_error_state = RETURNED_SQLSTATE,
            v_error_msg = MESSAGE_TEXT,
            v_error_detail = PG_EXCEPTION_DETAIL,
            v_error_hint = PG_EXCEPTION_HINT,
            v_error_context = PG_EXCEPTION_CONTEXT;

        RAISE WARNING 'ROLLBACK in import_flows_agg_5min_segmented() - SQLSTATE: %, Message: %, Detail: %, Hint: %, Context: %',
            v_error_state, v_error_msg, v_error_detail, v_error_hint, v_error_context;

        RAISE;
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


SELECT cron.schedule('*/4 * * * *', $$call import_exporters()$$);
SELECT cron.schedule('*/1 * * * *', $$call import_flows_agg_5min()$$);
SELECT cron.schedule('*/1 * * * *', $$call import_flows_agg_5min_segmented()$$);
SELECT cron.schedule('*/5 * * * *', $$call extract_and_insert_unique_interfaces_5min()$$);

