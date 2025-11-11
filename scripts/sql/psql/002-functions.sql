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
    max_first_time timestamp;
BEGIN
    -- Get the oldest timestamp to process (limit scope to avoid full table scan)
    SELECT MIN(first)
    INTO max_first_time
    FROM flows
    -- WHERE first < NOW() - INTERVAL '5 days'
    LIMIT 1;

    -- Exit early if nothing to process
    IF max_first_time IS NULL THEN
        RETURN;
    END IF;

    -- Process in small batches: aggregate only the oldest 5-minute bucket
    WITH to_process AS (SELECT *
                        FROM flows
                        WHERE first >= max_first_time
                          AND first < max_first_time + INTERVAL '5 minutes'
                        LIMIT 50000),
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
                 ON CONFLICT (flow_hash)
                     DO UPDATE SET total_packets = flows_agg_5min.total_packets + EXCLUDED.total_packets,
                         total_octets = flows_agg_5min.total_octets + EXCLUDED.total_octets
                 RETURNING 1),
         ids_to_delete AS (SELECT DISTINCT unnest(ids) AS id
                           FROM aggregated)
    DELETE
    FROM flows
    WHERE id IN (SELECT id FROM ids_to_delete);

    COMMIT;
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
SELECT cron.schedule('*/5 * * * *', $$call extract_and_insert_unique_interfaces_5min()$$);

