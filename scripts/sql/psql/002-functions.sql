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

drop function if exists import_exporters_v5();
drop procedure if exists import_exporters_v5();
create procedure import_exporters_v5()
    language plpgsql
as
$$
BEGIN
    insert into exporters (name, ip_bin, ip_inet)
    select int2inet(exporter)::text, exporter, int2inet(exporter)
    FROM (select distinct exporter
          from flows_v5) flows
    WHERE NOT EXISTS (SELECT 1
                      FROM exporters e
                      WHERE e.ip_bin = flows.exporter);

    -- insert into importers (name, ip, port);
END;
$$;

call import_exporters_v5();
drop function if exists import_exporters_v9();
drop procedure if exists import_exporters_v9();
create procedure import_exporters_v9()
    language plpgsql
as
$$
BEGIN
    insert into exporters (name, ip_bin, ip_inet)
    select int2inet(exporter)::text, exporter, int2inet(exporter)
    FROM (select distinct exporter
          from flows_v9) flows
    WHERE NOT EXISTS (SELECT 1
                      FROM exporters e
                      WHERE e.ip_bin = flows.exporter);

    -- insert into importers (name, ip, port);
END;
$$;


DROP PROCEDURE IF EXISTS import_flows_v9_agg_30min();
CREATE PROCEDURE import_flows_v9_agg_30min()
    LANGUAGE plpgsql
AS
$$
BEGIN
    INSERT INTO flows_v9_agg_30min (bucket_30min,
                                    exporter,
                                    srcaddr,
                                    dstaddr,
                                    srcport,
                                    dstport,
                                    protocol,
                                    input,
                                    output,
                                    total_packets,
                                    total_octets)
    SELECT time_bucket('30 minutes', bucket_5min) AS bucket_30min,
           exporter,
           srcaddr,
           dstaddr,
           srcport,
           dstport,
           protocol,
           input,
           output,
           SUM(total_packets)                     AS total_packets,
           SUM(total_octets)                      AS total_octets
    FROM flows_v9_agg_5min
    WHERE time_bucket('30 minutes', bucket_5min) = time_bucket('30 minutes', now())
    GROUP BY bucket_30min,
             exporter,
             srcaddr,
             dstaddr,
             srcport,
             dstport,
             protocol,
             input,
             output
    ORDER BY bucket_30min DESC;

    -- Delete the aggregated data from the 5-minute table
    DELETE
    FROM flows_v9_agg_5min
    WHERE time_bucket('30 minutes', bucket_5min) = time_bucket('30 minutes', now() - INTERVAL '7 days');
END;
$$;



DROP PROCEDURE IF EXISTS import_flows_v5_agg_30min();
CREATE PROCEDURE import_flows_v5_agg_30min()
    LANGUAGE plpgsql
AS
$$
BEGIN
    INSERT INTO flows_v5_agg_30min (bucket_30min,
                                    exporter,
                                    srcaddr,
                                    dstaddr,
                                    srcport,
                                    dstport,
                                    protocol,
                                    input,
                                    output,
                                    total_packets,
                                    total_octets)
    SELECT time_bucket('30 minutes', bucket_5min) AS bucket_30min,
           exporter,
           srcaddr,
           dstaddr,
           srcport,
           dstport,
           protocol,
           input,
           output,
           SUM(total_packets)                     AS total_packets,
           SUM(total_octets)                      AS total_octets
    FROM flows_v5_agg_5min
    WHERE time_bucket('30 minutes', bucket_5min) = time_bucket('30 minutes', now())
    GROUP BY bucket_30min,
             exporter,
             srcaddr,
             dstaddr,
             srcport,
             dstport,
             protocol,
             input,
             output
    ORDER BY bucket_30min DESC;

    -- Delete the aggregated data from the 5-minute table
    DELETE
    FROM flows_v9_agg_5min
    WHERE time_bucket('30 minutes', bucket_5min) = time_bucket('30 minutes', now() - INTERVAL '7 days');
END;
$$;



DROP PROCEDURE IF EXISTS import_flows_v9_agg_5min();
CREATE PROCEDURE import_flows_v9_agg_5min()
    LANGUAGE plpgsql
AS
$$
BEGIN
    INSERT INTO flows_v9_agg_5min (bucket_5min,
                                   exporter,
                                   srcaddr,
                                   dstaddr,
                                   srcport,
                                   dstport,
                                   protocol,
                                   input,
                                   output,
                                   total_packets,
                                   total_octets)
    SELECT time_bucket('5 minutes', to_timestamp(first)) AS bucket_5min,
           int2inet(exporter)                            AS exporter,
           int2inet(srcaddr)                             AS srcaddr,
           int2inet(dstaddr)                             AS dstaddr,
           int2port(srcport)                             AS srcport,
           int2port(dstport)                             AS dstport,
           ascii(prot)                                   AS protocol,
           input,
           output,
           SUM(dpkts)                                    AS total_packets,
           SUM(doctets)                                  AS total_octets
    FROM flows_v9
    WHERE time_bucket('5 minutes', to_timestamp(first)) = time_bucket('5 minutes', now())
    GROUP BY bucket_5min,
             exporter,
             srcaddr,
             dstaddr,
             srcport,
             dstport,
             prot,
             input,
             output,
             first
    ORDER BY bucket_5min DESC;
    -- Delete the just-aggregated rows from flows_v9
    DELETE
    FROM flows_v9
    WHERE time_bucket('5 minutes', to_timestamp(first)) = time_bucket('5 minutes', now() - INTERVAL '5 minutes');

END;
$$;



DROP PROCEDURE IF EXISTS import_flows_v5_agg_5min();
CREATE PROCEDURE import_flows_v5_agg_5min()
    LANGUAGE plpgsql
AS
$$
BEGIN
    INSERT INTO flows_v5_agg_5min (bucket_5min,
                                   exporter,
                                   srcaddr,
                                   dstaddr,
                                   srcport,
                                   dstport,
                                   protocol,
                                   input,
                                   output,
                                   total_packets,
                                   total_octets)
    SELECT time_bucket('5 minutes', to_timestamp(first)) AS bucket_5min,
           int2inet(exporter)                            AS exporter,
           int2inet(srcaddr)                             AS srcaddr,
           int2inet(dstaddr)                             AS dstaddr,
           int2port(srcport)                             AS srcport,
           int2port(dstport)                             AS dstport,
           ascii(prot)                                   AS protocol,
           input,
           output,
           SUM(dpkts)                                    AS total_packets,
           SUM(doctets)                                  AS total_octets
    FROM flows_v5
    WHERE time_bucket('5 minutes', to_timestamp(first)) = time_bucket('5 minutes', now())
    GROUP BY bucket_5min,
             exporter,
             srcaddr,
             dstaddr,
             srcport,
             dstport,
             prot,
             input,
             output,
             first
    ORDER BY bucket_5min DESC;
    -- Delete the just-aggregated rows from flows_v9
    DELETE
    FROM flows_v5
    WHERE time_bucket('5 minutes', to_timestamp(first)) = time_bucket('5 minutes', now() - INTERVAL '5 minutes');

END;
$$;



SELECT cron.schedule('*/5 * * * *', $$call import_exporters_v9()$$);
SELECT cron.schedule('*/5 * * * *', $$call import_exporters_v5()$$);
SELECT cron.schedule('*/1 * * * *', $$call import_flows_v5_agg_5min()$$);
SELECT cron.schedule('*/1 * * * *', $$call import_flows_v9_agg_5min()$$);
SELECT cron.schedule('*/15 * * * *', $$call import_flows_v5_agg_30min()$$);
SELECT cron.schedule('*/15 * * * *', $$call import_flows_v9_agg_30min()$$);
SELECT cron.schedule('0 * * * *', $$call import_flows_v9_agg_2hour()$$);
