create function int2inet(integer) returns inet immutable
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
:= ((($1 >>  8) % 256) + 256) % 256;
oct4
:= ((($1      ) % 256) + 256) % 256;
return oct1 || '.' || oct2 || '.' || oct3 || '.' || oct4;
end$$;

create function int2port(port smallint) returns numeric
    language plpgsql
as
$$declare oct1 int;
oct2
int;
BEGIN
oct1
:= ((($1 >>  8) % 256) + 256) % 256 * 256;
oct2
:= ((($1      ) % 256) + 256) % 256;
return oct1 + oct2;
END;$$;

create function int4touint4(int_in integer) returns bigint
    language plpgsql
as
$$declare oct1 int8;
oct2
int8;
oct3
int8;
oct4
int8;
begin
oct1
:= ((($1 >> 24) % 256) + 256) * (256*256*256);
oct2
:= ((($1 >> 16) % 256) + 256) * (256*256);
oct3
:= ((($1 >>  8) % 256) + 256) * (256);
oct4
:= ((($1      ) % 256) + 256) ;
return oct1 + oct2 + oct3 + oct4;
end$$;


create function get_flows() returns record
    language plpgsql
as
$$BEGIN
select int2inet(srcaddr) as srcaddr,
       int2port(srcport) as srcport,
       int2inet(dstaddr) as dstaddr,
       int2port(dstport) as dstport,
       ascii(prot), input, output, sum (doctets) as octets, sum (dpkts) as dpkts, (CASE when first < 0 then (cast (first as bigint)+(4294967296::bigint))/100 else first end) as first, (CASE when last < 0 then (cast (last as bigint)+(4294967296::bigint))/100 else last end) as last
from flows
group by srcaddr, srcport, dstaddr, dstport, prot, first, last, input, output
order by first desc, dstaddr, dstport, prot;
END;$$;

create function get_flow() returns record
    language plpgsql
as
$$DECLARE
  ret RECORD;
BEGIN
select int2inet(srcaddr) as srcaddr,
       int2port(srcport) as srcport,
       int2inet(dstaddr) as dstaddr,
       int2port(dstport) as dstport,
       ascii(prot) as prot, input, output, sum (doctets) as octets, sum (dpkts) as dpkts, (CASE when first < 0 then (cast (first as bigint)+(4294967296::bigint))/100 else first end) as first, (CASE when last < 0 then (cast (last as bigint)+(4294967296::bigint))/100 else last end) as last
from flows
group by srcaddr, srcport, dstaddr, dstport, prot, first, last, input, output
order by first desc, dstaddr, dstport, prot limit 1
into ret;
RETURN ret;
END;$$;

