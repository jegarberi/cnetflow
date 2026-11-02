-- Migration for existing databases: parsed IPv4 columns used by cnetflow-web for fast direction checks.
-- Safe to re-run. The collector does not need to change (it names its INSERT columns explicitly).
ALTER TABLE flows
    ADD COLUMN IF NOT EXISTS src_ip4 UInt32 MATERIALIZED toUInt32(toIPv4OrZero(srcaddr)),
    ADD COLUMN IF NOT EXISTS dst_ip4 UInt32 MATERIALIZED toUInt32(toIPv4OrZero(dstaddr));
-- Fill the columns for rows inserted before the migration (runs in the background).
ALTER TABLE flows MATERIALIZE COLUMN src_ip4;
ALTER TABLE flows MATERIALIZE COLUMN dst_ip4;
