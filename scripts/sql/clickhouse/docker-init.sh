#!/bin/bash
# Runs once, on first start of the clickhouse container (empty data volume).
set -e
ch=(clickhouse client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD")
"${ch[@]}" -q "CREATE DATABASE IF NOT EXISTS netflow"
for f in /schema/001-tables.sql /schema/002-materialized-views.sql; do
  "${ch[@]}" --database netflow --multiquery < "$f"
done
