#!/bin/bash
# Script to drop all materialized views

echo "Dropping ClickHouse materialized views..."

# You need to provide the password
if [ -z "$CH_PASSWORD" ]; then
    echo "Error: Set CH_PASSWORD environment variable"
    echo "Example: export CH_PASSWORD='your_password'"
    exit 1
fi

VIEWS=(
    "flows_5minute_mv"
    "flows_hourly_mv"
    "flows_daily_mv"
    "flows_top_talkers_hourly_mv"
    "flows_protocol_hourly_mv"
    "flows_dstport_hourly_mv"
    "flows_as_hourly_mv"
)

for view in "${VIEWS[@]}"; do
    echo "Dropping $view..."
    curl -s "http://127.0.0.1:8123/" --user "default:$CH_PASSWORD" --data "DROP TABLE IF EXISTS $view"
    echo ""
done

echo "Done! All materialized views dropped."
echo "Now run your application - the flows table will be created with exporter as String."
