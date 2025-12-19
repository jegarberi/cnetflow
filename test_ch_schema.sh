#!/bin/bash
# Test script to check ClickHouse schema

echo "Attempting to show table schema..."
echo ""

# Try with empty password
echo "=== Trying with empty password ==="
curl -s "http://127.0.0.1:8123/" --user "default:" --data "SHOW CREATE TABLE flows FORMAT Pretty"
echo ""

# Try to describe table
echo "=== Trying DESCRIBE ==="
curl -s "http://127.0.0.1:8123/" --user "default:" --data "DESCRIBE TABLE flows FORMAT Pretty"
echo ""

# List all columns
echo "=== Trying to list columns ==="
curl -s "http://127.0.0.1:8123/" --user "default:" --data "SELECT name, type FROM system.columns WHERE database='default' AND table='flows' FORMAT Pretty"
echo ""

echo "=== If you see authentication errors above, you need to set the password in CH_CONN_STRING ==="
