#!/bin/bash
# ============================================================
# CLICKHOUSE SETUP SCRIPT FOR NETFLOW COLLECTOR
# ============================================================
# This script automates the setup of ClickHouse database
# for the cnetflow NetFlow collector
# ============================================================

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
DEFAULT_HOST="localhost"
DEFAULT_PORT="9000"
DEFAULT_DATABASE="netflow"
DEFAULT_USER="default"
DEFAULT_PASSWORD=""

# Parse command line arguments
HOST="${1:-$DEFAULT_HOST}"
PORT="${2:-$DEFAULT_PORT}"
DATABASE="${3:-$DEFAULT_DATABASE}"
USER="${4:-$DEFAULT_USER}"
PASSWORD="${5:-$DEFAULT_PASSWORD}"

echo -e "${GREEN}===========================================================${NC}"
echo -e "${GREEN}ClickHouse NetFlow Database Setup${NC}"
echo -e "${GREEN}===========================================================${NC}"
echo ""
echo "Configuration:"
echo "  Host:     $HOST"
echo "  Port:     $PORT"
echo "  Database: $DATABASE"
echo "  User:     $USER"
echo ""

# Function to execute ClickHouse query
execute_query() {
    local query="$1"
    local description="$2"

    echo -e "${YELLOW}>>> $description${NC}"

    if [ -z "$PASSWORD" ]; then
        clickhouse-client \
            --host="$HOST" \
            --port="$PORT" \
            --user="$USER" \
            --query="$query"
    else
        clickhouse-client \
            --host="$HOST" \
            --port="$PORT" \
            --user="$USER" \
            --password="$PASSWORD" \
            --query="$query"
    fi

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ Success${NC}"
    else
        echo -e "${RED}✗ Failed${NC}"
        exit 1
    fi
    echo ""
}

# Function to execute SQL file
execute_file() {
    local file="$1"
    local description="$2"

    echo -e "${YELLOW}>>> $description${NC}"

    if [ ! -f "$file" ]; then
        echo -e "${RED}✗ File not found: $file${NC}"
        exit 1
    fi

    if [ -z "$PASSWORD" ]; then
        clickhouse-client \
            --host="$HOST" \
            --port="$PORT" \
            --user="$USER" \
            --database="$DATABASE" \
            < "$file"
    else
        clickhouse-client \
            --host="$HOST" \
            --port="$PORT" \
            --user="$USER" \
            --password="$PASSWORD" \
            --database="$DATABASE" \
            < "$file"
    fi

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ Success${NC}"
    else
        echo -e "${RED}✗ Failed${NC}"
        exit 1
    fi
    echo ""
}

# Check if clickhouse-client is installed
if ! command -v clickhouse-client &> /dev/null; then
    echo -e "${RED}Error: clickhouse-client not found${NC}"
    echo "Please install ClickHouse client:"
    echo "  Ubuntu/Debian: sudo apt-get install clickhouse-client"
    echo "  RHEL/CentOS:   sudo yum install clickhouse-client"
    exit 1
fi

# Test connection
echo -e "${YELLOW}Testing connection to ClickHouse...${NC}"
if [ -z "$PASSWORD" ]; then
    if ! clickhouse-client --host="$HOST" --port="$PORT" --user="$USER" --query="SELECT 1" &> /dev/null; then
        echo -e "${RED}✗ Cannot connect to ClickHouse server${NC}"
        echo "Please check:"
        echo "  1. ClickHouse server is running"
        echo "  2. Host and port are correct"
        echo "  3. Firewall allows connection"
        exit 1
    fi
else
    if ! clickhouse-client --host="$HOST" --port="$PORT" --user="$USER" --password="$PASSWORD" --query="SELECT 1" &> /dev/null; then
        echo -e "${RED}✗ Cannot connect to ClickHouse server${NC}"
        echo "Please check credentials and server status"
        exit 1
    fi
fi
echo -e "${GREEN}✓ Connection successful${NC}"
echo ""

# Create database
execute_query "CREATE DATABASE IF NOT EXISTS $DATABASE" "Creating database '$DATABASE'"

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Execute setup scripts
execute_file "$SCRIPT_DIR/001-tables.sql" "Creating tables"
execute_file "$SCRIPT_DIR/002-materialized-views.sql" "Creating materialized views"

# Verify installation
echo -e "${YELLOW}>>> Verifying installation${NC}"
TABLES=$(clickhouse-client \
    --host="$HOST" \
    --port="$PORT" \
    --user="$USER" \
    $([ -n "$PASSWORD" ] && echo "--password=$PASSWORD") \
    --database="$DATABASE" \
    --query="SHOW TABLES" | wc -l)

echo "Found $TABLES tables"
echo ""

if [ "$TABLES" -ge 11 ]; then
    echo -e "${GREEN}✓ All tables created successfully${NC}"
else
    echo -e "${YELLOW}⚠ Warning: Expected 11+ tables, found $TABLES${NC}"
fi

# Display tables
echo ""
echo -e "${YELLOW}>>> Created tables:${NC}"
if [ -z "$PASSWORD" ]; then
    clickhouse-client \
        --host="$HOST" \
        --port="$PORT" \
        --user="$USER" \
        --database="$DATABASE" \
        --query="SHOW TABLES"
else
    clickhouse-client \
        --host="$HOST" \
        --port="$PORT" \
        --user="$USER" \
        --password="$PASSWORD" \
        --database="$DATABASE" \
        --query="SHOW TABLES"
fi

echo ""
echo -e "${GREEN}===========================================================${NC}"
echo -e "${GREEN}Setup Complete!${NC}"
echo -e "${GREEN}===========================================================${NC}"
echo ""
echo "Next steps:"
echo ""
echo "1. Set connection string for cnetflow:"
echo "   export CH_CONN_STRING=\"$HOST:$PORT:$DATABASE:$USER:$PASSWORD\""
echo ""
echo "2. Test insertion:"
echo "   clickhouse-client --host=$HOST --port=$PORT --database=$DATABASE --query=\"SELECT count() FROM flows\""
echo ""
echo "3. View example queries:"
echo "   cat $SCRIPT_DIR/003-example-queries.sql"
echo ""
echo "4. Start cnetflow collector (if compiled with ClickHouse support)"
echo ""
