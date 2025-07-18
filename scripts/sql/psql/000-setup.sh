#!/bin/sh

# Remove last line "shared_preload_libraries='citus'"
sed -i '$ d' ${PGDATA}/postgresql.conf

cat <<EOT >> ${PGDATA}/postgresql.conf
shared_preload_libraries='pg_cron,timescaledb'
cron.database_name='${POSTGRES_DB:-postgres}'
EOT

# Required to load pg_cron
pg_ctl restart