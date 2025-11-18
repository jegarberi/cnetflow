#!/bin/sh

# Remove last line "shared_preload_libraries='citus'"
sed -i '$ d' ${PGDATA}/postgresql.conf

cat <<EOT >> ${PGDATA}/postgresql.conf
shared_preload_libraries='pg_cron,timescaledb'
cron.database_name='${POSTGRES_DB:-postgres}'
EOT

sed -i 's|#fsync = on|fsync = off|g' ${PGDATA}/postgresql.conf
sed -i 's|#synchronous_commit = on|synchronous_commit = off|g' ${PGDATA}/postgresql.conf
sed -i 's|#max_locks_per_transaction = 64|max_locks_per_transaction = 256 |g' ${PGDATA}/postgresql.conf
# Required to load pg_cron
pg_ctl restart
