#!/bin/sh
set -eu

if [ -z "${GRAFANA_DB_PASSWORD:-}" ]; then
  echo "GRAFANA_DB_PASSWORD is required for the Grafana read-only database role" >&2
  exit 1
fi

psql \
  --username "$POSTGRES_USER" \
  --dbname "$POSTGRES_DB" \
  -v ON_ERROR_STOP=1 \
  -v db_name="$POSTGRES_DB" \
  -v app_user="$POSTGRES_USER" \
  -v grafana_user="${GRAFANA_DB_USER:-grafana_reader}" \
  -v grafana_password="$GRAFANA_DB_PASSWORD" <<'EOSQL'
SELECT format('CREATE ROLE %I LOGIN PASSWORD %L', :'grafana_user', :'grafana_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'grafana_user') \gexec

SELECT format('ALTER ROLE %I WITH LOGIN PASSWORD %L', :'grafana_user', :'grafana_password') \gexec

GRANT CONNECT ON DATABASE :"db_name" TO :"grafana_user";
GRANT USAGE ON SCHEMA public TO :"grafana_user";
GRANT SELECT ON ALL TABLES IN SCHEMA public TO :"grafana_user";
GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO :"grafana_user";
ALTER DEFAULT PRIVILEGES FOR ROLE :"app_user" IN SCHEMA public
  GRANT SELECT ON TABLES TO :"grafana_user";
ALTER DEFAULT PRIVILEGES FOR ROLE :"app_user" IN SCHEMA public
  GRANT SELECT ON SEQUENCES TO :"grafana_user";
EOSQL
