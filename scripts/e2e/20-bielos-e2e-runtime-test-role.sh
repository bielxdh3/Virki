#!/bin/sh
set -eu

: "${POSTGRES_DB:?POSTGRES_DB is required}"
: "${POSTGRES_USER:?POSTGRES_USER must be the database bootstrap role}"
: "${BIELOS_E2E_DATABASE_PASSWORD:?BIELOS_E2E_DATABASE_PASSWORD is required}"

if [ "${#BIELOS_E2E_DATABASE_PASSWORD}" -ne 64 ]; then
  echo 'The isolated E2E database password must be 64 hexadecimal characters.' >&2
  exit 1
fi
case "$BIELOS_E2E_DATABASE_PASSWORD" in
  *[!0-9A-Fa-f]*)
    echo 'The isolated E2E database password must be 64 hexadecimal characters.' >&2
    exit 1
    ;;
esac

export BIELOS_E2E_DATABASE_PASSWORD

psql --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" --set ON_ERROR_STOP=1 <<'SQL'
\getenv database_name POSTGRES_DB
\getenv e2e_password BIELOS_E2E_DATABASE_PASSWORD

SELECT format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT', 'bielos_runtime_test')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'bielos_runtime_test')
\gexec

ALTER ROLE bielos_runtime_test LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT PASSWORD :'e2e_password';
GRANT CONNECT ON DATABASE :"database_name" TO bielos_runtime_test;
REVOKE CREATE, TEMPORARY ON DATABASE :"database_name" FROM bielos_runtime_test;
REVOKE ALL ON SCHEMA public FROM bielos_runtime_test;
GRANT USAGE ON SCHEMA public TO bielos_runtime_test;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO bielos_runtime_test;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO bielos_runtime_test;

DO $$
DECLARE
  item record;
BEGIN
  FOR item IN
    SELECT t.typname
    FROM pg_type AS t
    JOIN pg_namespace AS n ON n.oid = t.typnamespace
    WHERE n.nspname = 'public'
      AND t.typtype IN ('d', 'e', 'm', 'r')
      AND NOT EXISTS (
        SELECT 1 FROM pg_depend AS dependency
        WHERE dependency.classid = 'pg_type'::regclass
          AND dependency.objid = t.oid
          AND dependency.refclassid = 'pg_extension'::regclass
          AND dependency.deptype = 'e'
      )
  LOOP
    EXECUTE format('GRANT USAGE ON TYPE public.%I TO bielos_runtime_test', item.typname);
  END LOOP;
END
$$;

ALTER DEFAULT PRIVILEGES FOR ROLE bielos_migrator IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO bielos_runtime_test;
ALTER DEFAULT PRIVILEGES FOR ROLE bielos_migrator IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO bielos_runtime_test;
ALTER DEFAULT PRIVILEGES FOR ROLE bielos_migrator IN SCHEMA public
  GRANT USAGE ON TYPES TO bielos_runtime_test;
SQL
