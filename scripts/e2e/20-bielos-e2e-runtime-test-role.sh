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

DO $$
DECLARE
  membership record;
BEGIN
  FOR membership IN
    SELECT granted_role.rolname AS granted_role_name, member_role.rolname AS member_role_name
    FROM pg_auth_members AS role_membership
    JOIN pg_roles AS granted_role ON granted_role.oid = role_membership.roleid
    JOIN pg_roles AS member_role ON member_role.oid = role_membership.member
    WHERE granted_role.rolname = 'bielos_runtime_test'
       OR member_role.rolname = 'bielos_runtime_test'
  LOOP
    EXECUTE format('REVOKE %I FROM %I', membership.granted_role_name, membership.member_role_name);
  END LOOP;
END
$$;

GRANT CONNECT ON DATABASE :"database_name" TO bielos_runtime_test;
REVOKE CREATE, TEMPORARY ON DATABASE :"database_name" FROM bielos_runtime_test;
REVOKE ALL ON SCHEMA public FROM bielos_runtime_test;
GRANT USAGE ON SCHEMA public TO bielos_runtime_test;
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM bielos_runtime_test;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM bielos_runtime_test;
REVOKE ALL PRIVILEGES ON ALL ROUTINES IN SCHEMA public FROM bielos_runtime_test;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO bielos_runtime_test;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO bielos_runtime_test;

DO $$
BEGIN
  IF to_regclass('public."_prisma_migrations"') IS NOT NULL THEN
    EXECUTE 'REVOKE ALL PRIVILEGES ON TABLE public."_prisma_migrations" FROM PUBLIC, bielos_runtime_test';
  END IF;
END
$$;

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
    EXECUTE format('REVOKE ALL PRIVILEGES ON TYPE public.%I FROM bielos_runtime_test', item.typname);
    EXECUTE format('GRANT USAGE ON TYPE public.%I TO bielos_runtime_test', item.typname);
  END LOOP;
END
$$;

ALTER DEFAULT PRIVILEGES FOR ROLE bielos_migrator
  REVOKE ALL PRIVILEGES ON TABLES FROM bielos_runtime_test;
ALTER DEFAULT PRIVILEGES FOR ROLE bielos_migrator IN SCHEMA public
  REVOKE ALL PRIVILEGES ON TABLES FROM bielos_runtime_test;
ALTER DEFAULT PRIVILEGES FOR ROLE bielos_migrator
  REVOKE ALL PRIVILEGES ON SEQUENCES FROM bielos_runtime_test;
ALTER DEFAULT PRIVILEGES FOR ROLE bielos_migrator IN SCHEMA public
  REVOKE ALL PRIVILEGES ON SEQUENCES FROM bielos_runtime_test;
ALTER DEFAULT PRIVILEGES FOR ROLE bielos_migrator
  REVOKE ALL PRIVILEGES ON ROUTINES FROM bielos_runtime_test;
ALTER DEFAULT PRIVILEGES FOR ROLE bielos_migrator IN SCHEMA public
  REVOKE ALL PRIVILEGES ON ROUTINES FROM bielos_runtime_test;
ALTER DEFAULT PRIVILEGES FOR ROLE bielos_migrator
  REVOKE ALL PRIVILEGES ON TYPES FROM bielos_runtime_test;
ALTER DEFAULT PRIVILEGES FOR ROLE bielos_migrator IN SCHEMA public
  REVOKE ALL PRIVILEGES ON TYPES FROM bielos_runtime_test;
ALTER DEFAULT PRIVILEGES FOR ROLE bielos_migrator IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO bielos_runtime_test;
ALTER DEFAULT PRIVILEGES FOR ROLE bielos_migrator IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO bielos_runtime_test;
ALTER DEFAULT PRIVILEGES FOR ROLE bielos_migrator IN SCHEMA public
  GRANT USAGE ON TYPES TO bielos_runtime_test;
SQL
