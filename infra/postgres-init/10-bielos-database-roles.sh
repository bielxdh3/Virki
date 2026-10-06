#!/bin/sh
set -eu

: "${POSTGRES_DB:?POSTGRES_DB is required}"
: "${POSTGRES_USER:?POSTGRES_USER must be the database bootstrap role}"
: "${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is required}"
: "${BIELOS_RUNTIME_DB_PASSWORD:?BIELOS_RUNTIME_DB_PASSWORD is required}"
: "${BIELOS_MIGRATOR_DB_PASSWORD:?BIELOS_MIGRATOR_DB_PASSWORD is required}"

for secret in "$BIELOS_RUNTIME_DB_PASSWORD" "$BIELOS_MIGRATOR_DB_PASSWORD"; do
  if [ "${#secret}" -ne 64 ]; then
    echo 'BielOS database role passwords must be 64 hexadecimal characters.' >&2
    exit 1
  fi
  case "$secret" in
    *[!0-9A-Fa-f]*)
      echo 'BielOS database role passwords must be 64 hexadecimal characters.' >&2
      exit 1
      ;;
  esac
done

if [ "$BIELOS_RUNTIME_DB_PASSWORD" = "$BIELOS_MIGRATOR_DB_PASSWORD" ] || \
  [ "$BIELOS_RUNTIME_DB_PASSWORD" = "$POSTGRES_PASSWORD" ] || \
  [ "$BIELOS_MIGRATOR_DB_PASSWORD" = "$POSTGRES_PASSWORD" ]; then
  echo 'BielOS bootstrap, runtime, and migrator database passwords must differ.' >&2
  exit 1
fi

export BIELOS_RUNTIME_DB_PASSWORD BIELOS_MIGRATOR_DB_PASSWORD

psql --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" --set ON_ERROR_STOP=1 <<'SQL'
\getenv database_name POSTGRES_DB
\getenv runtime_password BIELOS_RUNTIME_DB_PASSWORD
\getenv migrator_password BIELOS_MIGRATOR_DB_PASSWORD

DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM pg_class AS relation
    JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
    WHERE namespace.nspname = 'public'
      AND relation.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
      AND relation.relname NOT IN (
        '_prisma_migrations', 'AccountRecoveryRequest', 'AdministrativeCredential',
        'AdministrativeRecoveryCode', 'AuditLog', 'DeviceChallenge', 'EmailDeliveryAttempt',
        'EmailOutboxMessage', 'LoginRateLimit', 'OidcArtifact', 'ProjectConnection',
        'RecoveryCode', 'SanitizedAuditReference', 'SecurityElevation', 'Session',
        'TotpFactor', 'TrustedDevice', 'User', 'UserProjectGrant'
      )
      AND NOT EXISTS (
        SELECT 1 FROM pg_depend AS dependency
        WHERE dependency.classid = 'pg_class'::regclass
          AND dependency.objid = relation.oid
          AND dependency.refclassid = 'pg_extension'::regclass
          AND dependency.deptype = 'e'
      )
  ) OR EXISTS (
    SELECT 1
    FROM pg_type AS type
    JOIN pg_namespace AS namespace ON namespace.oid = type.typnamespace
    WHERE namespace.nspname = 'public'
      AND type.typtype IN ('d', 'e', 'm', 'r')
      AND type.typname NOT IN (
        'AccountStatus', 'AdministrativeCredentialStatus', 'DeliveryAttemptStatus',
        'DeviceChallengeStatus', 'EmailMessageKind', 'OutboxMessageStatus',
        'RecoveryRequestStatus', 'SecondFactorMethod', 'SecurityElevationStatus',
        'SecurityFactorStatus', 'TrustedDeviceStatus', 'UserRole'
      )
      AND NOT EXISTS (
        SELECT 1 FROM pg_depend AS dependency
        WHERE dependency.classid = 'pg_type'::regclass
          AND dependency.objid = type.oid
          AND dependency.refclassid = 'pg_extension'::regclass
          AND dependency.deptype = 'e'
      )
  ) OR EXISTS (
    SELECT 1
    FROM pg_proc AS routine
    JOIN pg_namespace AS namespace ON namespace.oid = routine.pronamespace
    WHERE namespace.nspname = 'public'
      AND routine.prosecdef
      AND NOT EXISTS (
        SELECT 1 FROM pg_depend AS dependency
        WHERE dependency.classid = 'pg_proc'::regclass
          AND dependency.objid = routine.oid
          AND dependency.refclassid = 'pg_extension'::regclass
          AND dependency.deptype = 'e'
      )
  ) THEN
    RAISE EXCEPTION 'Unexpected objects or SECURITY DEFINER routines in public schema; manual database role review is required.';
  END IF;
END
$$;

SELECT format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT', 'bielos_runtime')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'bielos_runtime')
\gexec

SELECT format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT', 'bielos_migrator')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'bielos_migrator')
\gexec

ALTER ROLE bielos_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT PASSWORD :'runtime_password';
ALTER ROLE bielos_migrator LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT PASSWORD :'migrator_password';

DO $$
DECLARE
  membership record;
BEGIN
  FOR membership IN
    SELECT granted_role.rolname AS granted_role_name, member_role.rolname AS member_role_name
    FROM pg_auth_members AS role_membership
    JOIN pg_roles AS granted_role ON granted_role.oid = role_membership.roleid
    JOIN pg_roles AS member_role ON member_role.oid = role_membership.member
    WHERE granted_role.rolname IN ('bielos_runtime', 'bielos_migrator')
       OR member_role.rolname IN ('bielos_runtime', 'bielos_migrator')
  LOOP
    EXECUTE format('REVOKE %I FROM %I', membership.granted_role_name, membership.member_role_name);
  END LOOP;
END
$$;

GRANT CONNECT ON DATABASE :"database_name" TO bielos_runtime, bielos_migrator;
GRANT CREATE ON DATABASE :"database_name" TO bielos_migrator;
REVOKE CONNECT, CREATE, TEMPORARY ON DATABASE :"database_name" FROM PUBLIC;
REVOKE CREATE, TEMPORARY ON DATABASE :"database_name" FROM bielos_runtime;
GRANT TEMPORARY ON DATABASE :"database_name" TO bielos_migrator;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

ALTER SCHEMA public OWNER TO bielos_migrator;
REVOKE CREATE ON SCHEMA public FROM PUBLIC, bielos_runtime;
GRANT USAGE ON SCHEMA public TO bielos_runtime;
GRANT CREATE, USAGE ON SCHEMA public TO bielos_migrator;

DO $$
DECLARE
  item record;
BEGIN
  FOR item IN SELECT tablename FROM pg_tables WHERE schemaname = 'public' LOOP
    EXECUTE format('ALTER TABLE public.%I OWNER TO bielos_migrator', item.tablename);
  END LOOP;
  FOR item IN SELECT sequencename FROM pg_sequences WHERE schemaname = 'public' LOOP
    EXECUTE format('ALTER SEQUENCE public.%I OWNER TO bielos_migrator', item.sequencename);
  END LOOP;
  FOR item IN SELECT viewname FROM pg_views WHERE schemaname = 'public' LOOP
    EXECUTE format('ALTER VIEW public.%I OWNER TO bielos_migrator', item.viewname);
  END LOOP;
  FOR item IN SELECT matviewname FROM pg_matviews WHERE schemaname = 'public' LOOP
    EXECUTE format('ALTER MATERIALIZED VIEW public.%I OWNER TO bielos_migrator', item.matviewname);
  END LOOP;
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
    EXECUTE format('ALTER TYPE public.%I OWNER TO bielos_migrator', item.typname);
  END LOOP;
END
$$;

REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM PUBLIC;
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM bielos_runtime;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM bielos_runtime;
REVOKE ALL PRIVILEGES ON ALL ROUTINES IN SCHEMA public FROM PUBLIC;
REVOKE ALL PRIVILEGES ON ALL ROUTINES IN SCHEMA public FROM bielos_runtime;

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
    EXECUTE format('REVOKE ALL PRIVILEGES ON TYPE public.%I FROM PUBLIC', item.typname);
    EXECUTE format('REVOKE ALL PRIVILEGES ON TYPE public.%I FROM bielos_runtime', item.typname);
  END LOOP;
END
$$;

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO bielos_runtime;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO bielos_runtime;
GRANT EXECUTE ON FUNCTION public.digest(text, text) TO bielos_migrator;

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
    EXECUTE format('GRANT USAGE ON TYPE public.%I TO bielos_runtime', item.typname);
  END LOOP;
END
$$;

ALTER DEFAULT PRIVILEGES FOR ROLE bielos_migrator IN SCHEMA public
  REVOKE ALL PRIVILEGES ON TABLES FROM bielos_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE bielos_migrator
  REVOKE ALL PRIVILEGES ON TABLES FROM PUBLIC, bielos_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE bielos_migrator IN SCHEMA public
  REVOKE ALL PRIVILEGES ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE bielos_migrator IN SCHEMA public
  REVOKE ALL PRIVILEGES ON SEQUENCES FROM bielos_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE bielos_migrator
  REVOKE ALL PRIVILEGES ON SEQUENCES FROM PUBLIC, bielos_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE bielos_migrator IN SCHEMA public
  REVOKE ALL PRIVILEGES ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE bielos_migrator IN SCHEMA public
  REVOKE EXECUTE ON ROUTINES FROM bielos_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE bielos_migrator
  REVOKE EXECUTE ON ROUTINES FROM PUBLIC, bielos_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE bielos_migrator IN SCHEMA public
  REVOKE EXECUTE ON ROUTINES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE bielos_migrator IN SCHEMA public
  REVOKE USAGE ON TYPES FROM bielos_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE bielos_migrator
  REVOKE USAGE ON TYPES FROM PUBLIC, bielos_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE bielos_migrator IN SCHEMA public
  REVOKE USAGE ON TYPES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE bielos_migrator IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO bielos_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE bielos_migrator IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO bielos_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE bielos_migrator IN SCHEMA public
  GRANT USAGE ON TYPES TO bielos_runtime;
SQL

case "${BIELOS_LOCAL_MIGRATOR_CREATEDB:-false}" in
  false) ;;
  true)
    psql --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" --set ON_ERROR_STOP=1 \
      --command 'ALTER ROLE bielos_migrator CREATEDB'
    ;;
  *)
    echo 'BIELOS_LOCAL_MIGRATOR_CREATEDB must be true or false.' >&2
    exit 1
    ;;
esac
