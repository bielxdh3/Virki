#!/bin/sh
set -eu

: "${POSTGRES_DB:?POSTGRES_DB is required}"
: "${POSTGRES_USER:?POSTGRES_USER must be the database bootstrap role}"
: "${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is required}"
: "${VIRKI_RUNTIME_DB_PASSWORD:?VIRKI_RUNTIME_DB_PASSWORD is required}"
: "${VIRKI_MIGRATOR_DB_PASSWORD:?VIRKI_MIGRATOR_DB_PASSWORD is required}"
: "${VIRKI_AUDIT_MAINTENANCE_DB_PASSWORD:?VIRKI_AUDIT_MAINTENANCE_DB_PASSWORD is required}"
AUDIT_LOG_RETENTION_DAYS=${AUDIT_LOG_RETENTION_DAYS:-180}

case "$AUDIT_LOG_RETENTION_DAYS" in
  ''|*[!0-9]*)
    echo 'AUDIT_LOG_RETENTION_DAYS must be an integer between 1 and 3650.' >&2
    exit 1
    ;;
esac
if [ "${#AUDIT_LOG_RETENTION_DAYS}" -gt 4 ]; then
  echo 'AUDIT_LOG_RETENTION_DAYS must be an integer between 1 and 3650.' >&2
  exit 1
fi
while [ "${AUDIT_LOG_RETENTION_DAYS#0}" != "$AUDIT_LOG_RETENTION_DAYS" ]; do
  AUDIT_LOG_RETENTION_DAYS=${AUDIT_LOG_RETENTION_DAYS#0}
done
AUDIT_LOG_RETENTION_DAYS=${AUDIT_LOG_RETENTION_DAYS:-0}
if [ "$AUDIT_LOG_RETENTION_DAYS" -lt 1 ] || [ "$AUDIT_LOG_RETENTION_DAYS" -gt 3650 ]; then
  echo 'AUDIT_LOG_RETENTION_DAYS must be an integer between 1 and 3650.' >&2
  exit 1
fi

for secret in "$VIRKI_RUNTIME_DB_PASSWORD" "$VIRKI_MIGRATOR_DB_PASSWORD" "$VIRKI_AUDIT_MAINTENANCE_DB_PASSWORD"; do
  if [ "${#secret}" -ne 64 ]; then
    echo 'Virki database role passwords must be 64 hexadecimal characters.' >&2
    exit 1
  fi
  case "$secret" in
    *[!0-9A-Fa-f]*)
      echo 'Virki database role passwords must be 64 hexadecimal characters.' >&2
      exit 1
      ;;
  esac
done

if [ "$VIRKI_RUNTIME_DB_PASSWORD" = "$VIRKI_MIGRATOR_DB_PASSWORD" ] || \
  [ "$VIRKI_RUNTIME_DB_PASSWORD" = "$POSTGRES_PASSWORD" ] || \
  [ "$VIRKI_MIGRATOR_DB_PASSWORD" = "$POSTGRES_PASSWORD" ] || \
  [ "$VIRKI_AUDIT_MAINTENANCE_DB_PASSWORD" = "$POSTGRES_PASSWORD" ] || \
  [ "$VIRKI_AUDIT_MAINTENANCE_DB_PASSWORD" = "$VIRKI_RUNTIME_DB_PASSWORD" ] || \
  [ "$VIRKI_AUDIT_MAINTENANCE_DB_PASSWORD" = "$VIRKI_MIGRATOR_DB_PASSWORD" ]; then
  echo 'Virki bootstrap, runtime, migrator, and audit-maintenance database passwords must differ.' >&2
  exit 1
fi

export VIRKI_RUNTIME_DB_PASSWORD VIRKI_MIGRATOR_DB_PASSWORD VIRKI_AUDIT_MAINTENANCE_DB_PASSWORD
export AUDIT_LOG_RETENTION_DAYS

psql --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" --set ON_ERROR_STOP=1 <<'SQL'
\getenv database_name POSTGRES_DB
\getenv runtime_password VIRKI_RUNTIME_DB_PASSWORD
\getenv migrator_password VIRKI_MIGRATOR_DB_PASSWORD
\getenv audit_pwd VIRKI_AUDIT_MAINTENANCE_DB_PASSWORD
\getenv audit_retention_days AUDIT_LOG_RETENTION_DAYS

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
        'RecoveryRequestPurpose', 'RecoveryRequestStatus', 'SecondFactorMethod', 'SecurityElevationStatus',
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

SELECT format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT', 'virki_runtime')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'virki_runtime')
\gexec

SELECT format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT', 'virki_migrator')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'virki_migrator')
\gexec

SELECT format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT', 'virki_audit_maintenance')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'virki_audit_maintenance')
\gexec

ALTER ROLE virki_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT PASSWORD :'runtime_password';
ALTER ROLE virki_migrator LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT PASSWORD :'migrator_password';
ALTER ROLE virki_audit_maintenance LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT PASSWORD :'audit_pwd';

DO $$
DECLARE
  membership record;
BEGIN
  FOR membership IN
    SELECT granted_role.rolname AS granted_role_name, member_role.rolname AS member_role_name
    FROM pg_auth_members AS role_membership
    JOIN pg_roles AS granted_role ON granted_role.oid = role_membership.roleid
    JOIN pg_roles AS member_role ON member_role.oid = role_membership.member
    WHERE granted_role.rolname IN ('virki_runtime', 'virki_migrator', 'virki_audit_maintenance')
       OR member_role.rolname IN ('virki_runtime', 'virki_migrator', 'virki_audit_maintenance')
  LOOP
    EXECUTE format('REVOKE %I FROM %I', membership.granted_role_name, membership.member_role_name);
  END LOOP;
END
$$;

GRANT CONNECT ON DATABASE :"database_name" TO virki_runtime, virki_migrator, virki_audit_maintenance;
-- The committed 0_init migration starts with CREATE SCHEMA IF NOT EXISTS public.
-- PostgreSQL requires database CREATE for that statement, even though public exists.
GRANT CREATE ON DATABASE :"database_name" TO virki_migrator;
REVOKE CONNECT, CREATE, TEMPORARY ON DATABASE :"database_name" FROM PUBLIC;
REVOKE CREATE, TEMPORARY ON DATABASE :"database_name" FROM virki_runtime;
REVOKE CREATE, TEMPORARY ON DATABASE :"database_name" FROM virki_audit_maintenance;
GRANT TEMPORARY ON DATABASE :"database_name" TO virki_migrator;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

ALTER SCHEMA public OWNER TO virki_migrator;
REVOKE CREATE ON SCHEMA public FROM PUBLIC, virki_runtime;
GRANT USAGE ON SCHEMA public TO virki_runtime;
GRANT USAGE ON SCHEMA public TO virki_audit_maintenance;
GRANT CREATE, USAGE ON SCHEMA public TO virki_migrator;

DO $$
DECLARE
  item record;
BEGIN
  FOR item IN SELECT tablename FROM pg_tables WHERE schemaname = 'public' LOOP
    EXECUTE format('ALTER TABLE public.%I OWNER TO virki_migrator', item.tablename);
  END LOOP;
  FOR item IN SELECT sequencename FROM pg_sequences WHERE schemaname = 'public' LOOP
    EXECUTE format('ALTER SEQUENCE public.%I OWNER TO virki_migrator', item.sequencename);
  END LOOP;
  FOR item IN SELECT viewname FROM pg_views WHERE schemaname = 'public' LOOP
    EXECUTE format('ALTER VIEW public.%I OWNER TO virki_migrator', item.viewname);
  END LOOP;
  FOR item IN SELECT matviewname FROM pg_matviews WHERE schemaname = 'public' LOOP
    EXECUTE format('ALTER MATERIALIZED VIEW public.%I OWNER TO virki_migrator', item.matviewname);
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
    EXECUTE format('ALTER TYPE public.%I OWNER TO virki_migrator', item.typname);
  END LOOP;
END
$$;

REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM PUBLIC;
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM virki_runtime;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM virki_runtime;
REVOKE ALL PRIVILEGES ON ALL ROUTINES IN SCHEMA public FROM PUBLIC;
REVOKE ALL PRIVILEGES ON ALL ROUTINES IN SCHEMA public FROM virki_runtime;

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
    EXECUTE format('REVOKE ALL PRIVILEGES ON TYPE public.%I FROM virki_runtime', item.typname);
  END LOOP;
END
$$;

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO virki_runtime;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO virki_runtime;
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM virki_audit_maintenance;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM virki_audit_maintenance;
REVOKE ALL PRIVILEGES ON ALL ROUTINES IN SCHEMA public FROM virki_audit_maintenance;
DO $$
BEGIN
  IF to_regclass('public."AuditLog"') IS NOT NULL THEN
    EXECUTE 'REVOKE UPDATE, DELETE ON TABLE public."AuditLog" FROM virki_runtime';
    EXECUTE 'REVOKE INSERT ON TABLE public."AuditLog" FROM virki_runtime';
    EXECUTE 'REVOKE INSERT ("createdAt") ON TABLE public."AuditLog" FROM virki_runtime';
    EXECUTE 'GRANT INSERT ("id", "eventType", "actorUserId", "actorEmailHash", "result", "resource", "message", "metadata", "schemaVersion", "category", "severity", "action", "reason", "actorRef", "actorRole", "targetRef", "sessionRef", "deviceRef", "requestId", "service", "route", "method", "networkProvenance", "beforeState", "afterState") ON TABLE public."AuditLog" TO virki_runtime';
    EXECUTE 'GRANT INSERT ("createdAt") ON TABLE public."AuditLog" TO virki_runtime';
    EXECUTE 'REVOKE SELECT, INSERT, DELETE ON TABLE public."AuditLog" FROM virki_audit_maintenance';
    EXECUTE 'REVOKE SELECT ("createdAt") ON TABLE public."AuditLog" FROM virki_audit_maintenance';
    EXECUTE 'REVOKE INSERT ("createdAt") ON TABLE public."AuditLog" FROM virki_audit_maintenance';
  END IF;
  IF to_regclass('public."SanitizedAuditReference"') IS NOT NULL THEN
    EXECUTE 'REVOKE INSERT, UPDATE, DELETE ON TABLE public."SanitizedAuditReference" FROM virki_runtime';
    EXECUTE 'GRANT SELECT ON TABLE public."SanitizedAuditReference" TO virki_runtime';
  END IF;
END
$$;
GRANT EXECUTE ON FUNCTION public.digest(text, text) TO virki_migrator;

DO $$
DECLARE
  migrator_oid oid;
  security_owner_oid oid;
  bootstrap_oid oid;
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'virki_migrator') THEN
    SELECT oid INTO migrator_oid FROM pg_roles WHERE rolname = 'virki_migrator';
    IF to_regnamespace('virki_security') IS NULL THEN
      EXECUTE 'CREATE SCHEMA virki_security AUTHORIZATION virki_migrator';
    ELSE
      SELECT namespace.nspowner INTO security_owner_oid
      FROM pg_namespace AS namespace
      WHERE namespace.nspname = 'virki_security';

      IF security_owner_oid <> migrator_oid THEN
        SELECT oid INTO bootstrap_oid FROM pg_roles WHERE rolname = current_user;

        IF security_owner_oid = bootstrap_oid
          AND to_regclass('virki_security.audit_retention_policy') IS NOT NULL
          AND to_regprocedure('virki_security.enforce_audit_log_timestamp()') IS NOT NULL
          AND to_regprocedure('virki_security.delete_expired_audit_logs()') IS NOT NULL
          AND NOT EXISTS (
            SELECT 1
            FROM pg_class AS relation
            JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
            WHERE namespace.nspname = 'virki_security'
              AND relation.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
              AND relation.relname <> 'audit_retention_policy'
          )
          AND NOT EXISTS (
            SELECT 1
            FROM pg_proc AS routine
            JOIN pg_namespace AS namespace ON namespace.oid = routine.pronamespace
            WHERE namespace.nspname = 'virki_security'
              AND NOT (
                (routine.proname = 'enforce_audit_log_timestamp' AND routine.pronargs = 0)
                OR (routine.proname = 'delete_expired_audit_logs' AND routine.pronargs = 0)
                OR (
                  routine.proname = 'delete_expired_audit_logs'
                  AND routine.pronargs = 1
                  AND routine.proargtypes[0] = 'integer'::regtype
                )
              )
          )
          AND NOT EXISTS (
            SELECT 1
            FROM pg_type AS type
            JOIN pg_namespace AS namespace ON namespace.oid = type.typnamespace
            WHERE namespace.nspname = 'virki_security'
              AND type.typtype IN ('d', 'e', 'm', 'r')
          ) THEN
          EXECUTE 'ALTER SCHEMA virki_security OWNER TO virki_migrator';
        ELSE
          RAISE EXCEPTION 'virki_security must be owned by virki_migrator';
        END IF;
      END IF;
    END IF;
    IF NOT EXISTS (
      SELECT 1
      FROM pg_namespace AS namespace
      WHERE namespace.nspname = 'virki_security'
        AND namespace.nspowner = (SELECT oid FROM pg_roles WHERE rolname = 'virki_migrator')
    ) THEN
      RAISE EXCEPTION 'virki_security must be owned by virki_migrator';
    END IF;

    EXECUTE $policy$
      CREATE TABLE IF NOT EXISTS virki_security.audit_retention_policy (
        singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
        retention_days integer NOT NULL CHECK (retention_days BETWEEN 1 AND 3650)
      )
    $policy$;
    EXECUTE 'ALTER TABLE virki_security.audit_retention_policy OWNER TO virki_migrator';
    EXECUTE 'REVOKE ALL ON TABLE virki_security.audit_retention_policy FROM PUBLIC';
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'virki_runtime') THEN
      EXECUTE 'REVOKE ALL ON TABLE virki_security.audit_retention_policy FROM virki_runtime';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'virki_runtime_test') THEN
      EXECUTE 'REVOKE ALL ON TABLE virki_security.audit_retention_policy FROM virki_runtime_test';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'virki_audit_maintenance') THEN
      EXECUTE 'REVOKE ALL ON TABLE virki_security.audit_retention_policy FROM virki_audit_maintenance';
    END IF;

    IF to_regclass('public."AuditLog"') IS NOT NULL THEN
      EXECUTE $timestamp_function$
        CREATE OR REPLACE FUNCTION virki_security.enforce_audit_log_timestamp()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog
        AS $body$
        BEGIN
          IF current_user IN ('virki_runtime', 'virki_runtime_test') THEN
            NEW."createdAt" := pg_catalog.clock_timestamp();
          END IF;
          RETURN NEW;
        END;
        $body$
      $timestamp_function$;
      EXECUTE 'ALTER FUNCTION virki_security.enforce_audit_log_timestamp() OWNER TO virki_migrator';
      EXECUTE 'REVOKE ALL ON FUNCTION virki_security.enforce_audit_log_timestamp() FROM PUBLIC';
      IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'virki_runtime') THEN
        EXECUTE 'REVOKE ALL ON FUNCTION virki_security.enforce_audit_log_timestamp() FROM virki_runtime';
      END IF;
      IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'virki_runtime_test') THEN
        EXECUTE 'REVOKE ALL ON FUNCTION virki_security.enforce_audit_log_timestamp() FROM virki_runtime_test';
      END IF;
      IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'virki_audit_maintenance') THEN
        EXECUTE 'REVOKE ALL ON FUNCTION virki_security.enforce_audit_log_timestamp() FROM virki_audit_maintenance';
      END IF;
      EXECUTE 'DROP TRIGGER IF EXISTS virki_audit_log_created_at_guard ON public."AuditLog"';
      EXECUTE 'CREATE TRIGGER virki_audit_log_created_at_guard BEFORE INSERT ON public."AuditLog" FOR EACH ROW EXECUTE FUNCTION virki_security.enforce_audit_log_timestamp()';

      EXECUTE 'DROP FUNCTION IF EXISTS virki_security.delete_expired_audit_logs(integer)';
      EXECUTE $function$
        CREATE OR REPLACE FUNCTION virki_security.delete_expired_audit_logs()
        RETURNS TABLE (deleted_count bigint, retention_days integer)
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog
        AS $body$
        DECLARE
          configured_retention_days integer;
          deleted_rows bigint;
        BEGIN
          SELECT policy.retention_days
          INTO STRICT configured_retention_days
          FROM virki_security.audit_retention_policy AS policy
          WHERE policy.singleton = true;

          DELETE FROM public."AuditLog"
          WHERE "createdAt" < pg_catalog.clock_timestamp() - (configured_retention_days * INTERVAL '1 day');

          GET DIAGNOSTICS deleted_rows = ROW_COUNT;

          IF deleted_rows > 0 THEN
            INSERT INTO public."AuditLog" ("id", "eventType", "result", "resource", "message", "metadata", "schemaVersion", "category", "severity", "action", "reason")
            VALUES (
              pg_catalog.gen_random_uuid()::text,
              'AUTH_AUDIT_LOG_CLEANUP',
              'SUCCESS',
              'audit-log',
              'Expired audit logs cleaned up.',
              pg_catalog.jsonb_build_object(
                'source', 'audit-log-cleanup',
                'deletedCount', deleted_rows,
                'retentionDays', configured_retention_days
              ),
              1,
              'AUTH',
              'INFO',
              'auth.audit.log.cleanup',
              'completed'
            );
          END IF;

          RETURN QUERY SELECT deleted_rows, configured_retention_days;
        END;
        $body$
      $function$;
      EXECUTE 'ALTER FUNCTION virki_security.delete_expired_audit_logs() OWNER TO virki_migrator';
    END IF;
  END IF;

  IF to_regnamespace('virki_security') IS NOT NULL THEN
    EXECUTE 'REVOKE ALL ON SCHEMA virki_security FROM PUBLIC';
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'virki_runtime') THEN
      EXECUTE 'REVOKE ALL ON SCHEMA virki_security FROM virki_runtime';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'virki_runtime_test') THEN
      EXECUTE 'REVOKE ALL ON SCHEMA virki_security FROM virki_runtime_test';
    END IF;
  END IF;

  IF to_regprocedure('virki_security.delete_expired_audit_logs()') IS NOT NULL THEN
    EXECUTE 'REVOKE ALL ON FUNCTION virki_security.delete_expired_audit_logs() FROM PUBLIC';
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'virki_runtime') THEN
      EXECUTE 'REVOKE ALL ON FUNCTION virki_security.delete_expired_audit_logs() FROM virki_runtime';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'virki_runtime_test') THEN
      EXECUTE 'REVOKE ALL ON FUNCTION virki_security.delete_expired_audit_logs() FROM virki_runtime_test';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'virki_audit_maintenance') THEN
      EXECUTE 'GRANT USAGE ON SCHEMA virki_security TO virki_audit_maintenance';
      EXECUTE 'GRANT EXECUTE ON FUNCTION virki_security.delete_expired_audit_logs() TO virki_audit_maintenance';
    END IF;
  END IF;
END
$$;

INSERT INTO virki_security.audit_retention_policy (singleton, retention_days)
VALUES (true, :'audit_retention_days'::integer)
ON CONFLICT (singleton) DO UPDATE SET retention_days = EXCLUDED.retention_days;

DO $$
BEGIN
  IF to_regclass('public."_prisma_migrations"') IS NOT NULL THEN
    EXECUTE 'REVOKE ALL PRIVILEGES ON TABLE public."_prisma_migrations" FROM PUBLIC, virki_runtime';
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'virki_runtime_test') THEN
      EXECUTE 'REVOKE ALL PRIVILEGES ON TABLE public."_prisma_migrations" FROM virki_runtime_test';
    END IF;
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
    EXECUTE format('GRANT USAGE ON TYPE public.%I TO virki_runtime', item.typname);
  END LOOP;
END
$$;

ALTER DEFAULT PRIVILEGES FOR ROLE virki_migrator IN SCHEMA public
  REVOKE ALL PRIVILEGES ON TABLES FROM virki_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE virki_migrator
  REVOKE ALL PRIVILEGES ON TABLES FROM PUBLIC, virki_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE virki_migrator IN SCHEMA public
  REVOKE ALL PRIVILEGES ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE virki_migrator IN SCHEMA public
  REVOKE ALL PRIVILEGES ON SEQUENCES FROM virki_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE virki_migrator
  REVOKE ALL PRIVILEGES ON SEQUENCES FROM PUBLIC, virki_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE virki_migrator IN SCHEMA public
  REVOKE ALL PRIVILEGES ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE virki_migrator IN SCHEMA public
  REVOKE EXECUTE ON ROUTINES FROM virki_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE virki_migrator
  REVOKE EXECUTE ON ROUTINES FROM PUBLIC, virki_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE virki_migrator IN SCHEMA public
  REVOKE EXECUTE ON ROUTINES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE virki_migrator IN SCHEMA public
  REVOKE USAGE ON TYPES FROM virki_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE virki_migrator
  REVOKE USAGE ON TYPES FROM PUBLIC, virki_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE virki_migrator IN SCHEMA public
  REVOKE USAGE ON TYPES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE virki_migrator IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO virki_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE virki_migrator
  REVOKE ALL PRIVILEGES ON TABLES FROM virki_audit_maintenance;
ALTER DEFAULT PRIVILEGES FOR ROLE virki_migrator IN SCHEMA public
  REVOKE ALL PRIVILEGES ON TABLES FROM virki_audit_maintenance;
ALTER DEFAULT PRIVILEGES FOR ROLE virki_migrator
  REVOKE ALL PRIVILEGES ON SEQUENCES FROM virki_audit_maintenance;
ALTER DEFAULT PRIVILEGES FOR ROLE virki_migrator IN SCHEMA public
  REVOKE ALL PRIVILEGES ON SEQUENCES FROM virki_audit_maintenance;
ALTER DEFAULT PRIVILEGES FOR ROLE virki_migrator
  REVOKE ALL PRIVILEGES ON ROUTINES FROM virki_audit_maintenance;
ALTER DEFAULT PRIVILEGES FOR ROLE virki_migrator IN SCHEMA public
  REVOKE ALL PRIVILEGES ON ROUTINES FROM virki_audit_maintenance;
ALTER DEFAULT PRIVILEGES FOR ROLE virki_migrator IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO virki_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE virki_migrator IN SCHEMA public
  GRANT USAGE ON TYPES TO virki_runtime;
SQL

case "${VIRKI_LOCAL_MIGRATOR_CREATEDB:-false}" in
  false) ;;
  true)
    psql --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" --set ON_ERROR_STOP=1 \
      --command 'ALTER ROLE virki_migrator CREATEDB'
    ;;
  *)
    echo 'VIRKI_LOCAL_MIGRATOR_CREATEDB must be true or false.' >&2
    exit 1
    ;;
esac
