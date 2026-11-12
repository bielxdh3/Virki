#!/bin/sh
set -eu

# Run only AFTER committed Prisma migrations have created both mail tables.
# This is not a Docker entrypoint initializer: the worker may not inherit the
# generic application role or gain access to User, Session or AuditLog.
: "${POSTGRES_DB:?POSTGRES_DB is required}"
: "${POSTGRES_USER:?POSTGRES_USER is required}"
: "${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is required}"
: "${VIRKI_EMAIL_WORKER_DB_PASSWORD:?VIRKI_EMAIL_WORKER_DB_PASSWORD is required}"
: "${VIRKI_RUNTIME_DB_PASSWORD:?VIRKI_RUNTIME_DB_PASSWORD is required}"
: "${VIRKI_MIGRATOR_DB_PASSWORD:?VIRKI_MIGRATOR_DB_PASSWORD is required}"
: "${VIRKI_AUDIT_MAINTENANCE_DB_PASSWORD:?VIRKI_AUDIT_MAINTENANCE_DB_PASSWORD is required}"

if [ "${#VIRKI_EMAIL_WORKER_DB_PASSWORD}" -ne 64 ]; then
  echo 'Worker database password must be 64 hexadecimal characters.' >&2
  exit 1
fi
case "$VIRKI_EMAIL_WORKER_DB_PASSWORD" in
  *[!0-9A-Fa-f]*)
    echo 'Worker database password must be 64 hexadecimal characters.' >&2
    exit 1
    ;;
esac
for other in "$POSTGRES_PASSWORD" "$VIRKI_RUNTIME_DB_PASSWORD" "$VIRKI_MIGRATOR_DB_PASSWORD" "$VIRKI_AUDIT_MAINTENANCE_DB_PASSWORD"; do
  if [ "$VIRKI_EMAIL_WORKER_DB_PASSWORD" = "$other" ]; then
    echo 'Worker database password must differ from every existing database identity.' >&2
    exit 1
  fi
done

export VIRKI_EMAIL_WORKER_DB_PASSWORD
# libpq PGHOSTADDR can override the destination even when --host specifies a
# socket, and PGPORT/PGSERVICE/PGOPTIONS can also redirect or alter a session.
# Start with a clean libpq environment, pin Unix socket + local port and never
# solicit an interactive password or consult an ambient PGPASSFILE.
unset PGHOSTADDR PGHOST PGPORT PGSERVICE PGSERVICEFILE PGOPTIONS PGUSER PGDATABASE
unset PGPASSWORD PGPASSFILE PGSSLMODE PGSSLCERT PGSSLKEY PGSSLROOTCERT PGSSLCRL
unset PGSSLMINPROTOCOLVERSION PGSSLMAXPROTOCOLVERSION PGCHANNELBINDING
unset PGCONNECT_TIMEOUT PGTARGETSESSIONATTRS PGAPPNAME PGCLIENTENCODING
unset PGSSLNEGOTIATION PGREQUIREPEER PGGSSENCMODE PGGSSDELEGATION PGKRBSRVNAME
unset PGREQUIRESSL PGSSLCOMPRESSION PGLOADBALANCEHOSTS
psql --no-psqlrc --no-password --host=/var/run/postgresql --port=5432 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" --set ON_ERROR_STOP=1 <<'SQL'
\getenv database_name POSTGRES_DB
\getenv worker_password VIRKI_EMAIL_WORKER_DB_PASSWORD

DO $$
BEGIN
  IF inet_server_addr() IS NOT NULL OR current_setting('port') <> '5432' THEN
    RAISE EXCEPTION 'Worker role provisioning requires the local PostgreSQL Unix socket on port 5432.';
  END IF;
END
$$;

-- Transactional provisioning: a missing migrated table, permission error or
-- interrupted command cannot leave an incompletely reconciled worker role.
BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '15s';

DO $$
BEGIN
  IF to_regclass('public."EmailOutboxMessage"') IS NULL
     OR to_regclass('public."EmailDeliveryAttempt"') IS NULL
     OR to_regclass('public."User"') IS NULL
     OR to_regclass('public."Session"') IS NULL THEN
    RAISE EXCEPTION 'Worker role provisioning requires the committed, migrated Virki schema.';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'virki_migrator') THEN
    RAISE EXCEPTION 'Worker role provisioning requires the reviewed Virki migrator identity.';
  END IF;
END
$$;

SELECT format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT', 'virki_email_worker')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'virki_email_worker')
\gexec

ALTER ROLE virki_email_worker LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT PASSWORD :'worker_password';

DO $$
DECLARE member record;
BEGIN
  FOR member IN
    SELECT granted.rolname AS granted_role, recipient.rolname AS recipient_role
    FROM pg_auth_members AS membership
    JOIN pg_roles AS granted ON granted.oid = membership.roleid
    JOIN pg_roles AS recipient ON recipient.oid = membership.member
    WHERE granted.rolname = 'virki_email_worker' OR recipient.rolname = 'virki_email_worker'
  LOOP
    EXECUTE format('REVOKE %I FROM %I', member.granted_role, member.recipient_role);
  END LOOP;
END
$$;

GRANT CONNECT ON DATABASE :"database_name" TO virki_email_worker;
REVOKE CREATE, TEMPORARY ON DATABASE :"database_name" FROM virki_email_worker;
REVOKE CREATE ON SCHEMA public FROM virki_email_worker;
GRANT USAGE ON SCHEMA public TO virki_email_worker;

REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM virki_email_worker;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM virki_email_worker;
REVOKE ALL PRIVILEGES ON ALL ROUTINES IN SCHEMA public FROM virki_email_worker;
-- The runtime-only security schema must never become visible to a worker.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'virki_security') THEN
    EXECUTE 'REVOKE ALL ON SCHEMA virki_security FROM virki_email_worker';
  END IF;
END
$$;

-- The worker reads ciphertext for delivery but cannot enqueue, change
-- recipients/payloads, delete outbox records, or inspect identity tables.
GRANT SELECT ON TABLE public."EmailOutboxMessage" TO virki_email_worker;
GRANT UPDATE ("status", "attemptCount", "availableAt", "sentAt", "terminalFailedAt", "processingLeaseExpiresAt", "pendingSmtpHeaderMessageId", "updatedAt")
  ON TABLE public."EmailOutboxMessage" TO virki_email_worker;
GRANT SELECT ON TABLE public."EmailDeliveryAttempt" TO virki_email_worker;
GRANT INSERT ("id", "messageId", "attempt", "status", "errorCode", "smtpHeaderMessageId", "attemptedAt")
  ON TABLE public."EmailDeliveryAttempt" TO virki_email_worker;

-- Column values and Prisma comparisons use these enum types; nothing else
-- in the schema becomes available to the mail worker.
GRANT USAGE ON TYPE public."OutboxMessageStatus", public."DeliveryAttemptStatus", public."EmailMessageKind" TO virki_email_worker;

ALTER DEFAULT PRIVILEGES FOR ROLE virki_migrator IN SCHEMA public
  REVOKE ALL ON TABLES FROM virki_email_worker;
ALTER DEFAULT PRIVILEGES FOR ROLE virki_migrator IN SCHEMA public
  REVOKE ALL ON SEQUENCES FROM virki_email_worker;
ALTER DEFAULT PRIVILEGES FOR ROLE virki_migrator IN SCHEMA public
  REVOKE EXECUTE ON ROUTINES FROM virki_email_worker;

-- Direct REVOKE cannot override inherited PUBLIC grants. Reject a staging
-- database with an unsafe PUBLIC baseline instead of claiming a narrow role.
DO $$
BEGIN
  IF has_database_privilege('virki_email_worker', current_database(), 'CREATE')
     OR has_database_privilege('virki_email_worker', current_database(), 'TEMPORARY')
     OR has_schema_privilege('virki_email_worker', 'public', 'CREATE')
     OR has_table_privilege('virki_email_worker', 'public."User"', 'SELECT')
     OR has_table_privilege('virki_email_worker', 'public."Session"', 'SELECT')
     OR has_table_privilege('virki_email_worker', 'public."AuditLog"', 'SELECT')
     OR has_table_privilege('virki_email_worker', 'public."EmailOutboxMessage"', 'INSERT')
     OR has_table_privilege('virki_email_worker', 'public."EmailOutboxMessage"', 'DELETE')
     OR has_table_privilege('virki_email_worker', 'public."EmailOutboxMessage"', 'UPDATE')
     OR has_table_privilege('virki_email_worker', 'public."EmailOutboxMessage"', 'TRUNCATE')
     OR has_table_privilege('virki_email_worker', 'public."EmailOutboxMessage"', 'REFERENCES')
     OR has_table_privilege('virki_email_worker', 'public."EmailOutboxMessage"', 'TRIGGER')
     OR has_column_privilege('virki_email_worker', 'public."EmailOutboxMessage"', 'recipientEmail', 'UPDATE')
     OR has_column_privilege('virki_email_worker', 'public."EmailOutboxMessage"', 'payload', 'UPDATE')
     OR has_table_privilege('virki_email_worker', 'public."EmailDeliveryAttempt"', 'INSERT')
     OR has_table_privilege('virki_email_worker', 'public."EmailDeliveryAttempt"', 'UPDATE')
     OR has_table_privilege('virki_email_worker', 'public."EmailDeliveryAttempt"', 'DELETE')
     OR has_table_privilege('virki_email_worker', 'public."EmailDeliveryAttempt"', 'TRUNCATE')
     OR has_table_privilege('virki_email_worker', 'public."EmailDeliveryAttempt"', 'REFERENCES')
     OR has_table_privilege('virki_email_worker', 'public."EmailDeliveryAttempt"', 'TRIGGER')
     OR EXISTS (
       SELECT 1
       FROM pg_class AS relation
       JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
       WHERE namespace.nspname = 'public'
         AND relation.relkind IN ('r', 'p', 'v', 'm', 'f')
         AND relation.relname NOT IN ('EmailOutboxMessage', 'EmailDeliveryAttempt')
         AND (
           has_table_privilege('virki_email_worker', relation.oid, 'SELECT')
           OR has_table_privilege('virki_email_worker', relation.oid, 'INSERT')
           OR has_table_privilege('virki_email_worker', relation.oid, 'UPDATE')
           OR has_table_privilege('virki_email_worker', relation.oid, 'DELETE')
           OR has_table_privilege('virki_email_worker', relation.oid, 'TRUNCATE')
           OR has_table_privilege('virki_email_worker', relation.oid, 'REFERENCES')
           OR has_table_privilege('virki_email_worker', relation.oid, 'TRIGGER')
         )
     )
     OR EXISTS (
       -- Table-level privilege checks are not enough: PUBLIC may have been
       -- granted column-level SELECT/INSERT/UPDATE/REFERENCES on identity
       -- data even when has_table_privilege returns false.
       SELECT 1
       FROM pg_class AS relation
       JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
       JOIN pg_attribute AS attribute ON attribute.attrelid = relation.oid
       WHERE namespace.nspname = 'public'
         AND relation.relkind IN ('r', 'p', 'v', 'm', 'f')
         AND attribute.attnum > 0 AND NOT attribute.attisdropped
         AND (
           (relation.relname NOT IN ('EmailOutboxMessage', 'EmailDeliveryAttempt')
              AND (has_column_privilege('virki_email_worker', relation.oid, attribute.attname, 'SELECT')
                OR has_column_privilege('virki_email_worker', relation.oid, attribute.attname, 'INSERT')
                OR has_column_privilege('virki_email_worker', relation.oid, attribute.attname, 'UPDATE')
                OR has_column_privilege('virki_email_worker', relation.oid, attribute.attname, 'REFERENCES')))
           OR (relation.relname = 'EmailOutboxMessage'
              AND (has_column_privilege('virki_email_worker', relation.oid, attribute.attname, 'INSERT')
                OR has_column_privilege('virki_email_worker', relation.oid, attribute.attname, 'REFERENCES')
                OR (attribute.attname NOT IN
                   ('status', 'attemptCount', 'availableAt', 'sentAt', 'terminalFailedAt',
                    'processingLeaseExpiresAt', 'pendingSmtpHeaderMessageId', 'updatedAt')
                   AND has_column_privilege('virki_email_worker', relation.oid, attribute.attname, 'UPDATE'))))
           OR (relation.relname = 'EmailDeliveryAttempt'
              AND (has_column_privilege('virki_email_worker', relation.oid, attribute.attname, 'UPDATE')
                OR has_column_privilege('virki_email_worker', relation.oid, attribute.attname, 'REFERENCES')
                OR (attribute.attname NOT IN
                   ('id', 'messageId', 'attempt', 'status', 'errorCode', 'smtpHeaderMessageId', 'attemptedAt')
                   AND has_column_privilege('virki_email_worker', relation.oid, attribute.attname, 'INSERT'))))
         )
     )
     OR EXISTS (
       SELECT 1
       FROM pg_class AS sequence
       JOIN pg_namespace AS namespace ON namespace.oid = sequence.relnamespace
       WHERE namespace.nspname = 'public' AND sequence.relkind = 'S'
         AND (
           has_sequence_privilege('virki_email_worker', sequence.oid, 'USAGE')
           OR has_sequence_privilege('virki_email_worker', sequence.oid, 'SELECT')
           OR has_sequence_privilege('virki_email_worker', sequence.oid, 'UPDATE')
         )
     )
     OR EXISTS (
       SELECT 1
       FROM pg_proc AS routine
       JOIN pg_namespace AS namespace ON namespace.oid = routine.pronamespace
       WHERE namespace.nspname = 'public'
         AND has_function_privilege('virki_email_worker', routine.oid, 'EXECUTE')
     )
     OR EXISTS (
       -- PUBLIC can grant USAGE on a protected schema independently of the
       -- direct REVOKE above; deny every non-system, non-public schema.
       SELECT 1 FROM pg_namespace AS namespace
       WHERE namespace.nspname NOT IN ('public', 'information_schema')
         AND left(namespace.nspname, 3) <> 'pg_'
         AND (has_schema_privilege('virki_email_worker', namespace.oid, 'USAGE')
           OR has_schema_privilege('virki_email_worker', namespace.oid, 'CREATE'))
     )
     OR EXISTS (
       -- Also reject latent EXECUTE/TABLE/COLUMN grants in those schemas even
       -- if the worker lacks current USAGE; a later grant must not activate
       -- a previously hidden SECURITY DEFINER/audit-delete capability.
       SELECT 1 FROM pg_proc AS routine
       JOIN pg_namespace AS namespace ON namespace.oid = routine.pronamespace
       WHERE namespace.nspname <> 'public'
         AND namespace.nspname <> 'information_schema'
         AND left(namespace.nspname, 3) <> 'pg_'
         AND has_function_privilege('virki_email_worker', routine.oid, 'EXECUTE')
     )
     OR EXISTS (
       SELECT 1 FROM pg_class AS relation
       JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
       WHERE namespace.nspname <> 'public'
         AND namespace.nspname <> 'information_schema'
         AND left(namespace.nspname, 3) <> 'pg_'
         AND ((relation.relkind IN ('r', 'p', 'v', 'm', 'f')
           AND (has_table_privilege('virki_email_worker', relation.oid, 'SELECT')
             OR has_table_privilege('virki_email_worker', relation.oid, 'INSERT')
             OR has_table_privilege('virki_email_worker', relation.oid, 'UPDATE')
             OR has_table_privilege('virki_email_worker', relation.oid, 'DELETE')
             OR has_table_privilege('virki_email_worker', relation.oid, 'TRUNCATE')
             OR has_table_privilege('virki_email_worker', relation.oid, 'REFERENCES')
             OR has_table_privilege('virki_email_worker', relation.oid, 'TRIGGER')))
          OR (relation.relkind = 'S'
           AND (has_sequence_privilege('virki_email_worker', relation.oid, 'USAGE')
             OR has_sequence_privilege('virki_email_worker', relation.oid, 'SELECT')
             OR has_sequence_privilege('virki_email_worker', relation.oid, 'UPDATE'))))
     )
     OR EXISTS (
       SELECT 1 FROM pg_class AS relation
       JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
       JOIN pg_attribute AS attribute ON attribute.attrelid = relation.oid
       WHERE namespace.nspname <> 'public'
         AND namespace.nspname <> 'information_schema'
         AND left(namespace.nspname, 3) <> 'pg_'
         AND relation.relkind IN ('r', 'p', 'v', 'm', 'f')
         AND attribute.attnum > 0 AND NOT attribute.attisdropped
         AND (has_column_privilege('virki_email_worker', relation.oid, attribute.attname, 'SELECT')
           OR has_column_privilege('virki_email_worker', relation.oid, attribute.attname, 'INSERT')
           OR has_column_privilege('virki_email_worker', relation.oid, attribute.attname, 'UPDATE')
           OR has_column_privilege('virki_email_worker', relation.oid, attribute.attname, 'REFERENCES'))
     ) THEN
    RAISE EXCEPTION 'Staging database exposes excess worker privileges, possibly inherited from PUBLIC.';
  END IF;
END
$$;
COMMIT;
SQL
