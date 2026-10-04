# PostgreSQL privilege transition

## Current boundary

The tracked development example assigns `POSTGRES_USER=bielos_app` and uses the same login in `DATABASE_URL`. On a fresh official PostgreSQL image initialization, `POSTGRES_USER` is the bootstrap superuser; this is a reference-configuration risk, not evidence about the uninspected production cluster. The production Compose file also currently passes one `DATABASE_URL` to the Hub, issuer, email worker, session cleanup and migrator.

This change does not connect to a live database, alter an existing volume, or change production credentials. Existing official-image volumes do not replay initialization scripts when restarted, so changing the environment alone is not a role migration.

## Target identities

Use three distinct identities for a future owner-approved transition:

| Role | Intended use | Required limits |
| --- | --- | --- |
| Bootstrap administrator | PostgreSQL image initialization and owner-operated provisioning | Keep credentials out of application services; no routine application connection. |
| `bielos_migrator` | Explicit Prisma migration job | Owns the application schema and migration-created objects; no superuser, role creation, or database creation. Grant database `CREATE` only if the migration needs it. PostgreSQL 17 marks `pgcrypto` as trusted; its migration can install it with database `CREATE`, but the disposable migration test must confirm the actual image behavior. |
| `bielos_app` | Hub, issuer, outbox worker, and cleanup runtime | No superuser, `CREATEDB`, `CREATEROLE`, `BYPASSRLS`, schema `CREATE`, or object ownership. Grant `CONNECT`, schema `USAGE`, application table DML, and the sequence privileges required by observed queries. |

The runtime role needs `SELECT`, `INSERT`, `UPDATE`, and `DELETE` on current application tables and `USAGE`, `SELECT`, and `UPDATE` on sequences if used by Prisma. Confirm this against the complete schema and runtime query paths in disposable PostgreSQL before adoption. The migration role must set explicit default privileges for future migration-created tables and sequences; defaults are role-specific and do not repair existing objects.

## Owner-controlled transition procedure

Do not use this procedure until an owner has scheduled a maintenance window and approved an isolated clone result.

1. Confirm the expected production host and source revision through the normal release process. Create a protected backup outside the repository, record its SHA-256, and restore it to a disposable PostgreSQL 17 instance. Never use a production connection for trial SQL.
2. On the disposable restore, record `pg_roles`, database and schema ACLs, object owners, extension owners, `_prisma_migrations`, and the current application smoke results. Check for unknown roles or extensions and stop if the inventory does not match the reviewed baseline.
3. Create the runtime and migrator logins using owner-managed secret input. Do not place passwords in SQL files, shell history, command arguments, logs, or repository files. Create the restricted runtime grants and migrator default privileges as separate, reviewed statements.
4. Transfer only the inventoried BielOS schema objects to `bielos_migrator`; do not use an unreviewed blanket `REASSIGN OWNED`. Preserve extension and platform-owned objects. Ensure the migrator can run the committed `CREATE EXTENSION IF NOT EXISTS pgcrypto` migration without granting runtime `CREATE`.
5. Validate the disposable restore using both identities: migrations/status as migrator; CRUD, sessions, outbox, audit, login and OIDC reads/writes as runtime. Assert that runtime cannot create, alter, or drop a table, create an extension, create a role/database, bypass row security, or access unrelated schemas. Test the exact production Compose environment boundary and backup/restore with the restricted runtime credentials.
6. Prepare a rollback that keeps the bootstrap administrator available and restores the prior protected environment configuration if validation fails. Do not remove old logins or revoke their provisioning access until the owner accepts the restore test and has an independently verified rollback point.
7. Only after the owner explicitly approves the production operation, apply the same reviewed statements through the normal production change process, set separate runtime and migrator connection values in the ignored operator configuration, deploy the exact accepted image, and immediately repeat the privilege and health verification.

## Verification SQL for the disposable restore

Replace role/database identifiers only after reviewing the actual database inventory. These are verification queries, not a migration script.

```sql
SELECT rolname, rolsuper, rolcreatedb, rolcreaterole, rolbypassrls
FROM pg_roles
WHERE rolname IN ('bielos_app', 'bielos_migrator');

SELECT has_database_privilege('bielos_app', current_database(), 'CONNECT') AS app_can_connect,
       has_database_privilege('bielos_app', current_database(), 'CREATE') AS app_can_create;

SELECT has_schema_privilege('bielos_app', 'public', 'USAGE') AS app_can_use_schema,
       has_schema_privilege('bielos_app', 'public', 'CREATE') AS app_can_create_in_schema;

SELECT has_table_privilege('bielos_app', '"User"', 'SELECT') AS app_can_read_users,
       has_table_privilege('bielos_app', '"User"', 'INSERT') AS app_can_insert_users,
       has_table_privilege('bielos_app', '"User"', 'UPDATE') AS app_can_update_users,
       has_table_privilege('bielos_app', '"User"', 'DELETE') AS app_can_delete_users;

SELECT has_sequence_privilege('bielos_app', sequence_schema || '.' || sequence_name, 'USAGE') AS app_can_use_sequence
FROM information_schema.sequences
WHERE sequence_schema = 'public';

SELECT extname, pg_get_userbyid(extowner) AS extension_owner
FROM pg_extension
WHERE extname = 'pgcrypto';
```

The CI migration image currently validates migrations with a disposable database, but it does not yet prove this split-role transition. Local Docker/PostgreSQL role and restore tests remain an external prerequisite until a safe disposable engine is available.
