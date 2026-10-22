# Real PostgreSQL disposable offline recovery proof

**Development evidence only. Production offline activation remains blocked.**

The checked-in `scripts/backup-restore-validation.mjs` already exercises the
application's Prisma migration deployment, representative account/MFA/recovery/
audit/outbox records, `pg_dump --format=custom`, and `pg_restore
--exit-on-error`. Its Docker launcher publishes a randomly selected loopback
port and uses Prisma through the host test environment. The separate offline
proof here reuses **that same checked-in migration.sql tree** and the real
PostgreSQL `pg_dump`/`pg_restore` programs while constraining the entire
backup/migration/rollback transaction to one disposable, unnetworked database
container. It does not duplicate the full existing Prisma data seeding or
misrepresent its own SQL invocations as a Prisma engine migration deployment.

## Running

```bash
npm run test:offline:pg:container
```

The launcher runs the pre-cached, immutable PostgreSQL 17 Alpine image pinned
by digest in `infra/docker-compose.core-test.yml`. Every case has a freshly
created, randomly named and exclusively labelled Docker container, with:

- no network, published port, host Docker socket, production SSH or remote DB;
- no mounted writable host path and a read-only source checkout mount;
- `postgres` UID 70, all capabilities dropped, no new privileges and
  separate owner-only tmpfs mounts for PGDATA and temporary backups;
- automatic `--rm`, plus a best-effort final cleanup that requires matching
  the exact random ownership label before force-removing the **same** instance;
- scrubbed, bounded test output. Synthetic security records, dumps, SQL errors,
  connection strings and PostgreSQL log data stay in the private tmpfs.

The test process does not inherit `DATABASE_URL`, `PGHOST`,
`MIGRATION_DATABASE_URL`, service files or password variables. An adversarial
case confirms that an explicitly injected connection URL is rejected **before
the PostgreSQL cluster is initialized**. No external fixture/database URL is
supported.

Within the disposable container, `scripts/fixtures/offline-pg-recovery/run.sh`
starts PostgreSQL on its private Unix socket, executes all committed
`migration.sql` files in lexicographic order, seeds synthetic User, Session,
TOTP, recovery code, administrative credential/recovery code, recovery request,
audit log, email outbox/delivery and OIDC artifact rows, and calls
`scripts/lib/offline-pg-disposable-controller.sh`. The controller:

1. Captures a SHA-256 inventory of **every** regular table in both the
   `public` and `virki_security` application schemas using
   canonical JSONB representations sorted by row, with row counts and table
   names. The only intentionally ignored field is the test migration's new,
   NULL `offlineFixtureAdditive` column.
2. Inserts one unique journal reservation in a separate disposable control
   database and atomically creates an exclusive attempted filesystem latch.
3. Verifies the full `pg_dump -Fc` bytes and archive list, restores the
   immutable dump to a **new independent database**, then checks every
   table/row against the original inventory before migration.
4. Applies a real additive PostgreSQL `ALTER TABLE` first to the restored
   clone. It rejects missing TOTP ciphertext, recovery hash or outbox payload
   columns, and compares the protected data inventory again before changing
   the original fixture database.
5. Applies the fixture migration to the isolated source, checks data and
   application schema again, and records completion. For injected failure,
   it verifies the backup by SHA-256, restores to a separate rollback clone
   and checks its complete inventory **before** rebuilding the source.

The adversarial matrix includes a modified TOTP ciphertext, deleted TOTP
ciphertext column, intentionally failed live migration, corrupted backup,
SIGKILL between live migration and final health, two competing attempts,
and rejection of an injected PostgreSQL URL. A killed child leaves an
inspectable database journal and exclusive filesystem latch while its
disposable PostgreSQL supervisor survives. An explicit `reconcile` operation
rechecks the backup and restores the original data/schema; retries are never
automatic. Failed restoration preserves the maintenance state and attempted
marker. The latch remains after successful fixture rollback.

## What these tests do **not** prove

- `postgres` inside a disposable container is a real database, but the
  sample accounts/secrets are synthetic. The fixture does not read actual
  accounts, credentials, OIDC tokens, encryption keys or deManage data.
- SQL files applied with `psql` prove their PostgreSQL compatibility in
  this setup, not Prisma's own `_prisma_migrations` transaction history,
  true installed migrator-role access or a real server's migration status.
  Continue to run the existing `test:backup:restore` when testing complete
  Prisma ownership/migration behavior in its independently provisioned
  disposable environment.
- The fixture's simulated additive column is not an accepted future
  production migration. Rolling it back is a narrow, reversible test
  scenario; no claim is made about arbitrary irreversible migrations.
- The journal and backup live on tmpfs. A crash of the **entire container**
  destroys all evidence; the child-process crash test proves only
  process-level reconcilability under a surviving PostgreSQL supervisor.
  Native production needs external immutable backups, durable witnessed
  receipt storage, continuous quiescence/fencing, verified service ownership,
  independent health proofs and manually reviewed crash-recovery logic.
- A local checksum/inventory is not independent operator provenance, an
  owner-signed release acceptance, nor a guarantee against a compromised
  native host. There is no production adapter, no activation, no image import,
  no Docker tag and **no release authorization result**.

The production offline coordinator must first establish independently pinned
installed-code identity, both immutable image descriptors at use time, durable
attempt admission and an independently audited Postgres runtime owner. This
fixture deliberately exposes no interface that takes a `staged` string,
claimed image ID, live database address or credentials.
