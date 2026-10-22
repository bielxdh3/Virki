# Real PostgreSQL disposable offline recovery proof

**Development evidence only. Production offline activation remains blocked.**

The checked-in `scripts/backup-restore-validation.mjs` already exercises the
application's Prisma migration deployment, representative account/MFA/recovery/
audit/outbox records, `pg_dump --format=custom`, and `pg_restore
--exit-on-error`. Its Docker launcher requires an explicit local Windows
Docker Desktop Linux named-pipe opt-in, uses a pinned PostgreSQL digest already
cached locally, publishes a randomly selected loopback port, and runs Prisma
against generated disposable credentials. It refuses ambient Docker/Compose,
PostgreSQL, database URL, or Node environment overrides. The separate offline
proof here reuses **that same checked-in migration.sql tree** and the real
PostgreSQL `pg_dump`/`pg_restore` programs while constraining the entire
backup/migration/rollback transaction to one disposable, unnetworked database
container. It does not duplicate the full existing Prisma data seeding or
misrepresent its own SQL invocations as a Prisma engine migration deployment.

## Running

For the full Prisma migration and backup/restore validation, in Windows
PowerShell with Docker Desktop's Linux engine running:

```powershell
$env:VIRKI_BACKUP_VALIDATION_LOCAL_DOCKER = '1'
npm run test:backup:restore
Remove-Item Env:VIRKI_BACKUP_VALIDATION_LOCAL_DOCKER
```

This validation refuses other platforms, contexts, remote Docker hosts and
inherited database credentials. The local Windows mode requires a cached pinned
image. It uses the
installed Docker Desktop executable at
`C:\Program Files\Docker\Docker\resources\bin\docker.exe` and its explicit
Linux `npipe:////./pipe/dockerDesktopLinuxEngine` endpoint. No host Docker
socket or host directory is mounted. Its data directory is a disposable tmpfs;
every created container is labelled with an unpredictable owner token and
checked for the exact immutable Docker ID, image, network, mounts and engine
identity before use and force-removal. Failures that prevent independent owner
verification refuse deletion and require manual operator inspection. The
unpredictable name, owner label, engine identity, digest and endpoint are
written to a private `virki-backup-owner-*` directory under the runner's temp
directory **before** the detached run is attempted. An ambiguous Docker run,
lost response, mismatched owner or unconfirmed removal preserves this owner
receipt even if the container is created after the CLI has already failed.
Only an independently confirmed container removal deletes the receipt; the
binary dump is separately removed. An operator must manually inspect the
recorded owner label and exact engine before resolving abandoned fixtures;
the receipt alone never authorizes deletion. Docker
CLI stdout/stderr and Prisma failure logs are redacted to avoid leaking
synthetic credentials, URLs, dump contents and account records. The test uses
synthetic account/admin, TOTP, recovery, audit, outbox and delivery records,
and proves no real production backup's restore capability.

The **GitHub-hosted Ubuntu CI runner only** also runs the same Prisma test.
The checked-in `validate` job sets `VIRKI_BACKUP_VALIDATION_LINUX_CI=1`
exclusively on its backup/restore step. This mode additionally requires the
GitHub-hosted runner identity, expected Virki repository, nonempty run/attempt
identifiers, and an independently inspected canonical root-owned
`/run/docker.sock` Unix socket and root-owned `/usr/bin/docker` CLI. The CLI
always receives `--host unix:///var/run/docker.sock --config` with a private
empty config; it never reads the runner's Docker context or service URL.
The daemon must report the runner's kernel hostname and a stable Linux daemon
ID. The socket's kernel device/inode and hostname are checked before each
Docker operation, including cleanup. Only this mode may pull the exact pinned
PostgreSQL image digest, and it still verifies the resulting image ID and the
created disposable container before Prisma migrations or deletion.

The trust boundary is a GitHub-hosted ephemeral Linux runner and its root-owned
local daemon. Environment variables alone cannot attest the runner identity;
the local Unix socket, daemon hostname and runner host must also match. This
mode is not available on arbitrary Linux hosts, self-hosted runners, WSL,
Docker-in-Docker proxies or production Docker contexts. Root compromise of the
ephemeral CI runner itself remains outside this local fixture's threat model.

For the separate offline SQL crash/recovery fixture:

```bash
npm run test:offline:pg:container
```

The launcher runs the pre-cached, immutable PostgreSQL 17 Alpine image pinned
by digest in `infra/docker-compose.core-test.yml`. It accepts only the
explicit local Windows Docker Desktop Linux named pipe
(`npipe:////./pipe/dockerDesktopLinuxEngine`), checks the responding engine
identity, and ignores caller-supplied Docker contexts/remote endpoints. It
refuses other hosts until a separately reviewed local-only capability exists.
Every case has a freshly created, randomly named and exclusively labelled
Docker container, with:

- no network, published port, host Docker socket, production SSH or remote DB;
- no mounted writable host path and a read-only source checkout mount;
- `postgres` UID 70, all capabilities dropped, no new privileges and
  separate owner-only tmpfs mounts for PGDATA and temporary backups;
- automatic `--rm`, plus final cleanup that requires matching the exact
  random owner label and name before force-removing the container by its
  **immutable Docker ID**; an unknown or mismatched owner is never removed;
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
SIGKILL between exclusive file latch and journal INSERT, and rejection of an
injected PostgreSQL URL. A killed child leaves an
inspectable database journal and exclusive filesystem latch while its
disposable PostgreSQL supervisor survives. An explicit `reconcile` operation
rechecks the backup and restores the original data/schema; retries are never
automatic. Failed restoration preserves the maintenance state and attempted
marker. The latch remains after successful fixture rollback.

The rollback journal adds `rollback_started`, `rollback_proven`,
`rollback_rebuild`, and `rollback_restored` checkpoints. A resumed operation
reuses an already present rollback database **only after** verifying its
entire protected inventory and schema against the source backup. It safely
recreates the owned source fixture if a crash interrupted its drop, creation or
restore. Separate tests SIGKILL the process at each boundary and verify the
original User, MFA, recovery, audit, outbox and security-policy data after
manual reconciliation. If a crash leaves a **partially created rollback clone**,
reconciliation refuses it and preserves the attempt latch for explicit manual
inspection. The fixture never silently deletes an unverified rollback clone.
Each injected failure is accepted only if the child terminates with actual
SIGKILL status 137 **and** the durable journal equals the case's exact
checkpoint. The `rollback_restored` interruption happens directly in the
journal-recording function immediately after readback of its committed row,
before a `rolled_back` transition is possible. If validation fails, only an
enumerated journal phase or numeric child exit status may be printed; all raw
PostgreSQL/SQL/dump output remains redacted. A mismatch is a test failure,
never an accepted alternative outcome or silently retried test.
The separate `rollback_precheckpoint_error` adversarial case simulates a
non-signal exit (70) after a fully restored source but before
`rollback_restored` is persisted. It requires the journal to remain
`rollback_rebuild`, proves exact data preservation, keeps the attempt latch,
and succeeds only after explicit manual reconciliation. This reproduces the
**class** of early failure that the old permissive `wait` accepted as a
crash, without claiming the precise cause of a past intermittent early exit.

Admission first creates and synchronizes the exclusive `.attempted` marker,
then requires its *own* unique PostgreSQL journal INSERT to return an inserted
row. An already-existing `attempted` row is insufficient to authorize the
second process. An interrupted admission before the SQL commit leaves an orphan
marker and prevents automatic retries.

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
