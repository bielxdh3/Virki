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

The full Prisma migration transition proof (`npm run test:migration`) now uses
the same local-only Docker safety boundary as backup/restore, but with a separate
`prisma-migration` fixture identity, a cryptographically random name/owner label
and disposable database password. On Windows with Docker Desktop's local Linux
engine and the PostgreSQL digest already cached, run:

```powershell
$env:VIRKI_MIGRATION_VALIDATION_LOCAL_DOCKER = '1'
npm run test:migration
Remove-Item Env:VIRKI_MIGRATION_VALIDATION_LOCAL_DOCKER
```

The checked-in GitHub-hosted Ubuntu `validate` job supplies a separate
`VIRKI_MIGRATION_VALIDATION_LINUX_CI` opt-in only for that migration step,
conditional on workflow runner/repository contexts. The Linux path requires
the canonical root-owned `/run/docker.sock` socket and `/usr/bin/docker` CLI,
explicit `--host unix:///var/run/docker.sock` and a private empty CLI config.
The Windows path pins Docker Desktop's Linux named pipe and executable. Neither
accepts an inherited Docker context or arbitrary target; the pinned digest is
the only image allowed and pulls are disabled on Windows. GitHub/runner variables
and Docker metadata are *not* cryptographic attestation: an uncompromised
GitHub-hosted runner is a documented CI trust assumption.

Before `docker run` the migration script flushes a private owner manifest
**outside** its scratch directory. Every database health check, SQL execution
and cleanup rechecks the exact immutable container ID, owner/fixture labels,
image and loopback binding. If an invalid/lost CID or late creation leaves
container ownership uncertain, the owner manifest survives normal cleanup for
manual reconciliation; the script never guesses a target or cleans by PID/name.
The manifest cannot guarantee survival of a host power loss (its shared temp
parent is deliberately not opened for `fsync`) or destruction of the entire
ephemeral runner's temp storage. It is retained across ordinary script errors
and cleanup. This fixture cannot prove a production migration or authorize deploy.
The receipt parent is checked as a local, canonical directory without a
symbolic-link redirection before creation; the caller never opens the shared
parent for synchronization or recursively removes that parent.

For the full Prisma migration and backup/restore validation, in Windows
PowerShell with Docker Desktop's Linux engine running:

```powershell
$env:VIRKI_BACKUP_VALIDATION_LOCAL_DOCKER = '1'
npm run test:backup:restore
Remove-Item Env:VIRKI_BACKUP_VALIDATION_LOCAL_DOCKER
```

This validation refuses unapproved modes and inherited Docker context and
database credential overrides. The local Windows mode requires a cached pinned
image. It uses the
installed Docker Desktop executable at
`C:\Program Files\Docker\Docker\resources\bin\docker.exe` and its explicit
Linux `npipe:////./pipe/dockerDesktopLinuxEngine` endpoint. No host Docker
socket or host directory is mounted. Its data directory is a disposable tmpfs;
every created container is labelled with an unpredictable owner token and
checked for the exact immutable Docker ID, image, network, mounts and engine
identity before use and force-removal using Docker metadata. Inconsistent
ownership metadata prevents deletion and requires manual operator inspection. The
unpredictable name, owner label, engine identity, digest and endpoint are
written to a private `virki-backup-owner-*` directory under the runner's temp
directory **before** the detached run is attempted. The `owner.json` write is
flushed to disk; Linux also syncs the receipt directory and its parent before
attempting `docker run`. The receipt is outside the separately deleted dump
and Docker-config directory, and the runner's finalization preserves it even
when Docker returned an invalid CID and immediate inspection found no container.
An ambiguous Docker run,
lost response, mismatched owner or unconfirmed removal preserves this owner
receipt even if the container is created after the CLI has already failed.
Only a removal followed by a Docker status query showing the container absent
deletes the receipt. That query depends on the same daemon trust assumption; the
binary dump is separately removed. An operator must manually inspect the
recorded owner label and exact engine before resolving abandoned fixtures;
the receipt alone never authorizes deletion. Docker
CLI stdout/stderr and Prisma failure logs are redacted to avoid leaking
synthetic credentials, URLs, dump contents and account records. The test uses
synthetic account/admin, TOTP, recovery, audit, outbox and delivery records,
and proves no real production backup's restore capability.

This is durable **against the script's normal cleanup and process errors**;
it is not durable across deletion of the host's temp storage or teardown of
an ephemeral GitHub runner. A lost receipt or a daemon with false metadata
does not authorize speculative deletion of a container. Recover an uncertain
fixture only by operator review of the retained manifest and exact daemon.

The **intended GitHub-hosted Ubuntu CI runner** also runs the same Prisma test.
The checked-in `validate` job sets `VIRKI_BACKUP_VALIDATION_LINUX_CI=1`
only on its backup/restore step and only when GitHub workflow contexts report
`runner.environment=github-hosted`, `runner.os=Linux`, and the expected
repository. The script also checks corresponding environment variables, run/
attempt identifiers, and filesystem metadata for the canonical root-owned
`/run/docker.sock` Unix socket and root-owned `/usr/bin/docker` CLI. The CLI
always receives `--host unix:///var/run/docker.sock --config` with a private
empty config; it never reads the runner's Docker context or service URL.
The daemon must report the runner's kernel hostname and a stable Linux daemon
ID. The socket's kernel device/inode and hostname are checked before each
Docker operation, including cleanup. Only this mode may pull the exact pinned
PostgreSQL image digest, and it still verifies the resulting image ID and the
created disposable container before Prisma migrations or deletion.

**Trusted runner assumption:** the CI job actually executes on an uncompromised
GitHub-hosted ephemeral Linux runner with a local Docker daemon. GitHub and
runner environment variables are spoofable outside that trusted workflow.
Root ownership, canonical Unix socket paths, socket device/inode stability,
Docker `info` hostname and engine ID are **consistency checks only**; they do
not cryptographically attest the runner or daemon and cannot distinguish a
root-owned local forwarding proxy from a genuine local daemon. An arbitrary
Linux host or Docker-in-Docker proxy with forged matching metadata could pass
these checks. No authorization to use an arbitrary daemon follows from a
passing check; operators and CI policy must supply the trusted runner boundary.
The code fails closed if the expected local socket or metadata is missing or
changes, and it never accepts inherited Docker contexts. Compromise of root
on the trusted runner lies outside the fixture's threat model. None of this is
production-host identity, production recovery or release authorization.

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

### CLI hardening and separate Prisma-engine admission protocol

The disposable PostgreSQL container runner now uses the **fixed Authenticode-
verified Docker Desktop executable** instead of searching `PATH` for `docker`.
Every invocation uses the explicit local Linux named pipe, a fresh empty CLI
config, a scrubbed subprocess environment, and a narrow allowlist of exact
Docker commands. Ambient `DOCKER_*`, Compose, PostgreSQL connection/credential
and Node execution overrides are refused. The runner still inspects its own
random owner label and full immutable container ID before any cleanup; there
is no generic `docker rm` or user-selectable engine, host or image. These
consistency checks do not independently attest Docker daemon identity.

**Lost-ACK/late-create custody:** before any `docker run`, this runner now
creates a Windows NTFS ACL-guarded, handle-pinned, write-through owner intent
record with `runProtectedWindowsJournalOperation` under the existing
`~/.virki/offline-docker-reconciliation` directory. The record binds the
random owner token, real disposable container name, exact image and pinned
Docker Desktop endpoint. The journal file uses the existing restricted
`virki-offline-fixture-<owner>` key; the independently bound container name is
`virki-disposable-pg-<owner>`. If the CLI times out, loses its reply, reports an
error, or cannot establish immutable-ID/owner-safe cleanup, the record is
**retained for manual reconciliation**, even when an immediate inspect says
the container is absent. A delayed create could appear later. On an
acknowledged normal completion (or the sole expected pre-initialization
malicious-URL rejection, exit 97), the record is removed only after confirmed
absence or verified-ID removal followed by a second absence check. The
runner never deletes a container merely from a name or uncertain response.
This is a Windows disposable-fixture custody improvement, not guaranteed
power-loss durability on arbitrary host storage and not production authority.

`npm run test:offline:pg:protocol` additionally verifies a separate,
non-authorizing **Prisma-engine recovery admission boundary**. It hashes the
exact real `migration_lock.toml` and ordered checked-in `migration.sql` bytes
with symlink/inode/tamper protections. With an explicit disposable-Linux opt-in,
it atomically creates an owner-only, directory-fsynced exclusive attempt latch
and flushes its SHA-bound metadata. A process killed after the checkpoint,
partial payload, unsafe ownership, replay or changed migration SQL must NOT
automatically resume. The latch is never deleted by the library. It returns
`backupVerified:false`, `restoreVerified:false`,
`prismaMigrationVerified:false`, `healthVerified:false`,
`rollbackVerified:false`, and `deployAuthorized:false` even after a successful
checkpoint: no untrusted runner may self-attest work it did not perform.

The real no-network PostgreSQL suite proves its **committed Prisma SQL** can
be run by `psql` with actual dump/restore/rollback and durable journal phases
under a surviving disposable server; it does **not** run `prisma migrate deploy`
in that same database. The existing independent Prisma-engine backup/restore
fixture needs a randomly published **loopback host port**, so it is deliberately
not reused for this strictly *no-published-ports* slice. A future executable
integration requires an independently bounded Prisma runner inside the same
private no-network namespace (or an authenticated private Unix socket), real
`_prisma_migrations` validation, exact backup digest and schema/data health
checks, externally durable failure/recovery checkpoints, and a separately
audited rollback. The new protocol does not execute or approve that missing
stage. Production remains **NO-GO**.

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
