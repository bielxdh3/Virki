# Native Prisma CLI against a no-network disposable PostgreSQL

**DEV-ONLY evidence. Production offline activation remains NO-GO.**

**Current validation status (2026-10-28):** one owner-scoped, disposable
PostgreSQL 17 + Node 22 run **passed real Prisma 6.19.3** `migrate resolve`,
`migrate deploy` and `migrate status`. The CLI rejected an intentionally
nonexistent database on the private Unix socket with exact `P1003`. All 11
committed migration names and raw SHA-256 checksums matched the database;
`pg_dump -Fc`, independent `pg_restore`, synthetic data, a PostgreSQL restart,
and an independent predecessor rollback clone were verified. Both containers
and their socket volume were removed after exact owner checks, and the completed
run's protected journal was cleared.

Two separately bounded **schema-engine SIGKILL experiments failed closed** at
`engine-interrupt-await-real-ddl`. The original experiment held PostgreSQL
`AccessExclusiveLock` and launched the real Prisma CLI but could not identify
the expected blocked first DDL. The second experiment also verified a genuine
running schema-engine executable with UID 70 and the Prisma CLI parent command,
but exited `ENGINE_ACTIVE_BUT_FIRST_DDL_NOT_BLOCKED`: no real matching
PostgreSQL `ALTER TABLE` wait was observed. **No SIGKILL was sent in either
experiment**. Hence there is no `P3009`, engine-interruption or
`resolve --rolled-back` recovery proof. Both failed owner journals were
retained despite exact cleanup of those attempts' own containers/volumes;
older unresolved journals and a historical volume remain untouched.

The current Stage5 *diagnostic-only* static design (ported from W13 WIP after
the second failed run) locks `"ProjectConnection"` using
`SHARE UPDATE EXCLUSIVE`, which still conflicts with the
`AccessExclusiveLock` needed by the committed first
`ALTER TABLE "ProjectConnection" ADD COLUMN "launchUrl" TEXT` while
permitting preliminary `SELECT` reads. The old holder's
`ACCESS EXCLUSIVE` could have stopped Prisma before the expected DDL;
this is a **hypothesis, not a proven root cause**. No disposable Docker run
has tested the revised lock or observation code. The revised static contract
requires the real PostgreSQL DDL text and ungranted lock, the exact
`pg_blocking_pids` holder, a live UID/PPID/executable-checked schema engine,
an unfinished migration and missing target column immediately before sending
a signal. The PostgreSQL backend cannot independently attest to the Linux
PID's authorship, and none of these conditions has yet passed together in a
real run. The CLI, observation and blocker deadlines are bounded and ordered.

The independent P2-negative-result and verified-cleanup guards remain
mandatory: expected Prisma errors must result from a completed nonzero
unsignaled invocation; successful status requires confirmed owner-scoped
cleanup. This Stage5 forward-port is **not production or deployment approval**.

Adversarial completion checks require a completed nonzero, **unsignaled** Docker
CLI exit before accepting expected Prisma `P1003`/`P3009` or divergence errors.
An error-code string from a killed/timed-out child is insufficient. A successful
Prisma/database run is also only reported as successful when the disposable
owner's exact two containers and socket volume have been verifiably cleaned;
otherwise the protected journal stays and the command fails closed. The
standalone interrupted-engine experiment remains a separate unproven gate.

`npm run test:offline:prisma-native:unit` checks the Docker recipe,
the migration-history checksum verifier, the P2 result/cleanup predicates and
the static DDL/lock/process-observation contract without connecting to any
Docker daemon or PostgreSQL instance. `npm run test:offline:prisma-native:real`
is an explicit Windows Docker Desktop **local-only** opt-in. It refuses Docker
contexts, remote endpoints, ambient PostgreSQL URLs or credentials, and calls
only the Authenticode-verified Docker Desktop binary under the exact Linux
named pipe with a private empty CLI config. No image pull or external network
access is permitted. The only supported images are the two reviewed pinned
cached digests: `postgres:17-alpine` and `node:22.23.3-bookworm`.

The real runner uses **two disposable containers with `--network=none`**,
`--read-only`, `--cap-drop=ALL`, no-new-privileges, immutable image refs, random
owner labels, and no ports published on the host. The PostgreSQL data and
backups remain in private tmpfs. The single shared Docker volume contains
**only the Unix socket** at `/var/run/postgresql`, NEVER `PGDATA`, a writable
host path, the Docker socket or a production volume. PostgreSQL starts with
`listen_addresses=''` and the Unix-socket-only connection string is fixed in
trusted fixture code. The Node runner executes the actual pinned Prisma CLI
6.19.3 against that socket with a read-only mount of the checked-in migrations
and cached Linux schema engine. `psql` SQL scripts alone cannot substitute for
the `prisma migrate resolve`, `prisma migrate deploy`, and `prisma migrate status`
invocations. The test checks their exit statuses, the migration count and every
raw SHA-256 `migration.sql` checksum against PostgreSQL's `_prisma_migrations`
rows, with rejection of unknown/duplicate/divergent histories.

A protected Windows ACL/handle-pinned, write-through owner journal is created
**before** any Docker volume/container creation. It binds the exact randomized
volume/containers and pinned image identities and stores phase checkpoints.
Uncertain Docker responses, timeouts, validation failures and interrupted
attempts retain this journal for operator reconciliation. Cleanup never guesses
by name or deletes an unknown object: every container is re-inspected using
its immutable CID, exact image, owner label, no-network/no-ports metadata and
mount boundaries before removal, and confirmed absent afterwards; the private
socket volume is removed only after both containers are verified absent and
its own owner/driver/name match. A current not-found result after an ambiguous
create is **not proof against late creation**. Never automatically delete an
unresolved journal to make a test green.

The source database begins with the physically applied committed `0_init`
schema. Its actual `pg_dump -Fc` is hashed and restored to a distinct clone;
Prisma registers `0_init` as already applied and performs the remaining
committed migrations. The proof separately compares every migration name and
checksum, validates synthetic identity data and schema, restarts the disposable
PostgreSQL service and checks status again, then restores the original backup
to an independent rollback database and verifies the predecessor schema.
The `diverge` case is a developer-only negative history scenario, and
injected external `DATABASE_URL` / `PGHOSTADDR` values are refused at preflight
before Docker starts; none is allowed to grant release authority or retry a failed
recovery automatically.

A synchronized SIGKILL *during* the real Prisma schema-engine migration is still
missing. The revised experimental `interrupt` mode proposes a real PostgreSQL
`ShareUpdateExclusiveLock` holder and an independently observed blocked
`AccessExclusiveLock` on the exact first DDL, plus live UID, executable and
Prisma parent-process checks before signaling. Both earlier bounded live
experiments failed before that checkpoint. Killing an unrelated child or
merely observing Prisma launch would not prove interruption/recovery. The
new forward-port is static-only pending an independent security peer; **do not
run a third blind Docker attempt** or claim restored production trust.

Limitations: metadata provided by the local Docker daemon is a consistency
check, **not an independent attestation** of its kernel identity or custody.
Docker Desktop storage and the local temporary journal are not verified
cross-power-loss immutable backup media. Trust in the local Node/npm dependency
tree and images is a DEV assumption. PostgreSQL identity/account data is
synthetic; real operator credentials, production Docker, SSH, Cloudflare and
deManage are never touched. No live service writer fencing, independent health
attester, operator-signed acceptance, production rollback or deployment is
proven. Every reported result must explicitly keep `productionProof:false`
and `deployAuthorized:false`.
