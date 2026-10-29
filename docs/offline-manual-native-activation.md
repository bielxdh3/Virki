# Native manual activation lifecycle: security contract and disposable proof

The offline manual release avenue requires the Linux owner to install and pin
an independent verifier, source and image identities, private Docker daemon,
host identity, and an external monotonic witness. The already-reviewed
`scripts/production-server.sh` establishes the hosted route's operational
baseline (writer fence, PostgreSQL backup and independent restore, clone
migrations, actual migrations, health, recovery guard, rollback). The hosted
entrypoint and its GHCR/CI assumptions are unchanged.

The stage10 coordinator returns `deployAuthorized: false`, the native daemon
identity preview does not establish an independently authenticated daemon
peer, and the out-of-host floor evidence module does not provide installed
remote custody. An arbitrary checkout, an uploaded candidate, a self-signed
approval, or a disposable test therefore cannot activate production.

## Lifecycle boundaries

`infra/offline/manual-activation-transaction.mjs` records a *non-authorizing*
contract for the following ordered boundaries:

1. Fence writers and externally routed traffic before any database mutation.
2. Verify the original pre-migration backup and preserved identity baseline.
3. Restore the original archive into a separately owned clone.
4. Rehearse committed migrations against the restored clone.
5. Apply the committed migrations to the live database while writers remain fenced.
6. Verify private health, schema, protected account data and migration history.
7. Activate only the exact pinned runtime and migrator images.
8. Resume writers only after all previous checks have succeeded.

Each stage carries a unique attempt ID, host identity, manifest digest,
sequence, predecessor digest, and distinct owner/witness Ed25519 signatures.
Both signatures and the measured host are checked at prepare **and commit**.
An expired, replayed, missing or mismatched signature prevents advancement.
No completed stage is inferred from a successful process exit or from a
partial PostgreSQL write. Every commit requires a separately verified and
durably recorded outcome in a future authorized host implementation.

`infra/offline/manual-activation-journal.mjs` proves the append-only protocol
using actual exclusive file creation, single-link `0600` regular files,
`0700` root-owned directory, file and directory `fsync`, and a chained
intent/completion record. The intent is flushed **before** any hypothetical
side effect. A process death before the completion checkpoint leaves an
unresolved intent which cannot be silently retried, skipped or removed.
The exercise runs only as WSL root under a private `/dev/shm` Linux tmpfs
fixture; its entrypoints deliberately refuse native production Linux.

`infra/offline/manual-native-activation-safety.mjs` adds a separate read-only
native safety inspection. It reads a fixed root-owned policy and checkpoint,
verifies the owner and witness Ed25519 stage approval against distinct *installed*
SPKI pins, requires the complete disposable journal head to match the persisted
checkpoint (not merely its sequence), checks the actual protected maintenance
marker format, and requires the existing protected PostgreSQL rollback preflight
before live migration or later stages. A pending, changed or interrupted intent
blocks the next stage; it cannot automatically recover or resume writers.
The final use-point reinspection requires both the latest committed journal
sequence and the exact chained checkpoint digest to remain unchanged. A durable
concurrent completion at the next sequence therefore refuses a stale decision.
Only a separately installed owner supervisor with an exclusive transaction lock
could make this check atomic with subsequent production effects.
Its WSL-root fixture uses only scoped `/dev/shm/virki-manual-safety-fixture-*`
and `/dev/shm/virki-manual-activation-fixture-*` paths. Every result explicitly
retains false deployment, Docker, writer-resume, rollback, physical writer-fence,
host-measurement, off-host floor and private-health authorization flags.

This module is **not** part of the independently pinned production ESM closure.
The owner must first supply and independently peer-review a native installed
driver, immutable closure inventory, physical use-point checks, real monotonic
off-host floor, authentic writer-quiescence, health and rollback outcomes.
Native Linux use currently refuses because its durable journal implementation
is intentionally WSL-fixture-only. The new read-only guard therefore establishes
no production authority and must not be invoked as an activation entrypoint.

`infra/offline/native-supervisor/owner-installed-manual-supervisor.mjs`
assembles a narrowly scoped **read-only** use-point gate around the existing
activation safety and PostgreSQL rollback inspections. Native mode accepts no
arguments and requires an independently protected installed executable path,
its separately root-owned SHA-256 pin, and successful installed verifier
re-measurement. It loads the stage approval and witness HEAD from fixed owner
files, validates the Ed25519 witness signature and freshness, and cross-binds
host/manifest/source/attempt/owner/witness/floor pins with the separately
installed witness-bridge policy. It checks the protected Git commit pin against
the candidate SHA, then reuses the complete activation journal and, when
applicable, protected PostgreSQL migration/backup/restore preconditions.
All files are reread after the composed checks. A commit pin is **not** an
independent verification of the entire source archive; a signed HEAD is **not**
an independent monotonic floor or proof that the CAS committed. These remain
explicit external blockers. No action is authorized by this inspection.

`scripts/offline-manual-native-supervisor.mjs` is a zero-argument inspection
command whose exit status remains `2` even if all local nonauthorizing evidence
checks pass. It does not invoke `production-server.sh`, Docker, PostgreSQL,
SSH or any cloud route. The WSL disposable fixture mode accepts only a private
root-owned `/dev/shm/virki-manual-safety-fixture-*` directory; this grants no
native host, Docker or rollout authority. This supervisor is not in the
existing independently signed native executable/dependency inventory; owner
installation, auditing and durable native rollback execution remain **NO-GO**.

Rollback is an independently owner-approved reconciliation, not the next
normal activation stage. `manual-activation-rollback.mjs` validates a preview
binding the owner/witness signatures to the original writer fence, backup,
restored clone and pending migration checkpoint. Reconciliation requires
proving quiescence, authenticating the original backup, restoring and checking
a fresh independent clone, restoring under a verified writer fence, validating
the post-restore protected data inventory, and keeping external routes closed.
This preview **never** performs rollback or grants rollback authority.

## Validation and operational limit

The three accompanying suites test signed transition integrity, persistent
file journals, ordered full-lifecycle rehearsal, true subprocess `SIGKILL`
immediately after flushing a `migrate-live` intent, tampered history and
forged/expired owner or witness evidence. The rollback suite covers altered
backup/clone/writer proofs, interrupted migrations, replay and absent custody.
The tests use synthetic fingerprints; they do not claim a real PostgreSQL or
Docker execution. Existing separate disposable PostgreSQL/Prisma fixtures
provide the place for real database observations.

**Production remains blocked** until all of these independent controls exist:
owner-provisioned executable and key custody; authenticated native daemon
peer and lifecycle identity; signer-separated, out-of-host monotonic witness
CAS with protected nonrollbackable floor; a durable independent authorizing
reconciliation record; native verified Docker image custody and exact runtime
identities; and reviewed integration of real PG backup, restore, migration,
health and rollback. Do not reinterpret any `*_PREVIEW_ONLY`,
`*_NONAUTHORIZING` or `*_BLOCKED_*` result as a deployment capability. Never
set an environment variable to bypass these requirements.
