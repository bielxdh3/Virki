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
