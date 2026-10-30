# Owner-installed manual PostgreSQL rollback boundary

The production manual path cannot restore a live database until an independently
approved native Linux owner has authenticated the exact source, predecessor,
images, host, PostgreSQL custody, owner release signature, external witness CAS
and monotonic floor. `scripts/production-server.sh` currently verifies backups
using an isolated restore clone and leaves protected maintenance and migration
guards on a failed migration. It **does not restore the live PostgreSQL database**.
Its hosted `deploy` action authenticates GHCR/CI and must keep doing so.

`infra/offline/native-manual-pg-rollback-preflight.mjs` is a narrow reusable
read-only prerequisite for a future owner-installed native recovery entrypoint.
It refuses execution outside the fixed existing supervisor import tree,
`/usr/local/lib/virki/offline-release/infra/offline/native-manual-pg-rollback-preflight.mjs`,
and rejects WSL, non-root real/effective UID/GID, non-native filesystems,
unprotected ancestors or writable/non-root installed module bytes. These checks
run **after Node has loaded JavaScript**, so they cannot replace an independently
trusted native launcher and verified transitive ESM/ELF first-exec closure.
It validates protected root-owned `0700` release and backup directories, a
canonical predecessor `current` symlink, an intact predecessor release marker,
the pending `PREPARED`/`VERIFIED` migration guard, the maintenance marker and
verification marker, and reads the full original/current backup bytes through
single-link, root-owned `0600` pinned descriptors. Every backup SHA-256 is
rechecked against the durable guard; metadata is rechecked after reading.
An inconsistent checkpoint or altered predecessor refuses before any side
effect. `PREPARED` is accepted only as evidence of unresolved migration work,
never as proof that the migration or recovery completed.

This API accepts caller-provided expected SHAs and a root path **only for
inspection**. It cannot approve a release, verify a live writer fence, issue an
authorization, run PostgreSQL, tag Docker images or switch a route. Returned
`writerFenceVerified`, `ownerApprovalVerified`, `witnessFloorVerified`,
`rollbackAuthorized` and `deployAuthorized` remain `false`. A production
entrypoint must select `/srv/virki` and trusted identities from its immutable,
independently installed owner policy. It must never use an uploaded candidate,
environment variable or the nonauthorizing API result as deployment authority.

## Future native execution boundary

One fixed, independently owner-installed root entrypoint must own the entire
rollback transaction and exclusive host lock. Before touching PostgreSQL, it
must prove these inputs from protected native state, **not caller JSON**:

1. Signed and non-revoked owner authorization binding the rollback source SHA,
   exact predecessor source SHA, runtime/migrator image IDs, original backup
   SHA, host identity, attempt nonce, expiry and operation phase. It must
   also confirm independent witness CAS and nonrollbackable floor in a
   separate custody domain. Per-stage signer approval must survive process
   interruption without permission replay.
2. The actual native Docker daemon peer, no socket/environment substitution,
   exact installed binaries, fixed production project and pinned image IDs.
   Keep hosted GHCR/CI guards intact. The signed W34 eleven-file stage and W26
   nonauthorizing witness intent are prerequisites, never approval tokens.
3. Measured quiescence of Cloudflare Tunnel and every application writer, with
   the original protected maintenance and migration checkpoint still present.
   Confirm predecessor source/image/database schema compatibility before
   attempting recovery. Root ownership across SSH receiver, production root
   and the service account must be reconciled explicitly.
4. Re-restore the **original** backup in a newly allocated, private PostgreSQL
   clone and validate identity, recovery outbox, schema, and committed migration
   history against the predecessor. Perform a separately approved durable
   database recovery with the previously verified backup, recording an intent
   **before** the first database mutation. Verify live post-recovery identity
   and data against the independently checked clone. Do not rely on blind
   `pg_restore --clean` to remove objects from later schemas.
5. Confirm predecessor runtime and private health before resuming any public
   route. On timeout, `SIGKILL`, missing receipt, changed guard, wrong
   account inventory or any ambiguous partial restore, keep writers and Tunnel
   fenced. Recovery of a partial native rollback requires a new signed owner
   reconciliation; a retry cannot infer success from a process exit code.

The existing `production-server.sh` routines to reuse in a future shared
native execution path are `maintenance_on` (line 1782),
`create_verified_backup` (1249), `apply_production_migrations` (1755),
`assert_migration_guard_verified` (1548), `resume_services` (1828) and its
health checks. The native path must not call hosted `deploy` to skip GHCR
verification, nor source an uploaded production script. A peer-reviewed
installed adapter is still needed for source/image admission and actual
rollback; this read-only invariant checker is not that adapter.

The ordinary-user test in
`infra/offline/native-manual-pg-rollback-preflight.test.mjs` checks native
eligibility and WSL/checkout refusal without privileged execution. Its seven
root-only filesystem tests are **SKIPPED** from Windows/WSL and mutable
checkouts; they require a separately owner-installed and independently
verified native Linux fixture. Never run root Node/test scripts or generated
native binaries directly from DrvFS or an untrusted worktree. Previous WSL-root
fixture results are historical only, not current proof of native rollback,
writer fencing, PostgreSQL restore or installed-host attestation.
