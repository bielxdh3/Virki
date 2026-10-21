# Disposable offline maintenance and recovery coordinator

This module is a **development-only filesystem rehearsal** for a future
independently installed Virki offline release operator. It never contacts Docker,
SSH, the remote production host, Cloudflare, GHCR, or the existing online deploy
scripts, and its result is always `deployAuthorized: false`.

## Current behavior

The isolated coordinator at
`infra/offline/disposable-recovery-coordinator.mjs` exercises:

1. Preflight for a named predecessor, candidate, healthy application, compatible
   migration version, and absence of an unresolved attempt.
2. Exclusive `O_EXCL` attempt reservation and a journal with explicit
   `attempted` and subsequent phase checkpoints. The operation cannot silently
   retry after a crash.
3. Closed maintenance routing, with the predecessor identity recorded.
4. A byte-for-byte database snapshot retained at
   `backups/<attempt-id>.dump`, then an independent disposable copy at
   `restores/<attempt-id>.dump`. Both must match the original SHA-256.
5. Migration of the restored copy first, with an identity/account-data invariant,
   followed by migration of the fixture's live copy.
6. Candidate startup and health checks while maintenance stays enabled; a final
   comparison of the live data, migrated restore, original accounts and
   immutable backup before recording `committed`.
7. Reopening the route only after the journal records completion. Any ordinary
   error restores the prior database bytes, healthy predecessor and route.
   If rollback proof is lost, maintenance and the attempt lock remain in place.

The previous release folder and all backup/restore evidence remain available
after success and recoverable failures. SIGKILL or process termination may leave
an incomplete attempt; `inspectDisposableOfflineRecovery()` provides read-only
status, but intentionally has **no automatic stale-lock deletion or retry**.
Manual reconciliation is required after a crash.

## Run focused adversarial tests

```bash
node --test infra/offline/disposable-recovery-coordinator.test.mjs
```

The tests themselves provision and dispose of dedicated fixture directories
directly under the OS temporary directory. The module additionally requires
`VIRKI_DISPOSABLE_RECOVERY_TEST=1`, an exact fixture-name format, private
directories, and a disposable marker. Test cases cover all eight injected
failure checkpoints, retained snapshots, corrupt backups, tampered account
data, swapped candidate health, process death, two competing processes, and
invalid paths.

## Missing integration before an operational coordinator

The fixture has JSON account records, filesystem-backed migration and routing,
and a local health descriptor. Those model operation order and crash behavior
but **do not** demonstrate PostgreSQL migration compatibility, real `pg_dump`
and `pg_restore`, service quiescence, independent Docker image pinning,
network health, host identity, or safe runtime rollback.

It is not wired to the existing `trusted-release-coordinator.mjs`, which
currently stages a verified candidate with `deployAuthorized: false`.
In particular, a real offline implementation must authenticate its installed
code and exact candidate image bytes at the Docker use point, restrict every
new resource to explicit owned fixture identity, reconcile interrupted
operations with independent evidence, and never confuse a local test receipt
with signed owner acceptance or hosted CodeQL approval.

### Required trusted handoff

The current trusted coordinator closes its candidate files after inspection and
returns only a non-authorizing `staged` result. No caller should convert that
result, a manifest digest, a nonce, or a candidate directory path into
permission for the recovery fixture or a future production operator.

An operational handoff needs a single independently installed host process (or
a comparably authenticated local IPC peer) to retain the exclusive attempted
ledger boundary. It must bind the verified owner signature, sequence, host,
predecessor, candidate and immutable artifact bytes to a private operation
handle, not a JSON input from the uploader. The backup/maintenance state
machine can then run under that same operation identity. Docker must consume
the **same sealed private copy or pinned file descriptor bytes** that were
verified, followed by independently checked loaded-image metadata. If the
existing verifier releases mutable input paths, the consumer must authenticate
them again; a prior digest alone cannot eliminate this requirement.

The development fixture's journal and `O_EXCL` marker demonstrate interruption
behavior only. They are **not** the trusted ledger in
`scripts/lib/offline-release-ledger.mjs`, and they do not complete or clear its
durable attempted state. A real bridge must extend that trusted ledger with
reviewed terminal transitions and explicit recovery authorization before the
remaining host actions can be connected.
