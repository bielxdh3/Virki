# Native Linux offline recovery controller: isolated rehearsal

**Status: test-only integration milestone. Production activation remains
unauthorized.** This controller exercises the operation order against real
Linux filesystem atomicity and the existing offline ledger persistence
primitive. Its Docker and PostgreSQL effects are strictly simulated under a
private temporary filesystem in a disposable container.

## What is implemented

`infra/offline/trusted-native-recovery-fixture.mjs` exports:

- `rehearseProtectedNativeOfflineRecovery({ fixtureRoot })`: executes exactly
  one protected, staged **fixture-only** transaction, returning
  `deployAuthorized: false` even after successful completion.
- `inspectProtectedNativeOfflineRecoveryFixture({ fixtureRoot })`: returns
  read-only active revision, maintenance state, last checkpoint, ledger entry
  count, and whether an attempted/finalizing latch persists. It cannot remove
  locks, change acceptance, retry, or resume a crashed operation.

The request accepts only `fixtureRoot`. It cannot supply `staged` status,
image IDs, a ledger sequence, signer assertions, a Docker socket, Docker
commands, PostgreSQL credentials, or backend callbacks. The fixture's
independently provisioned `operator/accepted-plan.json` supplies the two
expected image IDs, archive sizes and SHA-256 values, previous/next source
revisions, and attempted ledger fields inside the **same process**. These
operator bytes are root-owned test data, **not** a substitute for signatures
or independent production trust.

The controller requires an explicit test opt-in, Linux/amd64 root inside a
container, an actual tmpfs-mounted OS temporary directory, the exact fixture
directory shape immediately beneath it, and root:root private directories and
regular files. It uses no runtime path or Docker object outside the fixture.
The container launcher has `--network none`, `--read-only`,
`--cap-drop ALL`, `--security-opt no-new-privileges`, and **no Docker
socket mount**. Its daemon is an on-disk fake, and PostgreSQL is an on-disk
JSON fixture preserving complete synthetic MFA, password, session, audit,
recovery and outbox records. WSL kernels are simulated as native only inside
the isolated test code for the existing ledger's Linux fsync/lock tests;
this is **never a native-host admission test**.

The sequence is:

1. Verify root/private fixture identity, predecessor state, both distinct
   protected image identities, compatible schema version and lack of a prior
   pending transaction.
2. Call the existing `recordOfflineReleaseAcceptance` **once** to persist an
   exclusive `attempted` ledger lock.
3. Open, hash and detach each image through its pinned descriptor, verify the
   actual Docker-save TAR parser proof, unlink the private verified copy
   while the descriptor stays open, then feed **that same descriptor** to
   the fake Docker sink. Inspect both untagged roles after each import.
4. Enter maintenance; record and SHA-256-check a complete, retained byte-copy
   backup. Restore it into a separate disposable clone; validate exact bytes.
5. Migrate the clone first and compare every protected non-schema field.
   Only then migrate the live fixture and check application/schema health.
6. Re-verify both images, backup, migrated live data and clone; record the
   candidate active while maintenance is enabled, then finalize the one
   attempted ledger using the existing persistence primitive. Reopen the
   application route only after durable completion.

On ordinary errors **before ledger finalization starts**, a verified backup
restores the exact original database bytes and healthy predecessor release.
The failed attempt stays locked, including after a successful rollback; no
retry is automatic. If backup or predecessor health cannot be proven, the
maintenance marker remains set and the attempted lock persists. A crash at any
phase likewise retains durable evidence for manual reconciliation.

Once ledger finalization begins, the state may have advanced even if the
caller throws or dies. An exception after that boundary therefore **never
automatically rolls back the database or rewinds the ledger head**. Review
both ledger and application state before any operator recovery.

## Run

```bash
node infra/offline/run-trusted-native-recovery-fixture-test.mjs
```

The pinned Node 22.23.3 container image must already exist locally
(`--pull=never`). The test suite covers both image roles and actual
detached file descriptor use, race admission, SIGKILL after migration,
corrupted backups, deliberately bad runtime metadata and archive bytes,
symlinks/hardlinks, forged client authority, ten distinct rollback phases,
and the irreversible ledger-finalization boundary.

## Production prerequisites still missing

**This is not a runnable offline production controller.** In particular:

- There is no separately installed and audited native production entrypoint
  for this module, nor independent root-owned pins that include it in the
  trusted verifier dependency graph. No host operator is authorized to call
  it with real server paths.
- The existing `trusted-release-coordinator.mjs` returns a non-authorizing
  `staged` string after closing/verifying candidate inputs and reserving the
  attempted ledger. That string can never become a caller-controlled
  permission. A real bridge must run inside the independently pinned host
  verifier, bind a private same-process capability to the **specific** owner
  Ed25519 signature, verified predecessor, host identity, sequence, and
  candidate; and retain the exclusive ledger boundary across every action.
  If an archive is reopened, its immutable authenticated bytes must be
  re-established at Docker's use point.
- This fixture does not launch or inspect an isolated Docker daemon or real
  PostgreSQL. Production needs independent daemon/socket and executable
  ownership checks, no host Docker socket reuse, exact content-ID and
  post-load OCI metadata checks for **both** images, and explicit container,
  volume, network and port ownership. Do not tag, route, or start untrusted
  images based on this fixture's results.
- Production database backup and restore must use real `pg_dump`/
  `pg_restore` with immutable, externally retained snapshots, disposable
  PostgreSQL, schema/role/migration-history checks, and authenticated
  preservation of all users, MFA, recovery, audit and outbox state. Some
  migrations are irreversible; restoring the old application code without
  restoring compatible database state is unsafe.
- Quiescing real writers, preserving prior release/images and persistent
  volumes, checking health over loopback/OIDC, controlled Cloudflare Tunnel
  re-entry, measuring disk resources, and deploying real rollback proofs are
  separate engineering and owner-approval prerequisites.
- Existing ledger finalization is a durable state primitive: the caller's
  `observedActiveSha` and health-report digest are **opaque assertions**.
  Production requires an independently trusted health attester and a formally
  reviewed reconciliation protocol for a partially committed ledger, including
  abrupt termination after ledger completion and before service exposure.

No successful fixture run, fake Docker evidence or backup checksum authorizes
production, hosted CI/CodeQL equivalence, GHCR publication, or owner approval.
