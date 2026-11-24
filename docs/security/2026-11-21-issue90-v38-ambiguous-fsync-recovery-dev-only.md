# Issue #90 — V38 DEV: ambiguous root-broker publication and safe recovery observation

V38 is a **DEV-only incremental** experiment after V37; V23–V37 patch SHA256 values and cumulative Git trees remain unchanged. The original #141 review target `1123f0f` (against `main@6802c432`) remains immutable. No C1/C4 release, protected production FileSync or administrative issue closure is permitted.

## Why this is needed

`RENAME_NOREPLACE` may succeed and publish an inode before `fsync(parent)` fails or a process crashes. Such a result is **published but unadmitted**, not “not published.” Reattempting the publication or recursively deleting the destination may destroy evidence or accidentally grant unapproved content. An operator needs a safe, read-only classification without confusing filesystem presence with an owner-authorized C4 release.

V38 adds a **private deterministic fsync fault seam** for tests while the normal V36 broker always uses `unix.Fsync`. On an injected parent `EIO` after a successful rename, the original terminal `V22PublishedButUnadmittedError` is retained. V38 additionally implements `inspectV38RootPublishedSnapshot`, which only executes as real/effective UID 0, validates the frozen V15 manifest, rejects symlink/foreign ancestor paths, pins the root-owned `0700` parent and destination via no-follow descriptor operations, rechecks inode identity and the full fixed file manifest, and never deletes, renames or admits the data. Its only non-error observations are `absent-needs-new-permit` or `present-requires-owner-reauthorization`. A correct SHA256 proves **only** that the bytes match the supplied manifest; it does **not** prove an owner permit or authorize a deployment.

`TestC1V38RootBrokerAmbiguousFsyncRequiresOwnerReauthorization` is an opt-in disposable root fixture (`VIRKI_V38_RUN_ROOT_FIXTURE=1`): verify an absent destination cannot count as release; inject EIO precisely at parent fsync; demonstrate SAFE bytes exist but publication returns terminal; prove recovery still requires owner reauthorization; verify a replay to the same destination refuses the existing name; then mutate content as privileged test adversary and replace the destination with a symlink, both of which must be rejected without deleting any suspect pathname. The fixture never touches user files or connects an endpoint.

## Immutable review artifacts

- V37 input tree: `fcaf997a3f72c64904a04fd5c240db44773f0b13`.
- V38 LF patch SHA-256: `df73e0d4fcf75aba4db6a86ee05f354bfc1f023f08d13050e983190c61464250`.
- V38 cumulative BuildKit tree: `86064bbbfdd3c6ebd9dfc6afc3bcd61938bfa10d`.
- All 16 patches replay offline in a temporary Git index using `bash scripts/security/issue90-replay-index.sh <pinned BuildKit source>`. Node 22 classifiers, vendored Go 1.26.10 `-race`, vet and root-supervised V24/V28–V31/V36–V38 fixtures are separate tests.

**Limits and production gate:** This inspector deliberately has **no side-effectful recovery**, no signed-owner/C4 durable permit/replay ledger, no crash-durable reservation state machine and no deployment interface. A host may suffer untrusted namespace/UID custody that these synthetic tests do not reproduce. V38 must never turn a valid hash into automatic owner admission. Protected C1/C4 remain **production NO-GO** until the operational authority, restart/replay workflow and independent sign-off are implemented, tested and separately authorized.
