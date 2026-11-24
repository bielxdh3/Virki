# Issue #90 ? V53 root-supervised FD-only FileSync publication (DEV-only)

## Result and exact security boundary

V23/V24's old receiver checks the stage inode and later performs `renameat2`
by its writable pathname. A malicious **same-UID** process replacing the name
between those operations can expose unverified bytes **transiently**, even if
a post-publication identity check correctly denies final admission. That
contract is not sufficient for protected C1/C4 publication.

The new **additive** `virki_c1c4_dev` V53 entry point uses actual V15 sealed
**gRPC FileSync**, but the root supervisor first allocates a private staging
directory beneath an independently trusted **root:root 0700** parent. The
supervisor retains the readable stage directory handle and passes only the
FD, not parent path authority, to the independently isolated receiver UID.
The receiver's process must be nonroot, have `NoNewPrivs`, no supplemental
groups/capabilities, and `PR_SET_DUMPABLE=0`. It uses `os.OpenRoot` on the
inherited `/proc/self/fd/<n>` handle plus `fsutil.ReceiveRoot`, rather than
path-based `recvDiffCopy`: this preserves the exact stage inode while the
receiver cannot traverse the root-only parent. **There is no unprivileged
stage-name rename or unverified destination publication.**

Before consuming a V40 permit, the root broker authenticates the real
PID/UID/GID and `SCM_CREDENTIALS` of the accepted receiver, obtains exactly
one `SCM_RIGHTS` directory FD, and requires its `dev/ino` and ownership to
match the root-supervisor-retained stage descriptor. V51R checks the live
V3 TEST scope before any claim. V40 durably consumes an authentic synthetic
V15 TEST-domain one-time permit; V36 copies the manifest-exact source bytes
into **new root-owned inodes**, verifies membership/digests, fsyncs the
protected copy, and performs the ONLY `RENAME_NOREPLACE` in a root-owned 0700
parent. Root-only protected output is remeasured and submitted to the real
`Manager.ContextConsumed` operation. A concurrent same-UID tamper can only
make that copy fail exact digest/manifest checks; it cannot publish malicious
bytes, even briefly, under the protected destination.

V52 remains the four-context pending/READY/FENCED coordinator using one
SolveScope and four distinct UID/PID publisher identities. V53 changes the
V52 publisher path to require a root-retained stage FD for **every** source;
losing or substituting that FD fails before the one-use V40 claim. It
preserves all historical V23?V52 patches verbatim and does not weaken
V51R's preclaim gates, V52's generation and replay fences, or the existing
V36 root-owned publisher. V52 native tests exercise four independent
root-supervised staging descriptors, verified copies and scope transitions.

## Deterministic RED ? GREEN evidence

- **RED negative control:** `TestC1V53LegacySameUIDCheckRenameNegativeControl`
  executes a separate same-UID attacker process AFTER the legacy pre-rename
  identity/hash check and BEFORE its pathname rename. It proves the old
  algorithm physically exposes `EVIL`, while the pre-pinned FD still reads
  `SAFE`; the postcommit identity check is too late. The negative control
  asserts the old vulnerability so the overall regression suite can pass.
- **GREEN real gRPC FileSync:**
  `TestC1V53FileSyncToRootBrokerSameUIDStageRace` uses different nonroot
  sender/receiver UIDs, real sealed gRPC, inherited supervisor stage FD,
  V50 kernel-authenticated rights handoff, V40, V36 and V3. An independent
  same-UID attacker tries stage path rename/replacement, `/proc/<pid>/fd`
  theft and protected final reads/writes **during receive, after receive and
  during publication**; all attempted accesses must fail, all published
  bytes must be the pinned manifest, and one V40 claim must remain durable.
- **V52 composition and negative gates:**
  `TestC1V52FourProtectedContextsOneSolve` retains the earlier cases for
  four distinct UIDs, duplicate/reused UID refusal, kernel-identity lies,
  cancellation, epoch-floor revocation, rollback, replay, aborted scope,
  crash and group fences. New `forged supervisor stage FD` case proves
  that exchanging a received source's trusted inode reference fails before
  *any* V40 permit is consumed, with a fenced V52 group and no publication.

Run with an isolated disposable Linux root environment (not the production
host) and BuildKit v0.34.1 plus the existing exact pinned patch chain:

```sh
export GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local
VIRKI_V53_RUN_ROOT_FIXTURE=1 go test -mod=vendor -tags virki_c1c4_dev -race -count=1 -timeout 120s ./session/filesync -run '^TestC1V53'
VIRKI_V52_RUN_ROOT_FIXTURE=1 go test -mod=vendor -tags virki_c1c4_dev -race -count=1 -timeout 120s ./session/filesync -run '^TestC1V52FourProtectedContextsOneSolve$'
go vet -mod=vendor -tags virki_c1c4_dev -copylocks=false ./session/filesync ./util/localcontext
```

Patch: `infra/offline/patches/buildkit-v0.34.1-c1-v52-to-v53-root-fd-filesync-dev.patch`.
It must apply **after** V51R plus V52 with the V52 unique-UID preclaim
fix. The patch changes only four BuildKit `session/filesync` source/test
files; no legacy patch is rewritten. The current PR source SHA does not
magically activate this patch in a production BuildKit or enable C1/C4.

## Limitations and explicit NO-GO

This is a DEV-gated integration, not a signed owner C4 production release.
It does not independently attest the trusted root supervisor, broker
binary, or native host, and does not implement owner C4 signing, a trusted
independent monotonic rollback witness, actual BuildKit solver/OCI binding,
or protected production FileSync activation. The synthetic V15 signer is
not a V3 owner approval. No merge, deploy, C4 cutover or issue closure is
authorized by this test. Production remains **NO-GO**. Issue #119 also
requires separately authorized public deployment before live CSP/headers
can be said to match the corrected local build.
