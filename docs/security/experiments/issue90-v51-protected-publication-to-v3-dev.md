# Issue #90 V51 — actual protected V50 publication into the V3 Manager (DEV)

## Result and precise boundary

The additive V51 BuildKit patch connects the **actual Linux C1 V50
authenticated FileSync stage FD, V40 durable synthetic permit and V36
root-owned protected publication** to the previously separate C4 V3
`Manager.ContextConsumed` implementation. This is a real physical
single-context handoff, not a new manually encoded context fixture.

**It is not the complete four-context C1→C4 solve.** The V51 function
explicitly does not create or authorize a V3 owner approval, complete
the solver graph, produce OCI content, emit a C4 candidate receipt or
sign a release. A separate signed V3-domain approval and actual solver/OCI
observations remain necessary. The V15 synthetic test signer is never
treated as a V3 owner. Production signing and deployment remain disabled.

The new public function `filesync.PublishV51DevContextToV3` is compiled
**only** with `-tags virki_c1c4_dev` on Linux. There is no caller from
the daemon's production service, no port, token or network endpoint, and
no production builds use this tag. The function requires an already
accepted private Unix connection and root broker, a frozen V15 manifest,
independently pinned sender UID/GID/PID, an already-authorized V3
`Manager` solve context and separately provisioned V40 ledger.

It compares V3 worker, session and context identifiers with the V15
manifest **before** any V40 claim. V39/V50 authenticates the actual FD
sender; V40 consumes the test permit; V36 creates the fresh root-owned
copy and fsyncs its protected parent. After success, V51 opens that exact
root-owned directory with `openat2` (no symlinks, magic links or mount
crossings), verifies root ownership, directory mode, pinned inode,
membership and every manifest-pinned file digest. It builds the physical
V3 canonical stream from this protected copy, rechecks the pinned inode
and contents after reading, and submits those bytes and verified
digests to `Manager.ContextConsumed`. The untrusted sender's directory
and caller-provided stream data are **not** forwarded to the manager.

The stream builder reopens filenames beneath a verified root-owned 0700
parent, not via an exclusively FD-relative streaming API. This is
adequate for the stated DEV model in which root is trusted and the
nonroot sender cannot replace the parent; it is **not** proof against
a compromised root, a full provenance witness or a release boundary.
Any failure after V40's durable claim leaves it consumed, with the
destination not automatically retried or admitted.

## How the 19 conflicts were reconciled

The exact upstream source is BuildKit
`f5b59a1f2fb25a0cb7072c398cab9aed7835da4e`.
The V23–V50 replayed tree is
`6d2225efbfd67865e08a726678b1a13361441eb5`.
The original V3 native patch plus the existing receipt-binding and
physical-stream addons produce the independent trees:

- V3 native: `a8620ea2ddadbe7125168d8edef8c58cc1b4ddb1`
- V3 receipt binding: `056ddc9815176e137117281e2d360a9c10048296`
- V3 physical producer: `8fa0196e163da1c0f40a2034a3d968ec5e1c469b`

A real three-way merge with the **V50 tree as base of the new patch**
initially had 19 conflicts. Twelve V3 files were semantically
ported because the V3 changes add service selection, stream/OCI
content, solver/exporter provenance and native Manager wiring without
removing their V50 behavior:

`cmd/buildkitd/config/config.go`,
`cmd/buildkitd/config/local_context_observer_test.go`,
`cmd/buildkitd/main.go`,
`exporter/containerimage/export.go`,
`session/filesync/localcontext.go`,
`session/filesync/localcontext_open_linux_test.go`,
`solver/llbsolver/local_context_causality.go`,
`source/local/{consumption,source}.go`,
`util/localcontext/{observer,service_linux,service_other}.go`.

The seven overlapping **V50 security/custody** files keep the exact
V50 contents (V3 would roll back V29+ ancestor validation, V30+
immutable root helper, V32 non-dumpability and later guards/tests):
`session/filesync/sealed_custody_v24_independent_linux_test.go`,
`sealed_custody_v24_linux.go`, `sealed_custody_v24_linux_test.go`,
`sealed_custody_v24_other.go`, `sealed_guard_v15_test.go`,
`sealed_stage_tree_v23_linux_test.go`,
`sealed_staging_v19_linux.go`.

The new **single additive patch**, applied after all historical V50
patches, is:

`infra/offline/patches/buildkit-v0.34.1-c1-v50-to-c4-v51-dev.patch`

- SHA-256: `c7bf1193a8f3e9d1e83d7cef3600b7a1fca118866a6fa804635bbb0eaf0600d3`
- Exact resulting Git tree: `b0b1507f6edd67f232728046263dda4fe8f4529e`
- Contents: 21 modified/added source and test files, including two
  new **DEV-tagged** V51 source/test files.
- Original V23–V50 patch files, 28 hashes and 28 cumulative Git
  trees are unchanged. The CI test replays those first, independently
  verifies the V51 patch bytes and resulting Git tree and then runs
  additional Linux tests.

## Actual executable evidence

- BuildKit hybrid `util/localcontext`, `session/filesync`,
  `source/local`, `solver/llbsolver`, `cmd/buildkitd/config` and
  `cmd/buildkitd` packages compile from the reconciled tree.
- WSL2 Linux, explicit root, distinct sender UID 60018, private
  `/var/tmp` root-owned destination:
  `VIRKI_V51_RUN_ROOT_FIXTURE=1 go test -race -mod=vendor
  -tags virki_c1c4_dev -count=1 ./session/filesync
  -run ^TestC1V51RealProtectedPublisherFeedsV3Manager$` **PASS**.
- Independent evidence includes the actual peer's `SCM_RIGHTS` FD
  and kernel `SCM_CREDENTIALS`, V40 replay consumption, root-owned
  published file bytes, physical stream matching an independently
  expected owner tree, V3 Manager rejection of duplicate context,
  missing-other-three-context refusal and post-publication tamper
  refusal.
- **RED mutation check:** temporarily disabled the V51 preclaim
  worker-identity comparison in the disposable BuildKit checkout.
  The same focused test failed because the hostile record reached
  V3 and the one-time V40 permit was wrongly spent. Original code
  restored byte-for-byte; protected identity check passed with
  `-race`. This is a behavioral regression-control mutation, not a
  previously exploited production weakness.
- The *same combined BuildKit tree* ran
  `TestVROAV3ServiceWithRealManagerAndNativeDaemon` with
  `-race`: both independent test-key
  `CANDIDATE_VERIFIED` and ordinary release-signing-disabled paths
  **PASS**. The V51 test's manager service is intentionally a
  non-signing test double; it does not claim to exercise those two
  C4 paths through the new V51 single-context handoff.
- The root-tagged combined tree also reran unmodified V39 publication,
  V44 cross-signature/refusal and V51 physical-admission tests with
  `-race`: **PASS**, zero skipped cases. The 28 historical V23–V50
  hashes and cumulative trees replayed independently: **PASS**.
- `go vet -mod=vendor -tags virki_c1c4_dev
  ./session/filesync ./util/localcontext ./cmd/buildkitd/config
  ./cmd/buildkitd`: **PASS**. An expanded vet to
  `./source/local ./solver/llbsolver` still reports four
  **pre-existing** `lostcancel` diagnostics in original BuildKit/V50
  sources: `source/local/source.go:224`,
  `solver/llbsolver/export.go:34,87`,
  `solver/llbsolver/history.go:110`. They are not caused by V51 and
  those two packages were not in the original V50 vet CI gate. The new
  CI requires the successful targeted vet without silently suppressing
  or modifying upstream tests.

## Still required for issue #90 closure

Wire four protected V24 FileSync sessions to the independent
root publisher as one uniquely scoped, crash-fenced group. Bind their
V15 manifests to a separately signed actual V3 owner envelope without
converting signed domains. Measure the actual immutable worker
source and solver roots, export the genuine OCI DAG, then connect
the complete four-stream candidate to native C4 with independent
signed receipt verification. Repeat negative real-kernel fault
injection and cross-process replay/crash cases. Production host,
owner-key custody and external rollback proof require separate
authorization; no V51 result provides these today.
