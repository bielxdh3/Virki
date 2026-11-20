# Virki — Native BuildKit Go to C4 Wire Bridge Readiness (2026-11-19)

**Disposition:** `DEV_BRIDGE_CANDIDATE: GO (DEV/DEFENSIVE ONLY)` | `PRODUCTION_READINESS: NO-GO`  
**Explicit Pinned Dependencies:**
- **C1 (Issue #90, PR #133):** `review/issue90-v25-20261118` @ `dfe721e254a6e28e9cffa073a74a881cf1019d73`
- **C4 (PR #134):** `feat/c4-owner-authority-readiness-20261119` @ `8c1d9ee7c8df2c93832a507e4466e0b3bd14715e`
- **C1→C4 Integration (PR #135):** `feat/c1-c4-integration-readiness-20261119` @ `5f895d5e4635303588c7c82437edbff86e7c0480`

---

## 1. Reconciled Go-to-C4 Wire Implementation

The repository contains the [V2 protocol](../../infra/offline/c1-c4-native-bridge/c4_protocol.go), [Linux client](../../infra/offline/c1-c4-native-bridge/c4_client_linux.go), [V3 protocol](../../infra/offline/c1-c4-native-bridge/c4_v3_protocol.go), [C authority protocol](../../infra/offline/native-owner-authority/native-owner-authority-protocol.h), and [BuildKit integration patch](../../infra/offline/patches/buildkit-v0.34.1-c1-c4-native.patch).

- **Protocol reconciliation:** V2 retains the existing ABI and four canonical contexts. V3 is implemented as a distinct DEV candidate-verification protocol, not as release authorization. Its fixed-frame layout, approval envelope, evidence bundle and candidate receipt are covered by dedicated Go/C tests.
- **Sealed `memfd` + `SCM_RIGHTS` + `SHUT_WR`:** Creates Linux `memfd` descriptors sealed with `F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL`, transmits them via `SCM_RIGHTS` over `AF_UNIX` `SOCK_STREAM`, half-closes with `CloseWrite()` (`SHUT_WR`), and verifies the `4455`-byte `VROA_V2` response.
- **Invariants preserved:** `SIGN_ACK` returns status `22` (`ERR_SIGNING_DISABLED`), `DeployAuthorized: false`, `WorkerReceiptPairAdmitted: false`, `ReleaseSignature: false`.
- **Test gate:** The CI bridge wrapper requires explicit PASS results for the live V2 test and the V3 ABI, evidence-binding and native-daemon tests. Test-only candidate receipts do not constitute release signatures.
- **Native evidence consistency:** V3 checks the payload schema and signed epoch, binds context session/identity/generation and tree schema, checks each canonical context path against its observation and verifies the ordered solver edge chain. It checks OCI root digest, size and media type against the output and requires a matching root node. The sealed context stream is parsed in its existing binary encoding and the canonical v2 tree hash is recomputed from the stream itself. None of these checks changes the wire frame sizes.
- **State serialization:** The JS DEV state uses a persistent private Linux kernel lock inode and a normal concurrent-writer regression. The non-Linux fallback fails closed on abandoned locks; upgrades must stop prior-version writers first.
- **Dependency provenance:** #135's previous head `4787effab0a0999f92ee9dc70696f5f66db0b364` is an ancestor of #136. The updated #135 pin is not an ancestor, but the JS integration contract matches it by content. The #133 and #134 pins are not ancestors of #136; #135's native owner-authority directory matches #134's pinned tree. All six C1 patches replay against `f5b59a1f2fb25a0cb7072c398cab9aed7835da4e` to the documented V28 tree `c7234b862c991a940c3047f05a6f2752d7fd1e6f`; the aggregate bridge patch reconstructs tree `a62182216ae33d45aa5106d047cda2c29d41d63f`. The V28 custody source blobs are preserved; three Go source/test modes are normalized and the linear stream observer is extended. These facts distinguish dependency pins from integrated commit history.

---

## 2. Remaining Assurance Requirements (`PRODUCTION_READINESS: NO-GO`)

- Merge of PRs #133, #134, #135, and this bridge PR.
- Complete validation of BuildKit v0.34.1 integration and end-to-end exporter evidence semantics against the pinned upstream and the native authority. OCI descriptor consistency is checked, but the current producer does not establish an independently verified full manifest/layer DAG. The existence of the V3 patch is not evidence of full acceptance.
- Hardware/OS-isolated Ed25519 key custody and multi-UID native Linux host validation (`ownerUid !== buildkitDaemonUid !== workerUid`).
- Hosted CI, CodeQL (C/Go/JS), and independent security sign-off on the final merged SHA.
