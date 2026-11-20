# Virki — Native BuildKit Go to C4 Wire Bridge Readiness (2026-11-19)

**Disposition:** `DEV_BRIDGE_CANDIDATE: GO (DEV/DEFENSIVE ONLY)` | `PRODUCTION_READINESS: NO-GO`  
**Explicit Pinned Dependencies:**
- **C1 (Issue #90, PR #133):** `review/issue90-v25-20261118` @ `dfe721e254a6e28e9cffa073a74a881cf1019d73`
- **C4 (PR #134):** `feat/c4-owner-authority-readiness-20261119` @ `8c1d9ee7c8df2c93832a507e4466e0b3bd14715e`
- **C1→C4 Integration (PR #135):** `feat/c1-c4-integration-readiness-20261119` @ `6da6c5856d3dda769d0fdc2d62d012689d2f5f3e`

---

## 1. Reconciled Go-to-C4 Wire Implementation

The repository contains the [V2 protocol](../../infra/offline/c1-c4-native-bridge/c4_protocol.go), [Linux client](../../infra/offline/c1-c4-native-bridge/c4_client_linux.go), [V3 protocol](../../infra/offline/c1-c4-native-bridge/c4_v3_protocol.go), [C authority protocol](../../infra/offline/native-owner-authority/native-owner-authority-protocol.h), and [BuildKit integration patch](../../infra/offline/patches/buildkit-v0.34.1-c1-c4-native.patch).

- **Protocol reconciliation:** V2 retains the existing ABI and four canonical contexts. V3 is implemented as a distinct DEV candidate-verification protocol, not as release authorization. Its fixed-frame layout, approval envelope, evidence bundle and candidate receipt are covered by dedicated Go/C tests.
- **Sealed `memfd` + `SCM_RIGHTS` + `SHUT_WR`:** Creates Linux `memfd` descriptors sealed with `F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL`, transmits them via `SCM_RIGHTS` over `AF_UNIX` `SOCK_STREAM`, half-closes with `CloseWrite()` (`SHUT_WR`), and verifies the `4455`-byte `VROA_V2` response.
- **Invariants preserved:** `SIGN_ACK` returns status `22` (`ERR_SIGNING_DISABLED`), `DeployAuthorized: false`, `WorkerReceiptPairAdmitted: false`, `ReleaseSignature: false`.
- **Test gate:** The CI bridge wrapper requires explicit PASS results for the live V2 test and the V3 ABI, evidence-binding and native-daemon tests. Test-only candidate receipts do not constitute release signatures.
- **Native evidence consistency:** V3 checks the payload schema and signed epoch, binds context session/identity/generation and tree schema, checks each canonical context path against its observation and verifies the ordered solver edge chain. It checks OCI root digest, size and media type against the output and requires a matching root node. The sealed context stream is parsed in its existing binary encoding and the canonical v2 tree hash is recomputed from the stream itself. None of these checks changes the wire frame sizes.
- **Independent OCI content graph (V3 DEV schema 2):** BuildKit reads the actual content store attached to the resolved non-publishing image exporter. It collects all unique reachable blobs, including indexes, manifests, configs and layers. The seventh read-only sealed descriptor carries the concatenated content in node order. C4 hashes every blob itself, checks exact descriptor sizes and media types, parses the actual index/manifest bytes, follows their references from the owner-signed image digest, and rejects incomplete or disconnected graphs. The earlier metadata-only schema cannot satisfy V3. Fixed request/response/header sizes are unchanged; old six-FD V3 clients must not be used with this verifier. V2 and legacy metadata remain distinct and non-authorizing.
- **Bounded DEV scope:** 64 MiB total OCI content, 4 MiB per index/manifest, 4096 nodes, 16384 edges, depth 64. Ordinary OCI/Docker images only; missing store blobs, unsupported artifacts/subjects and oversize graphs fail closed. This verifies the complete reachable content-addressed graph for admitted images, not layer unpacking, rootfs diff-ID semantics, build reproducibility or physical worker identity. No registry publication is performed.
- **State serialization:** The JS DEV state uses `/usr/bin/flock` on a persistent private Linux lock inode. Regressions cover concurrent writers, bounded contention, owner exit, automatic kernel release and epoch recovery. The non-Linux fallback fails closed on abandoned locks; upgrades must stop prior-version writers first.
- **Dependency provenance:** #135's previous head `4787effab0a0999f92ee9dc70696f5f66db0b364` is an ancestor of #136. The updated #135 pin is not an ancestor, but the JS integration contract matches it by content and both branches include the lock-exit regression. #135 pins Effect 3.22.1; this bridge retains 3.22.5. The #133 and #134 pins are not ancestors of #136; #135's native owner-authority directory matches #134's pinned tree. All six C1 patches replay against `f5b59a1f2fb25a0cb7072c398cab9aed7835da4e` to V28 tree `c7234b862c991a940c3047f05a6f2752d7fd1e6f`; the aggregate bridge patch reconstructs `3cabbc82887e87a900eeb7b838196bef00374055` (SHA-256 `660462d999e2d3c1a143a7b78577ecd95545cc4f82837f76fd7f8a9c392e696a`). Hosted CI replays that exact tree before the Go producer and native manager tests. V28 custody source blobs remain unchanged from the prior aggregate. Pins document provenance, not merged ancestry.

---

## 2. Remaining Assurance Requirements (`PRODUCTION_READINESS: NO-GO`)

- Merge of PRs #133, #134, #135, and this bridge PR.
- Full production image/exporter execution, including larger content and independently provisioned worker/owner custody, is not established by the local typed content-store and native-daemon fixtures. The bounded OCI DEV verifier does not grant release authority.
- Hardware/OS-isolated Ed25519 key custody and multi-UID native Linux host validation (`ownerUid !== buildkitDaemonUid !== workerUid`).
- Hosted CI and CodeQL on the configured languages, plus separate C/Go security assurance and independent sign-off on the final merged SHA.
