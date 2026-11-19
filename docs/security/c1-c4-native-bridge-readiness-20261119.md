# Virki — Native BuildKit Go to C4 Wire Bridge Readiness (2026-11-19)

**Disposition:** `DEV_BRIDGE_CANDIDATE: GO (DEV/DEFENSIVE ONLY)` | `PRODUCTION_READINESS: NO-GO`  
**Explicit Pinned Dependencies:**
- **C1 (Issue #90, PR #133):** `review/issue90-v25-20261118` @ `dfe721e254a6e28e9cffa073a74a881cf1019d73`
- **C4 (PR #134):** `feat/c4-owner-authority-readiness-20261119` @ `8c1d9ee7c8df2c93832a507e4466e0b3bd14715e`
- **C1→C4 Integration (PR #135):** `feat/c1-c4-integration-readiness-20261119` @ `4787effab0a0999f92ee9dc70696f5f66db0b364`

---

## 1. Reconciled Go-to-C4 Wire Implementation

Implemented in [c4_protocol.go](file:///E:/Virki/.worktrees/virki-c1-c4-native-bridge-20261119/infra/offline/c1-c4-native-bridge/c4_protocol.go) and [c4_client_linux.go](file:///E:/Virki/.worktrees/virki-c1-c4-native-bridge-20261119/infra/offline/c1-c4-native-bridge/c4_client_linux.go) using only the Go 1.26.10 standard library (`GOPROXY=off GOSUMDB=off`):

- **Protocol reconciliation:** Reconciles C1's `64 MiB` per-context ceiling (`64<<20`) and 4 canonical contexts (`source`, `dockerfile`, `offline-npm-cacache`, `offline-prisma-engines`) with C4's `VROA_V2` packed binary ABI (`1526`-byte `RequestFrame`, `4455`-byte `ResponseFrame`). Note: `VROA_V3` in prior docs remains unimplemented until `SIGN_ACK` signing is redesigned; this bridge speaks the live `VROA_V2` wire protocol and preserves `SIGN_ACK = 22`.
- **Sealed `memfd` + `SCM_RIGHTS` + `SHUT_WR`:** Creates Linux `memfd` descriptors sealed with `F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL`, transmits them via `SCM_RIGHTS` over `AF_UNIX` `SOCK_STREAM`, half-closes with `CloseWrite()` (`SHUT_WR`), and verifies the `4455`-byte `VROA_V2` response.
- **Invariants preserved:** `SIGN_ACK` returns status `22` (`ERR_SIGNING_DISABLED`), `DeployAuthorized: false`, `WorkerReceiptPairAdmitted: false`.

---

## 2. Remaining External Assurance Requirements (`PRODUCTION_READINESS: NO-GO`)

- Merge of PRs #133, #134, #135, and this bridge PR.
- Wiring `SendC4Request` into BuildKit v0.34.1's `solver/llbsolver` / `session/filesync` exporter path with `VROA_V3` signed owner permits.
- Hardware/OS-isolated Ed25519 key custody and multi-UID native Linux host validation (`ownerUid !== buildkitDaemonUid !== workerUid`).
- Hosted CI, CodeQL (C/Go/JS), and independent security sign-off on the final merged SHA.
