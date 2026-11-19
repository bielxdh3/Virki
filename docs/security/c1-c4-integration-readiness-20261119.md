# Virki — C1→C4 Integration & Defensive Readiness (2026-11-19)

**Disposition:** `INTEGRATION_CANDIDATE: GO (DEV/DEFENSIVE ONLY)` | `PRODUCTION_AUTHORIZATION: NO-GO`  
**Explicit Upstream Dependencies:**
- **C1 (Issue #90, PR #133):** `review/issue90-v25-20261118` @ `dfe721e254a6e28e9cffa073a74a881cf1019d73` (unmerged)
- **C4 (PR #134):** `feat/c4-owner-authority-readiness-20261119` @ `816713cfa80893b4e50dfb2870a634c65f460443` (unmerged)
- **Base `main`:** `caf3df893ab8909150a2c0197d2741d6f73e40cf`

---

## 1. Reconciled C1→C4 Integration Contracts

Implemented in [c1-c4-contract.mjs](file:///E:/Virki/.worktrees/virki-c1-c4-integration-20261119/infra/offline/c1-c4-integration/c1-c4-contract.mjs) and verified in [c1-c4-integration.test.mjs](file:///E:/Virki/.worktrees/virki-c1-c4-integration-20261119/infra/offline/c1-c4-integration/c1-c4-integration.test.mjs):

1. **Build input & artifact provenance:** Enforces the 4 canonical contexts (`source`, `dockerfile`, `offline-npm-cacache`, `offline-prisma-engines`), C1/C4's `64 MiB` per-context ceiling (`64<<20`), and SHA-256 stream-digest parity.
2. **FileSync manifest & ignore-rule consistency:** Rejects `includedPaths`/`excludedPaths` overlaps, path traversal, duplicates, and manifest SHA-256 drift.
3. **Output identity & non-publishing receipt:** Requires `exporterMode: "staged-nonpublishing"` (`store=false`, `push=false`, `pushByDigest=false`, `unpack=false`), `workerReceiptPairAdmitted: false`, and `deployAuthorized: false`.
4. **Cryptographic owner-authorization contract:** Domain-separated Ed25519 verification (`VIRKI_C1_C4_OWNER_APPROVAL_V1\0`) over the canonical contract SHA-256, bound to SPKI `pinSha256` and revocation lists (`revokedKeyIds`, `revokedPinsSha256`).
5. **Persistent authorization-state integrity & recovery:** Anchored (`O_EXCL`), hash-chained state transitions (`PREPARED`/`ABORTED`), epoch-fenced recovery, and fault-fencing (`faulted: true`).
6. **Anti-rollback assurance:** Rejects epoch, sequence, or head-digest regression against an external witness checkpoint.
7. **Identity & key custody separation:** Enforces distinct non-root numeric `ownerUid !== buildkitDaemonUid !== workerUid`, `isolated-spki-pin` custody, and zero inline private key material, while the live native C4 daemon continues to deny `SIGN_ACK` with status `22`.

---

## 2. Remaining External Assurance Gates (`PRODUCTION_AUTHORIZATION: NO-GO`)

- Merge of PR #133 (C1 `FSSyncSealedV15`) and PR #134 (C4 `native-owner-authority`).
- Real BuildKit v0.34.1 Go-to-C4 `VROA_V3` wire bridge (sealed `memfd` handoff + OCI exporter DAG causality).
- Hardware/OS-isolated Ed25519 key custody and multi-UID native Linux host execution.
- Hosted CI, CodeQL (C/JS), and independent security sign-off on the final merged SHA.
