# Virki — C4 Owner Authority & Protected FileSync Readiness (2026-11-19)

**Disposition:** `C4_MERGE_CANDIDATE: GO (DEV/DEFENSIVE ONLY)` | `PRODUCTION_ACTIVATION: NO-GO`  
**Base `main` SHA:** `caf3df893ab8909150a2c0197d2741d6f73e40cf`  
**Separate C1 PR #133 (`review/issue90-v25-20261118`):** `dfe721e254a6e28e9cffa073a74a881cf1019d73` (left intact and independent)  
**Historical C4 V23 Reference (`cos/pr88-c4-v23-20261101`):** `b645500bd7c5e6e325f946db388c5093e9be3c75`

---

## 1. Scope & Reconciliation with Current Architecture

This package reconciles the C4 native owner authority daemon (`infra/offline/native-owner-authority/`) onto `origin/main` as a self-contained, non-authorizing defensive component:

- **Default denial preserved:** `VIRKI_OWNER_CMD_SIGN_ACK` remains unconditionally denied (`VIRKI_OWNER_STATUS_ERR_SIGNING_DISABLED = 22`) via `const bool native_c4_verified_signer_ready = false;` with no CLI or environment override.
- **Host verifier closure preserved:** `infra/offline/trusted-owner-installation.mjs` (`AUDITED_FILES`), `trusted-release-coordinator.mjs` (`deployAuthorized: false`), and `scripts/lib/offline-release-*.mjs` remain untouched.
- **Issue #90 / PR #133 kept separate:** No BuildKit patches or `docs/security/experiments/` files from PR #133 are modified. Any future end-to-end C1→C4 integration depends on PR #133 (or its successor) landing C1's `FSSyncSealedV15` receiver custody first.

---

## 2. Defensive Hardening Applied Over Historical C4 V23

Reconciling three independent read-only reviews (architecture/scope, test quality/reproducibility, security/trust boundaries):

1. **Self-contained dependencies:** Vendored only `tweetnacl.h`, `tweetnacl.c`, and `buildkit-context-abi.h` inside `infra/offline/native-owner-authority/` (no `../native-bootstrap/` sprawl).
2. **No metadata disclosure on `ERR_PEERCRED`:** `resp.epoch`, `resp.sequence_number`, and `resp.owner_key_id` are populated only after `SO_PEERCRED` UID + primary GID validation succeeds.
3. **Aligned `cmsghdr` buffer & `poll()` loop:** Replaced `char control[...]` with an aligned `cmsghdr` union in `owner-frame-v21.h` and replaced `select()` with `poll()` in `native-owner-authority.c`.
4. **Fail-closed CLI & key custody:**
   - `--key-fd` uses strict `strtol` (`fd > 2`), `fstat()` type check, and `EINTR`/short-read looping.
   - Explicit `--key-fd` / `--key-file` failures exit non-zero instead of starting keyless.
   - `--dev-test-v9fs` relaxes `0400`/UID key-file checks only when `fstatfs()` reports `V9FS_MAGIC` (`0x01021997`).
   - `snprintf` path/ID truncation fails closed; trailing `/` on `--socket` is rejected; `geteuid() != getuid()` is rejected in strict mode; `explicit_wipe()` clears key material on all exit paths.
   - `sequence_floor` advances only after `write()` + `fsync(ledger_fd)` + `fsync(dir_fd)` succeed.
5. **Reproducible, hardened tests:**
   - `native-owner-authority.test.mjs` now compiles and runs `native-owner-authority.test.c`, uses hardened GCC flags (`-D_FORTIFY_SOURCE=2 -fstack-protector-strong`, `-fPIE -pie -Wl,-z,relro,-z,now`), per-run `mkdtempSync` binary dirs, `process.hrtime.bigint()` deadlines, explicit `{ skip }` gating on non-Linux/root, and regressions for `ERR_PEERCRED` metadata redaction, `--key-fd`, `0644` key files, and path truncation.

---

## 3. Remaining External & Pre-Activation Requirements (`PRODUCTION_ACTIVATION: NO-GO`)

Before `SIGN_ACK` (`VROA_V3`) or protected FileSync could ever be considered for production:

- **C1→C4 provenance bridge:** Dependent on PR #133 (C1 `FSSyncSealedV15` receiver custody) plus a real BuildKit v0.34.1 worker→owner contract verifying `.dockerignore` / FileSync manifest, OCI DAG/image ID, and tree+stream digest parity.
- **Signed owner approval & domain-separated ACK:** Replace caller-claimed `approval_*` fields with verified Ed25519 owner approval envelopes (`VIRKI_OFFLINE_OWNER_APPROVAL_V1\0`) and SPKI `pinSha256` / revocation policy parity with `scripts/lib/offline-trusted-release-policy.mjs`.
- **Durable ledger integrity & anti-rollback:** Add per-record hash chaining/MAC, authenticated ledger rotation/checkpointing, and external witness anti-rollback (`offline-independent-witness-service.mjs`).
- **Physical host & key custody:** Independent non-root OS UIDs/GIDs on native Linux/amd64, hardware/OS-isolated key custody, hosted CI + CodeQL green on the exact commit SHA, and independent security sign-off.
