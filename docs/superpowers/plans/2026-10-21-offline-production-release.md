# Owner-Approved Offline Virki Production Release Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) for tracking.

**Goal:** Deploy the exact reviewed Virki `main` SHA without GitHub Actions or GHCR, using separately signed local evidence and direct, authenticated artifact transport without weakening production safety or touching deManage.

**Architecture:** Add a strictly opt-in `offline-signed-v1` manual release route alongside (never as a fallback from) the existing GHCR/CodeQL route. The Windows builder prepares exact-SHA tests, scans and bundles; separate Ed25519 builder and owner signers authorize a canonical manifest. A preinstalled, independently protected verifier on the native Linux host validates trust roots, host identity, source, images, expiry and anti-replay before any uploaded application code executes or a production mutation occurs. Existing backup/restore, migration, maintenance, health and rollback controls remain mandatory.

**Tech stack:** Node 22/npm 10, node:test, Ed25519 via node:crypto, Git, Docker, Bash, SSH/SCP with strict pinned host key, PostgreSQL 17 disposable clones.

**Spec:** `docs/superpowers/specs/2026-10-21-offline-production-release-design.md`

## Global constraints

- Do not treat Semgrep as CodeQL or a developer-produced report as independent hosted provenance; offline assurance change requires an explicit owner acceptance distinct from requesting implementation.
- Never alter hosted-path `verifyExactShaCi()` semantics; no implicit retry, fallback or ignored failure.
- Do not store signing private keys in repo, local CI test worktree, `.env`, image, bundled archive or native production host.
- Production requires native Linux/amd64, SSH pinning, clean exact `main == origin/main`, an existing verified ADMIN, controlled backup and disposable recovery validation, and safe ingress/SMTP configuration.
- Worktrees remain under `E:\Virki\.worktrees`; tests/builds use isolated Node 22 Linux; deManage resources and credentials are off limits.
- Each substantial unit requires RED→GREEN regressions, fresh validations, review and a scoped local commit; never equate passing unit tests with release authorization.

## Review focus

1. **Trust-root substitution** — fake or swapped public keys, same key in builder/owner roles, revocation and expired approval must all fail prior to SSH.
2. **Source/artifact TOCTOU** — stat-to-open replacement, symlinks, path traversal, partial transfer and image reload substitution must fail before `docker load` or production writes.
3. **Replay/rollback ambiguity** — old signed SHA, mismatched predecessor, interrupted attempt and concurrent deploy must latch and refuse automatic continuation.
4. **Data/availability failure** — disk full, unsuccessful clone restore, absent ADMIN, incorrect migration state or Cloudflare routing failure must preserve data and a recoverable prior release.
5. **False CI evidence** — missing, duplicate or fabricated 19-stage results and unreviewed Semgrep findings must never be reported as CodeQL or automatic proof of safe deployment.

---

### Task 1 — Schema, cryptographic verification and local test evidence

**Files:** Create `scripts/lib/offline-release-attestation.mjs`, `scripts/offline-release-attestation.test.mjs`, `scripts/lib/offline-ci-evidence.mjs`, `scripts/offline-ci-evidence.test.mjs`.

**Interfaces:** Pure `verifyOfflineReleaseAttestation(...)` and `verifyOfflineCiEvidence(...)` functions with strict schema, pinned key material and expected host, exact SHA and platform values. No networking, file mutation, ambient environment fallback or production calls.

- [ ] Write adversarial tests for corrupt or oversized JSON, duplicate/unknown fields, mismatched SHA/host/predecessor/arch, invalid/stale/replayed/foreign-policy signatures, distinct-key requirement, stage duplication/skipping, dirty tree and invalid toolchain; verify expected RED.
- [ ] Implement minimal fail-closed Ed25519 builder/owner validation with domain separation, canonical serialization and report byte hash; verify GREEN.
- [ ] Run Node 22 tests, lint and diff check. Review independently and commit only the new files.

### Task 2 — Reproducible exact-SHA package preparation

**Files:** Create `scripts/offline-release-build.mjs`, `scripts/offline-release-build.test.mjs`; extract safe, read-only archive logic from `scripts/deploy-production.mjs` without altering hosted mode.

**Interfaces:** Input `main` exact SHA and verified local evidence/report files; output a manifest candidate, source archive, runtime/migrator image archives and hashes in a private, new, non-symlinked local staging directory; no signing keys read and no SSH.

- [ ] Write failing fixture tests for dirty tree/foreign remote, mismatched original-archive hash, untrusted scanner, image wrong label/arch, Docker save failure or swapped output file and inadequate free space.
- [ ] Implement source archive integrity checks, standalone builds and smokes, full raw evidence hashes and image archive content hashes/byte counts; verify RED→GREEN and independent report of exact SHA.
- [ ] Validate real `linux/amd64` OCI images and isolated CI on final source, check bundle confidentiality and perform independent review and logical commit.

### Task 3 — Owner approval and native-Linux trust root

**Files:** Create `scripts/offline-release-approve.mjs`, `scripts/offline-release-approve.test.mjs`, native trusted host verifier under `infra/` plus native-Linux tests; document one-time protected host/key provisioning in `docs/deployment.md`.

**Interfaces:** Builder signs manifest bytes, owner signs domain-separated digest after review; trusted verifier accepts separately provisioned owner/build public keys, explicit enabled-policy file and candidate bundle; rejects missing/revoked keys and caches no trust from uploaded source.

- [ ] Write RED tests for key collision, tampered approval, revoked/unpinned key, expired nonce, wrong host marker, replay or decreased sequence, failed atomic ledger update and concurrent verifier processes.
- [ ] Implement private-key handling without printing or copying secrets; independently protected server trust roots and ledger with no-follow/owner-only permissions and exclusive lock.
- [ ] RED→GREEN on native Linux fixture; independent hostile-input review. Do not provision live keys without explicit separate owner authorization.

### Task 4 — Offline transport and guarded deployment integration

**Files:** Adapt `scripts/deploy-production.mjs`, `scripts/production-preflight.mjs`, `scripts/production-remote.mjs`, `scripts/production-server.sh` and focused production tests; add explicit `npm run deploy:prod:offline` only after mode has a fully testable happy path.

**Interfaces:** Manual offline mode requires signed, bound manifest and trusted native-host loader. Preserve hosted mode unmodified; adapt protected remote source-state to accurately record `release_gate=offline-signed-v1` and approval digest, never `ci=success` for local-only scans.

- [ ] Write RED tests proving default GHCR mode still rejects missing CodeQL and offline mode refuses absent owner keys/host policy/ADMIN/backup, avoids production mutation on malformed packages, and never touches deManage or other Compose projects.
- [ ] Implement guarded SCP/staging; trusted host checks bytes/signatures before image import or source execution; verify loaded image ID/config/labels/arch, disk budget, predecessor and exclusive anti-replay ledger.
- [ ] Reuse existing protected data backup, disposable PostgreSQL restore, migration, health, Tunnel/Access and rollback controls; test interrupted image upload and simulated failed migrations; independent security code review.

### Task 5 — Final full SHA and live deployment decision

**Files:** PR #56 metadata and private operator-only evidence files (never tracked); no unrelated project modifications.

- [ ] Verify `origin/main` and PR branch, merge only after security reviews and green local tests, and preserve a recorded merge SHA.
- [ ] Run the full 19-stage Docker CI plus fresh scanner review, runtime/migrator image builds and smokes **on that final merged SHA**, produce full signed immutable bundle and independent owner approval explicitly accepting offline assurance limits.
- [ ] Reconfirm native host identity, ADMIN, free disk, real backup restore, maintenance and rollback; stage in native-Linux isolation, then perform owner-authorized one-shot deployment, no automatic fallback.
- [ ] Verify expected revision of every service, user portal/issuer, Cloudflare ADMIN boundary, SMTP and deManage continuity. On any failure, leave an accurate blocked/maintenance/recovery status rather than claiming deployment.
