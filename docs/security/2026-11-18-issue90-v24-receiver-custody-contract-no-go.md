# Virki #90 — C1 V24 Defensive Receiver Custody Contract (DEV-only, NO-GO)

**Date:** 2026-11-18  
**Isolated local branch:** `exp/issue90-receiver-custody-20261118`  
**Parent baseline:** `5fdcb5e0e147f99c1c443a01729539113f1f17d4` (on top of V23 `d12eeaacf9358ed6e099c369c3f45fe1789507e8`)  
**Pinned BuildKit v0.34.1 Git HEAD:** `f5b59a1f2fb25a0cb7072c398cab9aed7835da4e`  
**Incremental V24 custody patch:** `docs/security/experiments/buildkit-v0.34.1-c1-v24-receiver-custody-dev-only.patch`  
**SHA-256:** `7AE5639C932D468958D9F329F83E4DFBC368529680CCF5BDB1D22DF765038FFD`

**Disposition:** DEV-only defensive custody contract and synthetic permission-contract tests. Protected C1 FileSync remains disabled (`NO-GO` for merge, release, or production).

## Implemented defensive separation

- `session/filesync/sealed_custody_v24_linux.go` (`//go:build linux`) and `session/filesync/sealed_custody_v24_other.go` (`//go:build !linux`):
  - `V24ReceiverCustodyPolicy` and `validateV24ProcessIdentity`: fail-closed checks rejecting setuid/setgid transitions (`uid != euid || gid != egid`), root execution (`RequireUnprivileged`), UID/GID mismatches, and overlap with `ForbiddenPeerUIDs`.
  - `validateV24CustodyDirs`: `openat2` (`RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS`) verification requiring a receiver-owned `0700` parent directory (`RequirePrivateParent`) and, when `RequireImmutableGrandparent` is enabled, a non-receiver-owned, non-group/world-writable grandparent directory.
  - `receiveV24WithCustody`: enforces `V24ReceiverCustodyPolicy` before delegating to `receiveV23QuarantinedWithParentSync`.
  - `runV24IsolatedSubprocess`: launches a receiver helper with a stripped environment (`PATH`, `LC_ALL`, `HOME=/nonexistent`, `TMPDIR=/tmp`), `Pdeathsig: unix.SIGKILL`, optional `Credential` separation (failing closed if cross-UID separation is requested without privilege), and canonical absolute executable validation.
- `session/filesync/sealed_custody_v24_linux_test.go`: ordinary synthetic positive and permission-contract tests (`TestC1V24ReceiverCustodyIdentityContract`, `TestC1V24ReceiverCustodyParentAndGrandparentContract`, `TestC1V24IsolatedSubprocessStripsEnvAndEnforcesNoNewPrivs`).

## Limits and unmet acceptance criteria

- Ordinary synthetic tests on WSL/Linux without root do not prove multi-UID kernel isolation under active concurrent scheduling, mount-namespace isolation, or privileged `Credential` transitions.
- `scripts/experiments/issue90-receiver-custody.test.sh` continues to skip (`exit 77`) when run unprivileged.
- Does **not** satisfy adversarial same-UID race closure, native C4 `SIGN_ACK`, durable owner rollback floor, or production admission.
