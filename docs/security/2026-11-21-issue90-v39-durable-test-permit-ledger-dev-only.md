# Issue #90 — V39 DEV: crash-durable synthetic permit claims before authenticated FD handoff

V39 is an **incremental, unwired BuildKit experiment** after the immutable V38 tree. The existing 16 patches and SHA-256 records V23–V38 are unchanged. No production FileSync admission, C4 release, deploy, Cloudflare change, merge or issue closure occurs.

## Narrow guarantee and trust boundary

The V15 permit is an **Ed25519-signed test-only** fixture under `virki-c1-v15-test-owner-permit-1`; the actual C4 owner service **does not issue** it. The synthetic broker's independently trusted supervisor provides the frozen manifest, verification key, acceptable epoch interval, ledger path, peer PID/UID/GID and destination. None is accepted from the sender. A dedicated root real/effective UID process with a root:root `0700` ledger directory and root:root `0600`, nlink=1 **pre-provisioned** log is required; the log must be durably created by a trusted supervisor *before* any broker use. Missing log is a refusal, never silently recreated as an empty replay history.

With `openat2` no-follow/no-XDEV custody and root-owner checks, an exclusive `flock` serializes independent processes. Existing records are read within a 1 MiB bound; malformed, duplicate, un-terminated or corrupt entries fail closed. Replay keys hash the signed V15 domain, epoch and ApprovalID. The ledger tracks the greatest previously claimed epoch as a monotonic **local** floor. A new signed claim must also satisfy trusted minimum/maximum epochs, manifest and expiry checks. The broker appends the claim, syncs the log and parent directory **before** reading any SCM_RIGHTS FD or copying/publishing source bytes. A failed/partial write or fsync never authorizes publication. Exhaustion refuses safely; there is deliberately no unsafe truncation, compaction or rollover.

`publishV39FromAuthorizedTestPeer` composes that claim with the already tested V37 `SO_PEERCRED` + exactly-one-FD handoff and V36 independent root-owned manifest publication. Any later handoff or publication failure **consumes the permit**; it cannot be recovered by replay. It is not a listener or a deployed service and grants **no release** after V38's ambiguous parent-fsync result.

## Verification

Opt-in, disposable Linux root fixture `VIRKI_V39_RUN_ROOT_FIXTURE=1` exercises valid and invalid Ed25519 signatures, epoch floor/ceiling, independent process concurrency (exactly one claim), replay after reopening, corruption/truncated records, mode and hardlink attacks, symlink and missing log, overflow, deterministic file-fsync EIO, absence of publication on invalid permits, and an actual unprivileged UID 60014 peer sending one SCM_RIGHTS directory FD. V39's ledger uses `RESOLVE_NO_XDEV`; in the WSL test environment `/tmp` is a separate tmpfs, so the disposable fixture uses `/var/tmp` on the root filesystem. This does **not** mean actual deployment mount namespaces are trusted or that failures caused by host restrictions prove isolation. Re-run `-race` and Go vet and verify the 17-patch replay.

## Immutable review identities

- V38 input cumulative tree: `86064bbbfdd3c6ebd9dfc6afc3bcd61938bfa10d`.
- V39 LF incremental patch SHA-256: `c5741043a56ce70c48a2cfab8481924a0773dad925fa31d7d3df8ece5040ddc9`.
- V39 cumulative BuildKit tree: `0acbf322c771b6c00a2803438fda77ac82c81a40`.
- Offline deterministic verification: `bash scripts/security/issue90-replay-index.sh <pinned BuildKit checkout>`. Uses a temporary index, never resets the dirty checkout.

## What is *not* proved

Durable fixture claims after successful `fsync` are **not** a real C4 monotonic authority, owner-signed PREPARE/COMMIT, power-loss hardware attestation, attested root/supervisor lifetime or real release policy. No trusted authority can prevent replay after a malicious root process truncates the ledger; such an adversary is outside this fixture's trust model. Authentication of the peer's kernel credentials is not proof of C4 owner approval. Actual C4 issuance, operational UID/mount/namespace/descriptor custody, authenticated acceptance, restart/recovery, independent review and authorization to deploy all remain absent. **Production protected C1/C4 remains NO-GO; issue #90 Close Issue: NO.**
