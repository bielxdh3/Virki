# Issue #90 — V40 DEV: authenticated replay history and conservative rollback fence

V40 fixes the reviewer P2 in V39. The previous V23–V39 patches are immutable; V40 is one new incremental BuildKit patch. This is a **test-only, unwired** root-owned publisher. It does not issue real native C4 owner approvals or authorize release.

## Concrete failure fixed

V39 stored rows containing a SHA-256 claim key but no integrity MAC. Replacing one hexadecimal digit with another valid digit silently removed the real permit from the in-memory replay set. V40 refuses unauthenticated V39 log rows; migration or clearing of existing history is **never automatic**.

V40 stores each claim as `V40 epoch sha256Key chainedHmac`, where the MAC is HMAC-SHA256 over a domain label, canonical ledger path, prior MAC tip, canonical epoch and claim key. A distinct root-owned `0700` trust directory (sibling `-anchor`) contains a pre-provisioned 32-byte random `0400` HMAC key and an authenticated `0600` checkpoint. The checkpoint MAC binds a domain label, ledger path, trusted Ed25519 public key, record count, highest epoch and chain tip. All must match **exactly** before further claims; invalid hex (including valid-hex mutation of an already recorded claim), malformed/duplicate/intermediate rows, truncation, stale checkpoints, swapped path identities, ownership/mode/hardlink/symlink violations and empty/missing trust state refuse.

The ordinary V39 entrypoint now delegates to V40. A kernel flock on the root-owned `0600` log serializes independent processes. A transaction is first durably marked `inflight` in the trust directory; only after marker file and parent fsync is the bounded new row appended. The broker fsyncs log and ledger parent, writes and fsyncs a new checkpoint under `O_EXCL`, atomically renames it over the old checkpoint, fsyncs the trust parent, verifies the checkpoint, then removes the intent and fsyncs the trust parent again. Errors or crashes before the final durable commit leave a marker or an anchor/log mismatch; all later claim and publication attempts fail closed, including subprocess restart and alternative signed permits. No implicit history reconstruction, truncation, rollback, pending cleanup or compaction is provided.

Only a successfully committed new permit may proceed to the V37 bounded `SO_PEERCRED` + single `SCM_RIGHTS` directory FD handoff and V36 bounded root-owned copy to a private no-follow destination. If the subsequent peer or publish fails, that signed test permit stays consumed; an ambiguous V38 publication remains unadmitted.

## Tests and replay

Linux root DEV fixtures (opt-in `VIRKI_V39_RUN_ROOT_FIXTURE=1 VIRKI_V40_RUN_ROOT_FIXTURE=1`) cover valid-digit mutation of a prior claim hash, changed middle row, authenticated checkpoint tamper, stale independent log/anchor rollbacks, truncated records, log inode replacement with older signed prefix, key replacement, valid/invalid signed permits, monotonic epoch, two independent processes claiming the same permit, subprocess restart refusal, fault-injected log/checkpoint/parent fsync and blocked publish for both reused and different permits. Complete Go `-race`/vet and privileged V24–V40 synthetic fixtures remain mandatory. The WSL fixture uses `/var/tmp` because `/tmp` is a separate tmpfs; `RESOLVE_NO_XDEV` remains enforced.

- Immutable V39 base tree: `0acbf322c771b6c00a2803438fda77ac82c81a40`.
- V40 incremental LF patch SHA-256: `a20084bcced441d2604e11f8436979ee5db11df720f5d2cf344e01e4e5cadf46`.
- V40 cumulative tree: `50d92e619251b1b4a889f9c6f6d7489ce2a56f6f`.
- Deterministic `scripts/security/issue90-replay-index.sh` reconstructs all 18 patches/trees without resetting or modifying the caller's checkout.

## Trust limit and outstanding gates

The trust key and checkpoint must be independently provisioned and retained by a **trusted root principal**. A malicious root with authority to replace key, log and checkpoint together can roll back a locally authenticated history; no software MAC on the same privileged host prevents that. A truly root-independent monotonic C4 owner authority or hardware-backed antirollback requires a separate approved integration, and is **not simulated here**. EIO or power loss during fsync also cannot prove hardware durability; the error path blocks rather than admitting. Tests establish only synthetic controls and deterministic failure injection, not adversarial power failure, mount namespace isolation of an actual supervisor, or production C4 signature/authorization. The original same-UID V35 direct rename path is not enabled or certified. **Protected production C1/C4: NO-GO. Issue #90 closure: NO.**
