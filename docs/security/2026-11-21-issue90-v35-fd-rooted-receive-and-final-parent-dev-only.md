# Issue #90 — V35 DEV hardening: FD-rooted receive, parent pinning and postseal identity

This incremental, **DEV-only** patch is applied strictly after V34. All V23–V34 hashes and cumulative trees stay immutable. The original #141 reviewer target `1123f0fde7ca54b6553091f956c4ebd77b91852e` remains traceable against `main@6802c432163ef7270cdcedc6d9fb55120698a1f3`.

## Newly narrowed TOCTOU windows

1. **Pin staging before receiving.** The receiver now opens the freshly created quarantine directory FD immediately after `mkdirat` and gives the receive callback `/proc/self/fd/<stageFD>`, not `/proc/self/fd/<parentFD>/<mutable stageName>`. An attacker who swaps the stage basename while the callback writes does not redirect those bytes into the substituted directory. Source-name identity still must match at publication; a rename/symlink substitution fails closed. The original stage is retained if its name has been replaced, rather than recursively deleting a name that now points to a different inode.
2. **Keep the same owner directory for sync.** The parent fsync descriptor is opened as `openat(pinnedParentFD, ".")` and checked by dev/inode against that pin; it no longer traverses the mutable full parent pathname a second time. This is a correct sync FD for the directory actually used in `renameat2`.
3. **Fence false successful admission after publication.** Following the V33 membership/content rehash, recheck that the published destination basename still references the verified stage inode. Also resolve the requested absolute parent pathname without symlink/magic-link traversal and compare its identity against the pinned parent. A postseal destination swap, symlink substitution or ancestor parent replacement returns `V22PublishedButUnadmittedError` instead of falsely reporting success.

## Adversarial regressions

`TestC1V35PublishedPathSwapAfterLastContentSealNeverReportsAdmission`, `TestC1V35PublishedSymlinkSwapAfterSealNeverReportsAdmission`, `TestC1V35PinnedStageReceiverWritesSurviveStageNameSwap`, and `TestC1V35ParentPathSwapAfterFsyncNeverReportsAdmission` introduce controlled same-UID directory/symlink/parent races at independent phases. Positive controls check the originally approved FD-rooted content remains correct; negative checks require publication to be rejected or marked terminal **published-but-unadmitted**. Existing V23/V33 fsync, overwrite and injected-entry tests remain mandatory. The original `TestC1V32SameUIDPeerCannotPtraceReceiver` retains both unprotected same-UID positive controls and protected negatives on one pinned OS thread (V34). Environmental ptrace restrictions are **INCONCLUSIVE**, never evidence of isolation.

## Immutable chain

- V34 input Git tree: `a411d348f5946769f97a7c28dc169abc7b374384`.
- V35 LF incremental patch SHA-256: `f7c691d5ea9ec1f12a4b1b1a0d98cf3d6dca95e4c5ef4c5853b3eb0e310ee362`.
- V35 cumulative Git tree: `4da0f43bfcdad770f4a1bf5786ec6df79f6f4a97`.
- Replay all 13 patches using `bash scripts/security/issue90-replay-index.sh <pinned BuildKit checkout>`. CI reconstructs each exact tree in a disposable Git index. Test Go 1.26.10 vendored dependencies with `-race`, Go vet, root-supervised synthetic multi-UID fixtures and deterministic stage races; review the **latest** PR SHA independently.

## Explicit limits / production NO-GO

Linux `renameat2` still uses the **mutable source basename**, not an inode-bound source reference. A same-UID adversary with directory write authority can replace the basename immediately after a validation or mutate bytes after the final rehash. V35 can detect the tested races and avoid incorrect admission, but **cannot guarantee that unverified bytes are never transiently visible at the destination**. Pathname cleanup is best-effort; no recursive deletion scheme tied to the same hostile parent is an independent custody guarantee. A separately trusted publication broker that verifies a bounded deep copy into protected inodes under a different principal, or equivalently secured exclusive receiver UID and private mount/peer supervision, must be implemented and independently attested for real production C1 admission. This patch does not deploy, change Cloudflare, migrate data, enable protected FileSync or authorize C4 signing.
