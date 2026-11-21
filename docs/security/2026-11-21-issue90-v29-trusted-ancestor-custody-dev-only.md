# Issue #90 — V29 trusted ancestor custody and adversarial Linux fixture (2026-11-21)

## Scope and threat boundary

This is a **DEV-only defense-in-depth** supplement to the already merged PR #133 / V23–V28 experiment. It addresses a concrete gap in the Linux independently supervised receiver: `validateV24CustodyDirs` verified the receiver-owned private parent and its root-owned immediate grandparent, but did not validate every ancestor leading from `/` to that grandparent. A root-owned grandparent inside an attacker-writable ancestor could be renamed by the attacker before a later pathname lookup. Checking its own mode or inode alone is insufficient.

V29 opens and checks every ancestor through an FD-rooted, no-symlink/no-magiclink `openat2` walk. Each ancestor must be a root-owned directory and non-writable by untrusted peers. A root-owned sticky directory is permitted (for example `/tmp`), since an unprivileged caller cannot rename its root-owned children; a non-sticky group/world-writable directory and any user-owned ancestor are denied. The original receiver-owned 0700 parent, root-owned immutable grandparent, fixed-manifest, no-follow content inspection, no-replace rename, ambiguous fsync handling and replay fences remain unchanged. The receiver must still be a *distinct* unprivileged UID from the sender/observer.

## Reproduction and integrity

- Existing pinned BuildKit base: `f5b59a1f2fb25a0cb7072c398cab9aed7835da4e`.
- Existing cumulative V23–V28 chain: output tree `c7234b862c991a940c3047f05a6f2752d7fd1e6f` (unchanged).
- Additive V29 patch SHA-256 (canonical LF bytes): `b85225c7756ee736c20da1df34c9e07c3bea074951aadc0bcd370bee36eda292`.
- Resulting V29 Git tree: `9607e2d13c28168f2f00a9370737b622b080ccc9`.
- The existing CI replay step checks all seven SHA-256 values and the exact intermediate Git trees. Ordinary Linux tests now include `TestC1V29SupervisorAncestorChainRejectsUntrustedPaths`.
- The root-supervised synthetic Linux fixture additionally runs `TestC1V29SupervisorAncestorRejectsWritableRootPath`, the existing positive `TestC1V24IndependentReceiverProcess`, and `TestC1V28AdversarialMultiProcessCustodyAndSwapRace` with added peer syscalls for directory enumeration, bind mount and tmpfs mount (all expected to be denied). Each test uses disposable synthetic identities/files and no production data, network listener, or deployment.

## Local results and remaining acceptance

On 2026-11-21, reconstructed the full V23–V28 BuildKit source in a separate scratch clone, verified all six intermediate Git trees against the frozen manifest, and validated the V29 source under Go 1.26.10 with offline vendored dependencies. Unprivileged `TestC1V2*` PASS (the two privileged fixtures are explicitly SKIPPED in the unprivileged run); then, with a root-supervised synthetic Linux fixture, the new root-owned ancestor test, multi-process receiver/peer swap-race test and cross-UID positive receiver test all PASS. The incremental patch applied to the cached V28 tree and produced the exact expected V29 tree.

**Non-claims:** these results validate a synthetic Linux multi-UID permission boundary, not independently provisioned custody for a real production receiver throughout its lifetime, a complete peer-credential authentication protocol, immunity to a privileged attacker with CAP_SYS_ADMIN, proof against arbitrary hostile mount propagation, or C1/C4 release admission. Issue #90 must remain open until the operational custody and residual adversarial criteria are independently established. Protected FileSync, C4 signing and production publication remain NO-GO. No merge/deploy/production changes are authorized or performed.
