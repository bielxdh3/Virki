# Issue #90 — V30 receiver executable pinning (DEV-only)

## Confirmed implementation gap and correction

The V29 independent receiver validated the helper executable using `os.Lstat` and non-writable file mode, then executed the **path string** using `exec.CommandContext`. A root-owned, read-only helper underneath a receiver/peer-owned directory can be substituted by rename after that `Lstat` and before execution; merely refusing write access to the original inode does not prevent this. A substituted executable could inherit the supervisor-provisioned socket descriptors and the receiver's separated credentials. This is a DEV launcher hardening gap, not a claim about an existing production exploit.

V30 opens the helper once using Linux `O_PATH | O_NOFOLLOW | O_CLOEXEC`, checks that **pinned inode** for regular-file type and non-writable mode, and retains its descriptor until subprocess completion. In the independently supervised mode (`RequireImmutableGrandparent`), it also requires root inode ownership and verifies the entire executable-directory ancestry is root-owned and protected against untrusted rename. `v30PinnedHelperCommand` appends the executable FD **after** existing inherited socket FDs, preserving fd=3 for the existing session; the child executes `/proc/self/fd/<last-fd>` instead of re-resolving the mutable parent-supplied name. If `/proc/self/fd` is unavailable or the checks fail, the launch fails closed. No elevated execution path is enabled in production.

## Deterministic regression evidence and pinned bytes

- `TestC1V30PinnedHelperExecSurvivesAdversarialRename`: opens the approved script inode, renames the original path, creates a different script at that exact path, and confirms FD execution returns `SAFE`, not replacement `EVIL`.
- `TestC1V30RootSupervisorExecutableCustody`: root-supervised positive launch into UID 60001 succeeds only for a trusted root-owned helper under root-protected ancestors. It rejects a root-owned file inside a receiver-controlled directory and a receiver-owned executable in a root-owned directory before process start.
- Existing actual sender+receiver separate-UID integration and three-UID symlink/rename/write/mount race fixtures PASS under the same launcher code.
- Existing OIDC/public-site code, SARIF dispositions, VROA V3 exporter-intent patch hash/tree and production C1/C4 NO-GO remain untouched.

Baseline: BuildKit `f5b59a1f2fb25a0cb7072c398cab9aed7835da4e` plus existing V23–V29 tree `9607e2d13c28168f2f00a9370737b622b080ccc9`. V30 incremental LF patch SHA-256 `0d418e9fb5faa172b91514daa86522144be707b9724c5c16c257c81ece4a7d8b`. V30 reconstructed Git tree `c8f6df12b47ef2540bf2553ac5a9ecc9ce892971`. Offline Go 1.26.10 focus tests and `go vet -copylocks=false ./session/filesync` PASS locally; exact-SHA GitHub CI and independent review must be checked after publication.

**Remaining gate:** A synthetic owner/receiver identity cannot prove that a real production receiver UID has no untrusted same-UID processes for the complete lifetime, that namespaces/mount propagation are independently controlled, or that transport peers are authenticated. No protected FileSync, production signing, C1/C4 approval, merge, deploy, migration or issue closure occurs through V30.
