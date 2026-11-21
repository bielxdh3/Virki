# Issue #90 — V34: positive ptrace control must use the same OS thread (DEV only)

The original PR #141 review target `1123f0fde7ca54b6553091f956c4ebd77b91852e` remains immutable and traceable against `main@6802c432163ef7270cdcedc6d9fb55120698a1f3`. V34 is a strictly incremental patch on V33, not a rewrite of earlier releases or an authorization to activate protected C1/C4.

## Reviewer P2 and implementation

On Linux, the tracer identity for `PTRACE_ATTACH` / `PTRACE_DETACH` is tied to an OS thread ID. Go may migrate the goroutine that owns the V33 positive test between the attach, wait and detach syscalls. A successful positive attach on one thread followed by a detach on another can fail with `ESRCH`, incorrectly labeling a suitable host **INCONCLUSIVE** and blocking CI. V34 calls `runtime.LockOSThread()` before attaching the baseline child, defers `runtime.UnlockOSThread()` through the entire baseline and protected sequence, and asserts that the tracer TID did not change after detach or the protected denial. Failure cleanup remains on the same locked thread.

The V33 baseline remains mandatory: a same-UID, same-host, same-parent **unprotected** child with `PR_GET_DUMPABLE=1` must allow both `/proc/<pid>/fd` lookup and a successful `PTRACE_ATTACH`, observed stop and detach. Only then can a matched, protected `PR_SET_DUMPABLE=0` child be tested for denial of both operations. If Yama, seccomp, hidepid, LSM, a container policy or another host restriction makes the positive control impossible, the mandatory test must FAIL as **INCONCLUSIVE** and cannot be counted as proof of V32. A green negative-only test would be misleading.

## Integrity and evidence

- Immutable V33 input tree: `8f1537fd0132eeb12108a7faed4657ad019c8b41`.
- V34 LF patch SHA-256: `fb7f15e571c11ed553905c05fa433d6d740a64036fd64f2ef0c0a3ec15d642fc`.
- V34 BuildKit Git tree: `a411d348f5946769f97a7c28dc169abc7b374384`.
- Offline replay: `bash scripts/security/issue90-replay-index.sh <pinned-BuildKit-source>`, verifying twelve ordered patch hashes and exact cumulative Git trees through V34 without checking out or resetting the caller's worktree.
- Unprivileged Linux `go test -race -count=1 ./session/filesync -run '^TestC1V32SameUIDPeerCannotPtraceReceiver$'` must PASS with both positive and negative controls; `go vet -copylocks=false ./session/filesync` and privileged disposable multi-UID fixtures remain separately required by CI.

**Limits:** V34 proves an attributable process-memory/procfd denial on the **tested host**. It does NOT prevent a separate process using the receiver's UID from changing mutable stage-directory names or file contents before/after rename. V33 prevents false success for observed post-commit tampering but cannot prevent transient publication or mutation after final checks. Exclusive receiver UID, verified path/mount/peer custody, restart/replay/fsync evidence and independent operational sign-off remain prerequisites for issue #90 acceptance. Protected FileSync/C1 and C4 signing remain **production NO-GO**.
