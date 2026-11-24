# Issue #90 — V32 non-dumpable independent receiver (DEV only)

## Finding and security boundary

V23–V31 verified staged bytes, quarantined publication and a synthetic separate-UID receiver, but `PR_SET_NO_NEW_PRIVS` alone does **not** bar an untrusted *same-UID* process from using `ptrace` or accessing the receiver's `/proc/<pid>/fd` namespace. A same-UID process with that access could inspect or manipulate in-memory session/FD state. This is separate from the still-unresolved same-UID **filesystem pathname** race: disabling ptrace does not prevent an attacker who controls the same receiver UID from replacing `stageName` between `requireV23StageNameIdentity` and `renameat2`.

## V32 incremental, non-production fix

`validateV24IndependentCustody` now runs `enforceV32NonDumpableReceiver` **after all existing independent-identity, namespace and path permission checks, before the receiver reads sealed transport data**. It invokes Linux `PR_SET_DUMPABLE=0`, reads back `PR_GET_DUMPABLE`, and fails closed on syscall error or a nonzero result. The enforcement occurs **after execve** because the Linux kernel may reset dumpability when an executable starts. Ordinary V15 DEV paths and production C1/C4 admission are unchanged; V24 remains available only with explicit supervisor-custody policy.

`TestC1V32SameUIDPeerCannotPtraceReceiver` launches a separate child with the **same Linux UID** and applies the actual V32 guard. Its parent attempts `ptrace(PTRACE_ATTACH)` and `/proc/<pid>/fd/1` inspection, requiring both to be denied. The positive V24 root-supervised real gRPC synthetic FileSync receiver also asserts dumpability is zero **inside its isolated child** after receiving the transfer. This tests an actual kernel security boundary, not just a mocked flag. Root and unprivileged tests, `-race` and Go vet can run offline against the pinned BuildKit source and vendored modules.

Pinned BuildKit base: `f5b59a1f2fb25a0cb7072c398cab9aed7835da4e`. V31 input tree: `c8d30aca6c0df02cd49b5746d414194496fa72ff`. Incremental V32 LF patch SHA-256: `9940bb8aae77f727761bc9872e5e5170b331969b056052ec90a1c950f707144b`; V32 output Git tree: `fcecd3d1c3d9810bb3060310f822fcb7f6da5305`. The CI must verify all V23–V32 hashes/trees in application order. No earlier patch is regenerated or changed.

## Still not a closure or a production release

The root-supervised fixtures demonstrate known UID separation at the time of the tests; they **cannot prove exclusive custody of a real receiver UID throughout the entire operational lifetime**. Directory entries remain alterable by another process with that UID if such a process can exist. Before #90 can be closed, an independent operator must attest that the receiver UID/GID is exclusive, the root-owned supervisor executable and protected directory ancestor chain are correctly provisioned, peer/FD authentication and mount namespace/propagation are controlled, and adversarial publication/recovery/replay/fsync outcomes are validated under that runtime. A trusted supervisor must block activation upon failed controls, not silently fall back to the V15 path. An alternative fully inode-bound publication design would require its own implementation and proof.

**Status:** stronger DEV defense, **not** proof of same-UID pathname-race elimination. Protected FileSync/C1, C4 production signing, deployment and issue closure remain **NO-GO**. No production changes are made by this patch.
