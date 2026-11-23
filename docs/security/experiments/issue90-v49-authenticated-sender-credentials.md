# Issue #90 V49 — per-message sender authentication (DEV-only)

The historical V23–V48 BuildKit patches remain byte-for-byte immutable.
V49 is a new incremental, reproducible patch on top of the pinned V48 Git tree
`d63d46e43eedca0203cf555611b27c3cf03c49d0`, with the resulting
V49 tree `c02dad283db232bba7f02128e88697feeea6dffa`.
`scripts/security/issue90-replay-index.sh` verifies all **27** patch
hashes and cumulative trees without modifying its caller's Git index.

## Demonstrated defect (RED)

The Linux kernel's `SO_PEERCRED` describes the peer that connected the
AF_UNIX stream, **not** necessarily the process that later sends a
`SCM_RIGHTS` message. A synthetic sender A connects, forks/execs sender
B and exits; B inherits the same socket, sends a legitimate private directory
FD and the original connector's PID remains visible through `SO_PEERCRED`.
This was reproduced in WSL2 Ubuntu and a disposable Docker Linux container.

The new native Go regression
`TestC1V49InheritedUnixSocketCannotSpendPermit` reproduces both failures
against V48:

1. `receiveV37AuthenticatedStageFD` accepts B's FD as if A sent it.
2. `publishV39FromAuthorizedTestPeer` consumes a signed DEV permit,
   although A is already dead and B is not the trusted PID. The same permit
   subsequently fails with a replay error. No production C4 key is used.

## V49 correction (GREEN)

- The accepted Unix socket enables `SO_PASSCRED`; the bounded message
  requires exactly one `SCM_RIGHTS` and one kernel
  `SCM_CREDENTIALS` ancillary record.
- The actual sender PID/UID/GID must match the pinned supervisor identity,
  not just the original connection credentials. Truncation, unexpected CMSG
  records and extra descriptors fail closed; rejected FDs are closed.
- The V39 reference composition preflights the connection, receives and
  authenticates the **actual** descriptor sender, then performs the durable
  one-time V40 claim **before** the protected V36 publication.
- Unauthenticated senders no longer consume otherwise-valid DEV permits.
  Authenticated post-claim failures continue to require owner reauthorization.

Validation on WSL2 Linux with Go 1.26.10: V37/V39/V49 targeted tests passed
both ordinarily and with `-race`, no skipped tests; `go vet`
passed. The immutable V23–V49 SHA/tree replay passed.

## Trust boundary

V49 is synthetic, deliberately **unwired** to production FileSync. Neither
this test nor `SCM_CREDENTIALS` provisions actual C4 owner signing,
key custody, a monotonic external rollback witness or secure supervision.
Numeric PID identity does not itself pin process lifetime across PID reuse:
a real supervisor should retain independently authenticated process handles
(e.g. pidfd) and establish its host/namespace threat model before activation.
No deployment, release, merge, Cloudflare change or issue closure is authorized.
