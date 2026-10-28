# Disposable killable Linux staging supervisor (DEV-only)

The standalone C experiment in `infra/offline/native-supervisor/disposable-killable-stage.c`
is **non-authorizing**. It stages at most **64 MiB** of a protected,
SHA-256-pinned fixture archive into a sealed anonymous Linux `memfd`.
It never contacts a Docker daemon, opens a production socket, runs migration
SQL, changes application routing, invokes `scripts/production-server.sh`,
or claims hosted CI/real host identity. Its `deployAuthorized`,
`dockerLoadAuthorized`, and `transferAuthorized` responses are always false.
The approved W4 C transport is untouched: this is a separate staging
subsystem, **not yet wired to that transport**.

## Kernel enforcement and lifetime

The executable rejects normal hosts, Windows/WSL-only runs, user-provided
executables and source paths, unknown commands, and missing disposable gates.
It demands a root-run disposable container, owner-private fixture directories,
and finite root-owned **cgroup v2** `memory.max` (96–256 MiB) and `pids.max`
(4–64). It also requires a private ext4 filesystem mounted at
`/journal`, different from the container's root filesystem, plus `/tmp`
mounted as tmpfs. Test containers have no network and use a read-only root.
The fixture root is a strict six-character suffix directly under
`/journal/virki-killable-stage-XXXXXX`.

After pinning an owner-only 0600 SHA-256 plan and owner-only regular archive,
the parent creates `state/attempt.lock` with `O_EXCL|O_NOFOLLOW`, writes an
unpredictable nonce and expected digest, and **fsyncs the attempt file and its
containing ext4 directory before forking**. The lock is never stolen, cleared
or silently replayed, even after a successful stage. Failed or uncertain
transactions are terminal without independent reconciliation.

Each child arms its own kernel `CLOCK_MONOTONIC` SIGKILL timer
**before any blocking start-handshake receive**, including when its supervisor
is stopped before sending the first G byte. The parent also obtains `pidfd`
and an independently armed `timerfd`. The children drop supplemental groups,
UID/GID to 65534, capabilities and journal directory FDs, set
`PR_SET_NO_NEW_PRIVS`, then install `PR_SET_PDEATHSIG(SIGKILL)` after the
credential transition (Linux otherwise clears the death signal). The POSIX
timer delivers `SIGKILL` from the kernel **even if the supervisor is stopped**.
The staging child performs the
potentially blocking `pread`, `pwrite`, hashing, `fsync` and sealing;
the parent never performs untrusted source staging. Only a full SHA-256 match
and sealed snapshot is transmitted via `SCM_RIGHTS`. The parent requires
an exited, **reaped** staging child before forwarding the sealed FD to a
**second, independently killable, privilege-dropped verifier child**, which
re-reads the complete snapshot and checks its SHA-256 and seals. Neither
the parent nor an unsupervised thread performs full-file hash/pread. The
parent requires the verifier to exit and be reaped before fsyncing a separate
`complete.json` record. No staged FD is sent to
a network peer or used for any side effect.

The journal is addressed using pinned `/journal` / fixture / state directory
FDs and `openat`, with `fstatat` inode identity rechecks. The root-owned
0700 ext4 fixture and 0600 files are inaccessible to the UID 65534
children, and all inherited unrelated descriptors are closed before the
credential drop. A test explicitly verifies the child cannot open the
attempt journal for writing. Privileged same-container root compromise or
host-controlled mount substitution remains outside the trust model.

The watchdog is **1.5 seconds per child** for the test fixture and waits no more
than another **0.5 seconds** for kill/reap evidence. The two stages have
separate time budgets, so the overall transaction is not a single 1.5-second
deadline; parent journal `fsync` is also outside those timers. A child blocked
in an ordinary
interruptible kernel read, stopped with SIGSTOP, killed mid-operation, late
with a receipt, or caught after sending a snapshot without exiting is
refused. A tested kernel SIGKILL timer kills the child **while the supervisor
itself is SIGSTOPped**.

**Important kernel limitation:** An actual `TASK_UNINTERRUPTIBLE` (D-state)
task may ignore SIGKILL until its kernel syscall returns. No Linux userspace
supervisor, cgroup limit, pidfd, timerfd or POSIX kill timer can guarantee
immediate reaping in that state. This experimental subsystem therefore
returns a blocked/uncertain result after a bounded reap attempt, retains the
durable latch, and never claims hard real-time process disappearance. A true
D-state fault injection against a dedicated native-host kernel was **not
performed**; the tested blocking pipe is interruptible.

## Native test evidence and limitations

The focused suite requires the explicitly constrained disposable Docker
Desktop `desktop-linux` environment, an existing Node 22 image, no network,
a cgroup memory limit and a disposable ext4 journal volume. Example:

```sh
docker run --rm --network none --memory 192m --pids-limit 32 --read-only \
  --tmpfs /tmp:rw,exec,nosuid,nodev,size=96m \
  --mount type=volume,target=/journal \
  --mount type=bind,source=<OWN-STAGE2-WORKTREE>,target=/work,readonly \
  -w /work -e VIRKI_DISPOSABLE_KILLABLE_STAGE=1 node:22.23.3 \
  sh -c 'chmod 0700 /journal && node --test infra/offline/native-supervisor/disposable-killable-stage.test.mjs'
```

Tests exercise real native C, kernel cgroups, child SIGKILL with the supervisor
frozen **both before G and during an interruptible kernel read**, killed
independent verifier, crash before/after sealed FD receipt, concurrent admissions, source
hardlinks/symlinks, missing cgroup proof, byte digests, and a replay-resistant
ext4 latch. The separate `disposable-killable-stage-restart.mjs` fixture
supports a disposable **two-container** experiment: the first container dies
via SIGKILL of PID 1 with a journaled attempt, the second remounts the same
disposable ext4 volume and confirms replay is refused. Delete the test
volume afterwards; never touch existing application volumes.

Ext4 file and directory `fsync` plus remount survival are meaningful crash
evidence, **not** a hardware power-cut, filesystem corruption or independent
anti-rollback witness proof. A privileged attacker able to rewrite the
entire operator journal and plan can forge the locally provisioned dev
fixture. The test does not establish a trustworthy owner-installed
binary, external daemon isolation, policy approval, production host
identity, or real independently verified Docker import. Production is
**NO-GO** until those external controls, authenticated witness/monotonic
checkpoint, real database recovery and health checks are satisfied.

## Old test-process hang, forensic reconciliation (2026-10-28)

A **distinct, earlier binary** compiled at 18:13 UTC with ASan+UBSan and
**PIE** remained CPU-running in two normal-mode test children for more than
twenty minutes. Their root-owned processes had only FDs 0, 1 and 2, did not
create `state/attempt.lock`, and one had SIGSEGV pending while libasan was
mapped. This localizes the stall to startup/pre-journal execution, consistent
with ASan/PIE initialization trouble; a specific instruction-level stack
could not be captured because /proc/*/syscall and /proc/*/stack access was
denied. Do **not** attribute this to the corrected later C source or claim
that the precise ASan instruction is conclusively identified.

The old test harness also had an independently conclusive **test orchestration
bug**: concurrency testing used unbounded `spawn` plus `Promise.all` without
a child timeout, so any child stuck before native `main` held the Node process
and Docker container open forever. The corrected harness builds sanitizer
binaries with `-fno-pie -no-pie`, now sets an exact-child `SIGKILL` watchdog
and requires reaping even for pre-main CPU spins, and has a dedicated
regression using a deliberately CPU-idle nonexiting Node child. This harness
watchdog does not pretend to force-reap uninterruptible kernel-D-state tasks.

The original disposable container was verified by full Docker ID, creation
time, source worktree bind, image, network absence and anonymous volume.
Before targeted stopping, the original 141016-byte ELF, journal archive
and hash plan, process list, logs, and inspect metadata were copied to a
separate local forensic directory outside the worktree, with the binary
SHA-256 checked. Only that verified W6 owner container ID was stopped;
`--rm` removed its own anonymous volume. No other containers were
selected, stopped or pruned, and no production files were used. Forensic
evidence remains locally outside this repository.
