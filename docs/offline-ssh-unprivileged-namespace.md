# W49 — safe SSH test startup in an unprivileged namespace

**DEV-only, NONAUTHORIZING. This is not a native root SSH/sudo E2E, and it does
not make the W61 host-root script safe to execute as root.**

## The material W61 problem

`infra/offline/fixtures/run-owner-ssh-sshd-e2e.sh` on the mutable Windows
`E:/Virki` mount can be group/world writable. Its initial shebang and
`set -eu`, shell expansions, function bodies, command substitutions and
subprocess invocations all execute **before** its own checks, and root executes
`/bin/sh "$0"` AGAIN after `unshare`. Its test harness also imports mutable
JS files through Node ESM **as root**. Protecting only cached APT executables or
`/tmp` is not sufficient. A hash checked before executing the same mutable
pathname is not a safe solution (source replacement race).

Do **not** call `sudo sh ...run-owner-ssh-sshd-e2e.sh`,
`wsl -u root ...run-owner-ssh-sshd-e2e.sh`, or
`sudo node --test ...owner-ssh-sshd.e2e.test.mjs`. No W61 root test was
executed by this implementation. W61 is read-only.

## Safer bounded alternative

The first executed process is the **system-installed** `/usr/bin/bwrap`,
started by the ordinary host UID (tested as WSL UID **1000**, not sudo/root).
It creates a fresh unprivileged user namespace, PID/network/IPC/UTS namespaces,
an empty temporary root filesystem, a private process view and private
`/dev`. It bind-mounts only system `/usr` **read-only** and one explicitly
selected test-source directory **read-only** at `/workspace`. `/tmp` and
`/root` are fresh ephemeral tmpfs mounts. `--cap-drop ALL` removes
capabilities inside the sandbox. Only **then** is a shell or imported JS file
read. W49 originally used `--ro-bind sourceDirectory /workspace`, allowing a
same-UID attacker to replace the source directory after validation and cause
bwrap to mount unrelated private files. W20 reproduced this private-marker
disclosure on WSL before the fix. The launcher now uses bwrap's native
`--ro-bind-fd 3 /workspace` option: it opens the exact inspected directory
with `O_DIRECTORY|O_NOFOLLOW`, checks the inode identity, passes it as child
fd 3, and closes it only after bwrap exits. Renamed paths cannot redirect this
bind. Changes to the original scripts still run only inside the namespace.

**P2 host-loader boundary (W50 → W20):** bwrap's `--clearenv` happens *after*
`execve` starts its native ELF loader. A caller-inherited `LD_PRELOAD`,
`LD_AUDIT`, `LD_LIBRARY_PATH` or other hostile environment could therefore
execute a constructor as the **host UID** before bwrap unshares the sandbox.
The `run()` launcher now passes an explicit **empty child environment**
(`spawnSync(..., { env: {} })`) to `/usr/bin/bwrap`, retaining the exact
descriptor-based `--ro-bind-fd 3`. bwrap itself creates the intended
in-namespace `PATH`, `HOME` and `LC_ALL` with literal `--setenv` arguments.
No caller-provided environment is consulted for the executable or policy.
A real WSL nonroot adversarial regression compiles a disposable native
`LD_PRELOAD` constructor that activates **only inside the bwrap executable**,
confirms the constructor's live host-UID effect in a direct positive control,
then confirms no host marker appears when the same hostile environment calls
`plan.run()` and the fixture successfully starts inside the namespace.

Use the exact fixed argument builder in
`infra/offline/owner-ssh-unprivileged-namespace.mjs`, which accepts only
`sourceDirectory` and a single `.sh` basename. It reads both the **real
and effective UID and GID from the operating system**, requiring
`getuid() === geteuid() > 0` and `getgid() === getegid() > 0`.
No caller may provide a UID/EUID/GID/EGID or spoof privilege state.
This explicitly rejects setuid-root or setgid-root callers even when the
real UID is an ordinary user. It **does not read or authorize owner keys, repository pins or production
metadata**, and rejects a root/Windows caller and extra fields. The returned
status is always `DEV_ONLY_UNPRIVILEGED_SANDBOX_NO_NATIVE_ROOT`, never
SSH verification or deploy authority. The returned `run()` executes bwrap
with the required inherited directory descriptor; raw `args` are useful for
policy inspection only and cannot safely replace `run()`. An older bwrap
without `--ro-bind-fd` fails closed rather than reverting to path-based binds.

To prevent even the argument-builder JS from running outside the sandbox,
an independent operator may directly invoke the system binary with an
**explicitly reviewed argv**; this example executes only a system command:

```sh
# Run as an unprivileged Linux user, NOT via sudo / wsl -u root.
/usr/bin/bwrap --die-with-parent --new-session \
  --unshare-user --uid 0 --gid 0 \
  --unshare-pid --unshare-net --unshare-ipc --unshare-uts \
  --clearenv --tmpfs / \
  --ro-bind /usr /usr \
  --symlink usr/bin /bin --symlink usr/lib /lib \
  --symlink usr/lib64 /lib64 \
  --proc /proc --dev /dev \
  --tmpfs /tmp --tmpfs /root \
  --setenv PATH /usr/bin:/bin --setenv HOME /root \
  --setenv LC_ALL C --cap-drop ALL \
  -- /usr/bin/id
```

The displayed UID **0** is NOT native host root. Read
`/proc/self/uid_map` from inside the sandbox to establish its parent
mapping; on the tested WSL environment namespace UID 0 maps to host UID
1000. Never treat this as proof that genuine OpenSSH privsep, setuid sudo,
PAM, native root account provisioning or host service changes succeeded.

## Adversarial evidence and limitations

Run as ordinary Linux UID:

```sh
node --test infra/offline/owner-ssh-unprivileged-namespace.test.mjs
```

The test (1) rejects host-root startup; (2) asserts the literal bubblewrap
namespace/mount and argument boundary; (3) swaps a script *after* command
planning and confirms it cannot overwrite an unrelated host sentinel;
(4) checks namespace UID mapping (0 inside, 1000 on host), absent host
`/etc`, `/mnt/e`, `/run` and Docker socket; and (5) swaps a **transitive
Node ESM import**, which executes inside the sandbox but cannot write a host
file. A separate subprocess test forcibly reports a forged effective-root
UID or GID while retaining real UID 1000; the startup refuses *at the
effective-identity gate*, not merely at the input schema. These are real
processes; the test must not report green if the kernel
rejects user namespaces (a skip is a blocker, never evidence). All five tests
and the effective-identity regression were exercised on WSL as actual UID
1000, with **zero skips**.

**Remaining NO-GO:** This sandbox cannot represent the actual independent
native Linux root SSH environment. In particular, `--cap-drop ALL` and
UID namespace remapping prohibit the privileged root/1001 sudo path. W61's
full `sshd` startup, four authenticated sudo selectors, unauthorized shell,
PTY/forwarding denial and real preauth sshd-session remain **UNPROVEN**.
Do not loosen this sandbox to make the root E2E pass.

For a **genuine native root** E2E, a separate independently reviewed,
root-owned immutable launcher and **all transitive executable source/JS**
must first be copied through trusted system tooling into a protected
root-only directory, pinned against independently approved exact digests
**after copy**, safely opened by descriptor, and executed exclusively from
that protected immutable snapshot. The signer, trust pins and installation
authority cannot be derived from the candidate or this repo. That external
root installation/approval did not occur here and is a distinct physical
blocker. No host SSH files, installed packages, credentials, services,
production Docker, or deManage resources were touched.
