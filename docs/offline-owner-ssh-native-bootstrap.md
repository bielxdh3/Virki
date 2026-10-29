# Native owner SSH bootstrap — isolated, fail-closed preview

**Development only. No production listener, release activation, transfer
authority, or owner approval is created by this source tree.**

The existing offline transfer receiver already provides the fixed unprivileged
`--gate` and four exact elevated invocations. The missing trust boundary is
**independently provisioning and validating a real sshd account**, without
relaxing the normal hosted/main-only SSH path.

## Reviewed immutable configuration (dedicated sshd instance)

The canonical templates are returned by
`renderNativeOwnerSshdMatch()` and `renderNativeOwnerSudoers()` in
`infra/offline/native-owner-ssh-bootstrap.mjs`. The module NEVER installs,
starts, restarts or reloads sshd; NEVER edits `/etc/sudoers`; NEVER creates
keys/accounts; NEVER accepts a caller-provided policy or owner key for its
operational entry. It never executes an uploaded release or candidate file.

**Do not install the `Match` snippet in the global sshd_config or its
includes.** On several distributions, an included `Match` remains in scope
when the parent configuration resumes; adding it there can break hosted
logins. Instead the independently reviewed operator must install a **separate
sshd configuration and service** at:

- `/etc/virki/offline-transfer-ssh/sshd_config`: root:root 0600, exact template
- `/etc/virki/offline-transfer-ssh/authorized_keys`: root:root 0644, **one**
  canonical approved Ed25519 key, without comment, with exactly
  `restrict,command="/usr/bin/node /usr/local/lib/virki/offline-transfer/offline-host-transfer-receiver.mjs --gate"`
- `/etc/virki/offline-transfer-ssh/ssh_host_ed25519_key`: separately generated
  and owner-pinned Ed25519 host private key, root:root 0600
- `/etc/sudoers.d/virki-offline-transfer`: root:root 0440, exact sudoers
  template, allowing **only** the receiver and its `--read-probe`,
  `--read-docker` and `--read-identity` one-argument forms as root

**Important corrected SSH authentication boundary:** sshd temporarily switches
to the `virki-offline` UID to open its authorized key; the unprivileged
ForceCommand Node interpreter must open the installed receiver and imported
ESM modules **before** sudo elevates. Therefore public, nonsecret
`authorized_keys`, receiver `.mjs`, and its public ESM import closure must
be root-owned and **world-readable (0644)**, with all parent directories
traversable by the dedicated UID (root-owned **0755**, with no group/other
write permission). They must not be 0600 behind 0700 parents. This is not
permission to expose signer private keys or host policy: the owner
signer pins, host approval policy, nonce journal, private host key and ledger
remain independently root-private **0700/0600**, never readable by the SSH
account. The test performs a REAL `uid=65534` read and write-denial proof.
The direct public ESM closure consists of the fixed receiver plus
`lib/offline-ssh-stage-protocol.mjs` and
`lib/offline-ssh-transfer-permit.mjs`; all three are checked for protected
root ownership, mode 0644, non-symlink inodes and traversable protected
parents. Node's built-in imports are system-owned and remain a separate
independently pinned execution/loader authority gate.

Parent directories must be real, root-owned, not writable by unprivileged
users. The dedicated service uses **127.0.0.1:2223 only**, which cannot by
itself receive remote owner transfers. Reachability and external firewall
policy are separate owner-controlled gates; never silently broaden the
listener or port to make a demo work. The production sshd, its configuration,
host keys and hosted operator SSH path remain untouched.

The unprivileged `virki-offline` account must be independently provisioned
with a real shell needed by OpenSSH to launch its forced command, a disabled
password, no other authorized keys, and a protected home. The separately
installed receiver, its ESM dependency closure, Node 22 runtime and sudo
binary must be independently SHA-pinned and root-owned; repository copies and
release TAR contents are **not** installation authorities.

The account must have **no unrelated sudo rules** via group membership,
`/etc/sudoers` or other includes. A line omitting the receiver program
argument, any wildcard, `ALL`, `SETENV`, or an arbitrary interpreter is
unacceptable. Root logins are disabled on the dedicated instance; the normal
production SSH service is not modified.

The existing protected host transfer policy at
`/etc/virki/offline-transfer-host/host-policy.json` must independently pin
`sshUser=virki-offline`, `port=2223`, the exact client Ed25519 SPKI SHA-256,
the approved owner signer and host/revision. Independently provision the
release policy in `/etc/virki/offline-release/trust-policy.json` with the same
current, non-revoked owner key and host identity. **Never copy these secrets,
approvals or pins from the candidate.** The host machine ID must be a valid
root-owned `/etc/machine-id` and its domain-separated SHA-256 must match the
independent release policy. The owner's known_hosts must bind the same host
public key through an out-of-band authenticated fingerprint; `ssh-keyscan`
alone is not sufficient.

## Physical tests, before considering activation

On an **isolated native Linux root VM/container**, with disposable host keys,
test account, separate network namespace and no real workloads, the owner
must perform these read-only checks against the independently installed files:

```sh
/usr/sbin/visudo -cf /etc/sudoers.d/virki-offline-transfer
/usr/sbin/sshd -t -f /etc/virki/offline-transfer-ssh/sshd_config
/usr/sbin/sshd -T -f /etc/virki/offline-transfer-ssh/sshd_config \
  -C user=virki-offline,host=localhost,addr=127.0.0.1
/usr/bin/sudo -l -U virki-offline
/usr/bin/node /usr/local/lib/virki/offline-release/infra/offline/native-owner-ssh-bootstrap.mjs --inspect
```

Verify `ForceCommand`, `AuthorizedKeysFile`, public-key-only auth, no
root login, no forwarding or PTY, and exactly four root sudo invocations.
The `--inspect` command deliberately **exits nonzero** even after reporting
local parser validity: it is not a deploy or listener activation token.
Before use, perform a real disposable `ssh -F none -p 2223` login using the
approved test key on loopback: the four selectors must invoke only the
installed receiver; arbitrary remote shell, `bash`, `sftp`, `scp`,
unknown selector, port forwarding, agent forwarding and PTY requests must
all fail. Test password authentication and a second key are denied.

With the currently available WSL Ubuntu environment, `visudo -cf` can be
run against an ephemeral sudoers file. **The `sshd` executable is absent**,
so `sshd -t/-T` and real restricted SSH login remain **NOT PROVEN**. There
is no production readiness or authorization. Also unproven: owner-installed
runtime/module/hash closure, PAM/account status, exact full sudo policy
across other includes, external client network/host-key binding, off-host
monotonic witness, deployment rollback, and production host authority.

The adversarial, disposable Linux root test is:

```sh
node --test infra/offline/native-owner-ssh-bootstrap.test.mjs
```

It exercises the **real** installed `visudo` parser, root-owned protected
file checks, exact forced key/command matching, owner pin/revocation and
machine identity binding; malformed files cannot produce a readiness status.
The fixture path override is intentionally **non-authorizing** and cannot
be passed to the installed fixed-root inspection entrypoint.
