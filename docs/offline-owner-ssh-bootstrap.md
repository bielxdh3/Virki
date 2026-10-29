# Owner-pinned restricted native SSH bootstrap (review-only)

This is an **owner-installable readiness blueprint**, not installation approval
or a production deployment procedure. Implementation:
`infra/offline/owner-ssh-bootstrap.mjs`.
The default hosted `main` path is unchanged.

## Explicit owner-controlled inputs

The owner, **not the uploaded candidate or SSH session**, must independently
review and supply one canonical JSON document in exact field order:

```json
{
  "clientPublicKey": "ssh-ed25519 <approved client public key>",
  "independentlyPinnedClientSpkiSha256": "<64 lowercase hex>",
  "hostPublicKey": "ssh-ed25519 <approved native sshd host public key>",
  "independentlyPinnedHostSpkiSha256": "<64 lowercase hex>",
  "reviewedReceiverFiles": [
    {"path": "offline-host-transfer-receiver.mjs", "sha256": "<64 lowercase hex>"},
    {"path": "lib/offline-ssh-stage-protocol.mjs", "sha256": "<64 lowercase hex>"},
    {"path": "lib/offline-ssh-transfer-permit.mjs", "sha256": "<64 lowercase hex>"}
  ],
  "reviewedNode22ExecutableSha256": "<64 lowercase hex>",
  "unrelatedSshdBaselineSha256": "<64 lowercase hex of canonical pre-install baselines>"
}
```

The public-key placeholders above are **not** valid credentials or trust.
The production operator must independently pin the native Linux SSH host's
Ed25519 public key (not its private host key), the owner's dedicated client
Ed25519 public key, the three exact receiver source SHA-256 digests, and the
**actual root-owned /usr/bin/node executable** on Node 22. An SSH identity
alone never authorizes a transfer: the receiver independently checks a
short-lived owner-signed, single-use transfer permit.

The reviewed policy must be installed separately by an authorized owner as:
`/etc/virki/offline-ssh-bootstrap/owner-pins.json`, **canonical JSON**,
root:root mode 0600, parent directory root:root 0700. This document must
never be obtained from a remote client, application TAR, or checkout. The
owner must also independently capture and review **before introducing the
Match Include** the full output of `sshd -T -C` for the fixed nine unrelated
user/context tuples specified in `SHARED_SSHD_BASELINE_CONTEXTS`, using the
real pre-install native config, real binary and unchanged production settings.
Store canonical JSON with exactly `version:1` and ordered `snapshots` pairs
`{context,effective}` in
`/etc/virki/offline-ssh-bootstrap/shared-sshd-baseline.json` (root:root
0600); the owner must authenticate its full SHA-256 and put it in
`unrelatedSshdBaselineSha256`. This baseline is NOT obtained from a
candidate archive, user-supplied SSH payload, or recomputed after applying
the Match. The native readiness check **blocks** if this independently
pinned file is missing, has been modified, or if any of the nine current
effective outputs differs from its baseline. These samples do not
establish invariance for all possible SSH accounts, hostnames, Match
selectors, or a running sshd process; independent operator verification
remains mandatory.
The
blueprint generator `renderOwnerPinnedOfflineSshBootstrap(pins)` returns
three *nonauthorizing* exact file recipes:

| Recipe | Native destination | Owner/mode |
|---|---|---|
| `authorized_keys` | `/etc/ssh/virki-offline/authorized_keys` | root:root 0644; parent root:root 0755 |
| `sudoers` | `/etc/sudoers.d/virki-offline` | root:root 0440; parent root:root 0755 |
| `sshd_config` | `/etc/ssh/sshd_config.d/90-virki-offline.conf` | root:root 0644; parent root:root 0755 |

These paths are **output descriptions, not automatic installation targets**.
No program in this change installs, removes, restarts, or edits the real
`sshd`, `sudoers`, user database, host keys, or production workloads.
`writeDisposableOwnerSshBootstrapReviewBundle({directory,independentlyReviewed})`
can materialize and fsync the **three inert recipe files** only within a new,
empty root-owned directory whose literal shape is
`/tmp/virki-offline-ssh-bootstrap-test-XXXXXX/reviewed` on native Linux
tmpfs. It then checks the bytes and modes itself and refuses repeated writes.
It cannot target `/etc` or an existing installation. The resulting files
are **review artifacts**, not an installer or independently accepted trust.

## Native account and receiver prerequisites

Separately and explicitly authorize a dedicated non-root login named
`virki-offline`. This account cannot belong to `sudo` or any broad
privileged group, cannot use a password or keyboard-interactive login, and
must have no other authorized keys, shell startup overrides or SSH
authentication paths. OpenSSH's forced command uses the user's login shell
to start a fixed process; using `/usr/sbin/nologin` as its shell can
prevent the forced command from launching. If `/bin/sh` is used, independently
prove that both `ForceCommand` and the matching `authorized_keys`
`restrict,command=...` directive take effect, and that a requested
interactive command cannot reach a shell.

The code is installed only from audited owner-approved bytes under
`/usr/local/lib/virki/offline-transfer`, root:root 0755;
`lib/` root:root 0755; the three reviewed module files root:root 0644.
The receiver must be readable by the unprivileged forced-command gate.
The authorized key also needs root ownership **and mode 0644** and a
traversable root-owned 0755 parent. A root-only 0600 receiver/key would
prevent `virki-offline` from running the forced gate or authenticating; a
real WSL unprivileged test (`setpriv --reuid=65534`) confirms readable
0644 receiver/key and inaccessible 0600 owner pins.
`/usr/bin/node` must be a non-symlinked root:root 0755 **Node 22**
executable matching the independently pinned full SHA-256. No code may be
loaded from an uploaded source archive.

The sudoers file must grant **exactly four invocations**, and no shell,
wildcards, arbitrary arguments, `SETENV` or alternate runas identities.
The Debian sudoers implementation tested here rejects `!requiretty` as an
unknown setting, so the generated rule uses only
`Defaults:virki-offline env_reset,!setenv`. The account has no TTY via
sshd, and `sudo -n -u root --` invokes only the exact receiver selectors.

The exact `Match User virki-offline` snippet explicitly forbids passwords,
keyboard interaction, PTY, agent/TCP/X11/tunnel forwarding, user rc and
arbitrary commands. It also sets a server-side `ForceCommand`, separate
from the authorized key's forced command. More importantly, **an inherited
global `AuthorizedKeysCommand` can supply additional trusted public keys**.
The snippet explicitly sets `AuthorizedKeysCommand none`,
`TrustedUserCAKeys none`, both principals command/file to `none`, and
`PubkeyAcceptedAlgorithms ssh-ed25519`; the installed-readiness gate
checks these exact values in `sshd -T -C`, rather than trusting the file's
text. The native gate requires `StrictModes yes` effectively as well.

Modern OpenSSH scopes a `Match` block in an included file to that file.
An adversarial real OpenSSH 10.2 fixture places the Include **before**
trailing global directives (including `PermitTTY yes`,
`AllowTcpForwarding yes`, `ClientAliveInterval 37`, `MaxAuthTries 3`).
The pre-Include global policy also enables a deliberately conflicting
`AuthorizedKeysCommand /usr/bin/true`. The `virki-offline` account
still has only `authorizedkeyscommand none`, while the full effective
`sshd -T -C` output of `root`, `nobody` and `unrelated-admin` is compared
*byte for byte* with the original configuration for each of three distinct
IPv4/IPv6 and local/remote contexts (nine comparisons). A negative
control inserts `Match` directly into the main file instead of using
`Include` and demonstrates a detectable difference. These native
`sshd -t/-T` tests are independent of the still failing login E2E.
The actual shared production sshd configuration and installed version must
be independently inspected in their entirety. No production Include
is created by this software.

The SSH host is authenticated independently. The native guard reads and
checks the full owner-pinned Ed25519 SPKI against the fixed installed
`/etc/ssh/ssh_host_ed25519_key.pub` (root:root 0644), then invokes the
root-protected `/usr/bin/ssh-keygen -y` against the corresponding
root:root **0600 private host key** and compares the derived public SPKI
again. It also requires the effective `sshd -T` hostkey list to reference
that fixed file. Thus a replaced public file alone, or a substituted private
key with the old public file, cannot pass this read-only inspection.
The remote SSH client still independently requires strict known_hosts and
the `ssh-ed25519` host-key algorithm; host-key inspection does not start
or attest the currently running daemon.

## Readiness and bounded validation

`inspectInstalledOwnerSshBootstrapReadiness()` takes **no caller inputs**
and returns `blocked` unless running as root on genuine native Linux/amd64
(WSL explicitly refused) with the fixed owner pins, exact root-owned file
content and permissions, matching Ed25519 client/host public pins,
root-owned Node22 and reviewed code bytes. It also checks the native
  `visudo -c -f`, `sshd -t` and **effective** `sshd -T -C
user=virki-offline,host=localhost,addr=127.0.0.1`, followed by nine
independently owner-pinned pre-install unrelated-principal contexts. Even a passing report
has `installAuthorized=false` and `deployAuthorized=false`; SSH
service/account state and live transfer permissions still require independent
owner review.

The fixture-only attestation for an entirely disposable `/tmp` tmpfs
checks SHA and file permissions; it is never an installation or production
attestation. Test-only Ed25519 keys must never be reused outside the fixture.
Use real isolated sshd E2E (separate host keys, port, home, socket, sudoers
and SSH client) to prove accepted selectors, denied commands, denied forwarding,
and no shell before any production write. This E2E is **not yet proved**.
A real OpenSSH 10.2 `sshd` and its split
`sshd-auth`/`sshd-session` helpers were extracted from a test-only
Ubuntu `openssh-server` package into WSL `/tmp`, then executed only inside
an `unshare -m` namespace with its own `/etc`, `/run`, `/usr/sbin`,
`/usr/lib/openssh` and `/usr/local/lib` tmpfs. Test-only SSH host/client
keys and a synthetic login were generated there, with a separately isolated
network namespace (no shared loopback listener). The actual `sshd -t`,
effective `sshd -T -C` and `visudo -c` succeeded, but the first loopback
SSH handshake terminated at `rexec start` / pre-authentication child exit 127,
with connection reset before identity or sudo execution. Therefore **SSH
login, effective sudo elevation, four selector transport and shell denial
remain unproven end to end**. This is a NO-GO for production readiness, not a
reason to relax the restrictions. The opt-in reproducible fixture is
`infra/offline/fixtures/run-owner-ssh-sshd-e2e.sh` with
`owner-ssh-sshd.e2e.test.mjs`. A Windows `sshd` is not a valid substitute.
No live sshd, private host keys, production accounts or shared Docker daemon
may be touched to close this gate.
