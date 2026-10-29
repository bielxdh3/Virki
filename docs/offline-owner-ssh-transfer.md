# Owner-approved SSH transfer of an offline release candidate

This protocol stages eleven signed files. It does not deploy, activate, load
Docker images, change the database, write the release ledger or interact with
deManage/Cloudflare. The owner must independently provision the restricted
SSH login, fixed privileged native receiver and signed transfer permit before
any host write.

## Local owner authorization

The client entrypoint is scripts/offline-host-transfer-client.mjs, with three
absolute paths: --candidate, --trust and --repository. The existing
prepareVerifiedOfflineTransportPlan first authenticates the candidate's
owner/builder signatures, the independent operator's host key/revision/ledger,
the exact clean source and the read-only native SSH probes. Its return value
explicitly DOES NOT authorize transfer.

The independently approved operator trust directory is an existing root-owned
0700 directory containing exactly four root-owned 0600 files:
trust-policy.json, ledger.json, transport-policy.json, ssh-known-hosts.
The transport policy must independently pin sshUser=virki-offline (a dedicated
unprivileged SSH login), root=/srv/virki, host, port, sshAlias, expectedRevision and the exact
SHA-256 of a single canonical Ed25519 known_hosts entry. The owner-signed
permit must bind the same login; any request to SSH as root is refused.
Existing operator policy and owner revocations must remain current.

The owner additionally creates this CLIENT-SIDE authority directory:

    /etc/virki/offline-transfer/              root-owned, 0700
      permit.json                             root-owned, 0600
      permit.sig                              root-owned, 0600
      ssh-identity                            root-owned, 0600

No other entries or symlinked ancestors are allowed. The SSH private identity
must be a real unencrypted ssh-keygen/OpenSSH Ed25519 identity independently accepted by
the remote forced-command key. The client derives its public key with protected
/usr/bin/ssh-keygen -y (Node's createPrivateKey cannot parse a standard
OPENSSH PRIVATE KEY); the public SPKI SHA-256 must match the signed permit.
The owner prepares the following JSON object in the exact field order,
serializes it canonically (JSON.stringify, with no whitespace or newline),
and independently reviews each identity and SHA. Values below are placeholders
and NEVER authorize anything:

    {
      "version":1,
      "mode":"owner-signed-ssh-stage-v1",
      "sourceSha":"<40 lowercase hex>",
      "manifestSha256":"<64 lowercase hex>",
      "envelopeSha256":"<64 lowercase hex>",
      "sshAlias":"<pinned alias>",
      "host":"<pinned host>",
      "port":22,
      "sshUser":"virki-offline",
      "knownHostsSha256":"<64 lowercase hex>",
      "clientSshKeyPinSha256":"<64 lowercase hex>",
      "receiverPath":"/usr/local/lib/virki/offline-transfer/offline-host-transfer-receiver.mjs",
      "stageRoot":"/var/lib/virki/offline-staging",
      "nonce":"<fresh 32 lowercase hex>",
      "expiresAt":0
    }

The permit signature is detached Ed25519 over the exact concatenation of the
UTF-8 bytes for VIRKI_OFFLINE_SSH_TRANSFER_PERMIT_V1 followed by one NUL byte,
and the unmodified permit.json bytes. Store the signature as canonical 88-char
base64 in permit.sig, with no newline. It must be signed with the same
independently pinned, non-revoked OWNER release key already accepted by the
protected trust-policy.json. Do not sign with the SSH identity or a key from
the candidate. The owner private release key stays off the server.

Expiry must be greater than current Unix seconds and no more than 600 seconds
ahead when the client verifies the permit. The permission binds the source Git
SHA, manifest SHA, exact canonical signature-envelope SHA, SSH client public
SPKI SHA-256, pinned host/port/restricted login, known_hosts SHA-256, receiver binary
location, private staging root and fresh owner nonce.

## Remote native restricted SSH + root receiver: required owner handoff

1. Independently audit, approve and pin the EXACT executable/dependency SHA-256
   digests for offline-host-transfer-receiver.mjs,
   lib/offline-ssh-stage-protocol.mjs, lib/offline-ssh-transfer-permit.mjs
   and the Node runtime/loader, and the
   separately installed trusted verifier. Install this code only from an
   independently trusted source into /usr/local/lib/virki/offline-transfer,
   preserving its lib/ child. Never execute code, scripts or installers from
   an uploaded source TAR. The receiver dynamically imports ONLY the
   owner-installed verifier from the fixed location:
   /usr/local/lib/virki/offline-release/infra/offline/trusted-host-entry.mjs.
   The verifier and dependency closure must already have been independently
   audited, installed and pinned under protected root-owned paths.
2. Independently create /var/lib/virki/offline-staging, owner root, mode 0700,
   existing, real and empty. Keep it separate from release ledger, source Git,
   backups, application volumes and deManage. Require enough disk free for
   all eleven transferred file lengths PLUS at least 4 GiB reserve. Any
   leftover pending/completed stage requires owner reconciliation first.
   This minimal native read-only probe assumes the pre-provisioned production
   root is EXACTLY /srv/virki, owned by root, mode 0700, with root-owned
   .deploy-tmp, releases, backups directories (0700) and protected env
   files (0600). No arbitrary root path is accepted. The root-owned marker
   must contain the four expected native hostname/root/protocol lines.
   Independently install /etc/virki/offline-transfer-host (root 0700)
   containing EXACTLY one file, host-policy.json (root 0600) with canonical
   JSON keys IN THIS ORDER (examples are placeholders, not valid authority):

    {"version":1,"mode":"offline-host-transfer-v1","expectedSourceSha":"<40 lowercase hex>","host":"<owner-pinned host>","port":22,"sshAlias":"<owner-pinned alias>","sshUser":"virki-offline","knownHostsSha256":"<64 lowercase hex>","clientSshKeyPinSha256":"<64 lowercase hex>","ownerPublicKeyPem":"<independently authenticated current owner Ed25519 SPKI PEM>"}

   The public owner key MUST match the non-revoked owner trust pin and
   revocation policy already installed under offline-release. Re-provision
   when rotated or revoked; never derive the remote pin from wire,
   unsigned local policy or candidate. Independently verify that
   authorized_keys contains only the Ed25519 key corresponding to the
   public SPKI digest pinned in host-policy.json.
   Independently create /var/lib/virki/offline-transfer-nonces (root 0700,
   canonical path). It stores one root-owned 0600 O_EXCL nonce record per
   approved transfer, fsynced with its directory BEFORE archive payload.
   NEVER reset this journal during retry or automatic cleanup; a crash
   consumes the nonce and the owner must explicitly issue a new permit
   after reconciliation.
3. Independently provision the dedicated non-root virki-offline login. Install
   the exact approved client Ed25519 public key only in that account's
   authorized_keys with a restricted fixed command (replace the placeholder
   with the independently approved public key):

    restrict,command="/usr/bin/node /usr/local/lib/virki/offline-transfer/offline-host-transfer-receiver.mjs --gate" ssh-ed25519 <APPROVED_CLIENT_PUBLIC_KEY>

   Independently verify effective sshd configuration, forced-command-only
   access, immutable host key, file permissions, no other login keys, no
   password or keyboard-interactive login, no forwarding and no PTY. The
   unprivileged gate accepts SSH_ORIGINAL_COMMAND only from the exact
   offline-receive-v1, offline-probe-v1, offline-docker-v1 and
   offline-identity-v1 allowlist. The first transfers data; the latter
   three only execute preinstalled read-only host/Docker/machine-id checks,
   with no remote Bash or caller-supplied script. The 8 preflight probe
   repeats use offline-probe-v1; Docker and identity are separate selectors.
   Deny all SSH root logins for this workflow.
   Install an owner-reviewed sudoers entry with root ownership and mode 0440,
   using visudo -c to validate it. The only delegated privileges are exactly
   FOUR argument-exact commands (no wildcards, shell, arbitrary options or SETENV):

    Defaults:virki-offline env_reset,!setenv
    Cmnd_Alias VIRKI_OFFLINE_TRANSFER = /usr/bin/node /usr/local/lib/virki/offline-transfer/offline-host-transfer-receiver.mjs, \
        /usr/bin/node /usr/local/lib/virki/offline-transfer/offline-host-transfer-receiver.mjs --read-probe, \
        /usr/bin/node /usr/local/lib/virki/offline-transfer/offline-host-transfer-receiver.mjs --read-docker, \
        /usr/bin/node /usr/local/lib/virki/offline-transfer/offline-host-transfer-receiver.mjs --read-identity
    virki-offline ALL=(root) NOPASSWD: VIRKI_OFFLINE_TRANSFER

   The gate execs sudo -n -u root with only those four exact invocations
   without a shell. The root receiver independently checks SUDO_USER,
   SUDO_UID and SUDO_COMMAND, then checks the installed executable path and
   refuses NODE_OPTIONS, NODE_PATH or dynamic-library injection variables.
   Sudo policy and the installed Node runtime must be independently audited;
   sudo env_reset must remain in effect. No unrestricted sudo permissions
   may be granted to this account.
   For an independently pinned owner-installable native account/authorized_keys,
   exact sudoers and per-user Match readiness blueprint, see
   [offline-owner-ssh-bootstrap.md](offline-owner-ssh-bootstrap.md).
   The native readiness guard must prove that an inherited
   `AuthorizedKeysCommand` and trusted user CA are both disabled
   specifically for `virki-offline` in effective `sshd -T -C`; otherwise
   an unrelated ambient SSH key source could bypass the pinned single
   `authorized_keys` file. The host's effective Ed25519 private key must
   independently derive the owner-pinned public SPKI. These checks do
   not change other users' shared sshd settings.
   Before the Include is installed, independently capture and owner-pin
   the nine exact root/nobody/unrelated-admin sshd -T/-C baseline contexts
   in /etc/virki/offline-ssh-bootstrap/shared-sshd-baseline.json.
   The native inspector compares the full current outputs against these
   pre-install bytes and refuses drift. The disposable native regression
   places Include EARLY before trailing globals; parser success or nine
   contexts does not attest every principal or an already running daemon.
   This setup still requires effective native sshd inspection and a real
   disposable sshd E2E; no live host installation is authorized.
4. Provision and attest existing native Linux/amd64 release trust:
   /etc/virki/offline-release and /var/lib/virki/offline-release, signer
   revocations, builder/owner pins, machine-id, replay predecessor and ledger.
   WSL must never be accepted as the production host.
5. Independently approve the exact reviewed source/manifest/signature envelope,
   local client SSH identity and short-lived owner transfer permit, then run:

    node scripts/offline-host-transfer-client.mjs \
      --candidate /private/approved/candidate \
      --trust /private/approved/trust \
      --repository /private/approved/clean-main

The client executes the pinned root-protected /usr/bin/ssh with -F none, exact
host/port/virki-offline login, strict Ed25519 host key, only the owner-installed SSH
identity, disabled agent/password/proxy/forwarding, and the fixed
offline-receive-v1 remote command. The unprivileged forced-command gate checks
the original command and uses fixed sudo to start the owner-installed root
receiver; no candidate command or path is executed on the remote host.
All preflight connections MUST use the same root-protected client SSH identity
and pinned known_hosts, without sending or executing Bash via stdin. These
restrictions apply only to the offline transport; hosted main-only deploy SSH
scripts remain unchanged.

The sender streams a V2 bounded canonical metadata preamble containing the
exact owner-signed permit bytes (base64) and detached signature, followed by
exactly eleven filenames in fixed order with canonical binary
lengths and SHA-256 hashes. Native root ALWAYS rejects unsigned V1.
The native receiver independently verifies owner Ed25519 from the
protected host-policy.json, exact source/manifest/signature envelope,
destination/login/host-key/client SSH identity public pin, expiry <=600s,
and single-use nonce BEFORE accepting large payloads. It durably consumes
the nonce with O_EXCL+fsync; an SSH key alone or an old signed bundle
cannot authorize a new transfer.
The sender pins each local FD with O_NOFOLLOW, and
checks the signed manifest and signature-envelope SHA before writing. The
receiver first acquires a root-owned 0600 exclusive O_EXCL .receiver-lock in
the empty staging root and fsyncs its parent. Concurrent SSH sessions cannot
enter while the receiver holds this lock. Crashes preserve the lock for owner
reconciliation. It then uses exclusive no-follow 0600 opens in a private
.incoming directory, hashes during copy, fsyncs each file, then independently
reopens and hashes all bytes. The fixed host verifier authenticates owner and
builder Ed25519 signatures, native host marker and protected policy and
inspects the signed Docker image archives. Only then may it fsync the pending
directory, atomically rename it to candidate-<random>, fsync the parent and
return its bounded JSON staging receipt. All receipts explicitly mark
deployAuthorized=false and transferAuthorized=false; the stage cannot be
interpreted as activated or released.

The receiver removes only its own unpublished pending directory after a
refusal. If the parent fsync fails after rename, it preserves the uncertain
published stage for owner reconciliation and refuses to report success.

## Evidence boundary

The 11-file byte protocol, independent readback, remotely signed permit
authentication and durable nonce replay refusal, and
adversarial corrupt/truncated/path inputs are testable in a disposable native
Node 22 container without network or elevated host capabilities. A real
local SSH session to an independently installed disposable native sshd with
the exact forced command remains to be demonstrated before production writes.
That local fixture is NOT independent production host attestation. The
owner's actual remote root provisioning, independently pinned verifier bytes
and external monotonic witness/activation protocol remain separate gates.
