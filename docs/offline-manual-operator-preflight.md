# Independent manual release: operator-provisioning preflight

**Development / inspection only. Production release remains NO-GO.** This is an
additional **read-only manual preparation path**, not a workaround for failing
hosted CI and not a deploy implementation. It neither generates trust roots
nor installs files. It never calls Docker, PostgreSQL, migration, backup,
release activation or `scripts/production-server.sh`.

## Operator custody, not source checkout custody

The operator must independently create and protect this exact directory **on a
Linux SSH client** (a local WSL2 Linux user may run the client but is NOT a
production host):

`$HOME/.virki/offline-manual-operator/` — 0700, owned by the invoking UID.

It contains **exactly seven regular 0600 files**, owned by that UID with one
hardlink: `owner-pin.json`, `owner-public.pem`, `identity.json`, `known_hosts`,
`checklist.json`, `checklist-signature.json`, and `ssh-identity`.
Symlinks, extra files, unsafe modes, wrong owners, or missing files are denied.
The SSH private identity is **never read by Node or printed**; OpenSSH handles
it through an explicit file path. Provision the SSH key and owner signing key
**out of band**, not from the untrusted release bundle or the PR checkout.
The signing private key must **not** be stored in this directory or on the
production host. Do not commit any real identity, pins or signatures.

All JSON documents must be canonical one-line `JSON.stringify` output with
these exact keys, in this order:

```text
identity.json:
  version (1), mode (virki-manual-operator-identity-v1), host,
  port (integer), sshUser, hostKeyAlias, sshHostPublicKey,
  expectedSourceSha (40 lowercase hex)

owner-pin.json:
  version (1), mode (separately-provisioned-owner-pin-v1),
  ownerSignerSpkiSha256 (64 lowercase hex)

checklist.json:
  version (1), mode (virki-manual-provision-checklist-v1),
  checklistId (64 lowercase hex, unique externally assigned), identitySha256,
  sourceSha, issuedAt, expiresAt (integer epoch seconds, <=300s window),
  components (exact five ordered labels below)

checklist-signature.json:
  version (1), signature (canonical Ed25519 64-byte Base64)
```

The independent operator's signed checklist names these five **required
metadata checks**, in this exact order: `TRUST_POLICY`, `VERIFIER_MODULE`,
`LEDGER`, `ISOLATED_DOCKER_SOCKET`, `OWNER_BOOTSTRAP`. `identitySha256` is the
SHA-256 of the **exact bytes** of `identity.json`. `sourceSha` must equal its
`expectedSourceSha`. The owner's key is Ed25519 SPKI, whose DER SHA-256 must
match the independently provisioned `owner-pin.json` pin.

Sign the **binary concatenation** of ASCII
`VIRKI_MANUAL_OFFLINE_PROVISION_CHECKLIST_V1`, one zero byte, and the exact
UTF-8 `checklist.json` bytes, using Ed25519 (no prehash), and store the
canonical Base64 signature in `checklist-signature.json`.

The `sshHostPublicKey` must be a canonical OpenSSH `ssh-ed25519` key (key type
plus Base64 encoded SSH wire format). `known_hosts` must contain **exactly**
`<hostKeyAlias> <sshHostPublicKey>\n`, with no other entries. The operator
must verify this server host key through an independent trusted channel,
never blindly accept it from `ssh-keyscan` or a first-use prompt.

These locally stored pins **do not by themselves prove independent root
custody**. A compromised same-UID client can replace the entire pin/key/consent
set. The preflight treats a valid signature as a signed **operator checklist**
only, not as a native installed-owner or witness attestation.

## Safe diagnostic, from the Stage8 source only

After independently provisioning the files, run:

```sh
npm run preflight:offline:manual:operator
```

The command accepts no host, key, path, action or arbitrary SSH arguments.
It uses `/usr/bin/ssh`, `-F none` to disable ambient `ssh_config` (including
`Match exec`), explicitly pins host/port/user/host key alias, one known-hosts
file, an exact Ed25519 host-key algorithm and one identity file. Proxies,
forwarding, password/keyboard-interactive auth, agent use, updating host keys,
and local SSH commands are disabled. A bounded SSH subprocess only performs
five fixed remote `stat -c '%u|%a|%F'` queries; it returns only fixed
component labels, `METADATA_OBSERVED` or `UNVERIFIED`, never file contents.

`MANUAL_OPERATOR_PREFLIGHT_BLOCKED` means local signature/identity/SSH
validation or remote response failed. `MANUAL_OPERATOR_PROVISIONING_INCOMPLETE`
indicates one or more expected host objects are missing, inaccessible or have
unexpected metadata; the `unverified` array is the operator's remedial list.
In particular, a host with correctly protected **0700 root-owned parent
directories** can return all five `UNVERIFIED` to a non-root SSH account:
`stat` cannot traverse those parents. **Do not make private directories
world-readable just to turn these diagnostic results green.** The remote
operator must inspect and install them using a separate reviewed, root-owned
native bootstrap on the host. The local client does not execute `sudo`,
acquire root rights over SSH, or auto-install any missing file.

The five expected native objects are, respectively:

| Label | Independently provisioned host location | Metadata |
| --- | --- | --- |
| `TRUST_POLICY` | `/etc/virki/offline-release/trust-policy.json` | root regular 0600 |
| `VERIFIER_MODULE` | `/usr/local/lib/virki/offline-release/infra/offline/trusted-release-coordinator.mjs` | root regular 0600 |
| `LEDGER` | `/var/lib/virki/offline-release/ledger.json` | root regular 0600 |
| `ISOLATED_DOCKER_SOCKET` | `/run/virki-offline-import/docker.sock` | root socket 0600 |
| `OWNER_BOOTSTRAP` | `/etc/virki/offline-bootstrap/bootstrap-policy.json` | root regular 0600 |

Never populate these with placeholders, copied signing private keys, or
candidate-generated trust policies. File existence and mode are only
preliminary metadata, not proof of trusted content or custody.

`SIGNED_PROVISION_CHECKLIST_AND_HOST_METADATA_INSPECTED_ONLY` means only that
all five **metadata** checks responded successfully. It **does not** confirm
the content of policies/keys, host root of trust, signer custody, native
launcher integrity, backup restoration, external monotonic mTLS witness,
Prisma migration, production health, rollback, or approval to deploy.

Even with five out of five metadata observations, the output always has
`ownerTrustInstalledVerified:false`, `witnessCasAuthorized:false`,
`transferAuthorized:false`, `dockerLoadAuthorized:false`, and
`deployAuthorized:false`. Exit zero is limited to this nonauthorizing
five-metadata-result state. The trusted native operator remains responsible for
installing the actual root-owned components under independently signed and
reviewed policy; do not grant the source checkout permission to create them.

The existing `npm run preflight:offline:host` uses separate private production
configuration and reports metadata without this signed checklist. It is **not**
equivalent to this new pinned-identity diagnostic.

### Production release still blocked

Independent native host/source/runtime execution, verified isolation of the
real Docker daemon, owner provisioned trust and revocation, irreversible
external witness CAS, backup/restore/Prisma/health/rollback rehearsals, and
explicit authorized release transport must all be provided and reviewed
before a true GitHub-independent manual deployment path exists. The current
`npm run deploy:prod` continues to require a clean published `main` and hosted
CI/CodeQL/GHCR evidence; no code here bypasses those gates or imports PR78.

Run focused non-Docker tests on the local WSL/Linux client with Node 22:

```sh
npm run test:offline:manual:operator
```
