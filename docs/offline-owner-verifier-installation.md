# Independently approved native verifier installation

**Development status: PRODUCTION NO-GO.** The implementation lives in
`infra/offline/trusted-owner-installation.mjs`. Its guarded fixture can be tested
in an isolated Linux/amd64 root Docker container with a private tmpfs. No
production trust anchor, owner installation approval or deploy permission is
created by this repository. This installer does not modify Docker, Git, SSH,
services, Cloudflare, deManage or any live production host.

## The trust boundary

The installation *executable* must be independently reviewed, then physically
provisioned by the operator at the fixed root-owned file
`/usr/local/lib/virki/offline-bootstrap/trusted-owner-installation.mjs`.
The source checkout and the uploaded release candidate cannot select its path,
bootstrap trust policy, approval signer or executable dependency pins. Calling
the checked-out module in native mode fails; the command-line `--install` flag
is deliberately not an installation API. A trusted operator may explicitly
invoke the exported `installOwnerApprovedVerifier({})` from this already
installed bootstrap module after reviewing the independent consent and host.

The following inputs must be established through a separate root-controlled
provisioning ceremony, with root-owned 0700 directories and 0600 regular files:

| Location | Contents |
| --- | --- |
| `/etc/virki/offline-bootstrap` | `bootstrap-policy.json`, `owner-key.pem`, `installation-state.json`, and, only after review, `installation-approval.json` |
| `/etc/virki/offline-verifier-operator` | `verifier-pins.json`, `trust-policy.json`, `ledger.json` |
| `/var/lib/virki/owner-reviewed-verifier` | Exactly the eleven separately audited ESM source modules, all pinned in the verifier inventory |

The independent bootstrap policy uses canonical minified JSON and *exactly*
the following keys, in order: `version` (1), `mode`
(`virki-owner-bootstrap-v1`), `hostIdentitySha256`, `signerKeyId`,
`ownerPublicKeySha256` (SHA-256 of Ed25519 SPKI DER), `installerSha256`
(hash of independently installed bootstrap executable bytes),
`nodeExecutablePath`, `nodeExecutableSha256` (hash of exact trusted Node 22
interpreter binary), `maxValiditySeconds` (1 to 86400), `revokedKeyIds`,
`revokedApprovalIds`. Arrays must contain unique, valid identifiers. Revocations
are enforced before signature acceptance. A public key is not trusted just
because it appears in an installation bundle; its exact DER digest must already
be pinned by this separately installed bootstrap policy.

The bootstrap's independently initialized `installation-state.json` is exactly
`{"version":1,"lastSequence":0,"status":"ready","approvalDigest":null}`
for an initial installation. The state is not a template that can be reset by a
candidate. Preserve it across restarts and backups. Changing it manually is a
separate break-glass decision requiring human review of all prior attempts.

## Distinct setup and consent

Provisioning the bootstrap and signer key is **setup**, not consent to install
a verifier. The separate owner-controlled Ed25519 private key, never resident
on the target host or in the repository, must later sign a specific review
decision. The signature is over the binary concatenation of the exact ASCII
domain `Virki/offline-verifier/owner-install/v1` followed by `0x00`, and the
UTF-8 canonical `JSON.stringify(approval)` bytes. It uses native Ed25519 with
no additional hash/prehash. The envelope is canonical JSON with exactly the
keys `approval`, `signature`; `signature` is standard 64-byte Ed25519 Base64.

The nested canonical `approval` object contains these keys **in order**:

1. `version`: `1`; `mode`: `virki-native-verifier-install-v1`; `approvalId`:
   independently generated random 32-byte lower-hex identifier.
2. `sequence`: the protected previous bootstrap sequence plus one;
   `signerKeyId`: exact active bootstrap signer ID.
3. `hostIdentitySha256`: the host's measured machine-id domain digest;
   `bootstrapPolicySha256`: hash of the exact protected bootstrap policy bytes.
4. `verifierPinsSha256`, `trustPolicySha256`, `ledgerSha256`: exact digests of
   the three independently inspected operator files.
5. `verifierDirectory`, `policyDirectory`, `ledgerDirectory`: the fixed target
   paths `/usr/local/lib/virki/offline-release`,
   `/etc/virki/offline-release`, `/var/lib/virki/offline-release`.
6. `issuedAt`, `expiresAt`: integer Unix seconds, with bounded validity and
   a maximum of 60 seconds future clock skew.

The SHA-256 host identity is `SHA256(UTF8("VIRKI_OFFLINE_HOST_MACHINE_ID_V1\\0"
+ measured 32-character lowercase machine-id))`, where `\\0` denotes the
single zero byte. The installer reads the native `/etc/machine-id` and accepts
only a root-owned, stable, single-link regular file.

The independently approved verifier pin inventory is canonical JSON with the
exact keys `version`, `mode`, `files`, `trustPolicySha256`, `ledgerSha256`.
`mode` is `independent-native-verifier-pins-v1`; `files` has exactly eleven
lexicographically ordered `{"path":"...","sha256":"..."}` entries from
`AUDITED_VERIFIER_FILES` in `trusted-host-installer.mjs`. The project has a
separate TypeScript-parser-based closure test in
`trusted-verifier-dependency-closure.test.mjs` that rejects dynamic imports,
unreviewed builtins, missing ESM dependencies and executable escapes. The
operator must run and inspect that test on the same reviewed source bytes
before signing their hashes. The installer subsequently remeasures each
individually pinned source inode and the exact installed dependency tree.

The release trust policy must independently accept the offline assurance
tradeoff, bind the exact host and `linux/amd64`, and contain distinct active
Ed25519 builder and owner pins. The ledger must have the expected pinned
anchor, continuous predecessor chain, strictly increasing sequences and no
replayed nonces, manifest hashes or approval digests. A valid operator
installation signature does not turn CodeQL, GitHub Actions or GHCR checks
into successful evidence, and never authorizes a release on its own. The
bootstrap installation signer must have a different public-key pin from both
the release builder and release owner, preventing reuse of release credentials
as authority to replace trusted executable code.

## Crash and filesystem semantics

The native installer refuses symlinks, hardlinks, untrusted modes, missing
files, unexpected modules, replaced pinned bytes, unexpected existing target
paths (including dangling symlinks), key revocations, outdated or forged
consent, and attempts made from WSL or Windows. It accepts only root and a
root-owned, independently pinned Node 22 binary. All target parents must
already exist as private root directories on their respective native Linux
filesystems.

After verification and *before any installation file is published*, a
root-only exclusive `.installation-lock` directory is created, fsynced, and
the protected bootstrap state is atomically replaced with `status: "pending"`
and the consumed signed approval sequence. Each target is first written into
its own parent filesystem as a private `.verifier-install-pending` directory,
using no-follow exclusive file creation, `fsync` for files/directories, and a
same-parent atomic rename to the final destination. Policy and ledger are
published first; the complete eleven-module verifier directory is published last.
The installed files and policies are remeasured before the bootstrap state
becomes `status: "installed"`.

The installed state and exclusive lock remain after success, preventing
unnoticed replay or an unreviewed upgrade. A process crash or any failure
after the lock is acquired leaves a durable failure latch that refuses retry
until a separate manual recovery procedure is formally specified and reviewed.
The three different target filesystems do not support one atomic transaction;
`pending` and the permanent lock are therefore necessary. No production
runtime activation is provided by this installer; deployment remains NO-GO.

## Re-measure installed trust at use time

`measureInstalledTrustedVerifierAtUseTime({})` is a read-only exported function
of the **independently pinned bootstrap executable**, not an entrypoint loaded
from the candidate or the release archive. It is usable only when the bootstrap
module is already installed at the fixed native root path. The function accepts
no caller-selected production trust roots, pins, public keys, interpreter,
ledger head, image IDs or expected source hashes.

Every call independently rechecks the immutable root/owner-protected bootstrap
policy, its Ed25519 public-key pin, the exact SHA-256 of the bootstrap module,
the Node 22 executable's canonical path and SHA-256, and the measured host
identity. It then requires the protected `.installation-lock` and a canonical
`installation-state.json` with `status: "installed"`, positive exact sequence,
and the SHA-256 digest of the signed owner approval. The approval's signature,
host, policy version, verifier pin inventory, destinations, state sequence,
revocations and maximum originally signed duration are verified again. Owner
approval expiration bounds the *installation act* and is not a time-to-live for
already installed executable code: an otherwise accepted installation does not
become untrusted just because the original installation authorization expires.
Subsequent revocation still refuses fresh measurement.

The module checks the **eleven** exact installed ESM file paths and their
complete private directory tree. Each file is opened with `O_NOFOLLOW` from an
anchored directory descriptor, with regular-file, root:root 0600, single-link,
size, inode metadata and SHA-256 requirements. Missing, reordered, injected,
modified, linked or publicly writable paths fail closed. The installed release
trust policy must exactly match the independently approved immutable digest.
This measurement cannot be replaced by a statement in Git, an image label or a
result supplied by a release candidate.

The installed `ledger.json` is deliberately **mutable** after legitimate
release transitions. The approval binds its independently held *initial*
ledger; a current ledger may contain additional entries. The function checks
that the original ledger history remains an exact prefix, that all current
entries have strictly increasing sequences, valid predecessor links and unique
release hashes, nonces and approval digests. The returned status is always
`INSTALLED_VERIFIER_BYTES_MEASURED_ONLY`, and the ledger is classified either
`INITIAL_LEDGER_INSPECTED_NOT_AUTHORIZED` or
`DYNAMIC_LEDGER_INSPECTED_NOT_AUTHORIZED`. No returned field permits a release,
Docker load, migration or service activation.

**Remaining security boundary:** a read-only inspection cannot establish that
a newly appended ledger entry was produced by a trusted atomic admission CAS,
or detect a rollback of previously observed history to an earlier *valid*
prefix without an independent monotonic checkpoint. It also does not prove
that the modules later loaded by another process are the exact bytes just
measured: an installed-verifier invocation must protect its execution and
loader boundary, with remeasurement within that boundary and prevention of
post-check replacement, before it can be a production authority. An audited
Node binary hash alone does not attest every dynamic library, preload or Node
startup argument. Those dependencies, witness semantics and end-to-end native
host rehearsal remain blockers. **PRODUCTION NO-GO.**

## Disposable native validation

The root fixture writes only beneath `/tmp/virki-owner-install-fixture-XXXXXX`
on a private Linux tmpfs, inside a disposable root container, with the explicit
environment variable `VIRKI_OWNER_INSTALL_DISPOSABLE_FIXTURE=1`. All fixture
roots (bootstrap, operator, source, and three target parents) are independent
siblings. Production paths cannot be supplied to the fixture API. The fixture
exercises signed approval, verified publication, digest tampering, malformed
and replayed signatures, revocation, unsafe policy/ledger even when freshly
signed, symlinks, mode errors and simulated crash/SIGKILL failure latches.

Rehearsal command (development only):

```sh
docker run --rm --network none --read-only \
  --tmpfs /tmp:rw,nosuid,nodev,size=128m,mode=1777 \
  --mount type=bind,source="$PWD",target=/work,readonly \
  -w /work -e VIRKI_OWNER_INSTALL_DISPOSABLE_FIXTURE=1 \
  node:22.23.3 node --test infra/offline/trusted-owner-installation.test.mjs
```

No tested production host trust-anchor installation, installed-verifier
activation, live rollback, disk budget or external-owner authorization was
performed by this implementation. An owner must decide those separately.
