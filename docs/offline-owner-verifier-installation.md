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
interpreter binary), `gitExecutableSha256` (hash of the reviewed native
`/usr/bin/git` binary), `maxValiditySeconds` (1 to 86400), `revokedKeyIds`,
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
the Node 22 executable's canonical path and SHA-256, the root-owned native
`/usr/bin/git` executable's fixed path and SHA-256, and the measured host
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
Node/Git binary hashes alone do not attest every dynamic library, helper,
preload or Node startup argument. Neither binary is executed by this check.
Those dependencies, witness semantics and end-to-end native
host rehearsal remain blockers. **PRODUCTION NO-GO.**

### Exact source bytes delivered to Node's ESM compiler

`rehearseInstalledVerifierPinnedEsmImport(request)` is a diagnostic experiment
restricted to the independently signed **disposable native Linux root tmpfs**
fixture. It invokes `measureInstalledTrustedVerifierAtUseTime` and then copies
the eleven installed, root-protected, digest-checked modules to a private
in-process byte snapshot. Node 22's synchronous `node:module.registerHooks`
then resolves only modules inside the approved graph and supplies all eleven
exact snapshot byte buffers to the ESM loader by importing the six reviewed
host entry modules. All builtin imports are checked
against the reviewed builtin allowlist; package imports, extra filesystem
modules, data URLs, query variants and other graph escapes fail closed.
Returned `loadedPaths` represent hashes of the buffers that Node's real ESM
loader consumed, not merely prior disk inspection. Every reviewed host entry
is imported, but none of its release methods is called.

Adversarial Linux tests use **all eleven real project ESM files** and an actual
Ed25519 installation approval confined to the disposable fixture.
Post-snapshot replacement of an entry, a transitive dependency or the image
import module cannot change the compiler's source: the tests compare
actual loader bytes against the signed hashes. Removal or symlink replacement
of the entry's path is refused when Node cannot resolve it to the exact pinned
URL. A compromised source before the snapshot, an altered owner state, or an
unreviewed `NODE_OPTIONS`, `LD_PRELOAD` or Node command-line flag is refused.

A separate, explicitly read-only installed-bootstrap entrypoint can inspect the
native Linux closure when independently approved and installed:
`node /usr/local/lib/virki/offline-bootstrap/trusted-owner-installation.mjs
--inspect-installed-esm`. This example documents the interface; production
execution remains unapproved. The fixed native entry checks the exact bootstrap
path, Node 22 and Git executable pins, root-owned signed installation state,
approved ESM files, no startup flags or preloads, and an unchanged policy and
ledger during inspection. Source checkouts, arbitrary trust roots and fixture
parameters cannot access this native entry. It returns
`NATIVE_PINNED_ESM_CLOSURE_MEASURED_ONLY` with
`independentLedgerWitnessVerified:false`, `dockerLoadAuthorized:false`,
and `deployAuthorized:false`; no release methods are invoked.

This inspection **does not launch a production release verifier**.
A flag/environment check inside JavaScript runs after Node and its native
startup code have already executed. It therefore cannot attest absence of
earlier `--import`, `--require`, `LD_PRELOAD`, loader hooks, startup snapshots,
interpreter helpers or dynamic-library injection. A separately installed,
audited **native launcher** must validate those inputs before Node executes,
start a fresh process under a restrictive execution environment, and bind its
runtime loader to the approved snapshot without any module cache predating
the hooks. That separately audited native launcher, kernel policy, live host
test and externally monotonic ledger witness remain unproven. Every diagnostic
inspection sets `independentLedgerWitnessVerified: false` and cannot authorize
a release. **PRODUCTION NO-GO.**

### DEV-only static pre-Node byte guard (separate from the installer)

`infra/offline/native-bootstrap/native-pre-node-guard.c` is a distinct,
**non-authorizing** C launcher prototype. It is **not installed**, is not part
of the eleven signed verifier modules, and cannot run a verifier, release,
Docker API, ledger CAS, migration or deploy. The production-source binary
rejects WSL/Windows, non-root, arbitrary arguments and unprovisioned roots.
It requires separately operator-installed, root:root protected paths:
`/etc/virki/offline-native-guard/owner-pin.txt`,
`/etc/virki/offline-bootstrap/bootstrap-policy.json`,
`/usr/bin/node` and the guard executable at
`/usr/local/lib/virki/offline-bootstrap/native-pre-node-guard`.
The private 0600 pin file uses the exact format
`VIRKI_DEV_NATIVE_GUARD_PIN_V1` followed by lowercase SHA-256 values
`bootstrap_sha256`, `node_sha256` and `launcher_sha256`. It is **not
an owner signature**; no code here generates keys, derives an approval or
provisions it. These bytes must be independently audited and installed by an
operator, not constructed from source checkout or a release bundle.

The prototype itself must be **statically linked** with no ELF interpreter.
Before execution it measures three independent protected inodes through open
file descriptors, checks directory ownership and non-writable ancestors,
rejects symlinks/hardlinks, and compares SHA-256 using the kernel AF_ALG
interface without dynamically loading crypto libraries. It also rejects
unreviewed environment variables and ELF targets with `PT_INTERP` or
`PT_DYNAMIC`; a hash alone would not pin a dynamic loader or its libraries.
Only an owner-pinned static ELF copied into a sealed executable memfd may be
invoked via `execveat`, and then **only for `--version`** in a
privilege-dropped, no-new-privileges child with descriptor inheritance blocked
and a bounded child lifetime. The output is strictly
`DEV_ONLY_STATIC_BYTE_PROBE_NO_RELEASE_AUTHORITY`.

The child also refuses inherited nonzero Linux `securebits` or ambient
capabilities (notably `SECBIT_NO_SETUID_FIXUP` and locked variants). Before
execution, while still privileged, it drops every supported capability from
the kernel bounding set, clears the ambient set, drops supplementary groups
and real/effective/saved UID/GID to 65534, explicitly clears the permitted,
effective and inheritable sets through Linux `capset`, and verifies all
four sets **and the bounding set** are zero using `capget` and `prctl`.
An unavailable `CAP_SETPCAP`, an unsupported capability interface, a
non-root caller or any inconsistent result refuses the launch, rather than
silently skipping an incomplete drop.

An independent child deadline uses `alarm(3)`. After UID/GID changes the
child separately arms `PR_SET_PDEATHSIG=SIGKILL` and checks its original
parent PID, because Linux clears the parent-death signal on credential
transitions. Tests prove that parent `SIGKILL` terminates a fixture target
which deliberately ignores `SIGALRM`; they also reproduce hostile ambient
and no-setuid-fixup capabilities and test missing `CAP_SETPCAP`. A *trusted*
static target is still an assumption: arbitrary malicious child code can
change its own alarm or parent-death signal, and a child killed after orphaning
may remain a zombie until its reaper collects it. Neither local timer nor
fixture is a production isolation or unconditional scheduling guarantee.

The normal Linux Node 22 build has `PT_INTERP` and is therefore refused;
**this experiment does not establish a usable production Node launcher**.
Genuine runtime approval still needs separately audited ELF interpreter and
DSO provenance, pinned loader closure, native host/kernel provisioning and
independent owner approval. The fixture-only build uses separate compile-time
`VIRKI_TEST_ONLY_ROOT_FIXTURE` paths under private `/root` and synthetic
**non-signing** checksum data to exercise real Linux root/ELF/execveat
mechanics on WSL. It cannot authenticate a production host; normal builds
unconditionally reject WSL. No host `/etc` paths are written by the tests.

### Stage8 independent native dynamic-ELF closure preparation (non-authorizing)

`infra/offline/native-bootstrap/native-dynamic-closure.c` and its adversarial
Node22 test inspect a **real dynamically linked** Node Linux/amd64 binary. This
is a separate, statically linked, read-only diagnostic; it does not modify the
static launcher, execute dynamic Node, read private signing keys, or connect
to the eleven-file installed verifier. The production-source build rejects
WSL and missing, non-root-owned or writable operator inventory bytes at the
fixed `/etc/virki/offline-native-guard/operator-elf-closure.txt` path.

The exact inventory starts with `VIRKI_DEV_ELF_CLOSURE_V1` followed by
ordered `SONAME canonical-absolute-path sha256` rows (starting with the
fixed `node` executable and the loader). It is an **untrusted proposal**,
not an owner signature. The diagnostic validates the complete transitive
`DT_NEEDED` graph, SONAME names, `PT_INTERP` target, kernel-visible root
file ownership, unwritable path ancestors, regular single-link inodes,
canonical paths, bounded ELF metadata and SHA-256 of each opened FD. Verified
bytes are copied into separate sealed `memfd` FDs and parsed from those
immutable snapshots, not reloaded from mutable paths. The Debian/Ubuntu
Node22 `$ORIGIN/../lib:$ORIGIN/` RUNPATH and its root-owned interpreter
symlinks are accepted as **observed data only**, not as safe runtime
resolution. Other RUNPATH/RPATH/audit/filter entries fail closed.

The fixture-only binary uses an explicitly separate compile-time path under
`/root/virki-elf-closure-fixture-*`, never creates an owner root, never
signs an inventory and reads only the fixture's manifest and installed
system Node libraries. Tests prove that a wrong main/loader/transitive DSO
digest, missing or duplicate SONAME, altered inventory, injected environment
or wrong executable causes refusal. Even successful output is only
`DEV_ONLY_REAL_NODE22_ELF_CLOSURE_MEASURED_NO_EXEC_NO_AUTHORITY`.

**Still required before a real independently trusted dynamic launch:**
an operator-held Ed25519 public trust root, a signature on the exact
versioned inventory, independently audited kernel/host/launcher bytes, and
an immutable OS-enforced mount/loader namespace that binds the kernel's
`PT_INTERP` open and every subsequent `DT_NEEDED`, `dlopen`, NSS and addon
resolution to those approved bytes. The current pre-execution FD snapshots
are not automatically consulted by the kernel's ELF interpreter or ld.so.
An `execveat` of Node alone would restore the race; therefore **no dynamic
execveat or release permission is implemented**. A root-owned manifest is
not a substitute for an owner signature or a rollback-resistant witness.
Production and native release activation remain **NO-GO**.

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
