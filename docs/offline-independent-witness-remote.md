# Independently hosted witness CAS (native Linux)

The remote witness is an **independently deployable service** on an operator-controlled
Linux machine separate from the production application host. The witness verifies
owner-signed CAS transitions, persists an Ed25519-signed sequence in SQLite with
`BEGIN IMMEDIATE`, `WAL` and `synchronous=FULL`, and publishes fsynced receipt
anchors. A service process crash before commit aborts the transition; a crash
after commit can be reconciled on restart by rebuilding a missing anchor suffix
from the already committed, signed SQLite history. The server authenticates
mutual TLS 1.3, CA-valid client certificates and the **exact client certificate
DER SHA-256 pin**. The client also validates the server hostname, its CA and its
exact certificate DER pin, then checks the separately pinned Ed25519 signed
response. Every reply denies deployment and Docker permissions.

## Custody and deployment boundary

Run on an isolated native Linux host with Node.js 22 and a dedicated unprivileged
service account. Install the repository's `scripts/offline-independent-witness-server.mjs`
and its `scripts/lib/offline-independent-witness-service.mjs` dependencies.
Keep the following outside the repository and production application server:

* Witness receipt-signing Ed25519 **private key** (PEM PKCS#8), independent
  pinned SHA-256 of the DER SPKI public key, and separate TLS server key.
* The owner's **Ed25519 public verification key**, pinned by SPKI SHA-256.
  **Never place the owner's private signing key on the witness host.** Use a
  separately administered operator workstation or signing service for CAS.
* Distinct `0700` database and anchor directories (prefer independently
  managed storage); private TLS/key files and owner public-key files `0600`.
  The service refuses symlinks and unexpected inode/file owner changes.
* A dedicated mutually trusted TLS CA, a server certificate with a matching IP
  SAN, and a client certificate with clientAuth usage. Keep the CA file `0600`
  to meet the pinned-file check. The server checks the **single explicitly
  approved client certificate**, even if the CA issues another certificate.

Example **configuration names** in the witness host environment (values are
operator-supplied, not shipped as keys or identities):

```text
VIRKI_WITNESS_MODE=remote
VIRKI_WITNESS_DB_DIRECTORY=/var/lib/virki-witness/db
VIRKI_WITNESS_ANCHOR_DIRECTORY=/var/lib/virki-witness/anchors
VIRKI_WITNESS_SIGNER_KEY=/etc/virki-witness/witness-ed25519.pem
VIRKI_WITNESS_SIGNER_PIN=<SHA256 of Ed25519 witness SPKI DER>
VIRKI_WITNESS_OWNER_PUBLIC_KEY=/etc/virki-witness/owner-public.pem
VIRKI_WITNESS_OWNER_PIN=<SHA256 of independent owner SPKI DER>
VIRKI_WITNESS_HOST_SHA256=<approved 64-hex host identity>
VIRKI_WITNESS_LEDGER_SHA256=<approved 64-hex ledger identity>
VIRKI_WITNESS_TLS_KEY=/etc/virki-witness/server-key.pem
VIRKI_WITNESS_TLS_CERT=/etc/virki-witness/server-cert.pem
VIRKI_WITNESS_TLS_CA=/etc/virki-witness/client-ca.pem
VIRKI_WITNESS_TLS_CLIENT_CERT_SHA256=<SHA256 of client certificate DER>
VIRKI_WITNESS_BIND_HOST=<explicit bound IP address>
VIRKI_WITNESS_BIND_PORT=<chosen nonzero TLS port>
```

Set the service account's umask to `0077` and bind only its explicitly
approved interface. Restrict network access with the host firewall or VPN.
Start with `node scripts/offline-independent-witness-server.mjs` on this host.
Use systemd `User=`, `Group=`, `UMask=0077`, `NoNewPrivileges=true`,
`ProtectSystem=strict`, `ReadWritePaths=` for the database and anchor paths,
`ProtectHome=true` and automatic restart on ordinary process failure. Preserve
database, WAL, anchors, keys and TLS pins between restarts. A new machine,
certificate rotation or signing-key rotation requires an explicit operator
trust migration, including preserving the independently held floor. No
automatic reset is safe.

## Client and independent floor

On the **owner's** trusted Linux workstation, configure:

```text
VIRKI_WITNESS_CLIENT_SERVER_HOST=<IP matching server certificate SAN>
VIRKI_WITNESS_CLIENT_SERVER_PORT=<TLS port>
VIRKI_WITNESS_CLIENT_SERVER_CERT_SHA256=<SHA256 of server certificate DER>
VIRKI_WITNESS_CLIENT_TLS_CA=/private/client/server-ca.pem
VIRKI_WITNESS_CLIENT_TLS_CERT=/private/client/client-cert.pem
VIRKI_WITNESS_CLIENT_TLS_KEY=/private/client/client-key.pem
VIRKI_WITNESS_SIGNER_PUBLIC_KEY=/private/client/witness-public.pem
VIRKI_WITNESS_SIGNER_PIN=<approved witness SPKI DER SHA256>
VIRKI_WITNESS_OWNER_PUBLIC_KEY=/private/client/owner-public.pem
VIRKI_WITNESS_OWNER_PIN=<approved owner SPKI DER SHA256>
VIRKI_WITNESS_CLIENT_OWNER_SIGNER_KEY=/private/client/owner-private.pem
VIRKI_WITNESS_HOST_SHA256=<approved host identity>
VIRKI_WITNESS_LEDGER_SHA256=<approved ledger identity>
```

Files must be regular owner-only `0600` files outside Git. Store the owner's
private key only under separately secured operator custody; prefer a hardware
backed signing workflow when available. The CLI reads the private owner key
only for CAS; it never sends or prints that key. Public keys and both SPKI pins
must be obtained independently of the witness endpoint.

```text
node scripts/offline-independent-witness-remote-client.mjs head <sequence> <headSha> <receiptSha256>
node scripts/offline-independent-witness-remote-client.mjs cas <sequence> <expectedHeadSha> <expectedReceiptSha256> <nextHeadSha> <transitionSha256>
```

The caller must retain the **exact** last trusted `{sequence, headSha,
receiptSha256}` off the witness host. The initial explicitly approved genesis
is sequence `0`, 40 zeroes for `headSha` and 64 zeroes for `receiptSha256`.
`head` requires an independently held exact sequence, head hash and receipt
hash; a newer, unknown state fails closed until independently reconciled. This avoids
mistaking a signed but forked head for the operator's established history.
`cas` independently authenticates the exact predecessor and proposal with the
owner's separate Ed25519 key and a 20-second expiry. The witness commits at
most one successor for a predecessor. A 409 is a stale CAS; an interrupted
network call can have committed even if no receipt was received. Never retry
blindly after an uncertain result: reconcile the independently trusted floor
and the server's signed history with the operator before proposing another
transition. The CLI outputs verified state and signed receipt JSON; save this
outside the service's trust domain.

The next head is a Git-style 40-hex digest; `transitionSha256` must be computed
and independently approved by the operator's release policy. The service
does **not** decide which source SHA is approved and does not override the
current main-only signed-release-bundle policy for draft PR #87.

## Exact trust and durability limits

The witness instance, its SQLite database, anchor storage and receipt signer
share one *witness-host trust domain*. The owner workstation/private key and
its durable saved floor are a distinct operator trust domain. Normal process
crashes, concurrent clients, stale state, a single database rollback and
modified signed history have local adversarial tests. Hardware power-loss
survivability depends on storage honesty and fsync semantics. A privileged
attacker who compromises the witness host and reverts **both** database and
anchors can defeat host-local monotonicity; a compromised owner signer can
authorize transitions. An independently maintained floor and separate key
custody constrain those cases but cannot magically restore lost evidence.
No physical second host, operator identity, independent floor medium, live
certificate issuance or remote deployment has been provisioned or attested
by these disposable WSL tests. The service is intentionally **not wired to
release authorization** and always returns `witnessCasAuthorized:false`,
`dockerLoadAuthorized:false`, `deployAuthorized:false`.

Run the tests on a Linux Node 22 host with `openssl` available:

```bash
node --test scripts/offline-independent-witness-remote.test.mjs scripts/offline-independent-witness-service.test.mjs
```

## Narrow host CAS-to-ledger/activation bridge (separate owner installation)

`infra/offline/host-witness-ledger-activation-bridge.mjs` implements a **local
use-point verification and durable intent**, independently of the existing
stage18 activation machinery. It is not a deploy, ledger-write or activation
entrypoint. On a native Linux host it requires root and reads only a fixed
owner-installed `0600` policy at `/etc/virki/offline-witness-bridge.json`;
the intent directory is fixed at `/var/lib/virki/offline-witness-bridge`
(`0700`, root-owned). A disposable WSL-root fixture accepts a strictly scoped
`/dev/shm/virki-witness-bridge-fixture-*` directory when
`VIRKI_DISPOSABLE_WITNESS_BRIDGE=1` is set. Never use this fixture for an
external operator installation.

The owner's policy has these exact ordered JSON fields:

```text
version: 1
hostIdentitySha256, ledgerIdSha256, manifestSha256: 64 lowercase hex
manifestFile: root-owned regular 0600 file holding the exact manifest bytes
sourceSha: approved 40 lowercase hex Git SHA
ledgerDirectory: root-owned 0700 directory with ledger.json (0600)
activationCheckpointFile: root-owned 0600 canonical JSON snapshot
activationAttemptId: 32 lowercase hex
expectedSequence: independently approved predecessor sequence
expectedHeadSha: 40 lowercase hex
expectedReceiptSha256: 64 lowercase hex
ownerPublicKeyPem, ownerPinSha256: owner Ed25519 public key and SPKI pin
witnessPublicKeyPem, witnessPinSha256: witness Ed25519 public key and SPKI pin
floorPublicKeyPem, floorPinSha256: distinct external custodian Ed25519 public key and SPKI pin
```

The proof package must contain exact, independently signed CAS request and
receipt, a fresh signed witness HEAD, and a challenge-bound external floor
acknowledgement with phase `after` and `ack=confirmed`. The bridge checks the
floor key differs from both owner and witness keys, verifies cryptographic
proofs with the **installed** pins, cross-checks the transition digest against
`offlineWitnessLedgerTransitionDigest(ledgerRequest)`, and reads real pinned
manifest, ledger and activation-checkpoint files. It requires an owner-signed
first `fence-writers` stage approval with the matching manifest, host identity,
attempt ID, sequence and previous checkpoint digest. It rechecks host files
immediately before writing an exclusive fsynced receipt-scoped intent.

The intent permanently blocks replay of that receipt on this host. A failed
operation after remote CAS and before intent, an interrupted write, or an
ambiguous network acknowledgement **requires owner reconciliation**; neither
client nor bridge retries or resets state. The bridge cannot prove that an
externally signed floor was delivered by a physically independent service;
actual separately operated custody, certificates, authenticated transport,
root policy and immutable independent sequence history must be owner-installed
and confirmed. The caller also needs an independently authenticated host
identity measurement and real host service fencing. Later activation stages
require their own durable journal and independently authorized use points;
this bridge covers the initial release entry only.

The production backup/migration/writer-fencing mechanisms already implemented
in `scripts/production-server.sh` are to be reused by a future owner-installed
supervisor; this bridge does not duplicate them. It also cannot authorize
source SHA `c3ea768` or draft stage17/18 code under the hosted main-only
release policy. Every result retains `ledgerAttemptAuthorized:false`,
`witnessCasAuthorized:false`, `dockerLoadAuthorized:false` and
`deployAuthorized:false`.

The adversarial WSL-root fixture is run with:

```bash
VIRKI_DISPOSABLE_WITNESS_BRIDGE=1 node --test infra/offline/host-witness-ledger-activation-bridge.test.mjs
```
