# Disposable independent witness CAS experiment

`scripts/offline-independent-witness-server.mjs` implements an isolated Linux
UNIX-socket witness. It is deliberately excluded from release authorization.
The existing `offline-ledger-witness-proof.mjs` remains an independent **read
proof only** and has not been reinterpreted as a CAS signer or deploy gate.

The external fixture operator provisions an Ed25519 private key (regular file,
mode 0600), a separately known SHA-256 pin of its SPKI DER public key, and
distinct private (0700) directories for SQLite storage, append-only receipt
anchors, and the UNIX socket. All must reside outside the Git repository.
The process requires `VIRKI_DISPOSABLE_WITNESS_SERVICE=1`, native Linux,
and explicitly configured `VIRKI_WITNESS_{DB_DIRECTORY,ANCHOR_DIRECTORY,
SIGNER_KEY,SIGNER_PIN,SOCKET,HOST_SHA256,LEDGER_SHA256}`. The key must remain
under the operator's control; do not copy keys into Git.

`POST /v1/cas` uses canonical JSON with version/domain, fresh 32-byte hex
challenge, unique 32-byte hex request ID, pinned host+ledger identities, exact
expected sequence/head/previous receipt digest, proposed next head and SHA-256
transition digest. SQLite `BEGIN IMMEDIATE` serializes competing CAS operations,
with WAL and FULL sync. On success, the service signs a 30-second Ed25519
challenge receipt, commits the record, writes a separate fsynced receipt anchor,
and returns HTTP 201. Stale or replayed transitions return 409. A process
crash after database commit but before anchoring is recovered by verifying the
signed SQL history and completing only the missing anchor suffix. Existing
anchors are never silently removed or overwritten. `POST /v1/head` signs a
fresh, challenge-bound view of the latest committed head; clients must verify
the signature, pin, challenge, freshness and independently held minimum head.

The database and anchor directories are on the same disposable Linux test
machine. In-place data corruption, rollback of *only* the SQLite database,
head forks, duplicate nonce IDs, and mismatched host/ledger identities are
rejected. A privileged adversary able to restore **both** data stores and
the signer or impersonate the operator can still roll back the service. WAL
`FULL` cannot guarantee persistence across arbitrary hardware failure or
untrusted storage stacks. Genuine operator independence, hardened key custody,
independent monotonic checkpoint storage, mTLS network transport, remote
authentication, and production service availability remain unproven. A single
UNIX socket in a test namespace is not a production witness.

Every response explicitly contains
`witnessCasAuthorized:false`, `dockerLoadAuthorized:false`, and
`deployAuthorized:false`. This protocol is not wired to the offline release
coordinator and cannot grant production, Docker, or release permissions.

## Disposable ledger-reservation CAS composition (not production wiring)

`infra/offline/disposable-witness-ledger-reservation.mjs` adds a **test-only**
composition of the existing pure ledger transition and witness verification.
It requires `VIRKI_DISPOSABLE_WITNESS_SERVICE=1` on Linux, a separately supplied
owner-signed CAS request, pinned Ed25519 witness and owner public keys, explicit
host/ledger scope, and a checkpoint held **outside the ledger**. Its CAS
`transitionSha256` is `SHA256("VIRKI_OFFLINE_WITNESS_LEDGER_RESERVATION_V1" +
NUL + canonical JSON of the entire reservation request)`, including ledger
directory, accepted manifest digest, predecessor/next SHA, nonce, sequence and
owner approval digest. The test bridge validates a fresh signed HEAD against
the external checkpoint, matches it with the ledger predecessor, verifies the
independently signed CAS receipt, then calls a separately provided reservation
function with an immutable exact request. It cannot issue owner approvals or
sign witness receipts. No signer or fake production trust key is embedded.

Witness CAS and ledger `O_EXCL` reservation are **not an atomic transaction**.
If power fails after CAS or the witness reply is lost, the witness has advanced
but the ledger reservation may not exist. The same transition MUST NOT be
automatically retried, its checkpoint silently reset, or its witness state
rewound. Independent operator recovery and monotonic checkpoint update must
precede any next attempt. The current code explicitly refuses such replay.

This bridge does **not** modify `trusted-release-coordinator.mjs`, enable an
installed host entrypoint, transport a release, or authorize any deployment.
It intentionally accepts in-process callbacks only in a disposable fixture:
callbacks and caller-supplied pins are **not authenticated production remote
trust**. Before any actual coordinator integration, the owner must independently
provision a witness service on a distinct trust domain, secure signing-key
custody, authenticated mutually pinned network transport, independently durable
monotonic checkpoints, a read-only/recovery reconciliation policy for ambiguous
CAS outcomes, and a separately reviewed native installed entrypoint. Existing
local SQLite+anchor rollback caveats still apply. Production remains NO-GO.

## Mutually authenticated remote-session and checkpoint experiment

`infra/offline/disposable-remote-witness-session.mjs` exercises a **real TLS
client/server transport** around the existing signed HEAD and CAS protocol
without contacting a production or external network. Its sole executable
surface is limited to Linux, `VIRKI_DISPOSABLE_REMOTE_WITNESS=1`, a private
operator-created `/tmp/virki-witness-transport-fixture-XXXXXX/checkpoint`
directory and `localhost`. No deployed endpoint, pin or private key is
selected by this repository and there is no coordinator import.

The fixture operator provisions an owner key pin separately in a private
`owner-root-pin.json`, then the owner signs a canonical, domain-separated
consent binding the exact localhost endpoint/port, TLS server certificate SPKI
SHA-256, client certificate SPKI SHA-256, witness signing-key pin, owner
signing-key pin, Virki host and ledger identities, one specific owner-signed
CAS request digest, initial checkpoint digest and expiration. The TLS client
supplies an actual client certificate to a server that requires mutual TLS.
Every connection checks the peer X.509 leaf certificate's DNS name, validity
and consented SPKI pin **before sending any protocol bytes**. The signed HEAD
must match a fresh client-generated challenge and the local checkpoint's
sequence/head/receipt. The owner-signed CAS transition then requires a
separately signed witness receipt for the exact request.

The private checkpoint directory is opened once with `O_NOFOLLOW` and held
by an inode-bound descriptor throughout both TLS exchanges. Subsequent
reads/writes use the Linux `/proc/self/fd/N` anchor rather than reopening a
replaceable pathname. The canonical directory inode, owner and mode are
rechecked on HEAD return, immediately before CAS protocol bytes leave the TLS
connection, after CAS and after persistence. A rename/swap of the checkpoint
directory after HEAD cannot silently redirect an intention or permit CAS.
Signed owner consent and CAS expiration are checked again after HEAD and
immediately before CAS egress; a delayed valid HEAD cannot revive expired
authorization. Keys, certificates and consent bytes are captured before awaits
to prevent caller-side rebinding.

Before CAS egress, a private `000000NN.intent` file is created with
`O_EXCL`, fsynced, and followed by a directory fsync. A successful response
produces a new exclusively created fsynced checkpoint containing its signed
receipt, the exact canonical owner-signed consent plus Ed25519 signature, the
durable original intent SHA-256 and predecessor digest, then an exclusive
completion marker. Every historical checkpoint validates the original owner's
consent signature against the separately pinned owner key, reconstructs
the exact owner-signed CAS request from its authenticated witness receipt,
and compares **both** original consent and CAS request hashes to the recorded
intent. Changing those two hashes in an otherwise canonical, private regular
intent file is now detected and rejected before any new HEAD/CAS exchange.
The complete signed history is additionally rechecked after the asynchronous
HEAD response and immediately before CAS bytes leave the authenticated TLS
socket. During the pending CAS the expected new intent digest is admitted only
as an unreconciled in-flight journal entry; completed checkpoints must still
match every original signed consent and owner CAS. An adversary modifying an
earlier intent while HEAD is in progress cannot advance the next sequence.
A partial
response, dropped connection, timeout, crash or failed fsync leaves an
incomplete intent and blocks subsequent attempts, even if the remote witness
committed. Existing checkpoints and signatures are checked before advancing.
The protocol never retries a CAS automatically. Tests exercise actual TLS
handshake/peer substitution, signed consent tampering, forged HEAD, replay, two
consecutive checkpoints, incomplete completion and lost/truncated/surplus
replies after a real disposable witness SQLite commit, path swaps during and
after CAS, historical-intent substitution and consent expiry during delayed
HEAD. Test keys/certificates
exist only in private temporary directories and are never release trust roots.

**Production limits:** the `localhost` consent and root-pin file are created
by a disposable test operator, not an independently provisioned native owner.
The witness service runs on the same test machine. Private local checkpoint
files and fsync provide crash evidence, but a privileged actor who restores
the entire checkpoint store to a previous valid prefix can still cause
rollback. An independently held, nonrollbackable monotonic checkpoint is
mandatory. No actual remote witness TLS host, CA, key custody or mutual TLS
deployment has been established. A separately audited native launcher,
operator reconciliation and coordinator integration remain blockers.
Every successful experiment reports `witnessCasAuthorized:false`,
`dockerLoadAuthorized:false` and `deployAuthorized:false`.

Independent owner provisioning for production would need a root-protected
owner public key/pin and revocation policy; a separately operated external
witness hostname with pinned TLS certificate/SPKI, isolated mTLS client
certificate and private key, and separately held witness Ed25519 signer key;
host/ledger/transition-scoped signed owner consent; a remote monotonically
durable checkpoint outside the witness database's rollback domain; a signed
read-only reconciliation procedure for ambiguous commits; independently
reviewed native launcher and isolation; and integration tests on the actual
owner-controlled host. **PRODUCTION NO-GO.**
