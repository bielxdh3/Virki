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
