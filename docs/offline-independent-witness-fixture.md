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
