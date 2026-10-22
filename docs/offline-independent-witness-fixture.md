# Disposable independent witness CAS experiment

`scripts/offline-independent-witness-server.mjs` implements an isolated Linux
UNIX-socket witness. It is deliberately excluded from release authorization.
The existing `offline-ledger-witness-proof.mjs` remains an independent **read
proof only** and has not been reinterpreted as a CAS signer or deploy gate.

The external fixture operator provisions an Ed25519 private key (regular file,
mode 0600), a separately known SHA-256 pin of its SPKI DER public key, and
distinct private (0700) directories for SQLite storage, append-only receipt
anchors, and the UNIX socket. All must reside outside the Git repository.
The operator must additionally pin a **different** Ed25519 owner public key
(`VIRKI_WITNESS_OWNER_PUBLIC_KEY`, `VIRKI_WITNESS_OWNER_PUBLIC_PIN`). Its private
key never belongs to the witness process, its filesystem, or this repository.
Every CAS proposal needs an owner signature over a domain-separated canonical
full request including challenge, request ID, predecessor sequence/head/receipt,
next head, transition digest, host/ledger identity and a bounded 30-second
expiry. An unauthenticated same-UID client of the test socket cannot advance
the head using merely the previous signed read. This is a fixture proof of
signature enforcement, not a provisioned external owner authority.
The process requires `VIRKI_DISPOSABLE_WITNESS_SERVICE=1`, native Linux,
and explicitly configured `VIRKI_WITNESS_{DB_DIRECTORY,ANCHOR_DIRECTORY,
SIGNER_KEY,SIGNER_PIN,OWNER_PUBLIC_KEY,OWNER_PUBLIC_PIN,SOCKET,HOST_SHA256,LEDGER_SHA256}`. The key must remain
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

To avoid a partially created authoritative receipt file, the fixture writes
and fsyncs each proposed anchor in a private `.staging` directory and publishes
the completed bytes by atomic no-replace hard link. A crash during staging
leaves only ignored, non-authorizing scratch data; a later independently signed
SQLite replay can reconstruct the missing anchored suffix. A writer-reserving
SQLite transaction protects each head read from concurrent CAS commits and
anchor publication races; this is still not multi-host monotonic authority.

Every response explicitly contains
`witnessCasAuthorized:false`, `dockerLoadAuthorized:false`, and
`deployAuthorized:false`. This protocol is not wired to the offline release
coordinator and cannot grant production, Docker, or release permissions.
