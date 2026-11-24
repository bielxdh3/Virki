# Issue #90 — V41 DEV-only: authenticate peer before consuming an owner permit

V41 is a strictly incremental hardening of the **unwired, synthetic** C1/C4 broker. V23–V40 patches and their checksums/trees are immutable. The V39 unauthenticated claim-history P2 was already superseded by V40: authenticated HMAC-linked claim records, a separately provisioned root-owned key/checkpoint, durable in-flight marker, and strict fail-closed recovery. V41 does not alter this replay/rollback model.

## Refusal before irreversible consumption

Before V41, `publishV39FromAuthorizedTestPeer` durably consumed a valid signed test permit **before** its V37 receiver checked `SO_PEERCRED`. A wrong process could therefore cause a non-retryable permit burn by reaching the already-accepted Unix socket without ever presenting an authorized source descriptor. This is a denial-of-service condition, not an unauthorized publication.

V41 checks the accepted socket's kernel-reported PID/UID/GID against the trusted supervisor's expected nonroot process identity **before** writing a V40 claim or consuming any socket bytes/SCM_RIGHTS. A mismatched/invalid peer is refused with no ledger mutation or publication. The V37 receiver **still reauthenticates** before reading the one-FD handoff and after receipt. A successfully authenticated peer must additionally present a correctly signed, policy-scoped V15 **test-domain** permit; identity alone never grants publication. After the ledger is committed, a later handoff or publication error still consumes the permit, as required for conservative replay safety.

New privileged regression: a real nonroot child connects and queues one SCM_RIGHTS directory FD. A first attempt with the **wrong supervisor-pinned PID** must fail without admitting the descriptor or consuming the signed permit; a second attempt on the **same connection and permit** using the correct PID must publish the verified root-owned copy. An invalid socket handle is also denied before a signed permit claim. This fixture preserves the `/var/tmp` root-mount path and the existing `RESOLVE_NO_XDEV` protections. Existing V40 valid-hex corruption, intermediate tamper, truncation, checkpoint/log rollback, restart, concurrent claims, and injected `fsync` tests remain unchanged.

## Limits and authorization

V41 is an additional denial-of-service hardening, **not** a C4 implementation, production receiver, anti-root-rollback guarantee, deployment, release decision or merge authorization. Neither V40 nor V41 makes the same-root HMAC key/checkpoint monotonic against a fully compromised root. The actual owner-signed monotonic C4 authority, operational UID/mount/supervisor attestation, recovery operator and production rollout remain separate owner-controlled gates; protected production C1/C4 is **NO-GO**. Neither issue #90 nor #119 should be administratively closed based on this DEV-only evidence.
