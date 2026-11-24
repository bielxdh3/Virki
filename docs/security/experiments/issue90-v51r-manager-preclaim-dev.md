# Issue #90 V51R — owner-scope preclaim gate (DEV only)

## Exact amendment

V51R is a **separate additive patch** applied strictly **after** the
historical 28 V23–V50 patches and the original V51 patch. Neither original
patch bytes nor their expected Git trees change.

| Stage | SHA-256 / exact Git tree |
| --- | --- |
| Frozen V50 Git tree | `6d2225efbfd67865e08a726678b1a13361441eb5` |
| Frozen V51 patch SHA-256 | `c7bf1193a8f3e9d1e83d7cef3600b7a1fca118866a6fa804635bbb0eaf0600d3` |
| Frozen V51 Git tree | `b0b1507f6edd67f232728046263dda4fe8f4529e` |
| New V51R patch | `infra/offline/patches/buildkit-v0.34.1-c1-v51-to-v51r-preclaim-dev.patch` |
| V51R patch SHA-256 | `86825e203a417970a2895c54201e28d18498ab53613d4abb07e90a377c3c15ce` |
| V51R Git tree | `bbf1938fe2ab81f7d1ca96d52d0e382bb5154dc9` |

V51R adds `Manager.DevV51Preflight`, present **only** on
`linux && virki_c1c4_dev`, and calls it from
`PublishV51DevContextToV3` **before** any V40 one-use durable claim or V36
root-owned publication. The preflight does not invoke `Service.Begin`,
`ContextConsumed`, `Service.Complete`, `Service.Abort`, a ledger write, or a
filesystem operation. It only reads the private, already-authorized,
mutex-protected solve state.

It refuses an optional Manager, missing/foreign solve context, expired or
terminating scope, duplicate admission, mismatched V15 manifest nonce/V3
generation, worker/context/session, owner-pinned identity/tree and malformed
source vertex/snapshot metadata. A separate
`Manager.ContextConsumed` check **still** runs after measuring the root-owned
copy. This second check is necessary: a concurrent abort, expiry, or other
state change between preflight and admission is not made impossible by a
read-only preflight.

## Reproduced RED → GREEN

The two security tests use an actual distinct-UID Linux source sender with
kernel `SCM_CREDENTIALS` + `SCM_RIGHTS`, V40 ledger and root-owned V36
destination under an explicitly disposable Linux/root fixture.

1. `TestC1V51RRequiresScopeBeforeClaim`: with a mandatory Manager but
   `context.Background()` (no V3 scope), **original V51** refused only
   *after* burning a one-time V40 permit (136-byte claim record) and creating
   the protected destination. **V51R** refuses before either side effect:
   empty ledger, absent destination.
2. `TestC1V51RRefusesOptionalManagerWithoutScope`: with an optional
   Manager and the same unscoped context, **original V51** returned **nil**
   (false success) after burning a permit and publishing. **V51R** returns
   an error, with no ledger entries and no destination.

The original positive
`TestC1V51RealProtectedPublisherFeedsV3Manager` still admits one protected
context, rejects duplicate admission and refuses replay. Separate Manager
unit tests exercise missing/wrong scope, optional Manager, expired/closed/
aborting scope, generation, context/worker/session/tree mismatches, malformed
source metadata and **no mutation** by preflight. The CI root fixture
explicitly runs all three tests with `-race` and treats **any SKIP** as a
failure. CI also pins the V51R SHA-256 and resulting Git tree, and requires
tagged `go vet`.

## Limits: no release authorization

This is a **single-context DEV composition**, not a complete four-context
C1→C4 solve. V15 uses a **synthetic C1 test-domain permit**, not a signed
V3 owner approval. The V51 fixture's Manager uses a non-signing test double.
V51R does **not** independently prove solver vertex/snapshot provenance,
create an OCI DAG, emit a signed candidate receipt, authorize production,
or sign/deploy a release. The independently controlled real V3 owner approval,
four committed context streams, full solver/OCI evidence, C4 signing
authority and crash-fenced grouped solve remain separate future gates.
