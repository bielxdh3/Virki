# Issue #90: C1→C4 DEV authorization-state ambiguous-fsync fence

**Scope:** the non-authorizing Node C1→C4 integration candidate in
`infra/offline/c1-c4-integration/c1-c4-contract.mjs`. This is **not** the
independent Linux BuildKit V40/V50 ledger, a native owner C4 release signature,
or a trusted production witness. Production publication and signing remain off.

## Reproduced failure before correction (RED)

Inject a recoverable `EIO` into the parent-directory `fsyncSync` immediately
after the atomic state `renameSync`. The caller gets an error but the renamed
state already contains the first `PREPARED` record. The old implementation did
not retain a durable in-flight marker, so another valid `PREPARED` could be
appended immediately without reconciliation:

```text
error: INJECTED_FINAL_PARENT_FSYNC_EIO
afterFault: 1
postFailureSecondMutationAllowed: true
```

An automated pre-fix test subsequently failed because `state.json.pending` was
absent after the injected `EIO`; legitimate ordinary writes were a positive
control. This is a DEV durability ambiguity, **not** evidence of an exposed
production release path.

## Correction and independent test seams (GREEN)

The writer now creates a private, exclusive `.pending` intent and synchronizes
both the file and parent directory **before** changing the state. It writes the
temporary state, synchronizes the file, renames and synchronizes the parent,
then removes the intent and synchronizes the parent again. Failed writes,
post-rename sync errors and abruptly terminated writers leave a marker that
blocks **all reads, DEV evaluations and subsequent mutations**, including an
otherwise valid different nonce. When removal of the final marker is followed
by a recoverable `fsync` failure, the implementation recreates and synchronizes
the marker instead of treating the ambiguous state as committed. Failure to
restore that marker is itself reported as an unresolvable durability error;
it is never silently counted as a successful commit.

`c1-c4-fsync-fault.test.mjs` covers real `fsyncSync` fault injection after
rename, after final marker removal, abrupt process exit with intent persisted,
refusal of dangling/substituted intent markers, and ordinary successful
multi-transition behavior. The independent Linux fixture is disposable; the
real CI script `npm run test:offline:c1-c4-integration` includes these tests
alongside the existing native daemon boundary suite. No SKIP, production
authority, test-policy relaxation, merge, deploy, or patch-history rewrite is
needed.

## Acceptance boundary

A pending marker is deliberately **not** automatically clearable through the
DEV API: unconditionally retrying or advancing the epoch could conceal a
committed-but-unacknowledged transition. Reconciliation requires an independent
trusted authority/witness and investigation of the actual storage state;
the same-UID synthetic history and same-directory marker cannot defend
against a privileged rollback of both. The existing `verifyAntiRollbackWitness`
still requires an externally trustworthy input. This correction must **never**
be promoted as actual owner C4 release approval or monotonic external custody.
