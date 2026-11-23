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

The hosted CodeQL run on `d7b25a7` found a new `js/file-system-race` in the
initial recovery implementation: following an unlink of the fixed `.pending`
name, a later `openSync` on that same name could race a same-UID replacement.
A new RED fixture installs a **dangling symlink** after marker removal and
before the injected parent fsync failure; the old recovery could not restore
a regular marker (5 pass / 1 fail in the focused six-test baseline suite).
The correction creates a fresh random, exclusive `.pending.restore.<nonce>`
inode, fsyncs it, atomically renames it over the fixed marker pathname, and
fsyncs the parent. This avoids check-then-reopen on the attacked name while
preserving fail-closed behavior. The new fixture is GREEN after correction.

The same ambiguity also existed in **initial genesis state creation**: an
injected `EIO` at its first parent-directory fsync returned failure while an
otherwise valid genesis JSON was already readable and accepted subsequent
`PREPARED` transitions without a reconciliation fence. Its disposable PoC
printed `fired=true, error=GENESIS_FINAL_PARENT_FSYNC_EIO, loaded=true,
appended=true, pending=false`. Two new automated Linux tests reproduced RED
(7/9 passed) for first and final parent syncs. `initAnchoredAuthState` now
exclusively reserves an initially empty state file, durably creates the same
`.pending` intent **before writing any valid JSON**, and completes the intent
using the same shared atomic recovery routine as later transitions. If a crash
occurs before that marker exists, the reserved file is still empty and cannot
pass the canonical JSON verifier; a second initializer still cannot overwrite
an already valid state. Linux focused fault injection and integration suite
finished GREEN (18/18, zero SKIPs) including real native C4 deny-by-default.

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
