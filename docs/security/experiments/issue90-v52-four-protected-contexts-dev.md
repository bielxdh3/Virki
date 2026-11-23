# Issue #90 V52: four genuine protected C1 publications → one V3 TEST scope (DEV ONLY)

## Exact result

V52 executes **four** independent V50 authenticated Linux SCM_RIGHTS
hand-offs, V40 one-time signed synthetic **V15 TEST-domain** permit claims,
V36 root-owned protected publications, physical stream measurements and
`Manager.ContextConsumed` calls **inside one preexisting V3-shaped
TEST-only SolveScope**. It returns the canonical four `CausalInputs`
only after remeasuring all four V36 destination directories.

The physical root test uses **four separate nonroot UIDs and processes**,
60020–60023, distinct process credentials, sockets, receiver-owned source
directories, V15 nonces, approvals, FileSync sessions, V36 destinations
and data. The V40 ledger and its root-only independent trust checkpoint
are shared, so all four individual claims are durable and replay-proof.

The group preclaim requires **pairwise-distinct sender UIDs as well as
PIDs**. A negative-control test launches four live processes with distinct
PIDs but the same UID `60020`; V52 must reject that group before creating
the group fence, consuming any V40 permit or publishing any V36 context.
A second negative control lies in the caller-supplied `SenderUID` fields,
claiming four distinct UIDs for those same-UID processes; kernel
SO_PEERCRED authentication must reject the lie before any fence or claim.

V15 has no per-`ApprovalID` revocation list. The durable V40 mechanism
provides epoch-floor revocation: each claim reloads the authenticated
checkpoint under the exclusive ledger lock, and a previously advanced floor
rejects lower-epoch permits. A V52 regression advances the floor to epoch 8
after all four group preclaims but before the first V52 claim; the epoch-7
group is rejected with no V36 publication, no V52 permit consumption and a
durable FENCED marker. This is epoch-wide revocation, not individual permit
revocation or a production owner-revocation authority.

**THIS IS NOT A COMPLETE C4 CANDIDATE OR OWNER APPROVAL.** The test owner
service is a deliberately nonauthorizing `localcontext.Service` double:
its independently precomputed per-context tree commitments are handed
to the real `Manager.BeginSolve`, but it does **not** sign a V3 approval
and always refuses `Complete`. Do not represent its test
`ApprovalEnvelope` as an actual Ed25519 owner grant. No solver vertices
or snapshots are independently observed by V52: those IDs in the V52
test are fixtures. No actual OCI DAG/root or C4 candidate is created.
Production owner signing, release, deploy and C4 cutover remain forbidden.
The native C4 V3 receiver still has its separate existing test suite.

## Code and authority boundary

V52 is an **additive** BuildKit patch applied after original V51 **and V51R**, only
compiled on Linux with `-tags virki_c1c4_dev` for the coordinator,
TEST gates and tests. It adds
`session/filesync/PublishV52DevFourProtectedContexts`, an additive
`SolveScope` pending-group field (default false in normal builds)
and DEV-tagged `DevV52*` Manager helper methods. The group never calls
`scope.Complete`, never signs, never exports and never deploys.

Before spending the FIRST V40 permit, the coordinator independently
checks:

- Same preapproved fresh Manager/SolveScope binding, generation and worker
  across all four contexts, with four owner TEST-side session IDs and tree
  digests. Rejects any previously consumed partial scope.
- The canonical four required context names in protocol order, unique
  V15 permit approval IDs, nonces, sessions, sender PIDs, sender UIDs and
  destinations.
- Four distinct cryptographically valid signed **V15 test-domain**
  permits (not V3 signatures), frozen V15 manifests and canonical paths.
- All four live senders' kernel SO_PEERCRED/PID/UID/GID *before* claiming
  any permit; sender UIDs and PIDs must both be pairwise distinct. V50 again
  checks SCM_CREDENTIALS on each actual FD message.

A root:root 0700 separately provisioned fence directory contains an
O_EXCL, O_NOFOLLOW, root-owned single-link 0600 group status file pinned
by descriptor. `PENDING` is synced **before the first V40 claim**.
The file is never deleted by the coordinator. A crash, EIO or replay
cannot open it again as a new attempt. Each successful V51 call spends
its V40 permit before publishing, pins the root-owned inode, verifies
manifest membership and creates the canonical physical stream, then
calls the **same** Manager's `ContextConsumed`.

The `SolveScope` is gated from the first publication until the group
completes: external `CausalInputs` and `Complete` are both refused
even **after** the fourth `ContextConsumed` but before recheck/fsync.
An exclusive nonzero-sized opaque capability is returned only to the
one trusted coordinator; an arbitrary caller holding ctx/scope/Manager
cannot re-acquire that capability or mark the group READY. This is a
Go in-process API ownership boundary, **not** protection from an
arbitrary malicious goroutine with unsafe memory access or compromised
root. On success the coordinator calls a capability-gated internal
four-context reader, remeasures all protected destinations, compares
every tree/stream byte to Manager evidence, fsyncs an inert
`FOUR_CONTEXTS_READY_DEV_NOT_OWNER_AUTHORIZED` marker and *then*
lifts the external group gate.

On **any** failed inter-publication step, source contamination, stale
scope, canceled context, tampered protected output, V40 rollback or
ambiguous fsync, V52 marks `FENCED_DEV_NO_CANDIDATE`, attempts
`scope.Abort` under a bounded, uncanceled context and returns no
observations. If the process is abruptly terminated, the earlier
`PENDING` marker remains and the process-scoped V3 TEST authorization
cannot be resumed. V40 permits already claimed remain consumed, and
earlier verified root-owned outputs remain inert. V52 does **not**
automatically roll back root-owned file publications or restore
V40 trust anchors: such a rollback could violate durability.

V52 independently rejects a missing scope (`context.Background()`)
and a `Manager` configured with `required=false` before the first
V40 claim. It does not fix the separately exported standalone V51
API's preclaim/optional-Manager P2 findings. Those require a separate
additive V51R patch before the V52 commit can be integrated or deployed.

The opaque in-process capability is cooperative DEV sequencing, **not**
proof against arbitrary trusted same-process Go/root code. Code able
to create its own TEST Manager, synthesize all four `ContextConsumed`
records and call DEV helper methods can reach an artificial READY
state without V40, the FD broker or protected V36 roots. The real
V52 root supervisor's entrypoint requires those physical operations;
there is no untrusted network endpoint to the helper methods. Neither
path proves an owner-signed V3 approval, a real OCI solve or release.

There is no automatic group recovery or production release path.

## Frozen replay inputs and additive SHA

- Upstream BuildKit:
  `f5b59a1f2fb25a0cb7072c398cab9aed7835da4e`
- V23–V50 tree:
  `6d2225efbfd67865e08a726678b1a13361441eb5` (28 patches unchanged)
- Frozen V51 tree:
  `b0b1507f6edd67f232728046263dda4fe8f4529e`
- V51R preclaim patch SHA-256:
  `86825e203a417970a2895c54201e28d18498ab53613d4abb07e90a377c3c15ce`
- V51R tree (before V52):
  `bbf1938fe2ab81f7d1ca96d52d0e382bb5154dc9`
- **Canonical additive V52 patch, after V51R**:
  `infra/offline/patches/buildkit-v0.34.1-c1-v51r-to-v52-four-protected-dev.patch`
- Canonical V52 patch SHA-256:
  `a348f5edb2eacde213932fb7b74b9ca7f478be2cd332a5b140ea7dd81d6d1104`
- Replayed canonical V51R+V52 Git tree:
  `5b2a745318a884d182c0e7a06fa49b627baa4455`.
- Retained pre-rebase V52 DEV source patch:
  `infra/offline/patches/buildkit-v0.34.1-c1-v51-to-v52-four-protected-dev.patch`
  with original patch SHA-256:
  `d3b2dcc83ea2e715ab41554b87a0b02536d47ae68bb2eb8be6845e3452a21030`
  and old V51-direct tree `009e67ba1dbba47c58cf12ba9afdac7e86c81a6f`.
  This reference patch is **not applied by the final CI**.

The CI workflow separately verifies V51 and V51R plus their tests **before**
applying the canonical V52 patch, then independently verifies its SHA-256/tree.
The initial direct replay of the two independent worker patches exposed a
real **RED**: V51R's standalone preflight required each signed V15 nonce
to equal the shared V3 generation, whereas V52 correctly has four distinct
signed V15 TEST nonces under one V3 TEST scope. No V40 claim passed the
preflight during this failed composition. The rebased V52 patch adds a
DEV-only exception **only while the scope is already group-pending**, with
the record's generation required to equal the authorized V3 generation.
Outside that pending gate, a mismatched V15 nonce continues to fail before
claim. A dedicated Manager regression, the 20-subtest root/race V52 suite
and V51R's standalone P2 regressions now pass **GREEN**.
This does not relax normal/prod builds or prove owner authorization.
The new privileged Linux suite is mandatory without SKIP and runs
from a disposable /var/tmp destination with real process UIDs.
No historical patch, cumulative Git tree, original V51 patch or
owner-signing capability was modified.

## Executed verification

- `VIRKI_V52_RUN_ROOT_FIXTURE=1 go test -race -mod=vendor
  -tags virki_c1c4_dev -count=1 ./session/filesync
  -run TestC1V52FourProtectedContextsOneSolve`: **PASS**,
  20 subtests using Linux WSL root plus real nonroot UIDs:
  four-context acceptance; external candidate/causal gate before fsync;
  faults before/after first, second, third and fourth;
  canceled context after second and **after fourth before READY**;
  independent checkpoint rollback after first;
  post-admission tamper before final remeasurement;
  duplicate signed permit; unscoped `context.Background()` and
  optional `Manager` (both rejected preclaim without consuming any
  permit); wrong fourth sender UID; preexisting
  interrupted PENDING; and genuine `os.Exit(77)` of the **root
  supervisor after first V40+V36 publication** with durable one-row
  ledger, protected first output and non-replayable PENDING marker.
- **RED→GREEN sender-UID isolation:** four real processes with distinct
  PIDs but shared UID `60020` were accepted by the earlier V52 patch,
  consuming four V40 permits and reaching `READY`. The retained regression
  now requires rejection during preclaim; after the fix it verifies zero
  V40 claims, no group fence and no V36 publication. A companion spoofing
  regression gives those same-UID processes distinct declared UID fields;
  kernel SO_PEERCRED rejects the false identity before any claim or fence.
- **Epoch-floor revocation after preclaim:** a separately signed epoch-8
  permit advances the durable V40 floor after V52 has authenticated all four
  epoch-7 publishers but before the first group claim. The stale V52 permit is
  rejected at the irreversible V40 boundary; no context is published, the
  only ledger row is the epoch-advance claim, the group is FENCED and the
  TEST scope is aborted. Individual ApprovalID revocation is not implemented.
- Behavioral **RED→GREEN** for premature C4 candidate exposure:
  removing the V52 `Complete` pending guard caused the fourth-context
  test to **FAIL**. Restoring it byte-for-byte passed with `-race`.
  A second RED PoC called the then-public `MarkFourReady` early
  after context four and incorrectly obtained `CausalInputs` before
  the READY fsync. The opaque one-use coordinator capability prevents
  that PoC, with explicit negative tests passing. The deterministic
  cancellation-after-fourth case also failed (returning four records
  without error) until context cancellation checks were added before
  revalidation, before/after READY and inside the gated scope methods.
- **RED→GREEN stream alias regression:** after four real root-owned
  publications, mutating a returned `CausalInputs()[0].StreamBytes`
  previously corrupted the Manager's next result. Bounded
  (`<=64 MiB`), length/hash-checked `bytes.Clone` on
  `ContextConsumed` storage and cloned output from both
  `CausalInputs` and `Complete` fixed the contamination. A
  separate nonauthorizing TEST scope re-consumes the already real
  protected streams; modifying the original input buffers after
  `ContextConsumed` must not corrupt its private records. Disabling
  only that input clone reproduced a behavioral RED
  (`Manager stored caller-mutated source buffer for 0`); restoring
  byte-for-byte passed the full root suite with `-race`.
- Native V3 Manager-to-C4 independent daemon `go test -race`: **PASS**
  for both DEV test-key `CANDIDATE_VERIFIED` and normal
  `SIGNING_DISABLED` behavior; **this is separate from V52's new
  protected four-context path**.
- V51 real root sender and V52 tests with `-race`: **PASS**.
- Normal (without DEV tag) Linux `filesync`, `localcontext`,
  `source/local`, `solver/llbsolver`, `cmd/buildkitd/config`
  and `cmd/buildkitd`: **compile PASS**.
- `go vet -mod=vendor -tags virki_c1c4_dev ./session/filesync
  ./util/localcontext ./cmd/buildkitd/config ./cmd/buildkitd`:
  **PASS**. Previously observed upstream `lostcancel` warnings
  in source/local and solver are outside this focused vet gate; no
  tests or gates were weakened.

## Next required interface for true issue #90 closure

Replace the isolated V52 TEST owner double with a real, separately
signed V3 TEST-domain approval and admitted native C4 scope; bind
four protected FileSync V24 sessions and root-custody receipts to
actual BuildKit committed snapshots, solver ancestry and OCI
exported content, then require a request-bound native C4 candidate
receipt. Independent production owner/key custody, rollout and
signing policy are still out of scope. **V52 READY is not a C4
candidate, release token or owner admission**.
