# PR #118: recovery restart / TOTP race — local evidence

**State:** Local-only security remediation, NOT production acceptance. The PR
remains OPEN/DRAFT; no merge, deployment, Cloudflare cutover, SMTP delivery, or
production operation is authorized by this record.

## Confirmed bug (parent d8f37671463bd9a38e454ea016150fdc76987582)

Two tabs shared the original browser-bound recovery cookies. The second tab
submitted another selected-recovery action before the first TOTP proof had
committed. The HTTP response to that request was deliberately held at the
browser boundary; then the first tab successfully committed its TOTP proof.
When delivered later, the already-generated second HTTP response overwrote
the original bearer pair with non-authorizing synthetic credentials.

This was reproduced with real Next Server Actions and disposable PostgreSQL.
The test restores original browser cookies after Playwright's `route.fetch()`
side effect, before verifying the TOTP, so that the observed failure comes
from the **late HTTP Set-Cookie delivery**, not a test-harness mutation.

RED evidence: isolated browser run
`d01ea07af27d488eb2dd8f3b75aa3235`, Chromium 153/Node 22, one
expected test failed on the original cookie value after TOTP proof succeeded;
Docker owner-identity cleanup verified, no mutation uncertainty.
**That runner used its default pinned PostgreSQL 17**, not PostgreSQL 18.

## Narrow mitigation

With any existing opaque request-key + browser-token pair, an anonymous
restart POST without an affirmative `confirmRecoveryRestart=yes` **never
issues replacement bearer cookies**, even if the previous pair has not yet
produced independent proof. It shows a generic confirmation stage instead.
The same visible consent gate applies to real unproven and synthetic requests.
An already proven recovery is retained by its independent server-side factor
binding even if the consent checkbox was submitted; the intent cookie is only
rendering metadata, not an authorization credential.

Consent is a **deliberate abandonment** mechanism: it can replace an unproven
capability, but not prevent a fully concurrent explicit abandonment from
deliberately discarding a proof subsequently obtained in another tab. This is
not a transactional coupling between browser Set-Cookie and PostgreSQL; it
requires the person to understand that confirmation may abandon the old flow.
Implicit restarts have no such authorization.

Tests include: actual overlapping Next POST + TOTP commitment + delayed
response; unchanged bearer cookie values and expiry; missing/foreign/wrong
intent, synthetic and real pre-proof retries; fresh legitimate retry with
explicit consent; older link GET/POST and explicit switch; CSRF and ADMIN
surface checks. Separate physical PostgreSQL 18 integration suites cover
strong-factor revocation/rotation, cross-role and reviewer authorization,
mailbox rebind, and one-winner replay.

### Follow-up: physical PostgreSQL 18 on Windows/Node 22

The private PG18 runner initially returned NO-GO despite integration suites
running because its exact-name gate requires TAP output but Node 22's Windows
test reporter defaulted to the human-readable spec format. The explicitly
admitted PG18 test environment now selects `--test-reporter=tap`; ordinary
integration runs remain unchanged. Focused runner contracts passed 13/13,
including negative checks for fake PASS/skip, child environment isolation,
owner identities and cleanup.

The follow-up local run of
`node scripts/integration/recovery-pg18-disposable.mjs` executed **5/5 named
ADMIN normal-password tests** and **4/4 named assisted-recovery tests** against
separate physically provisioned PostgreSQL 18 disposable databases. Output:
`PG18 RECOVERY REQUIRED GATE: 9 real PASS, 0 FAIL, 0 SKIP, both disposable
containers removed.` Log:
`.virki-mission-tmp/pr118-pg18-61f591c-tap-fixed.log`. This is a local
physical integration result, not hosted CI or external staging evidence.

## Additional fresh/fresh race and browser-origin serialization

Independent SOURCE NO-GO on `7ba895a` identified a distinct case: two tabs
both submit their **first** recovery form before receiving either bearer
cookie. The original server-side consent guard sees `hasOpaquePair=false`
twice. A genuine response can arrive and permit TOTP proof while the later
synthetic response still has a pending `Set-Cookie`, which can erase the
proven browser-bound pair without any explicit abandonment.

Physical RED `720c9cc1113f456b89eac424618805dd` used two genuine Next
Server Action POSTs and deliberately reordered their browser responses. The
first real POST's TOTP proof was committed before release of the second
synthetic response; the original bearer cookie was overwritten. Chromium
153/Node 22, disposable PostgreSQL 17, expected 1 FAIL, Docker ownership
cleanup verified with zero uncertainty. RED failures can contain random
**disposable test cookie** values; keep raw logs local/private.

The normal JavaScript recovery form now requires an exclusive per-origin
`navigator.locks` Web Lock before invoking the existing Server Action.
The lock includes the full asynchronous fetch and its `Set-Cookie` handling:
the second tab queues its submission and the server then sees the first
pair, rejecting implicit replacement. On browsers without Web Locks (or
without secure context), the form fails closed and displays an error rather
than falling back to an unsafe concurrent POST.

GREEN physical run `f8feaccfb4334a7ba1623517082a8e5d`: **2/2 PASS**
for fresh/fresh queued submission and the previous proven TOTP restart,
with original bearer pair/TTL preserved, PG17, owner-verified Docker cleanup
and zero uncertainty. The pending Web Lock assertion is real browser-side
evidence that both tabs attempted the operation. Source was a working-tree
snapshot on top of `7c657bc`; this result is **not** CI for a committed
child until the exact patch is committed.

**Security boundary/limitation:** Web Locks coordinate honest same-origin
browser forms, not arbitrary HTTP clients or extensions that bypass this UI.
The backend must continue enforcing host/CSRF, capability hashes, role,
expiry, proof and explicit abandonment. A direct POST that is deliberately
constructed outside the form can still induce the fresh/fresh cookie
response-order race against its own browser. This is not an MFA bypass or an
authorization grant, but it is a residual availability/UX risk requiring
independent acceptance; do not claim a universal atomic cookie+DB guarantee.

### ADMIN explicit restart and React Server Action field encoding

The separate Chromium/PG18 ADMIN synthetic-session restart exposed a
transport discrepancy: a client-form callback sending an explicit checked
`confirmRecoveryRestart=yes` resulted in a multipart field named
`_0_confirmRecoveryRestart` rather than the plain form field expected by
`read(formData, "confirmRecoveryRestart")`. The Server Action returned to
`?restart=1` and never rotated the opaque pair. The dedicated, bounded
consent parser now accepts **one** exact field or React numeric-prefixed field
with the literal value `yes`; conflicting or duplicate aliases fail closed.
The client also snapshots the visible controlled checkbox before awaiting
another tab's Web Lock. Neither changes role, CSRF, recovery proof, or browser
capability authorization. This behavior requires an actual Chromium/PG18
GREEN rerun; a matching raw POST alone is not a success attestation.

## Outstanding independent and operational gates

### Follow-up: legacy GET/POST response-order race (local patch after fa214e3)

The independent reviewer correctly identified an additional late-response
failure: a legacy `GET /recover/open` or initial `openRecoveryAction` could
adopt a recovery link *before* the modern recovery had a cookie, then its
response could arrive after the modern TOTP proof had committed and overwrite
the bearer pair. The exact concurrent GET was physically RED in disposable
PG17/Chromium 153, run `806b4860fb334e0faf6c227d6924b730`, after
confirming the original proof. This was an availability P2, not an MFA bypass.

The local remediation makes **both initial legacy link entrypoints
candidate-only**, even for a fresh browser: `/recover/open` emits only a
non-authorizing candidate cookie, and `openRecoveryAction` does the same
after normal host/CSRF/role checks. Neither writes the primary recovery key
nor expires the multi-method browser/intent cookies. The user must explicitly
confirm through `switchRecoveryAction`, which revalidates the exact
candidate's live role and request ID under the normal recovery-open CSRF gate.
Opening the same link again also requires this explicit adoption.

GREEN physical run `b03924a06978477fa278ce88c072be00`:
**2/2 Chromium E2E PASS**, including delayed GET while TOTP is already
verified, no bearer/TTL replacement, legacy GET and POST after a proven
modern session, and explicit adoption of a fresh legacy link.
PostgreSQL 17.11 disposable, clean Docker ID-based teardown,
`dockerMutationUncertain=false`. The focused run used the exact clean
base `fa214e3` plus a working-tree snapshot of the patch, not yet a
published/hosted CI commit. An independently reviewed final SHA and
additional ADMIN/PG18 tests are still required; the older NO-GO section
below describes the **prior** `ebcab0e` code and is not a new GO.

### Independent SOURCE NO-GO and PostgreSQL 18 browser blocker (13 Nov)

An independent read-only reviewer inspected the exact code commit
`ebcab0e7bf56f16c9cb6caaf5002763478e466d2` relative to `cd58c7e`
and reported **SOURCE NO-GO**:

- A legacy `GET /recover/open` or legacy `openRecoveryAction` started
  **before** a fresh modern browser recovery has issued its first cookies
  can return late and implicitly overwrite the newly TOTP-proven recovery.
  The modern Web Lock cannot coordinate an ordinary legacy GET. Existing
  legacy E2E checks start only after the modern TOTP proof, so they do not
  cover this precise response-order race. This is an availability/continuity
  P2, not an MFA bypass. It requires an independent, causally synchronized
  physical RED and a reviewed explicit-adoption remediation plus GREEN.
- The current explicit-restart UI for a synthetic ADMIN request also remains
  **not green on physical Chromium 153 / PostgreSQL 18.6**. The exact committed
  `ebcab0e` run `82b68636fcc644058fef65839fa85ba4` failed its
  ADMIN consent/rotation assertion. Prior runs `136dc31c`,
  `b84cd427`, and `09b5d0b1` likewise failed that one browser
  journey while other recovery/CSRF scenarios passed. Source/transport
  unit tests are **not** replacements for this failed browser gate.

The failing tests used owned disposable PostgreSQL and Chromium containers;
the runner recorded `dockerCleanupVerified=true` and
`dockerMutationUncertain=false`. A subsequent **uncommitted** set of
diagnostic hypotheses did not establish a passing ADMIN recovery path and
was preserved in ignored local evidence
`.virki-mission-tmp/pr118-admin-unvalidated-diagnostic-after-ebcab0e.patch`
before restoring the worktree to the last reviewed code commit.

**Disposition:** The local fresh/fresh Web Lock proof (2/2 PASS PG17) and
the separate PG18 recovery integrations (9/9 PASS) remain valid **only
for their exact respective snapshots and scenarios**. The whole PR is
SOURCE NO-GO; do not push, merge, deploy, change Cloudflare, or imply hosted
CI/CodeQL validation of any unpublished SHA.

Independent SOURCE review of the **exact final commit** and its callers is
required before a normal fast-forward publication. Hosted CI/CodeQL for that
published SHA cannot be claimed from local source scans or old CI.
Production remains NO-GO until an independently owned, segregated staging
host and immutable digest, correctly configured Cloudflare Access versus the
conditionally authorized native ADMIN perimeter, genuinely cold ADMIN owner
and reviewer reauthentication, real Brevo provider event and independently
controlled inbox receipt with quota/allowlist, verified backup/restore and
physical rollback, and explicit owner/independent release signatures are
all proven. See native-hub-staging-otp-acceptance-20261110.md and
cloudflare-access-cold-admin-recovery-gate-20261109.md.
