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

## Outstanding independent and operational gates

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
