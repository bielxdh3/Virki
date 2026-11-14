# PR #118 — segregated staging execution ledger (operator handoff)

> **NOT EXECUTED / EXTERNAL RELEASE NO-GO.** This is an unfilled operational ledger, not an authorization, staging observation, security approval, or proof of email delivery. Do not execute a production mutation from this document.

## Provenance and scope of the handoff

- Last **published** and CI-verified PR source: `678d81af31fb6aa5f1ab4effcdee823a030c38ce`, branch `feat/virki-native-admin-perimeter-20261110`. Staging transport/restart hardening is a **local-only descendant patch**, not yet independently accepted or published. Its commit SHA must be checked separately before any staging or release. Recheck the exact approved PR HEAD and immutable image digest at the beginning of a permitted staging window; any new source change invalidates earlier exact-SHA gates.
- GitHub checks verified on the **published parent only**: CI runs `43594678814` and `43594674461`, CodeQL `43594678827` — `SUCCESS`. The local patch has **no hosted checks or required independent SOURCE GO yet**. The production-image publication jobs were skipped by branch policy. The hosted native Hub Chromium tests are CI fixtures, **not a live external staging run**.
- Independent source reviews of the published code previously reported GO; this is **not** an independent operational-security sign-off, a GitHub `APPROVED` review, or permission to merge.
- GitHub PR #118 remains `OPEN/DRAFT`; at handoff there were **four unresolved threads** (two outdated). The native Cloudflare Access perimeter thread stays open pending operator cutover acceptance.
- Parent contracts, which take precedence if this ledger is incomplete: [`native-hub-staging-otp-acceptance-20261110.md`](native-hub-staging-otp-acceptance-20261110.md), [`native-hub-perimeter-cutover-20261110.md`](native-hub-perimeter-cutover-20261110.md), and [`staging-email-worker-role-20261112.md`](staging-email-worker-role-20261112.md).

### Four existing GitHub review threads reconciled against source

| Location of thread | Current code and decision | Remaining gate |
| --- | --- | --- |
| `apps/hub/src/lib/cloudflare-access.ts:19` (P1, not outdated) | `native` deliberately bypasses **application** Access JWT while protected Hub pages/mutations still require Virki ADMIN session, role, CSRF/Origin and scoped elevation. The default production mode stays `access`. No automatic ADMIN action bypass was established by the thread. | Independently approve the changed trust boundary on the real external native edge and its tested rollback, reconcile the contributor guide's older Access outer-boundary requirement; **leave open**. |
| `apps/hub/src/app/account/security/page.tsx:35` (P2, outdated) | UI now checks `canOfferRecoveryEmailRebind` against consumed non-EMAIL recovery provenance, matching the mutation's stricter recheck. Existing PostgreSQL fixtures reject modern and revoked/expired origins and admit eligible legacy non-EMAIL provenance. | Prior fix has source/CI evidence; request reviewer reconciliation before resolving, not a reason to invent a new code patch. |
| `apps/hub/src/app/recover/actions.ts:94` (P2, outdated) | Proven browser-bound modern recovery preserves its original key/token; explicit restart consent, reconstruction from independently validated bearer pair and shared origin Web Lock prevent the documented cooperating-tab late-response clobber. | Prior physical RED/GREEN browser and PostgreSQL evidence exists. Retain documented malicious raw HTTP response-order availability limitation, without treating it as an MFA bypass. |
| `packages/auth/src/security.ts:973` (P2, not outdated) | `getAccountRecoveryRequestId` intentionally remains legacy-only. `recover/open` GET and first POST emit a **candidate-only** cookie; explicit switching requires matching candidate, live role/status, origin and CSRF. | Prior causal browser RED/GREEN/source review covers this flow. Do not auto-resolve before reviewer reconciliation. |

No thread was resolved, dismissed, marked approved or posted to automatically by this staging preparation.

### Local patch evidence — not external acceptance

- Reproduced the previous worker-only Compose environment inheritance from the published parent: ordinary `VIRKI_EMAIL_*` SMTP/outbox sources remained after overriding only `DATABASE_URL`. A new contract assertion failed on the parent (3 PASS, 1 FAIL), then passed with the staging-only source override (4 PASS).
- Additional post-`f50fc58` causal RED: the manual Compose worker still inherited `depends_on.postgres` from the base production manifest. A regression test failed against that exact local parent (**4 PASS, 1 FAIL**); after `depends_on: !reset []`, the parsed effective worker dependency graph is **absent/empty**. This proves the worker no longer selects PostgreSQL through its dependency graph, **not** that Compose cannot prepare the base project's named volumes. No worker start or Docker volume mutation was tested or authorized.
- Effective Docker Compose interpolation with **synthetic values only**: deliberately injected ordinary SMTP/outbox/database sentinels were overridden for staging Hub/worker; both share the same synthetic staging outbox key, `restart=no`, the manual profile remains, and a distinct explicit staging project name renders. Missing any of the staging Compose project, SMTP password, outbox key, or Hub database URL failed rendering: **4/4 denied**. `-p` and `COMPOSE_PROJECT_NAME` still require a separately witnessed effective-project check. No Docker service/daemon activity or real SMTP was involved.
- The actual stage guard previously accepted an exited worker despite an inherited auto-restart policy. Stubbed physical-Bash guard test reproduced the negative case before the fix; after inspecting `HostConfig.RestartPolicy.Name`, the focused test passed and denies `unless-stopped`, `always`, `on-failure`, absent/unknown policy, or active worker state.
- Full local `scripts/production-ops.test.mjs` against temporarily linked approved dependencies: **64 total, 51 PASS, 0 FAIL, 13 platform-conditional SKIP**. The updated worker role/SCRAM suite: **8 PASS, 0 FAIL, 0 SKIP**. `npm run lint`, `npm run secrets:scan`, Bash syntax and `git diff --check` passed. The temporary dependency junction was checked and removed.
- A descendant-worktree `npm run typecheck` using a temporary dependency junction failed resolving the unchanged issuer's `oidc-provider` declarations, with cascading implicit-any diagnostics; a direct issuer typecheck passed in the previously approved parent worktree at `678d81a`. This local setup is **not** a full descendant typecheck PASS; fresh exact-SHA CI is required after independent SOURCE GO and eventual publication.

**Evidence location:** an operator-controlled, access-restricted repository **outside this Git tree**. Use opaque receipt references here; never commit or upload `.env` values, personal data, recipient addresses, screenshots of OTPs, passkeys, private keys, tokens, URLs containing capabilities, SQL dumps, raw headers or unredacted logs.

## Gate 0 — authorize and identify the independent staging target

All fields below must be completed by the actual owner/operator and independently verified before any external resource change. A blank or `NOT RUN` field is **BLOCK**, not implicit consent.

| Mandatory identity or approval | Operator receipt | State |
| --- | --- | --- |
| Owner-approved host and independent operator, exact maintenance window (UTC) | — | NOT RUN |
| Separate staging host, network boundary, TLS endpoint and routing; not production/deManage | — | NOT RUN |
| Separate PostgreSQL database, migrator/runtime/email-worker roles; no production credentials | — | NOT RUN |
| Designated USER and ADMIN test identities, independent elevated reviewer, authorized test inbox owners | — | NOT RUN |
| Staging-only SMTP tenant/relay, TLS/AUTH, hard receiver allowlist, rate and total-message budget | — | NOT RUN |
| Pre-approved staging-only immutable OCI digest and source SHA, verified independently on target | — | NOT RUN |
| Out-of-band pinned owner and observer Ed25519 identities, offline signed approvals | — | NOT RUN |
| Named rollback operator, baseline snapshot custody, restore rehearsal and stop conditions | — | NOT RUN |

**Stop immediately** if there is a target-identity mismatch, possible production/deManage crossover, untrusted signing key, unknown mailbox owner, unexpected inbound route, worker already running or unexplained queued email. Do not silently reconcile a discrepant environment.

## Gate 1 — establish provenance and start in a closed state

1. Operator independently compares approved source SHA, immutable OCI manifest digest, runtime image identifier and effective Compose configuration on the **staging host only**. Record opaque receipt IDs and UTC timestamps; no `docker compose config` dump containing secrets.
2. Verify host and database separation **against** production inventories held by the operator, with least-privilege accounts and committed migrations only. Record the actual PostgreSQL major/schema migration state, grants, TLS endpoint and fail-closed negative checks without identifiers or connection strings in this ledger.
3. Establish protected baseline backup, prove a restorable staging-only snapshot, and take redacted counts for users, sessions, pending recovery, outbox by kind/state, delivery attempts and audit events. Never restore a staging dump over production.
4. Start only the approved application components. The email worker stays **stopped** with zero replicas, no outbox drain and verified `HostConfig.RestartPolicy.Name=no` (for any existing staging worker container), not merely a corrected YAML file.
5. Inspect the effective **staging-only** Compose merge: an explicitly set `VIRKI_STAGING_COMPOSE_PROJECT` and actual final Docker project/context must differ from production, including if `-p` or `COMPOSE_PROJECT_NAME` is supplied. The manual worker override must have `profiles: ["staging-email-worker-manual"]`, `restart: "no"`, **no inherited `postgres` dependency**, a separately authenticated scoped `DATABASE_URL`, `VIRKI_EMAIL_WORKER_SCOPED_ROLE=required` and exclusively `VIRKI_STAGING_*` sources for its outbox key and SMTP credentials/sender/interval; the Hub must receive that same staging key and a separate staging Hub database URL. All other stack services still need an independently vetted staging-only base environment. Fail closed for any inherited normal `VIRKI_EMAIL_*` source or a mismatched identity. Do not use an unqualified `up` against the base Compose. Before any separately authorized `up --no-deps email-worker`, independently prove the **exact version and project** will not create/reconcile a production PostgreSQL volume; dependency removal alone cannot establish this.
6. Independently observe the worker stopped, restart/autostart disabled, empty virgin outbox and zero attempts. Sign the separate observation. Run `node scripts/staging-otp-preflight.mjs` with the two signed JSON declarations, two **public** keys and `--expected-source-sha` set to the approved exact SHA. A consistent result proves only signed declaration consistency; it never establishes live state or grants permission to send.

| Gate-1 proof | Operator receipt | State |
| --- | --- | --- |
| Image / SHA / effective configuration matched | — | NOT RUN |
| Host, origin, TLS and PostgreSQL isolation proved | — | NOT RUN |
| Fresh backup and restoration plan independently validated | — | NOT RUN |
| Worker physical stopped state, `no` restart, profile, no backlog, zero attempts | — | NOT RUN |
| Signed owner approval + independent observation, offline preflight consistent | — | NOT RUN |

## Gate 2 — browser, authorization, recovery and passkey acceptance

Use an **authorized external** staging deployment at the approved digest. Use clean real browsers on the correct HTTPS Portal/Hub origins. For native Hub, begin without a Cloudflare Access JWT/cookie and without a synthetic JWT issuer; this is not a production Access-policy modification. Log only redacted audit refs and aggregate database effects. Record exact test role, preconditions, positive result, negative result, whether a security state changed, UTC timestamp and opaque evidence receipt for each case.

| Required physical scenario on staging | PASS / FAIL / NOT RUN | Receipt |
| --- | --- | --- |
| Native Hub ADMIN login: valid password + live second factor; no Access JWT; no unauthorized ADMIN page/mutation | NOT RUN | — |
| Native perimeter: unauthenticated denial, forged Access/JWT/Origin/CSRF denial, valid USER Portal session refused by Hub, wrong host denied | NOT RUN | — |
| USER login and independent lost-original-mailbox recovery with verified replacement mailbox and exact Portal RP passkey/TOTP | NOT RUN | — |
| ADMIN lost-original-mailbox recovery with required independent factors and distinct active elevated ADMIN reviewer | NOT RUN | — |
| USER `TOTP_ADMIN` recovery and USER `PASSKEY_ADMIN` recovery as separate tests, with reviewer/role rejection | NOT RUN | — |
| ADMIN separate-credential rotation with original inbox OTP + current normal password + fresh session/CSRF | NOT RUN | — |
| ADMIN separate-credential rotation with unused recovery code + normal password, including concurrent same-code replay denial | NOT RUN | — |
| ADMIN separate-credential rotation with ACTIVE TOTP + normal password, preserving active TOTP and rotating codes | NOT RUN | — |
| ADMIN normal password unchanged; old admin password/codes denied; ten replacement recovery codes; new scoped elevation required | NOT RUN | — |
| USER and ADMIN passkey enrollment, assertion, revocation/replay, wrong role/origin/RP, forgotten device and expired challenge | NOT RUN | — |
| Post-recovery: revoke old sessions/devices/elevations, old credentials denied, new session and fresh MFA/new elevation allowed | NOT RUN | — |
| Recovery cross-tab restart/link races, explicit consent, expiry, one-winner, rate limit, revoked factors and audited denials | NOT RUN | — |

Any required scenario that is skipped, observed only in CI, backed solely by a database row, or lacks a browser and server-side audit correlation remains **NO-GO**. The Web Locks UI mitigates honest same-origin races but does not serialize malicious raw HTTP `Set-Cookie` responses; test the approved adversarial cases and record this residual availability risk for independent acceptance, not as an MFA bypass.

## Gate 3 — authenticated SMTP and one real OTP end-to-end

**Do not start a worker yet.** First the independent operator must prove the staging relay identity, certificate/TLS and AUTH, provider and worker quota, **provider-enforced** recipient allowlist including rejection of an unlisted address, empty backlog, dedicated SQL privileges and a bounded attended sending window. Recheck the physical worker state and sign a new observation immediately before the window. Do not use a production Brevo credential, mailbox or tenant.

Only after these gates and a distinct send authorization, the operator explicitly selects the manual Compose service/profile, supervises the approved number of OTP sends, and stops it before the window closes. A successful `docker compose config`, SMTP `250`, `SENT` database state, header `Message-ID`, or an earlier diagnostic email is **not** proof of recipient delivery.

| Distinct OTP chain observation | Operator receipt (non-secret) | State |
| --- | --- | --- |
| Virki action, authenticated USER/ADMIN role, ceremony isolation and redacted audit reference | — | NOT RUN |
| Real staging outbox kind, bounded age, recipient binding and HMAC-correlated opaque row reference | — | NOT RUN |
| Single worker claim/CAS winner, attempt record, verified STARTTLS/AUTH and bounded retry/lease state | — | NOT RUN |
| Relay/provider acceptance event and correctly matched provider message ID | — | NOT RUN |
| Authorized test inbox owner independently confirms actual Virki-generated OTP and matching safe message trace | — | NOT RUN |
| One-time OTP acceptance, expired/replayed/wrong-role denial, no second dispatch or secret in audit output | — | NOT RUN |
| Worker stopped after window, zero replicas, no restart/autostart; uncertain sends independently reconciled | — | NOT RUN |

If the provider-to-inbox join cannot be established without exposing sensitive headers or OTP data, record `OTP_CORRELATION_UNPROVEN`: **NO-GO**. Retry/relay acknowledgement ambiguities are not automatically successful or safe for resend.

## Gate 4 — physical rollback and final operator decision

1. Stop and physically verify the worker stopped and unable to restart before any restore. Reconcile every queued, processing, sent, retryable and uncertain message/attempt, including reserved Message-IDs and leases, without resending.
2. Restore only the approved independent staging database/snapshot to the staging target, with the named rollback owner present; exercise application rollback and verify the approved source/image and ingress configuration. Do not touch production or Cloudflare production policies.
3. Compare before/after sanitized counts across users, sessions, recoveries, outbox by kind, attempts, and audits. Confirm expired tokens, session revocation and negative replay behavior; retain immutable/redacted receipt IDs.
4. Review risks and evidence with an independent security reviewer, operator and owner; do not close GitHub threads, mark `APPROVED`, promote images, remove Draft or change the production perimeter based on this ledger.

| Final acceptance condition | State |
| --- | --- |
| Exact candidate SHA and staging immutable digest independently verified | NOT RUN |
| Every Gate-2 mandatory browser scenario PASS, no silent SKIP | NOT RUN |
| Real provider-to-recipient OTP matched for authorized test identities | NOT RUN |
| Physical staging rollback and post-restore invariant evidence PASS | NOT RUN |
| Independent operational-security approval, review-thread reconciliation and formal GitHub approval | NOT RUN |
| Separate explicit final owner approval for any production perimeter change | NOT RUN |

**Decision rule:** release remains **NO-GO** unless **all** applicable cells have external evidence and independent acceptance. Code/source review, green CI/CodeQL, a Compose dry run or a signed statement alone cannot substitute. Any blocker, unknown, missing receipt, secret spill, provider discrepancy or unverifiable restore forces **NO-GO** and a new reviewed window.

## Residual risks and follow-up ownership

- **Native outer boundary:** with `VIRKI_HUB_PERIMETER_MODE=native`, the application deliberately stops requiring the Access JWT. The documented production default remains Access. Independent operator must reconcile this design choice with `AGENTS.md` and approve an externally tested edge/rollback boundary; the open P1 thread is an acceptance gate, not evidence of a currently exploited bypass.
- **Browser response ordering:** Web Locks coordinate cooperating forms only; an adversarial direct HTTP client may induce availability races. Retain backend CSRF/role/proof/capability protections and record the residual limitation for reviewer acceptance.
- **Mail delivery:** an outbox receipt, SMTP acceptance or provider event alone does not prove inbox arrival; only the complete authorized chain does.
- **Worker restart:** staging `restart=no` and a profile do not prevent explicit starts or override a stale existing container. The stage guard now rejects any stopped-but-restartable worker it observes; the operator must still verify the physical container before **each** approved window.
- **Compose environment inheritance:** manual worker overrides merge, not replace, base service environment. Required staging-only variables prevent silent inheritance of ordinary SMTP/outbox sources, but **do not** independently prove a secret, host or account is different from production; the independent operator must inspect identity and segregation out of band.
- **Compose service dependencies and volumes:** the base worker otherwise depends on a production-style PostgreSQL service. The manual override resets the worker dependency, but the base project's named PostgreSQL volume remains declared; absence of Docker volume side effects is **not proven by `docker compose config`**. Require a separate approved project/volume inventory and a nonmutating exact-version plan or a staging-only base. No unqualified stack-wide `up` or production project/volume is authorized.
- **Operational authority:** SOURCE GO and CI on a code SHA do not authorize staging, SMTP, closing review threads, merge or production cutover. Keep PR #118 `DRAFT`, production native cutover blocked and the evidence outside source control.

All these observations are **local and review-pending**, not external staging acceptance. Do not transfer earlier SOURCE GO or hosted CI to the new descendant. Obtain a fresh formal independent SOURCE GO and new exact-SHA hosted CI/CodeQL after publication; staging itself needs separate owner/operator authorization.
