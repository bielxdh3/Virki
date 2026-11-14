# PR #118 — segregated staging execution ledger (operator handoff)

> **NOT EXECUTED / EXTERNAL RELEASE NO-GO.** This is an unfilled operational ledger, not an authorization, staging observation, security approval, or proof of email delivery. Do not execute a production mutation from this document.

## Provenance and scope of the handoff

- Last **published** and CI-verified PR source: `678d81af31fb6aa5f1ab4effcdee823a030c38ce`, branch `feat/virki-native-admin-perimeter-20261110`. Staging transport/restart hardening is a **local-only descendant patch**, not yet independently accepted or published. Its commit SHA must be checked separately before any staging or release. Recheck the exact approved PR HEAD and immutable image digest at the beginning of a permitted staging window; any new source change invalidates earlier exact-SHA gates.
- GitHub checks verified on the **published parent only**: CI runs `43594678814` and `43594674461`, CodeQL `43594678827` — `SUCCESS`. The local patch has **no hosted checks or required independent SOURCE GO yet**. The production-image publication jobs were skipped by branch policy. The hosted native Hub Chromium tests are CI fixtures, **not a live external staging run**.
- Independent source reviews of the published code previously reported GO; this is **not** an independent operational-security sign-off, a GitHub `APPROVED` review, or permission to merge.
- GitHub PR #118 remains `OPEN/DRAFT`. Reconciliation on local candidate `6feb2da5ab9bd25ce1cc2f53c6a7c4fc4807bd1c` posted evidence and resolved the two outdated P2 threads plus the P2 legacy-link thread after Chromium proof. The P1 native/Access trust-boundary thread remains open pending external edge/rollback acceptance. Resolving findings is not a GitHub APPROVED review.
- Parent contracts, which take precedence if this ledger is incomplete: [`native-hub-staging-otp-acceptance-20261110.md`](native-hub-staging-otp-acceptance-20261110.md), [`native-hub-perimeter-cutover-20261110.md`](native-hub-perimeter-cutover-20261110.md), and [`staging-email-worker-role-20261112.md`](staging-email-worker-role-20261112.md).

### Four existing GitHub review threads reconciled against source

| Location of thread | Current code and decision | Remaining gate |
| --- | --- | --- |
| `apps/hub/src/lib/cloudflare-access.ts:19` (P1, not outdated) | `native` deliberately bypasses **application** Access JWT while protected Hub pages/mutations still require Virki ADMIN session, role, CSRF/Origin and scoped elevation. The default production mode stays `access`. No automatic ADMIN action bypass was established by the thread. | Independently approve the changed trust boundary on the real external native edge and its tested rollback, reconcile the contributor guide's older Access outer-boundary requirement; **leave open**. |
| `apps/hub/src/app/account/security/page.tsx:35` (P2, outdated; resolved with reply) | UI checks `canOfferRecoveryEmailRebind` against consumed non-EMAIL recovery provenance, matching the mutation's strict recheck. PostgreSQL 18 integration: **5/5 PASS** including modern-origin denials, eligible legacy positive control, revoked/expired/foreign. |
| `apps/hub/src/app/recover/actions.ts:94` (P2, outdated; resolved with reply) | Proven browser-bound modern recovery preserves its original key/token; explicit restart consent, validated bearer pair and origin Web Lock prevent the documented cooperating-tab late-response clobber. Chromium recovery/passkey suite: **12/12 PASS**, including restart and USER/ADMIN races. |
| `packages/auth/src/security.ts:973` (P2, resolved with reply) | Legacy discovery remains restricted. Active GET/first POST only set a candidate; a separate CSRF/Origin/role/surface-validated POST performs an explicit switch. The previously cited `recovery-switch.ts` helper is unused and is not claimed as enforcement. Chromium proved the modern key/TTL survives legacy GET/POST until explicit switch. |

The three P2 threads were replied to with exact-candidate evidence and resolved. The P1 remains unresolved; no review was marked APPROVED.

### Local patch evidence — not external acceptance

- Reproduced the previous worker-only Compose environment inheritance from the published parent: ordinary `VIRKI_EMAIL_*` SMTP/outbox sources remained after overriding only `DATABASE_URL`. A new contract assertion failed on the parent (3 PASS, 1 FAIL), then passed with the staging-only source override (4 PASS).
- Additional post-`f50fc58` causal RED: the manual Compose worker still inherited `depends_on.postgres` from the base production manifest. A regression test failed against that exact local parent (**4 PASS, 1 FAIL**); after `depends_on: !reset []`, the parsed effective worker dependency graph is **absent/empty**. This proves the worker no longer selects PostgreSQL through its dependency graph, **not** that Compose cannot prepare the base project's named volumes. No external staging worker start or production/staging volume mutation was tested or authorized; the separate local disposable worker execution is recorded below.
- A new separately testable **standalone** manual worker manifest (`infra/docker-compose.staging-email-worker-only.yml`) avoids the production-style base entirely. Causal RED: its two contract tests both failed when the file was absent; after creation, its source and actual Docker Compose configuration both passed using **synthetic** inputs. The effective model has exactly one profiled worker service, only a pre-existing external network, no PostgreSQL services, no named volumes and no implicit dependencies. This still proves only the manifest's declared model, not the identity or behavior of any external host, project or existing Docker resources.
- Effective Docker Compose interpolation with **synthetic values only**: deliberately injected ordinary SMTP/outbox/database sentinels were overridden for staging Hub/worker; both share the same synthetic staging outbox key, `restart=no`, the manual profile remains, and a distinct explicit staging project name renders. Missing any of the staging Compose project, SMTP password, outbox key, or Hub database URL failed rendering: **4/4 denied**. `-p` and `COMPOSE_PROJECT_NAME` still require a separately witnessed effective-project check. No Docker service/daemon activity or real SMTP was involved.
- The actual stage guard previously accepted an exited worker despite an inherited auto-restart policy. Stubbed physical-Bash guard test reproduced the negative case before the fix; after inspecting `HostConfig.RestartPolicy.Name`, the focused test passed and denies `unless-stopped`, `always`, `on-failure`, absent/unknown policy, or active worker state.
- Full local `scripts/production-ops.test.mjs` against temporarily linked approved dependencies: **64 total, 51 PASS, 0 FAIL, 13 platform-conditional SKIP**. The updated worker role/SCRAM suite: **8 PASS, 0 FAIL, 0 SKIP**. `npm run lint`, `npm run secrets:scan`, Bash syntax and `git diff --check` passed. The temporary dependency junction was checked and removed.
- A descendant-worktree `npm run typecheck` using a temporary dependency junction failed resolving the unchanged issuer's `oidc-provider` declarations, with cascading implicit-any diagnostics; a direct issuer typecheck passed in the previously approved parent worktree at `678d81a`. This local setup is **not** a full descendant typecheck PASS; fresh exact-SHA CI is required after independent SOURCE GO and eventual publication.
- On the local Windows `desktop-linux` Docker engine, exact pinned Node 22.23.3, PostgreSQL 18.6 and Playwright images were already cached; no image pull was performed. Native Hub browser gate: **3/3 PASS** with no Access JWT or synthetic issuer/JWKS, but only against a disposable local database. Recovery/passkey browser selection: **12/12 PASS**, including USER/ADMIN TOTP_ADMIN, USER PASSKEY_ADMIN, USER/ADMIN passkey tests, same-browser partial-proof restart, delayed legacy GET, explicit legacy switch and two-tab races. These browser tests use local fixtures and are not external staging.
- Dedicated PostgreSQL 18.6 integration runner: `recovery-email-rebind.integration.test.ts` **5/5 PASS**; SMTP wire integration: **1/1 PASS** over verified loopback STARTTLS/AUTH using the actual worker and synthetic mailboxes, with zero external delivery. SMTP wire typecheck and lint both passed. The full-schema disposable worker rehearsal applied **19/19 migrations** and passed **5/5** tests with real scoped Prisma worker processes, SCRAM, STARTTLS/AUTH, two-worker CAS/reconciliation and ACL-drift fail-closed checks.
- Redacted local runner evidence is preserved under `.virki-mission-tmp/isolated-runs/`: native Hub Chromium `d6988c0c6f7e4b758a6b3b962b1d29fb`; recovery/passkey Chromium `6c6f808acf204cd89e4cd3cb7d10ec9b`; recovery-email-rebind PostgreSQL integration `74fb3b0c58084be5ad802ef4ddcb2692`; SMTP wire integration `ce36878e404d47b7bb0db72eca5329da`. Each manifest records exact source HEAD `6feb2da5ab9bd25ce1cc2f53c6a7c4fc4807bd1c`, exit 0 and `dockerCleanupVerified=true`. Logs remain local and are not committed.
- Local physical cleanup fault injection: failure after SMTP certificate creation returned the expected nonzero result and recorded runner/DB/network removal plus `CLEANUP_CONFIRMED`; simulated unacknowledged runner creation correctly withheld cleanup success and recorded `RECONCILIATION_REQUIRED`, while DB/network removal was confirmed. Private receipt journals are under the owner-private local HOL directory; do not copy them into Git. The E2E runner manifests report `dockerCleanupVerified=true` for all four runs. One unrelated empty Docker network labelled with prior run ID `06fc1622b8d7467bb8a3a1f5bd6ade40` was observed and left untouched.
- `scripts/staging-otp-preflight.test.mjs`: **52/52 PASS**. This proves the offline signature/declaration validator fails closed; no owner or observer signatures were supplied and no live target was observed.
- Compose inspection: the standalone worker manifest has one profiled service, no ports, mounts, dependencies or named volumes, and one pre-existing external network; read-only root, `node:node`, all capabilities dropped, `no-new-privileges`, `pull_policy: never`, and `restart: no`. It has **no Docker HEALTHCHECK or Compose CPU/memory/PID limits** and does not itself enforce network egress/recipient allowlisting; signed host/cgroup resource policy, runtime observation and firewall/provider evidence remain mandatory.
- The new operator runbook's five POSIX command blocks passed `bash -n`. Its Compose shape predicates were checked against an actual `docker compose config --format json` render with synthetic-only values: one service, one external network, exactly 13 declared environment keys, no volumes and no healthcheck. No staging environment was rendered.

**Evidence location:** an operator-controlled, access-restricted repository **outside this Git tree**. Use opaque receipt references here; never commit or upload `.env` values, personal data, recipient addresses, screenshots of OTPs, passkeys, private keys, tokens, URLs containing capabilities, SQL dumps, raw headers or unredacted logs.

The command-level staging and physical-rollback procedure is in
[`pr118-staging-operator-runbook-20261114.md`](pr118-staging-operator-runbook-20261114.md).

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
5. Use the preferred **standalone** worker-only manifest `infra/docker-compose.staging-email-worker-only.yml` with **no production or staging base Compose files combined**. Verify that the real parsed configuration has exactly one manual-profile email-worker, `restart=no`, only an approved pre-existing external staging network, no PostgreSQL service, no named volume and no dependencies. Verify the exact immutable image digest and all staging-only environment sources. Independently witness `VIRKI_STAGING_COMPOSE_PROJECT` and actual final project/context, including overriding `-p` or `COMPOSE_PROJECT_NAME`, and verify pre-existing worker resources and network/volume identity. The operator must still refuse any unqualified `up`; only a distinct approved attended `up --no-deps email-worker` after all gates. If using the **legacy layered override** instead, an independently vetted staging-only base and a nonmutating command plan showing no production volume/resource impact are mandatory. Do not claim that `depends_on: !reset []` alone proves volume safety.
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
- **Compose service dependencies and volumes:** the legacy layered override resets worker dependencies but still includes the base project's named PostgreSQL volume. The **preferred standalone worker-only manifest** declares no PostgreSQL service, volume or implicit project network; it still cannot prove runtime host/project resource ownership or absence of side effects without external observation. Require an independently approved context/project/external network/volume inventory. No unqualified stack-wide `up` or production project/volume is authorized.
- **Operational authority:** SOURCE GO and CI on a code SHA do not authorize staging, SMTP, closing review threads, merge or production cutover. Keep PR #118 `DRAFT`, production native cutover blocked and the evidence outside source control.

All these observations are **local and review-pending**, not external staging acceptance. Do not transfer earlier SOURCE GO or hosted CI to the new descendant. Obtain a fresh formal independent SOURCE GO and new exact-SHA hosted CI/CodeQL after publication; staging itself needs separate owner/operator authorization.
