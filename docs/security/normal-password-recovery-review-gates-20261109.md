# Normal-password recovery: source and release gates

Date: 2026-11-09. Status: **local source/PG18/Node22 validation GO on the code SHA recorded below; operational production release NO-GO on external identity and browser gates**.

## Provenance: historical baseline versus current integrated candidate

Local branch: `feat/virki-recovery-multichoice-prime-20261109-1505`. Base `main` remains at `7c8914ed222f0672ccc87e0331daf6a4c3f0f5a7`; **no push, merge, deploy, production database changes, or real email sends**. The base `a814ed847688647b564099bd71ca1b4c7bd93e78` contains previous reviewed source and its initial evidence document. Later security fixes, additional PostgreSQL integration tests and Cloudflare policy findings are separate changes.

**Historical evidence only — not the final candidate:** commit `f72d0808a28fc473dba3e696dc420af21f6244c5` passed the full production build of OIDC + Portal + Hub and `npm run test:unit` with **496 passed, 0 failed, 8 skipped**, plus TypeScript, lint, Prisma validate, secret scan on official SHA-256-verified Node 22.22.1 with clean Next.js 16.4.5 installation. These checks **predate** the later code and integration-test changes and must **not** be cited as the validation of any successor SHA. The earlier `/_global-error` E1068 in contaminated dependencies did not reproduce after clean install; that is historical diagnosis only.

Later locally committed fixes include `9e411f5f66e9aefa2c8f6983802a7a7f7f5c01db` (administrative backup/email recovery now revokes sibling sessions, remembered devices, pending authentication and recovery proofs, OIDC artifacts and old passkeys in the same transaction) and `c46f004e9597ab3c611b9246d455a0900322b61a` (backend rejects undocumented three-factor selections; only three distinct pairs or one proof plus independent ADMIN are accepted). The `c46f004` changed-methods focused test run passed **10/10**, focused ESLint and `git diff --check` passed, but this does not replace full final CI-equivalent validation.

**Current fully checked code SHA and exact-tree commands/results:** see the final validation record below. Earlier PostgreSQL, SMTP and Edge checks against intermediate snapshots are labeled as such and are not silently promoted to exact-final-SHA evidence. A subsequent documentation-only commit must separately establish that the checked code files remain byte-for-byte unchanged.

## Implemented recovery contracts

Implementation now provides distinct normal-password recovery choices: any two independent proofs among registered passkey, active TOTP, and verified email OTP, or any one of these plus approval by a **different eligible active ADMIN** and an optional comment capped at 300 characters. Factor selection and proofs are persisted and bound to the exact account, role, request, challenge and browser capability. Synthetic requests are constructed to avoid leaking account existence via request IDs. Changing a factor or letting a proof expire before final consumption fails closed. ADMIN passkeys enroll against the separate hub RP, with current ADMIN session and independent elevation; this does not turn on passwordless ADMIN login.

For a pair/assisted method not proving the old mailbox, a **new mailbox must be independently verified before replacing login password/email or revoking existing authenticators**. The completed recovery revokes old login MFA, sessions and devices; a short-lived bound bootstrap session lets the owner safely continue. The separate **administrative elevation credential** retains its own recovery choices: current normal password plus (a) verified e-mail code, (b) saved administrative recovery code, or (c) currently active one-use TOTP. The TOTP path rotates the independent credential and ten backup codes, revokes old admin passkeys, elevations and sibling sessions, but preserves the normal login password and active login TOTP.

**Release remains NO-GO** despite the completed local CI-equivalent build, PostgreSQL tests and independent source GO: full Next UI HTTP/CSRF/cookie browser E2E for recovered USER/ADMIN at both RPs has not been demonstrated; Cloudflare Access has not been shown to permit authorized ADMIN lost-mailbox recovery in a cold browser **without bypassing Access**. Real Brevo SMTP delivery, live hosted CI, and production deployment are untested or intentionally not performed. ADMIN passkey functionality requires a separately security-reviewed feature flag. Green local build/unit/PG18 is not production release authorization.

### Cloudflare Access: live, read-only findings (2026-11-09)

The connected Cloudflare account was inspected using **GET-only** account, Access application, application policy and identity-provider endpoints. No Cloudflare settings or live sessions were changed.

- `hub.biel.dev.br` is an Access-protected self-hosted application named **hub**, with Access session duration **168 hours**.
- The sole configured application policy is **Owner only**, decision `allow`, with both `include` and `require` constrained to email identity. There is no configured exclusion/fallback policy.
- The account lists **One-Time PIN (`onetimepin`) as its only Access identity provider**; the hub Access app has no explicitly listed alternative identity providers.
- `portal.biel.dev.br` has **no Access application** in this account. This is expected and must **not** be treated as authorization to expose ADMIN recovery on the public Portal.

**Concrete release blocker:** an ADMIN without access to the old mailbox may be unable to reauthenticate to Cloudflare Access after the pre-existing Access session expires. Even after Virki verifies a replacement mailbox and changes the ADMIN's own login email, the separate **Owner only** Access policy may not recognize or permit the replacement identity. The source gate correctly refuses hub requests without valid Access; removing/bypassing that gate is **not an acceptable fix**. A reviewed identity-recovery strategy that preserves Cloudflare Access protection, including new-mailbox authorization and cold-browser access tests, is required before claiming end-to-end ADMIN lost-inbox recovery. Changing Cloudflare Access policy, identity provider or user authorization is **outside the scope of this source-only integration task**.

## Historical baseline findings retained for traceability

This document records independent read-only review findings against the starting Virki `main` (`7c8914ed222f0672ccc87e0331daf6a4c3f0f5a7`). It is not evidence that a successor fix is complete. No production changes or SMTP sends are authorized here.

## Critical integration gates

1. **Lost inbox must not block recovery.** Legacy recovery requires an email OTP, then an ADMIN approval and another emailed bearer link (`packages/auth/src/security.ts`, original 636-681, 705-721, 748-765, 771-800). A new `PASSKEY_TOTP` or `PASSKEY_ADMIN` ceremony needs its own durable browser-bound capability and server-side proof state, with no mailbox dependency. Do not count the same email link and emailed OTP as independent factors.
2. **Lost inbox must not block first login afterward.** Current new-device login sends email verification even for TOTP unless the device is already trusted; recovery revokes trusted-device state and USER recovery revokes passkeys/TOTP. Two-factor proof at reset must provide a carefully reviewed single-use bootstrap session or another equally strong path; then allow re-enrollment. Do not weaken default device login.
3. **ADMIN WebAuthn cannot reuse the USER-only RP implementation.** Current passkey enrollment and login are USER-only on `portal.biel.dev.br`; the ADMIN `hub.biel.dev.br` origin differs. A recovery assertion must not mint a normal login session prematurely. Until proper ADMIN passkey enrollment/cross-origin binding is demonstrated, gate ADMIN passkey combinations as unsupported.
4. **ADMIN lost-email recovery may be blocked before reaching the app.** `/recover` on the hub presently validates Cloudflare Access; the portal treats accounts as USER. Independently verify the external access policy and design a separately reviewed alternative if that gate itself requires the lost mailbox. Never bypass Access by simply accepting ADMIN recovery on an unguarded portal route.
5. **Prove each factor still counts at use-time.** Bind TOTP and WebAuthn assertions to exact account, role, request, browser, factor identity/revision, expiry and purpose. A factor revoked or rotated before password mutation must not authorize based solely on an old `verifiedAt` timestamp. Confirm at the final transaction's account lock, and prove one winner under races.
6. **Keep email verification truthful and invitation/ADMIN purposes separate.** Original password reset always writes `User.emailVerifiedAt=now`; a passkey+TOTP recovery without mailbox access cannot be used as proof that the inbox was verified. Existing recovery requests, invitation links, and the separate administrative elevation credential must remain isolated, with all sessions, remembered devices, OIDC artifacts and older recovery attempts revoked consistently.

## Review before any push, merge, deploy or release

Require tested code for three two-factor pairs (PASSKEY+TOTP, PASSKEY+EMAIL, TOTP+EMAIL), assisted single-factor choices (each factor plus a **different**, active/elevated ADMIN), comment 300-character validation server-side, account-enumeration-resistant initiation and synthetic stage, expiry, replay, cross-role/client/response cookies, stale proofs, lost-inbox first-login bootstrap, identity provider/session revocation, and migrations on a disposable PostgreSQL instance.

Review UI must never show a success or next-step option merely because a client set a form field, selected a radio button, or forged completion flags. Entirely unsupported methods must be hidden or disabled, without implying that an enrolled factor exists. Avoid secret or comment text in audit events.

## Intermediate physical evidence (not evidence of the final commit)

All tests below used disposable/local test resources, not production. Their code snapshots and coverage differ; counts are **not additive proof for a later SHA**.

| Evidence source | Exact scope and result | Limitation |
| --- | --- | --- |
| PostgreSQL 18.6 WSL loopback, `127.0.0.1:55873`, `virki_integration_test` | 16 migrations, role-bootstrap allowlist corrected for `RecoveryEmailRebind`; four selected integration suites **23 PASS / 0 FAIL / 0 SKIP**; source integrated through `74240f7` | Before additional uncommitted administrative revocation patch; no all-method coverage |
| Separate disposable PG18 database `virki_w18_extended` | `administration.integration.test.ts` and `passkeys.integration.test.ts`: **51 PASS / 0 FAIL / 0 SKIP** in worker18 snapshot `b8d5b39` | Not final code tree; additional administrative sibling/OIDC regression not yet included in this result |
| Dedicated PG18 `virki_w18_extended`, updated administration source as in prime `9e411f5` | `administration.integration.test.ts` + `administration-totp.integration.test.ts`: **48 PASS / 0 FAIL / 0 SKIP** on the revocation patch (worker18, 73.9s) | Existing suite before adding explicit new sibling/challenge/OIDC test fixtures; still not the final combined test tree |
| Local Node22 authenticated SMTP TLS/STARTTLS/AUTH harness and disposable PostgreSQL | Five encrypted queued messages sent through Nodemailer localhost with retry, fail-closed TLS, one-use OTP, normal recovery, new-mailbox verification and old-mail notice tested; 5 `SENT` | Not the remote Brevo SMTP account or external deliverability; scratch-only harness |
| Edge 157 isolated CDP authenticator + PG18 | Six signed WebAuthn enrollment/authentication assertions passed, including USER/ADMIN RP separation and replay; eight PG passkey tests passed from scoped temporary copy; 14 RP-isolation tests passed | Direct auth function/browser harness; not Next HTTP/CSRF/cookie/Access E2E; did not yet establish both passkey recovery pairs |
| Worker20 standalone PG18 cluster, `127.0.0.1:55874/virki_w20_passkey_test` | All 16 Prisma migrations; five `recovery-multimethod.integration.test.ts` cases **5 PASS / 0 FAIL / 0 SKIP** on a worker test-only source based on `74240f7`, including real ECDSA P-256 signed recovery assertions for `PASSKEY_EMAIL`/`PASSKEY_TOTP`, wrong RP/origin, missing UV, wrong browser, replay, second-factor independence, verified replacement mailbox, concurrent one-winner reset | Cryptographic auth-module + real PG18, **not** a browser-driven Next HTTP/Server Actions/Access E2E; later cherry-pick/immutable-final-tree evidence must be recorded separately |
| Independent read-only review of administrative revocation additions | Reviewer9 SOURCE GO, no demonstrated P0/P1/deadlock, with P2 requiring physical assertions for sibling sessions, DeviceChallenge, account recoveries, OIDC and active normal-login factors | Reviewed patch against `74240f7` with local diff; does not replace final committed SHA review |
| Worker18 additional disposable PG18 regression | Two new backup/email administrative recovery cases **2 PASS / 0 FAIL / 0 SKIP** with revoked sibling sessions, remembered device, login challenge, pending passkey challenge, OIDC grant and pending account recovery; active session/normal password/TOTP preserved; full administration + TOTP suite **48 PASS** on these files | Changes cherry-picked as `44354fa`; result remains a specifically scoped earlier source snapshot, not an assertion that every later new test was rerun here |

### Browser E2E environment blocker

An independent worker attempted to use the repository's isolated Playwright/Docker E2E harness; the Docker Desktop Linux Engine pipe was unavailable (`npipe:////./pipe/dockerDesktopLinuxEngine`). It **did not execute** a real Next/Playwright recovery HTTP flow. Discovery of six pre-existing recovery tests is not execution evidence. The alternative Windows runner would modify the CurrentUser certificate trust store, so it was intentionally not used for this unattended security gate. No docker daemon was started, no global trust store modified, and no Cloudflare Access protection bypassed. Full cross-role HTTP/CSRF/cookie/TLS/browser tests remain a release blocker.

## Exact final code validation record (2026-11-09)

**Code SHA:** `45fb6fecc887b0392d67b15b6edb59c5074d5f99`.

**Git tree OID:** `3eb65de7ca64d8c2f769c847624c141ddc1903b8`. The code SHA contains the prior integrated fixes plus `44354fa` (physical administrative revocation regression), `651afb7` (signed USER passkey recovery pairs), `0137489` (guarded independent-ADMIN assisted recovery tests), `16f24ab` (ADMIN normal-password independent pairs) and `45fb6fe` (strict dedicated-PG guard; post-approval disabled-flag/revoked-passkey/rotated-TOTP tests; scanner-safe local variable names). No production code was changed to make the tests green.

Environment: **Windows 10 / official Node.js 22.22.1 / bundled npm 10.9.4 / Next.js 16.4.5**, in worktree `E:\Virki\.worktrees\virki-recovery-multichoice-prime-20261109-1505`; `PATH` prefixed with the verified standalone Node 22 toolchain. Each command below executed after committing code at the exact SHA above, before this documentation-only record was prepared.

| Executed command on code SHA `45fb6fe` | Result |
| --- | --- |
| `npm run test:unit` | **499 PASS / 0 FAIL / 8 SKIP** (507 total); eight are explicitly skipped integration/resource-dependent unit-suite entries, not physical PG successes |
| `npm run typecheck` | **PASS**, all selected workspaces |
| `npm run lint` | **PASS**, ESLint repository-wide with zero warnings |
| `npm run prisma:validate` | **PASS**, schema validation; not a production database mutation |
| `npm run secrets:scan` | **PASS**; earlier scanner false positives on two test-local `const password` names were removed by renaming variables, without weakening scanner rules |
| `npm run build` | **PASS**, optimized OIDC, Portal and Hub production builds |
| `git diff --check`; `git status --porcelain` | **PASS**, clean code snapshot |

Inspectable local command logs (ignored scratch only, **not committed**): `.virki-mission-tmp/final-45fb6fe/{test-unit,typecheck,lint,prisma-validate,secrets-scan,build}.log`. SHA-256 of the six logs, respectively: `99C7EB8BB61D20C91ABFCFF112414F87DE4BDD75DB6CA596E08309F70B2D2D2D`, `D3BABFB640A16BA1CB5843EB90663EAF176E63406587D01DCFACBE84D81DF5E8`, `D4D2245B27521AA3B7B5C91863AB60192323FE55B4451AB7BE0FDC843592C328`, `CDFEF97AC1B800A8ABD646579FCBCC8DE3F90439989B4BAA8CA5ABFDCB09FB87`, `E5F75AFA655D35423E517632F8FE2CFCFC5679A439350B8A7B260E49CFA5A09D`, `2790000ACC44CA1F9B289CAF8217B467D74E33BA40D56D62A3C4022E3E029B29`. The command process checked that `HEAD` and `HEAD^{tree}` had not changed across the entire gate.

### Physical PostgreSQL 18 and independent source review

| Code SHA / environment | Actual physical execution and outcome | Scope |
| --- | --- | --- |
| **`45fb6fe`**, PostgreSQL **18.6**, dedicated `127.0.0.1:55873/virki_w11_admin_pairs_prime`, role `virki_runtime_test` | `node scripts/integration/run.mjs packages/auth/src/recovery-admin-pairs.integration.test.ts`: **5 PASS / 0 FAIL / 0 SKIP** (8.05 s) | ADMIN normal password `TOTP_EMAIL`, signed Hub `PASSKEY_EMAIL`, signed Hub `PASSKEY_TOTP`, new-mailbox-before-reset, one-winner, wrong RP/origin/UV/browser/role, replay and three post-approval fail-closed negatives (flag off, passkey revoked, TOTP rotated) |
| **`0137489`**, dedicated PG18 `virki_w2_assisted_prime` (16/16 migrations) | `node scripts/integration/run.mjs packages/auth/src/recovery-assisted.integration.test.ts`: **4 PASS / 0 FAIL / 0 SKIP** | `EMAIL_ADMIN`, `TOTP_ADMIN`, signed Hub `PASSKEY_ADMIN`, different eligible/elevated reviewer, reviewer demotion/revocation, self-review denial, new inbox proof; source logic was unchanged at final code SHA, but this execution is labeled as earlier |
| Worker20 `74240f7`-based source, separate PG18 `virki_w20_passkey_test` (16/16 migrations) | `node scripts/integration/run.mjs packages/auth/src/recovery-multimethod.integration.test.ts`: **5 PASS / 0 FAIL / 0 SKIP** | USER `EMAIL_TOTP`, signed `PASSKEY_EMAIL` and `PASSKEY_TOTP`, replay, independent proof, replacement email and one-winner; commit later integrated as `651afb7` |
| Worker18 updated administrative source matching `9e411f5` and committed regressions `44354fa`, PG18 `virki_w18_extended` | `administration.integration.test.ts` + `administration-totp.integration.test.ts`: **48 PASS / 0 FAIL / 0 SKIP** | ADMIN separate-credential backup/e-mail/TOTP recovery; old passkeys, challenges, OIDC and sibling sessions revoked; active TOTP and normal login password preserved |

All test databases above were confirmed disposable loopback resources. For the exact-final ADMIN-pair suite, the additional SQL witness reported PostgreSQL 18.6, 16/16 migrations, isolated database name, scoped runtime role and DML rights but **no Prisma migrations-ledger SELECT** for that role. The guarded runner required a matching test-role `DATABASE_URL` and `VIRKI_INTEGRATION_DATABASE_URL`, `VIRKI_CORE_TEST_DATABASE_CONFIRM=disposable`, and no production endpoint. No shared database, global PostgreSQL cleanup, live SMTP or external email was used.

**Independent read-only SOURCE GO:** reviewer9 checked ancestor `0137489` and then the exact `45fb6fe` delta. At `16f24ab` it identified two **P2** test findings (dedicated-DB isolation and missing stale-factor/flag negatives). Both were fixed in `45fb6fe` and independently reviewed again: **P0=0, P1=0, P2=0** for the combined code/source candidate. This is not a runtime Hub HTTP/Cloudflare approval or a hosted CI result.

### Coverage matrix and residual boundaries

| Flow | Confirmed scope | Not established |
| --- | --- | --- |
| Separate ADMIN credential: normal password + verified email / saved ADMIN code / active one-use TOTP | Real PG18 administrative recovery/revocation suite and single-use/CAS/source checks; normal password/TOTP preserved, old ADMIN passkeys and sibling proofs revoked | Cold external Access reauthentication without old mailbox |
| Normal password: `TOTP_EMAIL`, `PASSKEY_EMAIL`, `PASSKEY_TOTP` | PG18 real for ADMIN on exact code SHA (5 tests) and for USER in worker20 standalone PG snapshot; real ECDSA P-256 signed WebAuthn assertions | All combinations through full Next Hub/Portal HTTP/CSRF/cookies/TLS/browser in production-like Access context |
| Normal password: `EMAIL_ADMIN`, `TOTP_ADMIN`, `PASSKEY_ADMIN` | PG18 (4 tests) with different active/elevated reviewer and negative cases, signed Hub RP, new verified mailbox before reset; ADMIN and USER examples | Cold alternate ADMIN reviewer reaching Hub if outside the `Owner only` Cloudflare policy |
| UI, comments and enumeration | Unit/source checks for exactly six visible methods, assisted option hidden without another eligible ADMIN, 300 Unicode code points (including emojis), synthetic request IDs and unproven GET state, CSRF-bound Server Actions | Full real-browser HTTP/POST enumeration timing, cookie lifecycle, and end-to-end protected navigation |
| SMTP and WebAuthn transports | Authenticated STARTTLS SMTP localhost harness with five messages `SENT` and negative/retry checks; Edge 157 CDP signed USER/ADMIN ceremonies and separate RP isolation tests | Brevo SMTP external deliverability, final multi-method Next HTTP/browser ceremony, production Cloudflare Access session renewal |

No `git push`, merge, deploy, production DB/SMTP mutation, Cloudflare policy change or real external message delivery was performed. Hosted GitHub Actions/CodeQL **were not run** on this local branch SHA. Later documentation-only commits must not recharacterize this code SHA's validated test results as tests actually rerun on a different code tree.

### Coverage that must not be inferred

Three normal-password pairings are `PASSKEY_EMAIL`, `PASSKEY_TOTP` and `TOTP_EMAIL`; assisted methods are `PASSKEY_ADMIN`, `TOTP_ADMIN` and `EMAIL_ADMIN`. Merely listing these in UI or passing source-boundary tests does not prove cryptographic, database-transactional or full HTTP behavior of each method. Even if final PostgreSQL tests pass, a protected real Hub/Portal browser test, a cold ADMIN mailbox-loss case under `Owner only`, real Brevo SMTP delivery and hosted CI of the final SHA remain **not established** unless separately executed and documented. The release decision for that case is **NO-GO** without bypassing Cloudflare Access.
