# Normal-password recovery: source and release gates

Date: 2026-11-09. Status: **local integration under validation; release NO-GO until remaining external gates and exact-source evidence are satisfied**.

## Provenance: historical baseline versus current integrated candidate

Local branch: `feat/virki-recovery-multichoice-prime-20261109-1505`. Base `main` remains at `7c8914ed222f0672ccc87e0331daf6a4c3f0f5a7`; **no push, merge, deploy, production database changes, or real email sends**. The base `a814ed847688647b564099bd71ca1b4c7bd93e78` contains previous reviewed source and its initial evidence document. Later security fixes, additional PostgreSQL integration tests and Cloudflare policy findings are separate changes.

**Historical evidence only — not the final candidate:** commit `f72d0808a28fc473dba3e696dc420af21f6244c5` passed the full production build of OIDC + Portal + Hub and `npm run test:unit` with **496 passed, 0 failed, 8 skipped**, plus TypeScript, lint, Prisma validate, secret scan on official SHA-256-verified Node 22.22.1 with clean Next.js 16.4.5 installation. These checks **predate** the later code and integration-test changes and must **not** be cited as the validation of any successor SHA. The earlier `/_global-error` E1068 in contaminated dependencies did not reproduce after clean install; that is historical diagnosis only.

Later locally committed fixes include `9e411f5f66e9aefa2c8f6983802a7a7f7f5c01db` (administrative backup/email recovery now revokes sibling sessions, remembered devices, pending authentication and recovery proofs, OIDC artifacts and old passkeys in the same transaction) and `c46f004e9597ab3c611b9246d455a0900322b61a` (backend rejects undocumented three-factor selections; only three distinct pairs or one proof plus independent ADMIN are accepted). The `c46f004` changed-methods focused test run passed **10/10**, focused ESLint and `git diff --check` passed, but this does not replace full final CI-equivalent validation.

**Current candidate SHA and exact-tree commands/results:** see the final validation record below. The final publishable-tree evidence and independent source peer must be recorded after all changes are committed. PostgreSQL, SMTP and Edge checks performed against intermediate snapshots are identified as such and are not silently promoted to exact-final-SHA evidence.

## Implemented recovery contracts

Implementation now provides distinct normal-password recovery choices: any two independent proofs among registered passkey, active TOTP, and verified email OTP, or any one of these plus approval by a **different eligible active ADMIN** and an optional comment capped at 300 characters. Factor selection and proofs are persisted and bound to the exact account, role, request, challenge and browser capability. Synthetic requests are constructed to avoid leaking account existence via request IDs. Changing a factor or letting a proof expire before final consumption fails closed. ADMIN passkeys enroll against the separate hub RP, with current ADMIN session and independent elevation; this does not turn on passwordless ADMIN login.

For a pair/assisted method not proving the old mailbox, a **new mailbox must be independently verified before replacing login password/email or revoking existing authenticators**. The completed recovery revokes old login MFA, sessions and devices; a short-lived bound bootstrap session lets the owner safely continue. The separate **administrative elevation credential** retains its own recovery choices: current normal password plus (a) verified e-mail code, (b) saved administrative recovery code, or (c) currently active one-use TOTP. The TOTP path rotates the independent credential and ten backup codes, revokes old admin passkeys, elevations and sibling sessions, but preserves the normal login password and active login TOTP.

**Release remains NO-GO** even after isolated tests: the exact publishable tree still needs its complete local CI-equivalent gate and independent peer review, full Next UI HTTP/CSRF/cookie browser E2E for recovered USER/ADMIN at both RPs must be demonstrated, and Cloudflare Access must be independently shown to allow authorized ADMIN lost-mailbox recovery **without bypassing Access**. Real production Brevo SMTP deliveries, live hosted CI, deployment and the actual cold-browser Access reauthentication path are not demonstrated. ADMIN passkey functionality requires a separately reviewed feature flag. Green local build/unit/PG18 does **not** authorize a production release.

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
| Worker18 additional disposable PG18 regression | Two new backup/email administrative recovery cases **2 PASS / 0 FAIL / 0 SKIP** with revoked sibling sessions, remembered device, login challenge, pending passkey challenge, OIDC grant and pending account recovery; active session/normal password/TOTP preserved | Separate worker source snapshot pending test-only cherry-pick and final PG18 rerun |

### Browser E2E environment blocker

An independent worker attempted to use the repository's isolated Playwright/Docker E2E harness; the Docker Desktop Linux Engine pipe was unavailable (`npipe:////./pipe/dockerDesktopLinuxEngine`). It **did not execute** a real Next/Playwright recovery HTTP flow. Discovery of six pre-existing recovery tests is not execution evidence. The alternative Windows runner would modify the CurrentUser certificate trust store, so it was intentionally not used for this unattended security gate. No docker daemon was started, no global trust store modified, and no Cloudflare Access protection bypassed. Full cross-role HTTP/CSRF/cookie/TLS/browser tests remain a release blocker.

## Final validation record (complete only after the last code integration)

**Status at document preparation:** pending exact final code SHA and gates. The earlier `f72d0808` build and 496 PASS / 8 SKIP are historical, not current. Do not mark this record successful until each test command has actually run on the immutable final code snapshot.

Record separately: (1) final code SHA and Git tree OID; (2) Node/OS versions; (3) `npm run test:unit` PASS/FAIL/SKIP; (4) `npm run typecheck`, `npm run lint`, `npm run prisma:validate`, `npm run secrets:scan`, `npm run build`, `git diff --check`; (5) exact PG18 test files/database and any retries; (6) reviewer SHA and P0/P1/P2 findings; (7) final documentation-only SHA if distinct, with confirmation that no code changed; (8) clean branch and untouched `main`.

### Coverage that must not be inferred

Three normal-password pairings are `PASSKEY_EMAIL`, `PASSKEY_TOTP` and `TOTP_EMAIL`; assisted methods are `PASSKEY_ADMIN`, `TOTP_ADMIN` and `EMAIL_ADMIN`. Merely listing these in UI or passing source-boundary tests does not prove cryptographic, database-transactional or full HTTP behavior of each method. Even if final PostgreSQL tests pass, a protected real Hub/Portal browser test, a cold ADMIN mailbox-loss case under `Owner only`, real Brevo SMTP delivery and hosted CI of the final SHA remain **not established** unless separately executed and documented. The release decision for that case is **NO-GO** without bypassing Cloudflare Access.
