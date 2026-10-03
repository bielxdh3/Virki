# BielOS journey matrix

This matrix is the acceptance contract for the recovery work. It describes the expected user-visible behavior and the evidence still needed; a passing unit test alone does not prove a browser journey. No production behavior is inferred from local tests.

## Status key

- **Partial** — some policy or route tests exist, but the complete user journey is not proven.
- **Missing** — no matching journey-level evidence was found in the current test inventory.
- **Blocked** — the required check could not run with the current local tooling or external state.
- **Observed gap** — the current rendered state has a concrete usability gap.
- **External gate** — requires DNS, Cloudflare, a native Linux host, or operator-owned state.

Current test evidence at the start of this matrix: unit tests passed 85/85 and public-site tests passed 3/3. Browser E2E is **blocked** because the pinned Playwright Chromium is unavailable; the bounded install attempts timed out. E2E specs currently cover public entry, selected authenticated journeys, and JWKS service behavior, not the full matrix below. The migration and backup/restore checks are blocked because the Docker engine is unavailable. These statuses must be updated only after a relevant change or a new available prerequisite.

## Public entry

| Journey | Preconditions | Expected navigation, HTTP, and UI | Security and audit | Failure behavior | Current evidence |
|---|---|---|---|---|---|
| Visitor opens `biel.dev.br` | Public site deployed | Known public host returns 200 with sparse BielOS identity and a clear portal-entry state | No identity, project, or security data disclosed; no auth audit event | Site failure is explicit; never imply the portal is available when it is not | **Partial** — public-site test and screenshot; browser E2E blocked |
| Visitor selects Entrar, portal configured | Valid canonical public portal URL and route | CTA opens the configured portal origin over HTTPS; portal shows login without a valid session | No forwarding of public-site cookies or session | Invalid/non-HTTPS URL is rejected and CTA is not rendered | **Partial** — public-surface tests; DNS/Cloudflare route is an **external gate** |
| Visitor selects Entrar, portal unavailable or unconfigured | `BIELOS_PORTAL_URL` absent/invalid | No link to a guessed or nonexistent hostname; page explains that entry is unavailable | No fake auth result or unsafe redirect | A clear safe next step is required; current screenshot shows only an unavailable notice and no next step | **Observed gap** — public page test covers hidden CTA; reviewer saw no alternative |
| Request uses an unknown hostname | Host is not a configured public, portal, or Hub surface | 404 with no surface-specific redirect | Ignore untrusted forwarding headers; do not reveal protected surface data | Fail closed with a neutral response and no cookie mutation | **Partial** — surface/proxy unit tests; no browser journey |

## Portal — unauthenticated

| Journey | Preconditions | Expected navigation, HTTP, and UI | Security and audit | Failure behavior | Current evidence |
|---|---|---|---|---|---|
| Portal root, no cookie | Valid portal host | Login route, 200 page after navigation; return target is a safe portal path | No session assumed from cookie presence; no Hub route selected | Invalid return target falls back to portal root | **Partial** — proxy/surface tests; E2E blocked |
| Portal root, stale, expired, revoked, or malformed cookie | Cookie supplied but session invalid | Clear or ignore invalid cookie and show login; no forbidden dead end | Resolve session server-side; never treat cookie presence as identity | Generic login-required state; no internal origin redirect | **Partial/Missing** — policy coverage exists, complete cookie-to-browser cases are missing |
| Login with valid password, no MFA | Active USER or ADMIN account on correct surface | Redirect to role-appropriate portal/Hub destination; success page is not a dead end | Password verification, account-state check, source/account rate limits, session cookie host-only | Unavailable canonical redirect origin fails safely | **Partial** — route/security unit tests; browser login flow not proven |
| Invalid password, unknown email, disabled account | Login form submitted | Same generic authentication response and status family; no account-specific copy | Dummy hash and rate limits where applicable; sanitized audit | No session and no enumeration | **Partial** — auth unit tests; no browser negative-flow evidence |
| Login rate-limited | Source or account threshold exceeded | Generic throttled response with safe retry guidance | Atomic/consistent limits; no user-specific leak; audit records the denial | No credentials accepted until limit window allows | **Partial** — rate-limit tests; no route-level browser proof |
| MFA required after password | Valid password and active MFA | Navigate to verification form with clear next step | Challenge bound to pending login; no authenticated session before success | Expired/missing challenge returns to login safely | **Partial** — security and route tests; E2E MFA journey missing |
| Invalid or replayed MFA code | Active pending challenge | Keep user on a useful verification/error state without creating a session | TOTP replay prevention; one-time recovery-code consumption | Generic failure; challenge/session state remains bounded | **Partial** — security unit tests; browser replay journey missing |
| Recovery request for any address | Valid form input | Same generic confirmation response and status for active, inactive, and unknown addresses | Normalize/rate-limit input, do not send mail to unknown users, no raw email/token/code in audit | Missing delivery URL is a controlled unavailable state; no unsafe redirect | **Partial** — recovery/security tests; timing and browser response parity not proven |
| Recovery email link valid, invalid, expired, or replayed | Explicit configured recovery URL and link token | Valid link opens a clear confirmation/reset step; invalid states return to a safe portal page | Hash tokens at rest, enforce expiry/one-time use, bind proof to account | Generic safe failure; never put secrets in logs or redirect targets | **Partial** — helper tests; recovery-open browser states missing |

## Portal — authenticated USER

| Journey | Preconditions | Expected navigation, HTTP, and UI | Security and audit | Failure behavior | Current evidence |
|---|---|---|---|---|---|
| USER with zero grants | Active USER session | Portal explains that no projects are available and links to account/security/logout | Query only enabled projects with active explicit USER grants | No empty technical error or admin navigation | **Partial** — portal source test; browser empty state missing |
| USER with one or more grants | Active USER, enabled projects, active grants | Show only eligible projects with one clear Acessar action each | Recheck account, project, and grant state on every authorization | Missing/disabled grants disappear or deny launch | **Partial** — one authenticated E2E journey exists; multiple-project case missing |
| Grant revoked or project disabled after login | Existing session and prior grant | Project is removed or launch denied on next request | Live DB authorization; stale page/session cannot issue OIDC authorization | Safe project-access denial; audit denial without secret data | **Partial** — policy tests; browser race/stale-state journey missing |
| USER disabled after session creation | Existing session | Subsequent protected requests return to login or a clear disabled state | Recheck account active state; revoke sessions and auth artifacts | No continued portal or OIDC access | **Partial** — account state tests; browser journey missing |
| USER opens account security | Valid USER session | Account/security page loads without Hub admin navigation | Read-only access does not require admin elevation | Expired session returns to login with safe return target | **Partial** — route/unit coverage; visual flow incomplete |
| USER logs out | Valid or stale cookie | Cookie cleared; navigate to correct surface login/public page | Host-only cookie deletion uses matching attributes | If no safe public origin exists, return controlled response without unsafe Location | **Partial** — logout route tests pass; browser logout journey missing |
| USER launches granted project | Valid USER and current grant; configured OIDC client | Acessar starts the documented authorization-code flow at BielOS issuer | Exact client/redirect, PKCE S256, state, nonce, live account/project/grant | Invalid launch configuration fails before leaving BielOS | **Partial** — policy/E2E pieces exist; full relying-party handoff missing |
| USER attempts ungranted project or wrong client/redirect | Valid USER, but authorization mismatch | Deny without issuing code or token | Server-side grant and exact redirect/client checks; sanitized denial audit | No open redirect and no project session | **Partial** — authorization policy tests; browser negative flow missing |

## OIDC / SSO

| Journey | Preconditions | Expected navigation, HTTP, and UI | Security and audit | Failure behavior | Current evidence |
|---|---|---|---|---|---|
| Authorization Code + PKCE S256 | Registered client, exact redirect, active USER grant | Authorization endpoint and interaction lead to one short-lived code, then token response | Bind code to client, redirect, S256 challenge, subject, state, and nonce | Unsupported response type or PKCE downgrade is denied | **Partial** — policy/adapter tests; full relying-party exchange missing |
| State and nonce valid/missing/mismatched | Authorization flow in progress | Successful return only when supplied values validate at the relying party/provider boundary | Preserve client binding and nonce in signed ID token | Missing/mismatched values fail without code/token | **Partial** — helpers tested; browser relying-party assertion missing |
| Wrong client, redirect, verifier, or audience | Valid endpoint request with one invalid binding | Deny with protocol-safe response | Exact matching; issuer/audience/signature checks | No code/token leakage; denial audit is sanitized | **Partial** — policy tests; integration-negative suite missing |
| Authorization code expires or replays | Previously issued code | First valid exchange only; subsequent/expired use denied | One-time atomic consumption and expiry | Do not mint a second token; record safe denial | **Partial** — adapter tests; concurrent replay integration missing |
| Grant revoked mid-flow | Authorization interaction/code exists | Complete only if live grant still exists at authorization completion/exchange | Recheck current grant and project/account state at use time | Deny without relying on stale earlier approval | **Missing** — no journey-level race evidence |
| Account or project disabled mid-flow | Flow started while active | No new authorization/token after state change | Live account/project check and artifact invalidation where required | Safe denial; do not claim external RP session is revoked | **Partial** — unit policies; mid-flow integration missing |
| Client secret rotation | Existing client, old secret, rotated new secret | New credential is display-once; only valid active credential works | Store hash/secret material safely; invalidate relevant old artifacts | Old secret fails; response/logs never disclose it | **Partial** — helper coverage; lifecycle browser/integration missing |
| Cross-project token acceptance | Token from project A presented to project B | Project B rejects token with wrong audience/client binding | Signature, issuer, audience, and client validation | No identity/session created on mismatch | **Missing** — dedicated relying-party integration fixture not proven |
| Logout and already-issued tokens | Existing provider token/project session | BielOS logout ends central session; project owns its local session semantics | Invalidate central proofs/artifacts where defined; document access-token lifetime | Do not promise remote logout or revoke already-issued signed tokens | **Partial** — docs describe relying-party ownership; multi-party smoke missing |

## Hub / ADMIN boundary

| Journey | Preconditions | Expected navigation, HTTP, and UI | Security and audit | Failure behavior | Current evidence |
|---|---|---|---|---|---|
| Missing/invalid/expired Cloudflare Access | Hub host | Outer Access boundary denies before BielOS admin content | Validate issuer, audience, signature, expiry, and email policy | Never fall through to USER portal or admin login | **Partial** — Access verifier unit tests; real Access gate is external |
| Valid Access, no BielOS session | Hub host and valid Access identity | Hub login screen, not `/admin/*` forbidden page | Access is only outer boundary; BielOS auth remains required | Safe Hub login; no internal origin redirect | **Partial** — screenshot captured; browser Access simulation missing |
| Valid Access, stale/revoked/malformed session cookie | Valid Access, invalid BielOS session | Clear/ignore stale cookie and show Hub login | Server-side session validation; no cookie-presence trust | Never dead-end at generic forbidden page | **Partial** — proxy tests; end-to-end stale-cookie case missing |
| Valid Access plus USER session | USER session | Clear Hub denial explaining ADMIN access is required | Enforce role on server and every admin action | No portal behavior on Hub, no admin data disclosure | **Partial** — admin policy tests; browser journey missing |
| Valid Access plus ADMIN session | Active ADMIN session | Hub control plane with only Contas, Acessos, Segurança, Auditoria, Conexões | Require fresh proof only for policy-defined mutations | Expired/revoked session returns to login | **Partial** — admin route tests; full nav/browser evidence missing |
| Hub root and direct `/admin/*` entry | Any role/session combination above | Root makes one intentional auth/role decision; direct routes follow the same state machine | Do not redirect before Access/session/role resolution | Missing auth leads to login; USER to admin denial; ADMIN to requested admin page | **Partial** — root/proxy coverage does not prove all states |
| Fresh proof required / expired / wrong scope | ADMIN performs sensitive operation | Explain how to complete proof and return to the intended action | Proof is session-bound, scoped, short-lived, audited | No vague “check elevation” dead end; no action without proof | **Partial** — policy/action tests; UX completion flow missing |
| ADMIN logout | Valid Access and ADMIN session | Revoke central session and show Hub login or public landing safely | Clear cookie, audit logout, keep Cloudflare outer boundary intact | No redirect to portal or untrusted host | **Partial** — route tests; browser journey missing |

## Contas and Acessos

| Journey | Preconditions | Expected navigation, HTTP, and UI | Security and audit | Failure behavior | Current evidence |
|---|---|---|---|---|---|
| Create USER | ADMIN with required fresh proof | Form explains bootstrap credential and email-verification status | Server creates USER only; hash password; audit actor/action | Invalid or duplicate email is actionable without disclosure of unrelated account data | **Partial** — action/unit coverage; full browser journey missing |
| Invalid/duplicate email and password policy | ADMIN form submission | Inline field errors and preserved safe form state | Normalize/validate server-side; no plaintext credential logging | No account mutation on invalid input | **Partial** — unit/action tests; browser error associations missing |
| Email verification semantics | New USER not yet verified | UI accurately says whether email is verified and how to complete verification | `emailVerifiedAt` only set after mailbox proof | No `email_verified=true` based solely on admin provisioning | **Partial** — helper tests; complete user journey missing |
| Disable and reactivate account | ADMIN, active target account | Confirm consequence, then show current status and available next action | Revoke sessions/proofs/OIDC artifacts and open recovery proofs atomically | Reactivation does not revive stale recovery authorization | **Partial** — action tests; recovery race needs coverage |
| Grant USER access to project | ADMIN with proof, active USER, enabled project | Confirm project/user and show resulting access | Server enforces USER-only; enforce uniqueness and live state | Reject ADMIN, disabled USER/project, stale proof | **Partial** — grant policy tests; browser/concurrency proof missing |
| Duplicate grant, revoke, and regrant | Existing USER/project relation | Idempotent or clearly reported result; revoke changes visible status | Transactional uniqueness, actor/action audit, fresh proof | No stale grant continues authorizing after revoke | **Partial** — policy/action tests; concurrency journey missing |
| ADMIN grant attempt; disabled target/project | ADMIN or inactive entities submitted | Clear denial; no grant created | Never rely on UI filtering; server checks role and live state | Generic safe denial and audit | **Partial** — target page tests; all denial permutations missing |

## Segurança / account recovery

| Journey | Preconditions | Expected navigation, HTTP, and UI | Security and audit | Failure behavior | Current evidence |
|---|---|---|---|---|---|
| Admin credential setup/change/recovery | ADMIN session; recovery may be needed before elevation | Explain setup, change, or recovery path and return to security page | Current password/factor proof; one-use recovery code; scoped fresh proof where applicable | Recovery path must not require the elevation it restores | **Missing** — helper exists but no reachable recovery UI/action found |
| Proof expiry/scope/session binding | ADMIN starts sensitive operation | Proof progress and expiry are clear | Time-bounded, session-bound, action-scoped, audited | Wrong/expired proof denies action and provides restart path | **Partial** — policy tests; browser UX missing |
| TOTP enrollment, verify, disable, replay | USER or ADMIN security page | Clear QR/setup, confirmation, and recovery-code display state | Encrypt TOTP secret, rate-limit, prevent replay; rotate sessions/proofs as policy requires | Bad/replayed code creates no mutation | **Partial** — security unit tests; E2E enrollment/replay missing |
| Recovery-code use and device/session revoke | Authenticated user; valid one-time credential as applicable | Show remaining/revoked state without exposing full codes again | Hash one-time codes; revoke only intended device/session; audit redacted | Replay fails; no raw token/code/email in audit | **Partial** — unit tests; browser path missing |
| Recovery request, verification, ADMIN approval, completion | Active user and configured recovery workflow | Generic confirmation, explicit pending/approved state only after proof, safe completion page | One-time links, admin proof, account active-state recheck, serialized disable/request transitions | Unknown user is not enumerated; old pending proof cannot revive after reactivation | **Partial** — helper tests; disable race and timing ordering need proof |

## Auditoria

| Journey | Preconditions | Expected navigation, HTTP, and UI | Security and audit | Failure behavior | Current evidence |
|---|---|---|---|---|---|
| Auth, Access, MFA, recovery, grants, connections, OIDC, fresh-proof events | Relevant action occurs | Admin audit view identifies correct surface, actor, target/correlation, action, and time | Redact credentials, tokens, raw email from unverified recovery, and security payloads | Failed audit write does not silently authorize a protected mutation | **Partial** — sanitizer/gate tests exist; end-to-end event mapping incomplete |
| Login/recovery surface attribution | Public, portal, or Hub request | Event resource reflects the actual surface/action | Never label portal events as Hub by default; unverified requester is not recorded as victim actor | Unknown target is represented safely | **Partial** — login audit tests; full route mapping missing |
| Pagination, filters, details | ADMIN with valid session | Stable bounded pagination and filters; no empty technical state | Server-side authorization and bounded query parameters | Invalid cursor/filter fails safely | **Missing** — browser journey not identified |

## Conexões

| Journey | Preconditions | Expected navigation, HTTP, and UI | Security and audit | Failure behavior | Current evidence |
|---|---|---|---|---|---|
| Create/view/edit connection | ADMIN with required proof; registered external relying party | Form supports safe routine corrections to name, description, origin, redirects, and launch contract | Validate canonical HTTPS origin and exact redirect allowlist; audit actor/action | Invalid origins, wildcard redirects, and cross-origin launch URLs are rejected | **Partial** — connection-policy tests; full CRUD/browser evidence missing |
| Enable/disable connection | Existing connection | State and impact are explicit; disabled entry cannot launch | Recheck project enabled state at authorization; audit | No old OIDC interaction authorizes after disable | **Partial** — policy/issuer tests; browser transition missing |
| Rotate client secret | Existing client and ADMIN proof | Secret shown once with clear copy/close state | Store safely, never echo later, invalidate old secret/artifacts as defined | Old credential fails; no secret in errors/audit | **Partial** — secret helper tests; full lifecycle missing |
| Delete connection | Existing client and ADMIN proof | Proportional confirmation names affected relying party and consequences | Delete/revoke related provider artifacts consistently; audit | Cancel leaves all state unchanged | **Partial** — no full destructive-action browser proof |
| Launch contract | Enabled project and active USER grant | Acessar starts a deterministic OIDC authorization URL, not an implicit project homepage assumption | Standard OIDC Authorization Code + PKCE; exact redirect/client/state/nonce | Misconfigured launch fails before leaving BielOS | **Missing/Partial** — protocol units exist; relying-party integration not proven |
| Edit origin/redirect after artifacts exist | Existing client with in-flight OIDC data | Change is explicit and understandable | Old artifacts cannot authorize under changed config; exact redirect binding | Invalid changes do not partially update state | **Partial** — adapter/policy coverage; in-flight lifecycle missing |

## Evidence that closes a row

Update a row to **Proven** only when the linked focused tests cover both success and denial paths, browser behavior is inspected where the row is user-facing, and any external dependency is separately verified. Keep blockers visible. The current high-priority implementation risks are canonical redirect origin handling, recovery proof serialization with account disable, USER-only grants, OIDC artifact semantics, and reachable administrative credential recovery.
