# Issue #119 — defensive maintenance and acceptance boundaries

This revision continues the repository-owned work for issue #119 from starting main revision `669e897d0adf3d0457d18ff680b7cf2123a2885d` and PR #137. It records the public-site CSP baseline, makes OIDC grant/CORS behavior explicit, and hardens recovery-action surface and CSRF checks. It does not authorize merge, deployment, production activation, or external configuration changes.

## Public-site CSP

The public site uses the Next.js 16 request-time nonce pattern (see [Next.js CSP guide](https://nextjs.org/docs/app/guides/content-security-policy)). Its proxy sets the document policy and its root layout renders HTML dynamically, including the framework's not-found page. The production script policy no longer permits generic inline scripts; all other existing directives are retained, including the inline-style allowance needed by the default not-found document. Development retains the framework's existing eval allowance. Hub and Portal application configuration and the existing powered-by-header suppression from PR #132 remain unchanged.

The local browser validation covered normal 200 and 404 documents, matching script nonces, fresh nonces across requests, and absence of ordinary execution errors. Production HTML was private/no-store. Development-specific runtime-added nodes are not counted as scripts emitted by the server document; the regression checks the actual document response. The existing browser suite now includes not-found coverage and checks the normal landing document before navigating to the Portal. This is local/DEV evidence, not a live-edge attestation.

## OIDC discovery alignment

The supported protocol in `docs/sso-integration.md` is Authorization Code with PKCE S256. The existing client defaults and project registration adapter already select `code` and `authorization_code`. The discovery configuration now explicitly advertises only `code`, instead of inheriting broader library defaults. The ordinary local discovery fixture asserts that contract. There is no change to stored client secrets, accounts, grants, or session policy.

The provider configuration limits scopes to `openid`, `profile`, and `email`, keeps `authorization_code` as the only supported grant, and explicitly supplies a client-based CORS policy. `/userinfo` permits only an origin matching a redirect URI registered for that client; other client-bound CORS routes are limited to registered public clients. Opaque `Origin: null` values are denied. The response-policy middleware preserves public wildcard access for discovery, JWKS, and credential-issuer metadata, removes `Access-Control-Allow-Credentials` before downstream provider code can end a response, and strips reflected origins from non-preflight client-bound errors when no client was assigned. Its post-response cleanup is guarded by `response.headerSent`, avoiding header mutation after `interactionFinished()` has ended the response.

The local protocol test uses an actual `oidc-provider` client and an issued access token. It verifies an allowed registered origin, a rejected attacker origin, rejection of `Origin: null`, preflight without credentials, and an invalid bearer returning 401 without readable CORS. The PostgreSQL-backed issuer integration suite exercises the same policy with a database-registered client and the production-equivalent discovery configuration. A direct-response regression also verifies that the middleware does not mutate headers after a provider path has ended the response.

The token endpoint now explicitly emits both `Cache-Control: no-store` and `Pragma: no-cache`, including rejected token exchanges. `oidc-provider` already supplies `no-store`; the issuer middleware adds the RFC 6749 §5.1 `Pragma` requirement before the provider can end the response. `/me` and `/token/revocation` are also explicitly no-store. Local HTTP tests assert the real successful public-client token response, rejected public/confidential exchanges, and `/me` error response. Dynamic CORS responses retain `Vary: Origin`; preflight is not treated as authorization, and the actual client-bound response still enforces the registered-origin policy.

## Recovery access and CSRF

Anonymous recovery actions now derive the expected `USER` or `ADMIN` role from the exact configured host and required surface. Unknown hosts, surface mismatches, and hostname-suffix spoofing fail closed. The ADMIN path still requires Cloudflare Access. Before reading recovery input or performing a mutation, the action requires same-origin and a CSRF token scoped to that action (`recovery-request`, `recovery-admin-request`, `recovery-open`, `recovery-verify`, or `recovery-complete`). Existing authenticated approval actions retain their session-bound CSRF checks.

The Hub forms already carry the matching hidden tokens. Focused tests cover the helper's host/surface decisions, same-origin checks, missing/invalid tokens, wrong scopes, external and `null` origins, and port mismatches. Completion and modern recovery transitions use a same-origin Web Lock so two tabs serialize the final state transition; the server still consumes the approved recovery state transactionally. The source-contract test asserts the extracted helper boundary and preserves the order: surface/role rejection, ADMIN Access validation, then origin and scoped-CSRF validation.

The complete exported Server Action call graph in `apps/hub/src/app/recover/actions.ts` was reviewed against its callers in `recover/page.tsx`, `recovery-request-form.tsx`, `recovery-switch-form.tsx`, `recovery-verification-form.tsx`, `recovery-proof-stage.tsx`, `recovery-new-mail-stage.tsx`, and `recovery-completion-form.tsx`. Request, resume, legacy-link open/switch, email/TOTP/passkey proofs, new-mailbox verification, and completion all use `requireRecoveryAccess` with the corresponding scope. The separate administrator approval action requires the Hub surface, Cloudflare Access, same-origin, session-bound `admin-security` CSRF, an active ADMIN session, and security elevation. The account-security email-rebind actions remain authenticated session-bound mutations, not anonymous recovery endpoints.

Production recovery cookies use `__Host-` names, `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`, and no `Domain`; development uses separate non-prefixed names. Session cookie policy remains unchanged. Start, resume, legacy switch and completion serialize cookie mutation with the same per-origin Web Lock; browsers without Web Locks fail closed rather than silently submitting a concurrent cookie mutation.

## Cloudflare read-only configuration snapshot — 2026-11-21

The connected Cloudflare account was inspected with GET-only API calls. No Access application, policy, TLS, DNS, Tunnel, or production setting was changed.

- The `hub.biel.dev.br` self-hosted Access application exists and has one owner-only allow policy. The app and policy session durations are 168 hours. This matches the Hub's ADMIN perimeter; the application code independently fails closed when the Access assertion is missing or invalid.
- No Access application for `portal.biel.dev.br` was returned. This matches the intended split: Portal is the public USER surface, while Hub is the protected ADMIN surface. The app's recovery Server Actions still bind the role to the exact host and require same-origin plus scoped CSRF.
- The zone-level `min_tls_version` is still `1.0`; the zone SSL mode is `flexible`. This confirms that the TLS hardening item in issue #119 remains unresolved in Cloudflare configuration. The original issue records TLS 1.0/1.1 handshakes accepted on all three public hosts; this API read confirms the current zone setting but does not repeat the handshake test. `flexible` is recorded as the configured mode, not as proof that a particular Tunnel origin hop is plaintext.
- The user explicitly prohibited Cloudflare/TLS/production changes in this work. Therefore the TLS minimum was not raised, SSL mode was not changed, and no Tunnel or DNS setting was touched. This remains a production hardening blocker outside the code PR.

## Acceptance boundaries

- PR #132 already implemented powered-by-header suppression; its hosted evidence should not be repeated without cause.
- The fresh Cloudflare API read still reports minimum TLS 1.0 and SSL mode `flexible`. TLS 1.2 minimum and compatibility validation remain a separate authorized-infrastructure decision; this task's no-Cloudflare-change boundary was respected.
- Historical scan observations are not a complete security assessment; specialist validation and any required controlled authenticated assurance remain open. Do not attach raw reports or credentials. No live probing was performed.
- The historical main CodeQL run `44688261830` remains a hosted policy FAIL. A separate SARIF review is documented in `docs/security/codeql-reviewed-20261120.md`; its two test-harness dispositions are now mechanically restricted to the original `javascript.sarif` raw-byte SHA-256 `a3dd05e5c9557495963f946f5d5bb70df6bff3f8ef9dd0245f29f8ab8379137d`, each capped at one occurrence. Local policy evaluation accepts the original 55-result SARIF with zero violations; a different artifact with the same fingerprints is rejected. This does not retroactively change the hosted run or establish hosted CodeQL success for a new SHA.
- The separate security note `Revisão de segurança PR.txt` requested removal of a polynomial ReDoS and preservation of the SARIF artifact on policy failure. Both are already present on the current main: `decodeBase32()` no longer uses the trailing-padding regex, and the CodeQL artifact upload step uses `if: ${{ !cancelled() }}` so it runs after a policy failure. No redundant micro-PR is needed for those two items.
- Issue #90 is excluded. This revision does not modify its artifacts or operational controls.

## Validation snapshot

All commands below were run from `E:\Virki\.worktrees\issue119-functional-20261120` with Node 22.23.5. Focused test results:

- Six focused issuer/recovery unit-test files: 30/30 PASS.
- Issuer HTTP/CORS/cache integration fixtures after the RFC 6749 cache-header correction: 11/11 PASS.
- Isolated E2E runner unit suite: 39/39 PASS, including the exact Playwright image digest and Chromium revision lock.
- PostgreSQL-backed OIDC provider integration: 8/8 PASS.
- PostgreSQL-backed issuer interaction integration: 42/42 PASS.
- Playwright public entry (including 404 and nonce checks): 8/8 PASS.
- Playwright recovery cross-tab serialization cases: 3/3 PASS.
- Playwright OIDC Authorization Code + PKCE: 1/1 PASS.
- The isolated Linux browser runner was aligned to the official Playwright 1.65.0 image and Chromium headless-shell revision 1254; the targeted browser runs completed through that runner.

Repository checks:

- `npm run typecheck`: PASS.
- `npm run lint`: PASS.
- `npm run build`: PASS.
- `npm run secrets:scan`: PASS.
- `npm run prisma:validate`: PASS.
- `git diff --check`: PASS.

## Validation update — 2026-11-21

After the RFC 6749 §5.1 token-cache correction, the following checks were rerun from this worktree:

- Focused issuer HTTP/CORS/cache and recovery-access tests: `13/13 PASS`.
- Staging MFA bootstrap tests, including the real Prisma package import: `18/18 PASS`.
- Full `npm run test:unit` under WSL/Linux with Node 22.23.5: `873 total / 868 PASS / 5 SKIP / 0 FAIL`. The five skips are four Windows/PowerShell-specific cases and one `jq`-dependent case because `jq` is unavailable in the offline WSL environment.
- `npm run typecheck`, `npm run lint`, `npm run build`, `npm run secrets:scan`, `npm run prisma:validate`, and `git diff --check`: PASS.

The WSL run used Linux-native esbuild, Argon2, and Prisma binaries added only to the ignored `node_modules` tree for this worktree. The tracked dependency manifests and lockfile were not changed by this environment preparation. The earlier Windows-only unit run recorded 836 PASS, 2 FAIL, and 29 SKIPPED (867 total); its two failures were POSIX owner-only credential-file tests where Windows cannot guarantee mode `0600`. That Windows result is historical and is superseded by the full Linux run above. The complete Playwright suite was not run; only the targeted browser files/cases listed in the earlier snapshot were executed.

The independent #119 review was static and reported no confirmed P1/P2 finding in the then-current local delta. The subsequent token-cache header correction was covered by the local 11/11 HTTP/CORS tests but has not yet received a second independent review. The live Cloudflare Access configuration was read-only inspected; no CDN/TLS handshake or origin/Tunnel edge behavior was re-probed.

The published PR #137 SHA remains `96a86d0ecd05a083223a1bf5eb59dfe21ce45f89`; the additional changes described in this worktree are uncommitted and unpublished, and have no hosted CI/CodeQL result. No Cloudflare/TLS changes, production credential changes, deploy, cutover, merge, or production activation occurred.

Retain issue #119 until all applicable acceptance requirements and authorizations have been satisfied. Hosted check and review receipts must identify the exact published revision.
