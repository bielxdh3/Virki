# Virki Open Issues Mission Report

| Field | Value |
|---|---|
| Date | 2026-10-17 |
| Repository | `bielxdh3/Virki` |
| Verified base | `main` at `d4e9131df1876c7ce7c9d36035881e54887269aa` |
| Latest locally validated implementation head | `426040c8882f593f8ac34dde09228ac9b6bb4955` (Windows E2E dispatch through isolated Linux Docker; tested before this ledger closeout) |

## Outcome

The existing four implementation workstreams remain stacked in PRs #51–#53. The recovery password-error regression now has a role- and purpose-specific inline response, and the issuer response gate now handles disconnects, duplicate `end`, and late audit registration. The Windows default `npm run test:e2e` entry now dispatches to isolated Linux Docker; serialized Playwright arguments are validated and preserved as argv. A Windows PowerShell 5.1 array-wrapping bug was reproduced and corrected. Through the default entrypoint, the recovery-link-switch and short-password tests passed 2/2, and the post-gate OIDC PKCE test passed 1/1. The earlier full browser run was 19/20 before the response-gate fix; this is not reported as a full-suite pass. Node 22.23.3 unit tests passed 249/249, and the final disposable PostgreSQL integration run passed 67/0/1. The isolated runner uses normal TLS verification and automatically removes its dedicated network, containers, database, TLS material, and snapshot. The Windows `X509Store.Add` call is bounded to 15 seconds, but its underlying stall is still not diagnosed. The native Windows store still contains an older `CN=Virki E2E Root CA` certificate because automatic execution review rejected its exact-thumbprint removal; the Docker runner did not install it. CI and CodeQL runs on the previously inspected PR heads failed before steps because GitHub reported failed account payments or an insufficient spending limit. Issues #43 and #45–#50 remain open. No production host, database, deployment, secret, or production configuration was accessed or changed.

## Issue ledger

| Issue | Status | Evidence and remaining acceptance |
|---|---|---|
| #43 | Local browser checks pass; historical reproduction and old-certificate cleanup remain pending | Portal/Hub password-toggle E2E passed 2/2 with normal TLS verification. On Windows, default browser E2E now routes into isolated Linux Docker and avoids Windows `X509Store.Add`; that call remains bounded to 15 seconds, but its underlying stall is undiagnosed. The old `CN=Virki E2E Root CA` (`1BD824BCD9A259CA7C795A8B3DEF38F064FB885B`, no private key) remains in CurrentUser\Root. Automatic execution review rejected exact-thumbprint removal. The reported release and production behavior were not reproduced, so the issue remains open. |
| #45 | Local browser and integration acceptance passed; merge pending | The central `America/Porto_Velho` formatter labels UTC−4 while stored timestamps and expiry remain UTC. The audit browser test asserted `31/12/2025, 22:00 (UTC−4)`. The supported-runtime broad PostgreSQL integration run passed 67 tests with no failures and one dedicated-bootstrap skip. |
| #46 | Recovery/invitation browser criteria passed locally; merge pending | Persisted invitation/recovery purpose, expiry, replay, and query-purpose spoofing are covered by PostgreSQL tests. The fresh default-entrypoint browser run passed approved ADMIN link switching and USER short-password server rejection (2/2). The regression returned a redirect whose stale recovery page rendered generic invalid-link markup while the DB row and active cookie were still valid. Completion now returns action state and renders a role/purpose-specific inline error; server password validation and success-only consumption remain in place. Earlier USER/ADMIN authenticated recovery journeys also passed. |
| #47 | Local browser and integration acceptance passed; merge pending | Audit E2E passed ADMIN investigation and USER/missing-Access denial on disposable PostgreSQL, including paging, filters, URL state, ordering, redaction, invalid/empty states, keyboard disclosure, responsive widths, and revoked-session denial. The supported-runtime broad integration run also passed. |
| #48 | Local browser and integration acceptance passed; merge pending | Structured, queryable audit events and a focused persistence test are present. Audit E2E confirms raw legacy/private metadata is absent and safe details render; audit persistence passed 1/1 and the supported-runtime broad integration run passed. |
| #49 | Actionable items implemented locally; merge pending | See the original-ID checklist below. IDs [07] and [25] remain unconfirmed and are excluded as vulnerability claims. Items [12], [16], [26], and [27] passed recovery-switch, USER/ADMIN password, TOTP, and credential-challenge browser cases. After the issuer response-gate correction, the focused OIDC PKCE browser test passed 1/1 through the default Windows-to-Docker entrypoint; the earlier 19/20 suite remains recorded as pre-correction evidence. |
| #50 | Implemented/reviewed locally; not merged | All six original items are addressed in PR #51 with local PostgreSQL and authorization coverage. The supported-runtime broad integration suite passed; full mission acceptance and merge remain pending. |

## #49 original actionable IDs

| ID | Status and evidence |
|---|---|
| [01] | Implemented/reviewed locally: database-level historical actor attribution and FK invariant; focused PostgreSQL evidence passed. |
| [02] | Implemented/reviewed locally: backup temporary storage and interrupted-cleanup handling; focused operations tests passed. |
| [03] | Implemented/reviewed locally with a coverage limitation: bootstrap after pre-account traffic passed before the explicit test-entry guard; later normal discovery skips the dedicated fixture. |
| [04] | Implemented/reviewed locally; the recovery integration test directly checks USER/ADMIN source and address bucket isolation. The source bucket records all six portal requests; the address bucket is capped at five attempts. Assertions in commit `1bc328f` passed in the supported-runtime broad PostgreSQL run. |
| [05] | Implemented/reviewed locally: redact the canonical persisted value; focused tests passed. |
| [06] | Implemented/reviewed locally: successful MFA does not spend the failure budget; focused tests passed. |
| [08] | Implemented/reviewed locally: preserve the login result through forced reauthentication and consent; focused issuer checks passed. |
| [09] | Implemented/reviewed locally: explicit OIDC claims require consent; focused issuer checks passed. |
| [10] | Implemented/reviewed locally: observe concurrent/rejecting audit promises safely; focused tests passed. |
| [11] | Implemented/reviewed locally: enforce Portal/Hub server-action surface boundaries; focused tests passed. |
| [12] | Corrected and locally verified: the server action rejects a mismatched candidate without changing cookies and records a denial audit event. On success it switches the active cookie and clears the candidate. The approved ADMIN switch and short-password rejection passed the isolated browser run; the password error now stays inline instead of navigating to stale generic invalid-link markup. |
| [13] | Implemented/reviewed locally: preserve reauthentication navigation state without an MFA shortcut; focused tests passed. |
| [14] | Implemented/reviewed locally: expand secret-scan coverage for app-specific names and multiple URLs; scanner tests passed. |
| [15] | Implemented/reviewed locally: verify the exact approved revision despite remote `main` moving; focused operations tests passed. |
| [16] | Implemented/reviewed locally: USER/ADMIN recovery password minimums and control-character rejection; USER and ADMIN short-password flows passed browser checks with server validation. |
| [17] | Implemented/reviewed locally: enforce trusted-device age server-side; focused tests passed. |
| [18] | Implemented/reviewed locally: preserve distributed abuse history after successful login and normalize USER/ADMIN refund identifiers; review correction and regression tests passed. |
| [19] | Implemented/reviewed locally: make limiter cleanup/update race-safe; disposable PostgreSQL concurrency evidence passed. |
| [20] | Implemented/reviewed locally: require Cloudflare Access JWT temporal claims; focused tests passed. |
| [21] | Implemented/reviewed locally: remove expired OIDC artifacts for nonpositive TTL; focused provider/DB tests passed. |
| [22] | Implemented/reviewed locally: derive token-exchange actor from verified model state, otherwise null; focused tests passed. |
| [23] | Implemented/reviewed locally: purge pending OIDC interactions; focused tests passed. |
| [24] | Implemented/reviewed locally: normalize blank redirect-URI separators while validating actual entries; focused tests passed. |
| [26] | Implemented/reviewed locally: TOTP enrollment secret is hidden after success and recovery codes are shown once; the browser regression passed. |
| [27] | Implemented/reviewed locally: failed ADMIN credential setup can restart with fresh same-origin CSRF; the browser regression passed. |
| [28] | Implemented/reviewed locally: malformed/empty public origin does not crash robots metadata; public-site tests passed. |

Excluded from the actionable tally: [07] and [25] remain unconfirmed; no exploit or P2025 claim is made.

## #50 original six items

| Item | Status and evidence |
|---|---|
| [1] | Implemented/reviewed locally: recheck current ADMIN role/session for elevation and recovery-code regeneration, including demotion/revocation races. |
| [2] | Implemented/reviewed locally: conditional transactional password writes prevent revoked credentials from being reactivated. |
| [3] | Implemented/reviewed locally: revalidate account/connection eligibility inside grant transactions; disposable PostgreSQL race checks passed. |
| [4] | Implemented/reviewed locally: idempotent revocation preserves the original timestamp and avoids duplicate audit events. |
| [5] | Implemented/reviewed locally: remove the obsolete `/api/recover` public-route exception and cover classification. |
| [6] | Implemented/reviewed locally: narrowly ignore local `auditoria.txt` and verify no tracked disclosure. |

## Workstreams, commits, and PRs

| Workstream | Local commits | Review result | PR |
|---|---|---|---|
| Identity/auth/database and #50 | `f063ef5`, `98ca13a` | Independent review approved after one focused correction. | [#51](https://github.com/bielxdh3/Virki/pull/51), draft; updated head `ee83f52c9e88ead0c9b7b869c03e1c03cd38d044` |
| OIDC/operations and response-gate correction | `194c97e`, `ee83f52` | Earlier cleanup assertion review passed; this continuation received a same-agent adversarial review. Focused issuer gate tests pass 7/7; the focused post-fix OIDC browser case passed 1/1, while the full suite remains unrerun. | [#51](https://github.com/bielxdh3/Virki/pull/51), draft |
| Structured audit/timezone/search | `dd65ba1`, `eae4e61`, `3644e84`, `e1fb164` | Earlier fix review passed; this continuation received a same-agent adversarial review. The actor-role filter passed query, integration, and browser assertions. | [#52](https://github.com/bielxdh3/Virki/pull/52), draft; updated head `e1fb164526ee4ee1802b76019eabb0f975868106` |
| Login/invitation/recovery implementation | `2bd0082`, `d8e8515`, `867b8d9`, `6fe3fdd`, `f261a4d`, `ba07478` | Recovery regression and invitation flows passed browser E2E. Same-agent adversarial review found and corrected shell argument joining in the isolated runner; no full independent review is claimed. The Windows-dispatch follow-up is listed separately. | [#53](https://github.com/bielxdh3/Virki/pull/53), draft |
| Recovery rate-limit and restore-cleanup regression tests | `1bc328f` | Direct USER/ADMIN bucket assertions and exact `cleanup_clone` volume guard; Luna review found no remaining confirmed findings. PostgreSQL assertions passed in the supported-runtime broad run. | [#53](https://github.com/bielxdh3/Virki/pull/53), draft. |
| Windows E2E dispatch and argument forwarding | `426040c` | Same-agent adversarial review; Node dispatcher tests passed within the 249/249 unit run. Actual Windows PowerShell 5.1 invocation passed the recovery 2/2 and OIDC 1/1 filtered E2E runs; Docker cleanup completed. | [#53](https://github.com/bielxdh3/Virki/pull/53), draft. |
| Final whole-branch review | `679a656` | Fresh GPT-6 Luna/high review of that earlier full base-to-head diff found no confirmed code defect; reviewer ran no tests and did not review this continuation's fixes. | PRs #51–#53 remain open drafts. |
| Focused review of earlier continuation | Changes after `679a656` through `e6f92dc` | GPT-6 Luna/high read-only re-review found no confirmed findings. It did not run tests or inspect the full #51/#52 PR history. | Earlier #53 code head. |
| Adversarial review of this continuation | OIDC response gate, actor-role audit filter, recovery error form, and Docker runner changes through `ba07478` | Same-agent source/security review found no remaining confirmed blocker in the reviewed changes after replacing shell-string argument joining with argument-vector passing. This is not an independent reviewer result. | Current #51–#53 code heads; browser OIDC remains pending. |

The PRs remain stacked in order: #51 → #52 → #53. On the latest GitHub read before this code push, all three were open drafts. PR #51 head is `ee83f52c9e88ead0c9b7b869c03e1c03cd38d044`; PR #52 is `e1fb164526ee4ee1802b76019eabb0f975868106`; PR #53 was `e740a20eff87ed929873c14e3e45fe82edd24b96`. CI and CodeQL use GitHub-hosted `ubuntu-latest` runners and trigger on pull requests. The latest inspected runs at that snapshot were [#51 CI](https://github.com/bielxdh3/Virki/actions/runs/39093261472) and [CodeQL](https://github.com/bielxdh3/Virki/actions/runs/39093261457); [#52 CI](https://github.com/bielxdh3/Virki/actions/runs/39093266304) and [CodeQL](https://github.com/bielxdh3/Virki/actions/runs/39093266277); [#53 CI](https://github.com/bielxdh3/Virki/actions/runs/39093494891) and [CodeQL](https://github.com/bielxdh3/Virki/actions/runs/39093494884). These six runs failed within 3–4 seconds. The sampled jobs had zero steps; representative log retrieval returned `BlobNotFound`. Check annotations on the inspected PR heads reported failed recent account payments or an insufficient spending limit, so the jobs were not started. Production-image jobs were skipped. This is an external GitHub billing/runner-start blocker; available evidence does not show a repository workflow defect or a runner queue/quota error. No security check was bypassed. A fresh check state is required on the updated PR #53 head after push. Issues #43 and #45–#50 remain open; no PR was merged and no issue was closed.

## Validation record

Runtime for this continuation's local checks: Node `v22.23.3`, npm `10.9.9`, within the repository's declared Node `>=22.13.0 <23` range.

- `npm run test:unit`: 243 passed / 0 failed after the recovery-switch regression and CI/workflow changes.
- `npm run test:public-site`: 5/5 passed.
- Focused invitation/recovery PostgreSQL integration: 6/6 passed on a unique disposable PostgreSQL 17 fixture.
- Focused audit persistence PostgreSQL test: 1/1 passed. Task 1 and Task 2 reports record their disposable PostgreSQL, OIDC, bootstrap, provider, and production-operations test results.
- `node --test scripts/production-ops.test.mjs`: 45 passed / 4 platform-specific skipped after adding explicit checks for the complete `cleanup_clone` body, including its exact labeled-volume deletion guard.
- Independent GPT-6 Luna review and focused re-review of the `cleanup_clone` assertions found no remaining confirmed findings.
- An earlier broad `npm run test:integration` attempt reported 59 passed / 6 listener failures / 1 skipped under an unsupported Node runtime. It was superseded by the supported-runtime run below; the six earlier fetch errors were not reproduced in a focused 7/7 diagnostic.
- Broad PostgreSQL integration passed on Node 22.23.3 after creating a unique PostgreSQL 17 tmpfs fixture on a dedicated bridge network and copying init scripts into the container. All eight migrations applied; the suite reported 67 passed / 0 failed / 1 skipped because a dedicated virgin bootstrap fixture was not configured. The exact container and network were removed. The existing `virki-integration-postgres-local` container and shared helper/env state were untouched. The earlier `P1003` was caused by PowerShell parsing `$database?schema` as one variable. Using explicit subexpression delimiters corrected the URL.
- Historical browser checks: password-toggle passed 2/2, audit E2E passed 2/2, and the earlier focused recovery-switch E2E passed 1/1. The full Linux Docker browser run before the response-gate correction passed 19/20; OIDC PKCE failed with `ERR_STREAM_WRITE_AFTER_END` while replaying queued response operations. The gate now protects aborted connections, duplicate `end` calls, and audits registered while a response is waiting; its direct suite passed 7/7. The focused OIDC browser test later passed 1/1 through the Windows default entrypoint, but the full suite was not rerun. The isolated runner uses a per-run CA in Chromium's private NSS database with normal TLS verification (`ignoreHTTPSErrors` is not enabled), a private Docker network, no host database port, disposable PostgreSQL, and automatic removal of containers, network, TLS files, and snapshot. The Windows `X509Store.Add` invocation is bounded by a 15-second timeout, but its underlying stall remains undiagnosed; the Windows CurrentUser Root still contains the old public E2E CA (`1BD824BCD9A259CA7C795A8B3DEF38F064FB885B`, no private key) because automatic execution review rejected exact-thumbprint removal. The authenticated USER/ADMIN recovery journeys passed.
- `npm run secrets:scan`: passed.
- `npm run lint`: passed.
- `npm run prisma:validate`: passed.
- `npm run prisma:generate`: passed; required because the current `node_modules` client predated the integrated schema.
- `npm run typecheck`: passed for public-site, Hub, issuer, auth, and database after generation.
- `npm run build`: public-site and Hub Next builds both passed.
- Earlier continuation validation on Node 22: unit 243/243, public site 5/5, secrets scan, lint, typecheck, Prisma validate, and public-site/Hub build passed. Final current validation after the OIDC gate and recovery changes: Node 22.23.3 isolated Docker unit suite passed 247/247; isolated disposable PostgreSQL integration passed 67/0/1 (one dedicated virgin bootstrap fixture skipped); direct `apps/issuer/src/audit-gate.test.ts` passed 7/7; `npm run typecheck` passed for all five workspaces; `npm run lint`, secrets scan, Prisma validation, public-site/Hub build, and `git diff --check` passed. Running unit tests directly on Windows Node 24.14.1 produced 244 passes and one harness-import failure because the repository requires Node 22 and the test subprocess passed a Windows `E:\...` path to the ESM loader; do not count that unsupported-runtime run as CI evidence. A Linux Docker full-stage run reported production operations 93 passed / 23 failed because those host-only production-shell checks intentionally reject the Docker Desktop WSL kernel. It also exposed the prior issuer listener crash before the response-gate correction. No production runtime or database was used.
- The local `npm run test:database:roles` Windows Docker Desktop run is **not passed**: the interrupted/recreated PostgreSQL fixture remained `starting` for the bounded 90-second health wait with empty logs. The test cleaned up its test container/volume/image. A separate broad operations run in Linux Docker cannot validate the production-shell tests because they intentionally reject a WSL kernel as a production host; the host Windows targeted suite reports those tests as platform skips. The broad PostgreSQL integration suite passed, but role-isolation interrupted-container acceptance remains blocked on a supported native Linux/Docker runtime.
- `git diff --check d4e9131df1876c7ce7c9d36035881e54887269aa...HEAD`: passed.
- Final working-tree `git diff --check`: passed with no warnings before this report closeout commit.

Continuation after `e740a20`:
- `npm run test:unit` under the Node 22.23.3 isolated Linux runner: 249 passed / 0 failed / 0 skipped, including the Windows/Linux dispatcher contract tests.
- `npm run test:e2e -- --grep 'approved ADMIN recovery link switch|approved USER recovery keeps recovery copy'` from Windows through the default dispatcher: 2/2 passed. This reproduced the WinPS 5.1 nested-array rejection in the JSON argv bridge, corrected it, and then confirmed argument preservation, both recovery regressions, TLS verification, disposable PostgreSQL migrations, and automatic cleanup.
- `npm run test:e2e -- --grep 'Authorization Code'` through the same default entrypoint after the response-gate correction: OIDC PKCE 1/1 passed. The full 20-test suite was not rerun; 19/20 remains the pre-correction result.
- `npm run lint` and `npm run secrets:scan`: passed on the current worktree. The direct Windows lint invocation used Node 24.14.1; it is a static lint result, not supported-runtime test evidence.
- `git diff --check`: passed after the runner changes. No `virki-e2e-*` containers or networks remained after either E2E run.

## Migrations, security limits, and next gates

The branch contains additive audit and recovery-purpose schema migrations. They were validated/applied only on disposable local PostgreSQL fixtures; no production migration, backup/restore, deployment, secret rotation, or environment change occurred. Production rollout still requires the repository's backup/restore and exact-revision gates. No production rollback operation was attempted.

Remaining Minor review item: Task 3's audit view/query use long compressed expressions. The fresh whole-branch review found no confirmed code defects; Task 1's direct source/address bucket assertions now pass in PostgreSQL.

Next acceptance gates: reproduce #43 against the reported production release without changing production; resolve the exact old E2E certificate cleanup block; validate database-role interruption on a supported native Linux/Docker host; and obtain successful exact-head GitHub CI/CodeQL checks after the repository owner's billing/spending-limit block is resolved. The focused post-fix OIDC test now passes, but the full browser suite was not rerun. The current single-agent adversarial review did not cover the full stacked PR history; do not describe it as an independent second-agent review. Keep #49 [07] and [25] unconfirmed. Do not merge while required acceptance/checks remain missing. Do not close any issue until its complete acceptance is verified on the merged default branch.
