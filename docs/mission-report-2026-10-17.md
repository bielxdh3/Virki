# Virki Open Issues Mission Report

| Field | Value |
|---|---|
| Date | 2026-10-17 |
| Repository | `bielxdh3/Virki` |
| Verified base | `main` at `d4e9131df1876c7ce7c9d36035881e54887269aa` |
| Latest locally validated implementation head | `e6f92dc704818a15ac980c4f19de18ede1dce4f0` (code; report closeout follows) |

## Outcome

All four implementation workstreams and focused follow-up changes are present in the existing stacked PR branches. Earlier whole-branch reviews at `d8e8515` and `679a656` found no confirmed code defect. A separate read-only GPT-6 Luna/high review of the changes after `679a656` through code head `e6f92dc` found no confirmed findings; it did not run tests and did not re-review the entire stacked PR history. Local Node 22.23.3 unit, public-site, build, typecheck, lint, Prisma, secrets-scan, supported-runtime PostgreSQL integration, and focused browser checks pass as recorded below. Remote GitHub checks now trigger on all three PRs, but every job is rejected before runner allocation because GitHub reports failed recent account payments or a spending-limit issue. The seven issues remain open because the PRs are unmerged and some browser acceptance remains blocked. No production host, database, deployment, secret, or production configuration was accessed or changed.

## Issue ledger

| Issue | Status | Evidence and remaining acceptance |
|---|---|---|
| #43 | Local browser acceptance passed; merge and historical/production verification pending | Portal/Hub password-toggle E2E passed 2/2, including click, Enter, Space, retained value, ARIA state, and no accidental login submit. The isolated Linux Docker E2E uses a per-run CA in a private Chromium NSS database and normal certificate verification. The native Windows `X509Store.Add` hang remains unexplained; no certificate was left installed. The affected historical release and production behavior remain unverified. |
| #45 | Local browser and integration acceptance passed; merge pending | The central `America/Porto_Velho` formatter labels UTC−4 while stored timestamps and expiry remain UTC. The audit browser test asserted `31/12/2025, 22:00 (UTC−4)`. The supported-runtime broad PostgreSQL integration run passed 67 tests with no failures and one dedicated-bootstrap skip. |
| #46 | Purpose handling implemented; browser acceptance incomplete | Persisted invitation/recovery purpose and purpose-specific activation copy are covered by PostgreSQL tests, including expiry, replay, and query-purpose spoofing. A confirmed ADMIN recovery-link switch now forces browser navigation after the server updates the active cookie, so the page reloads against the newly active link. The isolated recovery-switch E2E passes 1/1. USER recovery after approval and invitation activation remain unverified because the broader authenticated journey still stops at the login verification redirect. |
| #47 | Local browser and integration acceptance passed; merge pending | Audit E2E passed ADMIN investigation and USER/missing-Access denial on disposable PostgreSQL, including paging, filters, URL state, ordering, redaction, invalid/empty states, keyboard disclosure, responsive widths, and revoked-session denial. The supported-runtime broad integration run also passed. |
| #48 | Local browser and integration acceptance passed; merge pending | Structured, queryable audit events and a focused persistence test are present. Audit E2E confirms raw legacy/private metadata is absent and safe details render; audit persistence passed 1/1 and the supported-runtime broad integration run passed. |
| #49 | Implemented locally; not merged | See the original-ID checklist below. IDs [07] and [25] remain unconfirmed and are excluded as vulnerability claims. Item [12] is corrected and has a focused passing browser regression test. Items [16], [26], and [27] still lack successful end-to-end browser acceptance; [12] no longer has that gap. |
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
| [12] | Corrected and locally verified: the server action returns an explicit success/error state, rejects a mismatched candidate without changing cookies, and records a denial audit event. On success it switches the active cookie and clears the candidate. Root cause: the server-action redirect updated the cookie and URL while leaving stale recovery-page markup visible; client navigation after confirmed success re-renders against the active cookie. The focused disposable-PostgreSQL E2E covers tampered request-ID denial and valid approved-link switching and passed 1/1 with normal TLS verification. |
| [13] | Implemented/reviewed locally: preserve reauthentication navigation state without an MFA shortcut; focused tests passed. |
| [14] | Implemented/reviewed locally: expand secret-scan coverage for app-specific names and multiple URLs; scanner tests passed. |
| [15] | Implemented/reviewed locally: verify the exact approved revision despite remote `main` moving; focused operations tests passed. |
| [16] | Implemented/reviewed locally: USER/ADMIN recovery password minimums and control-character rejection; server and UI are aligned, but browser flow is unverified. |
| [17] | Implemented/reviewed locally: enforce trusted-device age server-side; focused tests passed. |
| [18] | Implemented/reviewed locally: preserve distributed abuse history after successful login and normalize USER/ADMIN refund identifiers; review correction and regression tests passed. |
| [19] | Implemented/reviewed locally: make limiter cleanup/update race-safe; disposable PostgreSQL concurrency evidence passed. |
| [20] | Implemented/reviewed locally: require Cloudflare Access JWT temporal claims; focused tests passed. |
| [21] | Implemented/reviewed locally: remove expired OIDC artifacts for nonpositive TTL; focused provider/DB tests passed. |
| [22] | Implemented/reviewed locally: derive token-exchange actor from verified model state, otherwise null; focused tests passed. |
| [23] | Implemented/reviewed locally: purge pending OIDC interactions; focused tests passed. |
| [24] | Implemented/reviewed locally: normalize blank redirect-URI separators while validating actual entries; focused tests passed. |
| [26] | Implemented/reviewed locally: hide TOTP enrollment secret after success and show recovery codes once; browser interaction is unverified. |
| [27] | Implemented/reviewed locally: restart failed/expired admin challenge with fresh same-origin CSRF state; browser interaction is unverified. |
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
| Identity/auth/database and #50 | `f063ef5`, `98ca13a` | Independent review approved after one focused correction. | [#51](https://github.com/bielxdh3/Virki/pull/51), draft; updated head `d8b3460b30188ab46268851661aad950d801c445` |
| OIDC/operations | `194c97e` | Independent review approved; the `cleanup_clone` source-assertion gap was covered and independently re-reviewed without remaining findings. | [#51](https://github.com/bielxdh3/Virki/pull/51), draft |
| Structured audit/timezone/search | `dd65ba1`, `eae4e61` | Fix round 1 approved; no open Critical/Important findings. | [#52](https://github.com/bielxdh3/Virki/pull/52), draft; updated head `5069eb1302777ae9bbf31933917ff3dee296c916` |
| Login/invitation/recovery and follow-up | `2bd0082`, `d8e8515`, `867b8d9`, `6fe3fdd` | Earlier fixes reviewed. The recovery-switch fix has focused browser E2E evidence; independent review of the latest changes is pending. | [#53](https://github.com/bielxdh3/Virki/pull/53), draft; code head `e6f92dc704818a15ac980c4f19de18ede1dce4f0` before this report closeout commit. |
| Recovery rate-limit and restore-cleanup regression tests | `1bc328f` | Direct USER/ADMIN bucket assertions and exact `cleanup_clone` volume guard; Luna review found no remaining confirmed findings. PostgreSQL assertions passed in the supported-runtime broad run. | [#53](https://github.com/bielxdh3/Virki/pull/53), draft. |
| Final whole-branch review | `679a656` | Fresh GPT-6 Luna/high review of that earlier full base-to-head diff found no confirmed code defect; reviewer ran no tests and did not review this continuation's fixes. | PRs #51–#53 remain open drafts. |
| Focused review of this continuation | Changes after `679a656` through `e6f92dc` | Independent GPT-6 Luna/high read-only review found no confirmed findings. It did not run tests or inspect the full #51/#52 PR history. | #53 code head under review; PRs remain open drafts. |

The PRs remain stacked in order: #51 → #52 → #53. Latest GitHub state read on 2026-10-18 UTC: all three are open drafts. PR #51 head is `d8b3460b30188ab46268851661aad950d801c445`; PR #52 head is `5069eb1302777ae9bbf31933917ff3dee296c916`; PR #53 code head is `e6f92dc704818a15ac980c4f19de18ede1dce4f0` (this ledger update adds a documentation-only commit). CI and CodeQL now trigger on the `cdx/**` PR branches, including #52 and #53. Latest CI/CodeQL runs: [#51 CI](https://github.com/bielxdh3/Virki/actions/runs/39087584551) and [CodeQL](https://github.com/bielxdh3/Virki/actions/runs/39087584533); [#52 CI](https://github.com/bielxdh3/Virki/actions/runs/39087591890) and [CodeQL](https://github.com/bielxdh3/Virki/actions/runs/39087591894); [#53 CI](https://github.com/bielxdh3/Virki/actions/runs/39087641254) and [CodeQL](https://github.com/bielxdh3/Virki/actions/runs/39087641256). Every job failed before any runner steps (`steps: []`, runner id unavailable); GitHub's job annotations explicitly say recent account payments failed or the spending limit needs to be increased. Production-image jobs were skipped because prerequisite checks failed. This is an external account-level runner blocker, not evidence of code failure. No bypass or unchanged retry was used. Issues #43 and #45–#50 remain open. No merge or issue closure was performed.

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
- Browser: password-toggle E2E passed 2/2 in Portal and Hub. Audit E2E passed 2/2 on a unique tmpfs-backed PostgreSQL fixture. Recovery-switch E2E passed 1/1 in a disposable PostgreSQL environment: tampered request IDs are denied without cookie change, while a valid approved candidate switches the active cookie and re-renders the approved password form. Runner TLS was verified using a per-run CA in private Chromium NSS state and normal certificate verification; `ignoreHTTPSErrors` is not enabled. The native Windows `X509Store.Add` hang itself remains unexplained, but no certificate was left installed. The broader authenticated journey remains blocked at ADMIN email verification. An earlier attempt reached the code form but could not complete it; later safe response diagnostics showed `POST /api/login:303` to `/login/verify?...` followed by the browser ending at `/login` (`GET /login:200`). The underlying cause remains unknown; do not count the full journey as passing or repeat it without new evidence. The isolated test runner and DB used private Docker networking and no host DB port. Playwright cleaned runtime CA and fixture data after each run; final closeout removed the two named containers and their dedicated network.
- `npm run secrets:scan`: passed.
- `npm run lint`: passed.
- `npm run prisma:validate`: passed.
- `npm run prisma:generate`: passed; required because the current `node_modules` client predated the integrated schema.
- `npm run typecheck`: passed for public-site, Hub, issuer, auth, and database after generation.
- `npm run build`: public-site and Hub Next builds both passed.
- This continuation on the validated code head: `npm run test:unit` passed 243/243; `npm run test:public-site` passed 5/5; `npm run secrets:scan`, `npm run lint`, `npm run typecheck`, `npm run prisma:validate`, and `npm run build` passed. The broad PostgreSQL run above includes and passes the #49 [04] USER/ADMIN bucket assertions. `node --test scripts/production-ops.test.mjs scripts/production-ci.test.mjs` passed 54 with 0 failures and 4 platform-specific skips. `node --test scripts/ghcr-publication.test.mjs` passed 5/5 after fixing Windows CRLF parsing. The added production Prisma allowlist/model regression passed.
- The local `npm run test:database:roles` Windows Docker Desktop run is **not passed**: the interrupted/recreated PostgreSQL fixture remained `starting` for the bounded 90-second health wait with empty logs. The test cleaned up its test container/volume/image. A separate broad operations run in Linux Docker cannot validate the production-shell tests because they intentionally reject a WSL kernel as a production host; the host Windows targeted suite reports those tests as platform skips. The broad PostgreSQL integration suite passed, but role-isolation interrupted-container acceptance remains blocked on a supported native Linux/Docker runtime.
- `git diff --check d4e9131df1876c7ce7c9d36035881e54887269aa...HEAD`: passed.
- Final working-tree `git diff --check`: passed with no warnings before this report closeout commit.

## Migrations, security limits, and next gates

The branch contains additive audit and recovery-purpose schema migrations. They were validated/applied only on disposable local PostgreSQL fixtures; no production migration, backup/restore, deployment, secret rotation, or environment change occurred. Production rollout still requires the repository's backup/restore and exact-revision gates. No production rollback operation was attempted.

Remaining Minor review item: Task 3's audit view/query use long compressed expressions. The fresh whole-branch review found no confirmed code defects; Task 1's direct source/address bucket assertions now pass in PostgreSQL.

Next acceptance gates: classify the authenticated email-code verification rejection before claiming the full invitation/recovery journey; complete the remaining #49 UI flows and run role-isolation interruption validation on a supported native Linux/Docker host; and obtain successful exact-head GitHub CI/CodeQL checks after the repository owner's account-level billing/spending-limit blocker is resolved. The focused independent review found no confirmed findings for this continuation, but it did not review the full stacked history. Keep #49 [07] and [25] unconfirmed. The native Windows CA `X509Store.Add` hang remains unexplained, though isolated E2E now runs with normal TLS verification in Docker. Do not merge while required acceptance/checks remain missing. Do not close any issue until its complete acceptance is verified on the merged default branch.
