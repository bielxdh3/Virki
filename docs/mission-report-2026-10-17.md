# Virki Open Issues Mission Report

| Field | Value |
|---|---|
| Date | 2026-10-17 |
| Repository | `bielxdh3/Virki` |
| Verified base | `main` at `d4e9131df1876c7ce7c9d36035881e54887269aa` |
| Latest locally validated implementation head | `679a6562832c20b7b906495075099256751f41ab` |

## Outcome

All four implementation workstreams are present locally. The earlier whole-branch review at `d8e8515` found no Critical or Important code defect; a fresh GPT-6 Luna/high whole-branch review of current head `679a656` found no confirmed code defect; the reviewer did not run tests, so acceptance gaps remain. Unit, public-site, and broad disposable-PostgreSQL checks now pass on supported Node 22.23.3. The seven issues remain open because Windows/browser acceptance, recovery-link investigation, remote checks, and merge acceptance are incomplete. Three dependent draft PRs remain open. No production host, database, deployment, secret, or production configuration was accessed or changed.

## Issue ledger

| Issue | Status | Evidence and remaining acceptance |
|---|---|---|
| #43 | Browser coverage improved; acceptance incomplete | Added Portal/Hub browser interaction coverage. The local Edge run passed both surfaces, including click, Enter, Space, retained value, ARIA state, and no accidental login submit. The full Windows E2E is blocked before browser startup while the Playwright config installs its generated CA through `X509Store.Add`; the exact diagnostic CA was subsequently removed and verified absent. Browser TLS, the affected historical release, and production behavior remain unverified. |
| #45 | Local browser and integration acceptance passed; merge pending | The central `America/Porto_Velho` formatter labels UTC−4 while stored timestamps and expiry remain UTC. The audit browser test asserted `31/12/2025, 22:00 (UTC−4)`. The supported-runtime broad PostgreSQL integration run passed 67 tests with no failures and one dedicated-bootstrap skip. |
| #46 | Implemented locally; browser acceptance incomplete | Persisted invitation/recovery purpose and purpose-specific activation copy are covered by PostgreSQL tests, including expiry, replay, and query-purpose spoofing. An earlier browser journey reached ADMIN link switching but displayed the generic invalid-link page after confirmation. The later Windows run was blocked before browser startup by CA installation; USER recovery after approval and invitation activation remain unverified. |
| #47 | Local browser and integration acceptance passed; merge pending | Audit E2E passed ADMIN investigation and USER/missing-Access denial on disposable PostgreSQL, including paging, filters, URL state, ordering, redaction, invalid/empty states, keyboard disclosure, responsive widths, and revoked-session denial. The supported-runtime broad integration run also passed. |
| #48 | Local browser and integration acceptance passed; merge pending | Structured, queryable audit events and a focused persistence test are present. Audit E2E confirms raw legacy/private metadata is absent and safe details render; audit persistence passed 1/1 and the supported-runtime broad integration run passed. |
| #49 | Implemented/reviewed locally; not merged | See the original-ID checklist below. IDs [07] and [25] remain unconfirmed and are excluded as vulnerability claims. Four UI-linked items still lack successful browser acceptance; item [12] previously showed the generic invalid-link page after confirmation. |
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
| [12] | Implemented/reviewed locally: second recovery link is held separately and requires CSRF-confirmed switching. An earlier browser run reached the confirmation prompt, then showed the generic invalid-link state instead of the approved password form. Static review found no proven source cause, and the E2E failure's redirect/cookie diagnostics were not retained. The broad disposable fixture now works on Node 22; another browser diagnostic still requires resolving the Windows CA setup blocker. |
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
| Identity/auth/database and #50 | `f063ef5`, `98ca13a` | Independent review approved after one focused correction. | [#51](https://github.com/bielxdh3/Virki/pull/51), draft; head `194c97ed7b7ddbe4bdba44abb2288c741b9ee811` |
| OIDC/operations | `194c97e` | Independent review approved; the `cleanup_clone` source-assertion gap was covered and independently re-reviewed without remaining findings. | [#51](https://github.com/bielxdh3/Virki/pull/51), draft |
| Structured audit/timezone/search | `dd65ba1`, `eae4e61` | Fix round 1 approved; no open Critical/Important findings. | [#52](https://github.com/bielxdh3/Virki/pull/52), draft; head `eae4e617b6d1cc75625bfae4472d4c5c27f758d9` |
| Login/invitation/recovery | `2bd0082`, `d8e8515`, `867b8d9` | Fix round 1 approved; Windows CA trust and recovery-switch guard follow-up reviewed; acceptance remains incomplete. | [#53](https://github.com/bielxdh3/Virki/pull/53), draft. |
| Recovery rate-limit and restore-cleanup regression tests | `1bc328f` | Direct USER/ADMIN bucket assertions and exact `cleanup_clone` volume guard; Luna review found no remaining confirmed findings. PostgreSQL assertions passed in the supported-runtime broad run. | [#53](https://github.com/bielxdh3/Virki/pull/53), draft. |
| Final whole-branch review | `679a656` | Fresh GPT-6 Luna/high review of the full base-to-head diff found no confirmed code defect; reviewer ran no tests. | PRs #51–#53 remain open drafts. |

The PRs are stacked in order: #51 → #52 → #53. A fresh read on 2026-10-17 showed all three still open drafts with no review decision. PR #51 remains at `194c97ed7b7ddbe4bdba44abb2288c741b9ee811`; its CI and CodeQL jobs failed before runner allocation, consistent with the earlier account-level payment/spending-limit annotations. PR #52 remains at `eae4e617b6d1cc75625bfae4472d4c5c27f758d9` with no checks; PR #53 is at current head `679a6562832c20b7b906495075099256751f41ab` with no checks. Issues #43 and #45–#50 remain open. `origin/main` remains `d4e9131df1876c7ce7c9d36035881e54887269aa`. No merge or issue closure was performed.

## Validation record

Runtime for this continuation's local checks: Node `v22.23.3`, npm `10.9.9`, within the repository's declared Node `>=22.13.0 <23` range.

- `npm run test:unit`: 242/242 passed after the final E2E trust/discovery changes.
- `npm run test:public-site`: 5/5 passed.
- Focused invitation/recovery PostgreSQL integration: 6/6 passed on a unique disposable PostgreSQL 17 fixture.
- Focused audit persistence PostgreSQL test: 1/1 passed. Task 1 and Task 2 reports record their disposable PostgreSQL, OIDC, bootstrap, provider, and production-operations test results.
- `node --test scripts/production-ops.test.mjs`: 45 passed / 4 platform-specific skipped after adding explicit checks for the complete `cleanup_clone` body, including its exact labeled-volume deletion guard.
- Independent GPT-6 Luna review and focused re-review of the `cleanup_clone` assertions found no remaining confirmed findings.
- An earlier broad `npm run test:integration` attempt reported 59 passed / 6 listener failures / 1 skipped under an unsupported Node runtime. It was superseded by the supported-runtime run below; the six earlier fetch errors were not reproduced in a focused 7/7 diagnostic.
- Broad PostgreSQL integration passed on Node 22.23.3 after creating a unique PostgreSQL 17 tmpfs fixture on a dedicated bridge network and copying init scripts into the container. All eight migrations applied; the suite reported 67 passed / 0 failed / 1 skipped because a dedicated virgin bootstrap fixture was not configured. The exact container and network were removed. The existing `virki-integration-postgres-local` container and shared helper/env state were untouched. The earlier `P1003` was caused by PowerShell parsing `$database?schema` as one variable. Using explicit subexpression delimiters corrected the URL.
- Browser: Task 3 had 1 pass / 1 fail before the event-ID fix and was not rerun. The targeted password-toggle E2E passed 2/2 in local Edge for Portal and Hub. A fresh audit E2E passed 2/2 on a unique tmpfs-backed PostgreSQL fixture. The authenticated journey spec passed USER and ADMIN login, but its recovery scenario still fails after explicit link-switch confirmation with the generic invalid-link page. Its initial `/recover` crash from `undefined === undefined` was fixed by requiring both candidate and request ID. The latest Windows Playwright attempt used Node 22 and a disposable DB but timed out before `webServer` became ready. `DEBUG=pw:webserver` showed config blocked in `windowsCaTrust.install()` before the browser started. A bounded `X509Store.Add` probe opened CurrentUser Root then failed to return; a separate exact `certutil -addstore` diagnostic succeeded, but both .NET removal and `certutil -delstore` returned Windows `ERROR_CANCELLED` (`0x800704c7`). The exact generated test CA was removed from its HKCU Root registry key and then verified absent from both that key and the certificate store. No temporary test CA remains. Browser TLS handshake is still unverified. Playwright `--list` skips trust setup; focused trust/discovery/inventory checks passed 14/14. The password test filters only the observed Next devtools inline-style CSP messages by exact prefix and source path. These runs do not validate the historical #43 release or production behavior.
- `npm run secrets:scan`: passed.
- `npm run lint`: passed.
- `npm run prisma:validate`: passed.
- `npm run prisma:generate`: passed; required because the current `node_modules` client predated the integrated schema.
- `npm run typecheck`: passed for public-site, Hub, issuer, auth, and database after generation.
- `npm run build`: public-site and Hub Next builds both passed.
- This continuation on the validated head: `npm run test:unit` passed 242/242; `npm run test:public-site` passed 5/5; `npm run secrets:scan`, `npm run lint`, `npm run typecheck`, `npm run prisma:validate`, and `npm run build` all passed. The broad PostgreSQL run above includes and passes the #49 [04] USER/ADMIN bucket assertions.
- `git diff --check d4e9131df1876c7ce7c9d36035881e54887269aa...HEAD`: passed.
- Final working-tree `git diff --check`: passed with no warnings.

## Migrations, security limits, and next gates

The branch contains additive audit and recovery-purpose schema migrations. They were validated/applied only on disposable local PostgreSQL fixtures; no production migration, backup/restore, deployment, secret rotation, or environment change occurred. Production rollout still requires the repository's backup/restore and exact-revision gates. No production rollback operation was attempted.

Remaining Minor review item: Task 3's audit view/query use long compressed expressions. The fresh whole-branch review found no confirmed code defects; Task 1's direct source/address bucket assertions now pass in PostgreSQL.

Next acceptance gates: resolve the Windows generated-CA trust helper hang/cancellation using a supported, cleanable approach; rerun the approved recovery-link switch with redirect/cookie diagnostics and complete the remaining browser flows; obtain successful exact-head remote checks; then update the original issue checklists only for evidence that passes acceptance. Keep #49 [07] and [25] unconfirmed. Do not merge while required local/browser/remote acceptance is missing. Do not close any issue until its complete acceptance is verified on the merged default branch.
