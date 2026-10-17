# Virki Open Issues Mission Report

| Field | Value |
|---|---|
| Date | 2026-10-17 |
| Repository | `bielxdh3/Virki` |
| Verified base | `main` at `d4e9131df1876c7ce7c9d36035881e54887269aa` |
| Integrated implementation head before this report | `d8e8515f26922013ff8703620c6576ad3da3b558` |

## Outcome

All four implementation workstreams were completed locally and independently reviewed. The final whole-branch review found no Critical or Important code defect. The seven issues remain open because browser, broad integration, and remote-check acceptance is incomplete, and none of the changes has been merged. Three dependent draft PRs are open for review. No production host, database, deployment, secret, or production configuration was accessed or changed.

## Issue ledger

| Issue | Status | Evidence and remaining acceptance |
|---|---|---|
| #43 | Browser coverage improved; acceptance incomplete | Added Portal/Hub browser interaction coverage. The existing product toggle implementation was already present. The local Edge run passed both Portal and Hub show/hide interactions, including click, Enter, Space, retained value, ARIA state, and no accidental login submit. Windows E2E now trusts this run's generated CA in CurrentUser Root and removes it by exact thumbprint; browser TLS and the affected historical release still need validation, and no production reproduction is claimed. |
| #45 | Browser timezone acceptance passed; broader acceptance blocked | The central `America/Porto_Velho` formatter labels UTC−4 while stored timestamps and expiry remain UTC. The audit browser test asserted `31/12/2025, 22:00 (UTC−4)`; the broad integration run still has six listener failures. |
| #46 | Implemented locally; browser acceptance incomplete | Persisted invitation/recovery purpose and purpose-specific activation copy are covered by focused PostgreSQL tests, including expiry, replay, and query-purpose spoofing. Browser login and the initial ADMIN recovery request/approval flow ran, but the final approved-link switch redirects to an invalid-link state after confirmation. USER recovery after approval and invitation activation remain unverified. |
| #47 | Browser acceptance passed; broader acceptance blocked | The audit browser E2E passed both ADMIN investigation and USER/missing-Access denial scenarios on a disposable PostgreSQL database. It covered 50/3-row paging, filters, URL state, ordering, redaction, invalid/empty states, keyboard disclosure, responsive widths, and revoked-session denial. The broad integration run still has six listener failures. |
| #48 | Browser redaction acceptance passed; broader acceptance blocked | Structured, queryable audit events and a focused persistence test are present. The audit browser E2E confirms raw legacy/private metadata is absent from the page and safe detail fields render; the audit PostgreSQL test passed 1/1. The broad integration run remains unresolved. |
| #49 | Implemented/reviewed locally; not merged | See the original-ID checklist below. IDs [07] and [25] remain unconfirmed and are excluded as vulnerability claims. Four UI-linked items still lack successful browser acceptance; item [12] has a browser run that exposes an unresolved invalid-link result after confirmation. |
| #50 | Implemented/reviewed locally; not merged | All six original items are addressed in PR #51 with local PostgreSQL and authorization coverage. Full mission acceptance and merge remain pending. |

## #49 original actionable IDs

| ID | Status and evidence |
|---|---|
| [01] | Implemented/reviewed locally: database-level historical actor attribution and FK invariant; focused PostgreSQL evidence passed. |
| [02] | Implemented/reviewed locally: backup temporary storage and interrupted-cleanup handling; focused operations tests passed. |
| [03] | Implemented/reviewed locally with a coverage limitation: bootstrap after pre-account traffic passed before the explicit test-entry guard; later normal discovery skips the dedicated fixture. |
| [04] | Implemented locally; the recovery integration test now directly checks USER/ADMIN source and address bucket isolation. The source bucket records all six portal requests; the address bucket is capped at five attempts. Assertions are in commit `1bc328f` on PR #53; integration execution remains blocked by disposable fixture migration `P1003`. |
| [05] | Implemented/reviewed locally: redact the canonical persisted value; focused tests passed. |
| [06] | Implemented/reviewed locally: successful MFA does not spend the failure budget; focused tests passed. |
| [08] | Implemented/reviewed locally: preserve the login result through forced reauthentication and consent; focused issuer checks passed. |
| [09] | Implemented/reviewed locally: explicit OIDC claims require consent; focused issuer checks passed. |
| [10] | Implemented/reviewed locally: observe concurrent/rejecting audit promises safely; focused tests passed. |
| [11] | Implemented/reviewed locally: enforce Portal/Hub server-action surface boundaries; focused tests passed. |
| [12] | Implemented/reviewed locally: second recovery link is held separately and requires CSRF-confirmed switching. An earlier browser run reached the confirmation prompt, then showed the generic invalid-link state instead of the approved password form. Static review found no proven source cause, and the E2E failure's redirect/cookie diagnostics were not retained. Do not repeat the fixture run: disposable migration setup failed twice with `P1003`; a new diagnostic run requires a working disposable PostgreSQL fixture. |
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
| Recovery rate-limit and restore-cleanup regression tests | `1bc328f` | Direct USER/ADMIN bucket assertions and exact `cleanup_clone` volume guard; Luna review found no remaining confirmed findings. PostgreSQL assertion execution remains blocked by `P1003`. | [#53](https://github.com/bielxdh3/Virki/pull/53), draft. |
| Final whole-branch review | `d8e8515` | Seven-commit review against the verified base found no Critical/Important code defects; acceptance remains blocked. | PRs #51–#53 remain open drafts. |

The PRs are stacked in order: #51 → #52 → #53. Before the follow-up push in this turn, all three were open drafts with no review decisions; PR #53's remote head was `fc746f78c1f8fca471efb5888fffc6dd61e91459`. Follow-up commits `867b8d9` and `1bc328f` were prepared for PR #53. For PR #51, CodeQL run `39070308538` and CI run `39070308623` at head `194c97ed7b7ddbe4bdba44abb2288c741b9ee811` ended in 3–4 seconds before any runner was allocated; jobs had no steps, and GitHub annotations say jobs were not started because recent account payments failed or the spending limit must be increased. Log retrieval returned no log. This is an account-level execution blocker, not evidence of a code failure or successful remote validation. PRs #52 and #53 had no checks before the follow-up push. The issue tracker still showed #43 and #45–#50 open with no comments. `main` remained at `d4e9131df1876c7ce7c9d36035881e54887269aa`.

## Validation record

Runtime for final local checks: Node `v22.20.0`, npm `10.9.4`.

- `npm run test:unit`: 242/242 passed after the final E2E trust/discovery changes.
- `npm run test:public-site`: 5/5 passed.
- Focused invitation/recovery PostgreSQL integration: 6/6 passed on a unique disposable PostgreSQL 17 fixture.
- Focused audit persistence PostgreSQL test: 1/1 passed. Task 1 and Task 2 reports record their disposable PostgreSQL, OIDC, bootstrap, provider, and production-operations test results.
- `node --test scripts/production-ops.test.mjs`: 45 passed / 4 platform-specific skipped after adding explicit checks for the complete `cleanup_clone` body, including its exact labeled-volume deletion guard.
- Independent GPT-6 Luna review and focused re-review of the `cleanup_clone` assertions found no remaining confirmed findings.
- Earlier broad `npm run test:integration`: 59 passed / 6 failed / 1 skipped. The six listener `fetch failed` errors were not reproduced in a focused same-file 7/7 diagnostic, but their cause remains unproven.
- Final broad PostgreSQL integration could not be rerun: a unique fixture failed to start twice because Docker Desktop could not mount the E: workspace path (`/run/desktop/mnt/host/e`, `file exists`). The exact disposable container was absent afterward; its unique temporary helper was removed, and no credential file was created. The shared `virki-integration-postgres-local` container/env file was untouched.
- A separate one-off disposable E2E fixture bypassed the E: bind mount with `docker cp`; its loopback tmpfs container became healthy and was removed, but Prisma migration setup failed with `P1003` and the migration-ledger restriction step also failed. No browser test ran. Windows E2E startup exercised generated-CA installation in the actual CurrentUser root store before reaching database setup; the matching root-store subject count was 0 before and after, and no temporary container remained.
- Browser: Task 3 had 1 pass / 1 fail before the event-ID fix and was not rerun. The targeted password-toggle E2E passed 2/2 in local Edge for Portal and Hub. A fresh audit E2E passed 2/2 on a unique tmpfs-backed PostgreSQL fixture. The authenticated journey spec passed USER and ADMIN login, but its recovery scenario still fails after explicit link-switch confirmation with the generic invalid-link page. Its initial `/recover` crash from `undefined === undefined` was fixed by requiring both candidate and request ID. Windows browser TLS bypasses were removed; Windows now installs the generated test CA in CurrentUser Root and cleans the exact thumbprint on teardown/handled signals, while Linux retains private NSS trust. Playwright `--list` skips trust setup and the Windows discovery check confirms the root-store count stays unchanged. The focused trust/discovery/inventory checks passed 14/14, and the unit suite passed 242/242. The real Windows browser handshake remains unverified because fixture migration failed with `P1003`. The password test filters only the observed Next devtools inline-style CSP messages by exact prefix and source path. These runs do not validate the historical #43 release or production behavior.
- `npm run secrets:scan`: passed.
- `npm run lint`: passed.
- `npm run prisma:validate`: passed.
- `npm run prisma:generate`: passed; required because the current `node_modules` client predated the integrated schema.
- `npm run typecheck`: passed for public-site, Hub, issuer, auth, and database after generation.
- `npm run build`: public-site and Hub Next builds both passed.
- After adding the direct #49 [04] bucket assertions and full `cleanup_clone` source checks, `npm run typecheck`, `npm run lint`, `npm run secrets:scan`, `npm run prisma:validate`, and `npm run build` passed. The #49 PostgreSQL integration assertion itself remains unexecuted because the disposable fixture migration is blocked by `P1003`.
- `git diff --check d4e9131df1876c7ce7c9d36035881e54887269aa...HEAD`: passed.
- Final working-tree `git diff --check`: passed; Git emitted a line-ending warning for the mission report.

## Migrations, security limits, and next gates

The branch contains additive audit and recovery-purpose schema migrations. They were validated/applied only on disposable local PostgreSQL fixtures; no production migration, backup/restore, deployment, secret rotation, or environment change occurred. Production rollout still requires the repository's backup/restore and exact-revision gates. No production rollback operation was attempted.

Remaining Minor review items: Task 3's audit view/query use long compressed expressions. Task 1 now has direct source/address bucket assertions, but their PostgreSQL integration execution is blocked by the disposable fixture migration `P1003`. None was rated Critical or Important, and all are recorded in the local working ledger.

Next acceptance gates: isolate the approved recovery-link switch failure with new evidence; resolve the disposable fixture migration `P1003` blocker or provide another verified disposable PostgreSQL runtime; run browser UI assertions for remaining affected flows with generated-CA verification enabled on Windows and verify a browser handshake; review remote checks when available; then update the original issue checklists only for evidence that passes acceptance. Do not merge while required local/browser/remote acceptance is missing. Do not close any issue until its complete acceptance is verified on the merged default branch.
