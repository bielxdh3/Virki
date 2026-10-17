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
| #43 | Blocked | Added Portal/Hub browser interaction coverage. The existing product toggle implementation was already present. Chromium launched against the local fixture, but both navigations stopped at `ERR_CERT_AUTHORITY_INVALID` before UI assertions. The affected historical release was inspected but not launched; no production reproduction is claimed. |
| #45 | Implemented locally; acceptance blocked | A central `America/Porto_Velho` formatter labels UTC−4 while stored timestamps and expiry remain UTC. Browser acceptance after the final exact-ID correction is unverified; the broad integration run had six listener failures. |
| #46 | Implemented locally; acceptance incomplete | Persisted invitation/recovery purpose and purpose-specific activation copy are covered by focused PostgreSQL tests, including expiry, replay, and query-purpose spoofing. Full browser rendering and end-to-end invitation/recovery flow remain unverified. |
| #47 | Implemented locally; acceptance blocked | Audit search, filters, URL state, sorting, bounded server paging, redacted details, and accessible states are implemented. The browser run before the exact-ID correction was 1 pass / 1 fail; it was not repeated. Broad integration had six listener failures. |
| #48 | Implemented locally; acceptance blocked | Structured, queryable audit events and a focused persistence test are present. The audit PostgreSQL test passed 1/1. Broad integration and complete browser acceptance remain unresolved. |
| #49 | Implemented/reviewed locally; not merged | See the original-ID checklist below. IDs [07] and [25] remain unconfirmed and are excluded as vulnerability claims. Four UI-linked items still lack browser interaction evidence. |
| #50 | Implemented/reviewed locally; not merged | All six original items are addressed in PR #51 with local PostgreSQL and authorization coverage. Full mission acceptance and merge remain pending. |

## #49 original actionable IDs

| ID | Status and evidence |
|---|---|
| [01] | Implemented/reviewed locally: database-level historical actor attribution and FK invariant; focused PostgreSQL evidence passed. |
| [02] | Implemented/reviewed locally: backup temporary storage and interrupted-cleanup handling; focused operations tests passed. |
| [03] | Implemented/reviewed locally with a coverage limitation: bootstrap after pre-account traffic passed before the explicit test-entry guard; later normal discovery skips the dedicated fixture. |
| [04] | Implemented locally; source-budget regression evidence is partial. Address-bucket isolation is covered; the separate source bucket lacks a direct regression assertion. |
| [05] | Implemented/reviewed locally: redact the canonical persisted value; focused tests passed. |
| [06] | Implemented/reviewed locally: successful MFA does not spend the failure budget; focused tests passed. |
| [08] | Implemented/reviewed locally: preserve the login result through forced reauthentication and consent; focused issuer checks passed. |
| [09] | Implemented/reviewed locally: explicit OIDC claims require consent; focused issuer checks passed. |
| [10] | Implemented/reviewed locally: observe concurrent/rejecting audit promises safely; focused tests passed. |
| [11] | Implemented/reviewed locally: enforce Portal/Hub server-action surface boundaries; focused tests passed. |
| [12] | Implemented/reviewed locally: second recovery link is held separately and requires CSRF-confirmed switching; integration tests passed, but browser switching flow is unverified. |
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
| OIDC/operations | `194c97e` | Independent review approved; one Minor test-assertion coverage limitation remains. | [#51](https://github.com/bielxdh3/Virki/pull/51), draft |
| Structured audit/timezone/search | `dd65ba1`, `eae4e61` | Fix round 1 approved; no open Critical/Important findings. | [#52](https://github.com/bielxdh3/Virki/pull/52), draft; head `eae4e617b6d1cc75625bfae4472d4c5c27f758d9` |
| Login/invitation/recovery | `2bd0082`, `d8e8515` | Fix round 1 approved; no open Critical/Important findings. | [#53](https://github.com/bielxdh3/Virki/pull/53), draft; includes this tracked mission report. |
| Final whole-branch review | `d8e8515` | Seven-commit review against the verified base found no Critical/Important code defects; acceptance remains blocked. | PRs #51–#53 remain open drafts. |

The PRs are stacked in order: #51 → #52 → #53. At the latest check, all three were open drafts with no reviews. PR #51's CI and CodeQL workflow runs completed with failure; the listed jobs had no step summaries and log retrieval returned 404 `BlobNotFound`, so the failure cause is unconfirmed and the workflows were not rerun. PRs #52 and #53 had no workflow runs or status checks reported. Remote validation is not green. The issue tracker still showed #43 and #45–#50 open with no comments. `main` remained at `d4e9131df1876c7ce7c9d36035881e54887269aa`.

## Validation record

Runtime for final local checks: Node `v22.20.0`, npm `10.9.4`.

- `npm run test:unit`: 238/238 passed.
- `npm run test:public-site`: 5/5 passed.
- Focused invitation/recovery PostgreSQL integration: 6/6 passed on a unique disposable PostgreSQL 17 fixture.
- Focused audit persistence PostgreSQL test: 1/1 passed. Task 1 and Task 2 reports record their disposable PostgreSQL, OIDC, bootstrap, provider, and production-operations test results.
- Earlier broad `npm run test:integration`: 59 passed / 6 failed / 1 skipped. The six listener `fetch failed` errors were not reproduced in a focused same-file 7/7 diagnostic, but their cause remains unproven.
- Final broad PostgreSQL integration could not be rerun: a unique fixture failed to start twice because Docker Desktop could not mount the E: workspace path (`/run/desktop/mnt/host/e`, `file exists`). The exact disposable container was absent afterward; its unique temporary helper was removed, and no credential file was created. The shared `virki-integration-postgres-local` container/env file was untouched.
- Browser: Task 3 had 1 pass / 1 fail before the event-ID fix and was not rerun. Task 4 Chromium launched but Portal and Hub navigations failed with local certificate authority errors before assertions. The historical #43 release was not launched. No TLS bypass was used.
- `npm run secrets:scan`: passed.
- `npm run lint`: passed.
- `npm run prisma:validate`: passed.
- `npm run prisma:generate`: passed; required because the current `node_modules` client predated the integrated schema.
- `npm run typecheck`: passed for public-site, Hub, issuer, auth, and database after generation.
- `npm run build`: public-site and Hub Next builds both passed.
- `git diff --check d4e9131df1876c7ce7c9d36035881e54887269aa...HEAD`: passed.

## Migrations, security limits, and next gates

The branch contains additive audit and recovery-purpose schema migrations. They were validated/applied only on disposable local PostgreSQL fixtures; no production migration, backup/restore, deployment, secret rotation, or environment change occurred. Production rollout still requires the repository's backup/restore and exact-revision gates. No production rollback operation was attempted.

Remaining Minor review items: Task 1 recovery rate-limit tests directly assert the address bucket but not the separate source bucket; Task 2's production-ops source assertion excludes the full `cleanup_clone` body; Task 3's audit view/query use long compressed expressions. None was rated Critical or Important, and all are recorded in the local working ledger.

Next acceptance gates: resolve the Docker Desktop fixture-mount blocker or provide another verified disposable PostgreSQL runtime; complete browser UI assertions for the affected flows without weakening TLS; review remote checks when available; then update the original issue checklists only for evidence that passes acceptance. Do not merge while required local/browser/remote acceptance is missing. Do not close any issue until its complete acceptance is verified on the merged default branch.
