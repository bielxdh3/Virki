# Final local security gate closure

Date: 2026-10-19
Disposition: **BLOCKED_WITH_EVIDENCE**

## Source and final run

- Worktree: `E:\Virki\.worktrees\virki-full-security-remediation-20261019`
- Branch: `cdx/virki-full-security-remediation-20261019`
- HEAD: `a532560a3c2c32f05ed8ff3d415778be11d83581`
- Final isolated run: `780a48000c`; Node `v22.23.3`; npm `10.9.9`; evidence: `.superpowers/sdd/2026-10-19-virki-final-gates/runs/780a48000c/`. The manifest records 17/17 stages with exit 0; full unit, integration, browser, and production-operations TAP logs are retained.
- PostgreSQL role-isolation run: `4f6a1e3de7`; Node `v22.23.3`; npm `10.9.9`; pass for fresh, interrupted-init, and populated PostgreSQL 17 fixtures; evidence: `.superpowers/sdd/2026-10-19-virki-final-gates/role-tests/4f6a1e3de7/database-role-isolation.log`
- Focused production-mode LOW-05 run: `210cd37481`; production Hub build and browser E2E passed 1/1. Earlier failed attempts and bounded runner setup failures remain recorded in the [final report](final-local-security-gates-report.md).

All 17 stages in final run `780a48000c` exited 0 with `failedStages=[]`; it confirmed the stated branch and HEAD. PostgreSQL and browser tests used isolated disposable runners. The integration TAP is retained as `integration-tests.tap.log`; it records 86 pass, 0 fail, 1 skip and includes the new PostgreSQL 17 test for the inventory privilege queries. The role-isolation command ran under the supported Windows Node 22 runtime against its own labeled PostgreSQL fixtures and removed those fixtures. The focused production-mode LOW-05 run used a local production Hub behind a loopback HTTPS adapter and passed its browser test. No production host, Cloudflare/Tunnel, external GitHub state, or production database was contacted.

## Final validation

| Gate | Result |
|---|---|
| Production operations | 100 TAP tests: 98 pass, 0 fail, 2 native-Linux-only skips on WSL |
| Public site | 7/7 pass |
| Unit | 307/307 pass; complete TAP retained |
| Integration | 86 pass, 0 fail, 1 skip; complete TAP retained and referenced by the manifest |
| Browser E2E | Final Next dev run: 21/21 pass; focused production Hub LOW-05 run: 1/1 pass. |
| PostgreSQL role isolation | Fresh, interrupted-init, and populated disposable PostgreSQL 17 fixtures passed. |
| Secrets scan, lint, typecheck, Prisma validate, build, and other manifest stages | Exit 0 |

The two production-operations skips cover the native shell probe and pristine first-install shell guard; both require native Linux, and the current environment is WSL. The single integration skip is `legitimate bootstrap survives real pre-account authentication, audit and limiter activity in an otherwise virgin DB`; the dedicated virgin fixture was not configured. The earlier `044d469937` run's integration TAP was not retained, so its pass/skip counts are superseded by the complete log in `780a48000c`. The older SDD ledger's 96-pass figure conflicts with the retained `1790baebb5` log's 97-pass figure; no matching run id/log for 96 is available, so that historical discrepancy remains unresolved. See the [final report](final-local-security-gates-report.md) for the failure crosswalk and safe future fixture requirements.

The earlier production-operations run `1790baebb5` had 23 failures: one isolated-root path assertion and 22 Linux-only tests that reached the expected WSL rejection. The path assertion now resolves the isolated root from `package.json`; the test's WSL predicate reads the same normalized `/proc/sys/kernel/osrelease` value as `production-server.sh`. The final run has no operations-test failures. Native Linux behavior remains unverified.

## Findings

The [security remediation matrix](security-remediation-matrix.md) records 50 unique findings: 33 `FIXED_AND_REVIEWED`, 13 `JUSTIFIED_NO_CHANGE`, and 4 `BLOCKED_UNVERIFIED`; `BLIND-01` aliases `MED-03`.

| Blocked ID | Remaining evidence |
|---|---|
| `HIGH-16` | Real aggregate counts for missing/cross-owner elevations and active duplicates, plus a reviewed session/elevation deletion and retention policy before DDL. |
| `MED-20` | Real null/blank/mismatch/canonical-collision counts, reviewed per-account resolution, and an approved canonical account-state policy before backfill or constraints. |
| `MED-22` | Real outbox lease/timestamp and grantor/reviewer aggregate counts, reviewed state/attribution policy, and disposable-restore migration compatibility. |
| `LOW-08` | Representative query plans, key skew and call frequency, row/table/index sizes, and read/write workload evidence. The current synthetic plan does not provide this. |

LOW-05 is fixed for the reported user-visible stale-content behavior. The production-mode browser run observed the protected route's `private, no-store, max-age=0, must-revalidate` policy, a 303 no-store logout, cleared session cookie, revoked session, and a safe login page after Back. In both production and final development browser runs, `pagehide.persisted=false` and `pageshow.persisted=false`, with `notRestoredReasons` empty; neither run observed a BFCache restoration. The E2E proves the final sensitive state stayed absent but does not directly assert the protected document's `PerformanceNavigationTiming.type` or that the hydration history detector caused the revalidation; unit tests cover those detector branches. `no-store` is not treated as a BFCache exclusion. The final independent reviewer found no stale-content defect or reload loop and retained that P2 evidence limitation. Effective reviewer model/effort is not exposed; requested GPT-6 Luna/High is not independently attested (`USER_CONFIGURED_NOT_API_ATTESTED`). HIGH distribution: 11 fixed/reviewed, 4 justified/no change, 1 blocked.

Exact-SHA remote CI, CodeQL/SARIF, registry state, native Linux production operations, production topology, production-shaped data/workload inventories, and human acceptance remain unverified. No commit, push, merge, release, or deployment occurred; staged, unstaged, and untracked work was preserved.

**Final disposition: `BLOCKED_WITH_EVIDENCE`.** Final local validations, including LOW-05 production-mode browser verification, passed. Four other findings remain blocked, and exact-SHA remote CI, CodeQL/SARIF, registry, native Linux, production topology, and human acceptance remain unverified. The result does not authorize production or release. See the [Brazilian Portuguese final report](final-local-security-gates-report.md).

## Final four finding remediation

The latest unit, integration, and E2E run `780a48000c` passed all selected stages: 307/307 unit, 86 integration pass with 1 virgin-database skip, and 21/21 browser E2E. Lint, typecheck, Prisma validation, build, secret scan, production revision/backup/operations contracts, public-site checks, and the runner's diff check also exited 0. `test:database:roles` separately passed all three owned PostgreSQL 17 role fixtures in `4f6a1e3de7`.

### Independent review follow-ups

Two new review follow-ups were found after the previous run and corrected without changing the original 50-ID count: `NEW-01` closes the legacy inventory's overbroad privilege claim by checking effective privileges across all public relations, column grants, sequences, routines, schemas, database/object ownership and applicable default ACLs; `NEW-02` retains complete integration TAP and its manifest reference. Unit counterexamples and a disposable PostgreSQL 17 integration test exercise `NEW-01`; runner contract tests exercise `NEW-02`. A targeted independent rereview found no remaining actionable P1/P2 issue in either correction. Requested reviewer model/effort was GPT-6 Luna/High; effective metadata is `USER_CONFIGURED_NOT_API_ATTESTED` and is not an execution blocker.

MED-20's admin UI and server action now use canonical `accountStatus` and require consistent current state before a toggle. MED-22's worker reclaims PROCESSING rows whose lease is NULL through its existing compare-and-swap claim, and stale attempt finalizers remain fenced. HIGH-16 regression coverage demonstrates fail-closed behavior for missing, cross-user, revoked, and expired session references, duplicate scope behavior, and cleanup leaving inert stale rows. No DDL or workload-driven index was added.

The four dispositions remain `BLOCKED_UNVERIFIED` because a real operator-approved aggregate inventory and finding-specific policy decisions are still required. `docs/legacy-data-closure-plan.md` defines a fail-closed PostgreSQL 17 inventory that was exercised only against the disposable application role; it was not run against real data or a snapshot. Requested model/effort provenance remains `USER_CONFIGURED_NOT_API_ATTESTED`, as instructed by the active objective; this is not an execution blocker.
