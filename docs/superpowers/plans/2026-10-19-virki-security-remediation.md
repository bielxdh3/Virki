# Virki security and reliability remediation

## Objective

Work through the user's 50 distinct audit IDs on the isolated `cdx/virki-full-security-remediation-20261019` branch at the verified `a532560a3c2c32f05ed8ff3d415778be11d83581` baseline. Fix only defects that are reproducible and in scope, preserve fail-closed and intentional behavior, add regression coverage for accepted fixes, and record an evidence-backed disposition for every ID. `BLIND-01` aliases `MED-03` and is counted once.

## Boundaries

- Local work only. No production host, SSH, real database, secrets, Cloudflare, GHCR, GitHub issue/PR, push, merge, release, or remote CI activity.
- Use only disposable owned fixtures/containers for database or Docker checks; if ownership or cleanup is uncertain, leave the runtime claim blocked with exact missing evidence.
- Use the repository's Node `>=22.13 <23` and npm `>=10.9.3 <11` toolchain.
- Preserve the minimal Virki UI and its accessibility patterns. Apply UI-UX-PRO-MAX only to affected security messages/flows; no broad redesign.
- Keep tests focused while developing; run the requested repository checks once on the final changed tree. Do not represent local checks as remote CI or production evidence.
- Lead configuration evidence: `MAIN_MODEL_EFFORT=USER_CONFIGURED_NOT_API_ATTESTED`. Native workers were explicitly requested as GPT-6 Luna/HIGH for the initial read-only triage; hidden effective metadata is not available.

## Work sequence

### Task 1 — Workflow, audit, abuse limits, and release-state defects

Address CRIT-01, HIGH-03, HIGH-08, MED-06, MED-16, MED-17, MED-18, LOW-01, and HIGH-11 where the current-source reproductions support a fix. Write failing fixtures first for SARIF/package-token separation, audit sanitizer/bootstrap compatibility, interaction audit amplification, provider route normalization, successful rerun/run selection, secret scanner coverage, cleanup target behavior, and backup-gated staged-source activation. Keep production shell tests isolated with temporary roots and mocks. Do not change conditional HIGH-12 absent a concrete, supported provenance gap.

Acceptance: focused RED/GREEN tests prove each accepted root-cause fix; the deployment state machine remains fail-closed and selection remains exact-SHA/main/push/success. Independent native Codex HIGH read-only review records any blocker or a clean result before the next phase.

### Task 2 — Authentication, OIDC, authorization, recovery, and security UX

Address actionable items from HIGH-01/02/04/05/07/09/10/16, MED-01 through MED-15, MED-24, LOW-03/04/05/06/07, and BLIND-01/MED-03. Keep justified no-change and blocked-unverified findings distinct. Add RED tests before changing behavior, especially around active-session revocation versus privileged writes, OIDC artifact revocation, login throttling and device identity, recovery ceremonies, and audit redaction. UI changes must preserve keyboard access, focus, labels, contrast, responsive behavior, and existing compact surfaces.

Acceptance: focused auth/OIDC/action tests cover accepted fixes and protected flows; valid sign-in, recovery, MFA, logout, grants, and SSO remain usable. Ingress-dependent HIGH-06 and database-concurrency claims stay blocked unless an owned supported fixture can reproduce them. Independent native Codex HIGH review follows this phase.

### Task 3 — PostgreSQL roles, data invariants, migrations, containers, and operations

Address HIGH-13/14/15/16, MED-19/20/21/22/23, LOW-01/02/07/08/09, coordinating shared role and cleanup files with Task 1. Preserve `AuditLog.actorUserId ON DELETE RESTRICT`, retention reads/events, existing encrypted data, and supported Compose topology. For any DDL, inspect production-shaped edge cases on a disposable restore before adding constraints or indexes. Do not claim DB behavior proven without an isolated PostgreSQL/Linux run.

Acceptance: least-privilege and migration tests cover accepted changes; existing actor audit history and configured retention remain intact; new migration rerun/upgrade checks pass where infrastructure permits. Independent native Codex HIGH review follows this phase.

### Task 4 — Consolidated matrix, adversarial review, and local release candidate

Update `docs/security-remediation-matrix.md` with all 50 IDs exactly once plus the `BLIND-01` duplicate mapping, evidence, severity reassessment, code/test references, disposition, and unresolved external/runtime evidence. Run one independent native Codex HIGH adversarial review on the complete diff, with emphasis on new P1/P2 regressions, race conditions, authorization, leaked secrets, OIDC/session behavior, and operational gates. Correct actionable blockers with targeted RED/GREEN tests and bounded re-review.

Run the focused tests selected by the changes, then one final pass of `npm run test:unit`, `npm run secrets:scan`, `npm run lint`, `npm run typecheck`, `npm run prisma:validate`, `npm run build`, and `git diff --check`. Add disposable Docker/PostgreSQL and Compose validation only if the local runtime and cleanup boundary are verified. Inspect final status and the full diff; do not commit unless all work is reviewable and repository policy supports a local commit.

## Evidence and reporting

Keep an SDD ledger in this plan's ignored `.superpowers/sdd` workspace. Each accepted fix records the initial failing test, correction, passing focused test, reviewer identity/configuration evidence, and any targeted correction/re-review. The final matrix distinguishes `FIXED_AND_REVIEWED`, `JUSTIFIED_NO_CHANGE`, `NOT_REPRODUCED`, and `BLOCKED_UNVERIFIED`; severity labels from the audits are not treated as proof. Final report is in Brazilian Portuguese and includes branch/HEAD, per-disposition counts, exact local exit statuses and test counts, model/effort evidence level, delegation ledger/HIGH share, every unresolved P1/P2 and external gate, and the decision `READY_FOR_EXTERNAL_REVIEW` or `BLOCKED_WITH_EVIDENCE`. Remote CodeQL/GitHub Checks remain `UNVERIFIED_PENDING_REMOTE_CI` unless actually run by an authorized external workflow.

## Final disposition — 2026-10-19

**The latest recorded local validation is `780a48000c`; overall closure remains `BLOCKED_WITH_EVIDENCE`.** It verified the worktree branch and HEAD and completed all 17 stages with exit code 0. The run recorded 307/307 unit tests, 86 integration tests passed plus one virgin-database fixture skip, 21/21 browser E2E, a focused production-mode Hub E2E of 1/1, and 98 production-operations tests passed plus two native-Linux-only skips. The complete integration TAP was retained. The current security matrix contains 50 distinct findings: `33 FIXED_AND_REVIEWED`, `13 JUSTIFIED_NO_CHANGE`, and `4 BLOCKED_UNVERIFIED`.

The four remaining blocked IDs are `HIGH-16`, `MED-20`, `MED-22`, and `LOW-08`. `LOW-05` is `FIXED_AND_REVIEWED`; its remaining P2 evidence limitation is that the browser run did not observe a BFCache restoration or directly establish that the protected USER-page navigation detector fired. Remote exact-SHA CI/CodeQL/SARIF, native production Linux, production topology, production-shaped data/workload inventories, and human acceptance remain unverified. See [the final local security gates report](../../final-local-security-gates-report.md), [the finding matrix](../../security-remediation-matrix.md), and `.superpowers/sdd/2026-10-19-virki-final-gates/final-ledger.md`.
