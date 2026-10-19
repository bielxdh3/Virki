# Virki final four findings — implementation plan

## Goal

Complete the local remediation and evidence closure for HIGH-16, MED-20, MED-22, and LOW-08 in the existing dirty worktree. Fix only defects demonstrated by current code and deterministic tests. Keep changes that depend on real legacy data, production workload, deletion policy, or external operations explicitly blocked.

## Fixed boundaries

- Work only in `E:\Virki\.worktrees\virki-full-security-remediation-20261019`, preserving all staged, unstaged, and untracked work.
- No production, SSH, real database/snapshot/credentials, Cloudflare, GHCR, GitHub state, deManage, commit, push, PR, merge, release, or deployment activity.
- Use mission-owned disposable PostgreSQL 17 resources only; never stop or remove resources not created and exclusively owned by this mission.
- Supported validation must use Node `>=22.13.0 <23` and npm `>=10.9.3 <11`. The host's Node 24 is not supported-runtime evidence.
- Keep `SecurityElevation` FK/uniqueness DDL, account-email backfills/merges, outbox CHECK/FK constraints, and workload-driven index changes unapplied absent real aggregate inventory and policy approval.
- Requested agent model/effort metadata unavailable to this harness is recorded as `USER_CONFIGURED_NOT_API_ATTESTED`; this is not a blocker under the active objective.

## Work sequence

### 1. HIGH-16 — elevation/session lifecycle

1. Confirm current authorization paths and session cleanup behavior against source and existing integration fixtures.
2. Add or extend owned PostgreSQL 17 regression cases for orphaned elevation, cross-user session linkage, revoked and expired sessions, duplicate effective rows, cleanup behavior, and revocation-versus-privileged-mutation ordering. Use deterministic transaction barriers where applicable.
3. Fix only any demonstrated application-level authorization/lifecycle issue; preserve transaction locking, rechecks, and existing audit semantics.
4. If authorization already rejects every invalid linkage and cleanup only leaves inert rows, retain no-change for runtime and keep relational DDL blocked pending count-only inventory and deletion policy.

### 2. MED-20 — email and account state

1. Derive normalization and admission behavior from the current `normalizeEmail` helper and account authorization paths; do not introduce new Unicode equivalence or fallback identity matching.
2. Write regression tests first for the admin account list's status label and actions across `ACTIVE`, `INACTIVE`, `BLOCKED`, and `PENDING_ACTIVATION`, including inconsistent legacy field combinations.
3. Change the display to follow canonical `accountStatus`; ensure the existing state toggle cannot silently promote blocked, pending, or contradictory rows. Preserve the explicit `setAccountStateAction` contract and audit trail.
4. Cover relevant normalization boundaries and ambiguous legacy records without merging accounts or changing recovery lookup semantics absent a safe policy.

### 3. MED-22 — outbox, grantor, reviewer integrity

1. Trace claim, lease, finalization, retry, approval, and attribution transitions in source and current migrations.
2. Add a deterministic PostgreSQL 17 RED regression showing whether `PROCESSING` with a null lease is permanently unclaimable, plus a stale-finalizer/concurrent-claim case.
3. If reproduced, make a null lease immediately reclaimable through the existing claim compare-and-swap/fencing contract; verify concurrent claims remain exclusive and stale finalizers cannot overwrite a newer claim.
4. Retain existing reviewer self-approval rejection. Do not add grantor/reviewer/outbox DDL until aggregate legacy evidence and explicit retention/deletion semantics exist.

### 4. LOW-08 — source mapping and workload evidence

1. Correct `docs/index-query-plan-evidence.md` so every synthetic query is clearly labeled and the active-elevation plan maps to the actual list and authorization callers separately.
2. Document limits of audit-filter coverage and missing FK-side indexes without claiming production impact or speedup.
3. Do not change indexes without production workload evidence or a reproducible correctness defect.
4. Provide a count-only operator collection procedure and workload checklist; it must validate target/schema/read-only access before counts and emit aggregates only. It will not be run against any real database in this mission.

### 5. Legacy compatibility, exact finding ledger, and reports

1. Add a legacy-data closure plan documenting code invariants, synthetic proof, operator-only counts, policy decisions, and fail-closed migration gates for all four findings.
2. Update the existing 50-ID security matrix without changing unrelated dispositions; preserve the `BLIND-01 -> MED-03` alias and record paths, test evidence, and remaining evidence for the four rows.
3. Reconcile `docs/gate-closure-report.md`, `docs/final-local-security-gates-report.md`, and the LOW-08 evidence report against actual fresh local output; keep hosted CI, CodeQL/SARIF, registry, production, Cloudflare, and human/operator gates separate and unverified.

### 6. Independent review and validation

1. Request an independent read-only native Codex review of the changed findings and supporting artifacts, including P1/P2 attack paths, transactional races, unsafe migration behavior, and sensitive-output leakage. Request a separate blind review of the final delta where available. Preserve requested-model/effort provenance as unverified if the runtime does not expose it.
2. Fix actionable P1/P2 findings using a bounded RED/GREEN/review cycle; do not exceed three review/fix rounds for the same implementation.
3. Use the repository's isolated supported-runtime runner only after inspecting its current safety and ownership behavior. Run focused regressions first, then the requested supported Node 22/npm 10 local gate set after the last code change: secret scan, unit, public site, database roles, applicable integration/E2E, production-revision local contracts where affected, lint, typecheck, Prisma validation, build, and `git diff --check HEAD`.
4. Record exact commands, versions, exit codes, counts, skips and SHA. Do not run tests on Node 24 as supported evidence or remove preexisting resources.
5. Recheck branch, HEAD and full porcelain status; verify all 50 matrix IDs remain unique and the alias is exact; inspect the complete task diff and new files for unintended content.

## Acceptance criteria

- Demonstrated application-level defects have a failing regression before the minimal fix and a passing supported-runtime regression afterward.
- No authorization, session ownership, account identity, outbox fencing, reviewer, audit, or recovery invariant is weakened.
- No speculative or data-destructive DDL/index change is applied.
- Safe operator-only aggregate procedures and precise blockers cover evidence that cannot be collected locally.
- The 50-ID matrix and three closure reports agree with observed evidence and distinguish local proof from external gates.
- Independent review finds no unresolved P1/P2 in the final delta, or each remaining issue is explicitly blocked with its evidence dependency.
- The existing dirty worktree is preserved and no publishing or production boundary is crossed.

## Execution policy

Follow the repository and global AGENTS instructions, AI Memory retrieval policy, Ponytail, UI-UX-Pro-Max for the account interface, and applicable Superpowers planning, TDD, debugging, review, and verification instructions. Keep edits minimal, validate only relevant acceptance criteria, and stop repeated phases at the documented retry limits.
