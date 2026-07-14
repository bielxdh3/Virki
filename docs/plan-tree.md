# BielOS Plan Tree

Status labels:

- `[DONE]` already implemented or documented.
- `[CURRENT]` active planning focus.
- `[NEXT]` should be implemented soon.
- `[LATER]` planned after production safety.
- `[BLOCKED]` blocked until prerequisites are complete.
- `[DO NOT IMPLEMENT YET]` reserved future module.

## 0. Project Goal

BielOS is a private personal hub, not a public SaaS.

- `[DONE]` Public site target: `biel.dev.br`.
- `[DONE]` Private hub target: `hub.biel.dev.br`.
- `[DONE]` Hub security model: Cloudflare Access first, BielOS internal auth second.
- `[DONE]` Private/non-discardable data ingestion safety prerequisites now include committed migrations plus documented and disposable-tested backup/restore.

## 1. Foundation

- `[DONE]` Monorepo with Next.js apps, shared packages, TypeScript, Prisma, PostgreSQL, Docker Compose, CI, lint, build validation, and secret scan.
- `[DONE]` Codex control layer:
  - `AGENTS.md`
  - `.agents/skills/bielos-phase-review/SKILL.md`
  - `.agents/skills/bielos-security-review/SKILL.md`
  - `.agents/skills/bielos-publication-check/SKILL.md`

## 2. Public Site Plan

- `[DONE]` Public site app exists at `apps/public-site`.
- `[DONE]` Public site builds independently from PostgreSQL.
- `[DONE]` Public site production container starts locally.
- `[DONE]` Local public site health responds at `http://127.0.0.1:3000`.
- `[DONE]` Live public route smoke test for `https://biel.dev.br` and `https://www.biel.dev.br`.
- `[LATER]` Expand public content only with safe, non-private information.

## 3. Private Hub Plan

- `[DONE]` Private hub app exists at `apps/hub`.
- `[DONE]` Hub depends on PostgreSQL where needed.
- `[DONE]` Hub dashboard shell exists.
- `[DONE]` Safe hub health endpoint exists at `GET /api/health`.
- `[DONE]` Local hub health responds at `http://127.0.0.1:3001/api/health`.
- `[DONE]` Live private route smoke test for `https://hub.biel.dev.br`.
- `[DONE]` Private hub module shell registry exists.
- `[DONE]` Module security design template exists.
- `[DONE]` Consolidated module planning index exists at `docs/modules/README.md`.
- `[CURRENT]` BielOS Core expansion is explicitly authorized and is the active product path.
- `[DONE]` The existing Core data foundation includes `Project`, `ProjectAccess`, `Session`, `SecurityUnlock`, and `AuditLog` models.
- `[DONE]` BielOS Core security and architecture gate exists at `docs/modules/bielos-core.md`.
- `[DONE]` Core project registry and project management use the existing `Project` model with bounded authorization, CSRF, archive-only deletion policy, and sanitized audits.
- `[DONE]` Core project access management uses `ProjectAccess` with OWNER/ADMIN authority limits, serializable invariants, duplicate prevention, CSRF, and sanitized audits.
- `[DONE]` `SecurityUnlock` completed Outcome B as a design-only boundary; runtime remains blocked in `docs/security-unlock.md`.
- `[DONE]` Personal Core session management uses the existing `Session` model without exposing tokens, hashes, cookies, headers, or cross-user data.
- `[DONE]` The typed hub registry separates Core workspace surfaces, available GymForge, and inert reserved modules.
- `[DONE]` Core operations visibility separates verified request-time checks, configured architecture, and external manual checks without fabricated telemetry.
- `[DONE]` The owner-only audit activity viewer exposes a bounded, sanitized, read-only event summary without raw metadata, messages, emails, or identifiers.
- `[DONE]` BielOS Core adversarial security/static-UI review found no medium/high/critical issue and fixed bounded identifiers, generic audit failure logging, and operations probe accumulation.
- `[DONE]` Full Core validation, current backup, committed migration deployment, production restart, and unauthenticated smoke checks passed.
- `[DONE]` Database-backed Core authorization, mutation, access-invariant, session-isolation, audit-bound, operations, and concurrency tests run against disposable migrated PostgreSQL and are integrated into CI.
- `[NEXT]` Complete the authenticated OWNER/MEMBER browser smoke with existing disposable identities; do not bypass Cloudflare Access or BielOS authentication.
- `[DONE]` GymForge is an available authenticated application integrated into the private hub at `/gymforge`.
- `[BLOCKED]` Further GymForge feature expansion is frozen; preserve its implemented functionality without continuing its optional roadmap.
- `[BLOCKED]` New real module implementations remain blocked until each completes `docs/module-security-template.md` and any required module architecture document.
- `[BLOCKED]` root.ark implementation also requires a dedicated public zero-knowledge architecture phase.
- `[DONE]` GymForge MVP foundation exists behind the private hub with an authenticated route and implemented foundation features.
- `[DONE]` GymForge participant/admin read foundation exists behind the private hub.
- `[DONE]` GymForge admin-only participant management exists behind the private hub.
- `[DONE]` GymForge admin-only exercise catalog management exists behind the private hub.
- `[DONE]` GymForge participant attendance check-in foundation exists behind the private hub.
- `[DONE]` GymForge attendance uses explicit `America/Sao_Paulo` day boundaries.
- `[DONE]` GymForge workout entry foundation exists for linked ACTIVE participants.
- `[DONE]` GymForge ranking and streak foundation exists for active participants.
- `[DONE]` GymForge competition foundation exists for admin-created metadata and read-only display.
- `[DONE]` GymForge competition assignment and scoring design exists.
- `[DONE]` GymForge competition participant assignment and automatic scoring implementation exists.
- `[DONE]` GymForge competition lifecycle management exists for admin-only metadata/status edits and archival.
- `[DONE]` GymForge UI usability pass and safe competition deletion exists for non-ACTIVE competitions with zero assignments.
- `[DONE]` GymForge admin attendance correction exists behind OWNER/ADMIN, CSRF, and sanitized audit events.
- `[DONE]` GymForge workout editing/deletion exists with participant ownership, OWNER/ADMIN override, CSRF, and sanitized audit events.
- `[DONE]` GymForge workout integrity intentionally keeps creation/editing to exactly one set, rejects updates for unexpected zero/multi-set records, and transactionally removes all dependent sets on explicit workout deletion.
- `[DONE]` GymForge competition score-correction Phases 2 and 3 exist with additive history, deterministic current-state scoring, guarded lifecycle mutations, private bilingual UI, and redacted audits.
- `[DONE]` BielOS language selector exists with Portuguese default and English option.

## 4. Cloudflare, Tunnel, And Access Plan

- `[DONE]` Cloudflare Tunnel Compose service exists.
- `[DONE]` Docker-mode tunnel routing is documented to use service names:
  - `http://public-site:3000`
  - `http://hub:3001`
- `[DONE]` `cloudflared` publishes no host ports.
- `[DONE]` Cloudflare Access is the required outer boundary for `hub.biel.dev.br`.
- `[DONE]` Optional origin-side Cloudflare Access JWT validation exists.
- `[DONE]` Required-and-missing/invalid Access JWT returns HTTP `403`.
- `[DONE]` Live Cloudflare smoke test confirmed the public site is public and the hub shows Cloudflare Access first.

## 5. Auth, Session, And CSRF Plan

- `[DONE]` OWNER seed flow uses private local env values.
- `[DONE]` Internal BielOS login is implemented.
- `[DONE]` Session tokens are stored hashed at rest.
- `[DONE]` Production session cookies are HttpOnly, SameSite=Lax, and Secure.
- `[DONE]` Logout revokes the session and clears the cookie.
- `[DONE]` CSRF protection covers:
  - login and logout
  - Core project lifecycle and project access mutations
  - personal session mutations
  - existing mutable GymForge flows
- `[DONE]` Missing/invalid CSRF returns HTTP `403`.
- `[DONE]` Production session cleanup worker runs on an interval.
- `[DONE]` Persistent login rate limiting.
- `[LATER]` Edge-level or broader abuse controls if needed.
- `[LATER]` Session management improvements after launch safety is proven.
- `[LATER]` Shared CSRF secret or alternate strategy only if multiple hub replicas are used.

## 6. Docker And Production Plan

- `[DONE]` Production Compose includes:
  - `public-site`
  - `hub`
  - `postgres`
  - `cloudflared`
  - `session-cleanup`
- `[DONE]` App host-published ports are bound to `127.0.0.1`.
- `[DONE]` `session-cleanup` has no host-published ports.
- `[DONE]` `cloudflared` has no host-published ports.
- `[DONE]` Hub healthcheck uses `/api/health`.
- `[DONE]` Local production stack starts from `E:\BielOS`.
- `[DONE]` Local production health checks pass.
- `[NEXT]` Keep Docker changes limited to real launch blockers.

## 7. Launch Validation Plan

- `[DONE]` First production launch checklist exists in `docs/deployment-verification.md`.
- `[DONE]` Local launch execution passed:
  - secret scan
  - lint
  - typecheck
  - Prisma validation
  - build
  - Compose config validation
  - production stack start
  - status checks
  - local health checks
- `[DONE]` Live Cloudflare smoke test.
- `[LATER]` Fix only real launch blockers found during future smoke testing.
- `[LATER]` Add safe diagnostics only if repeated manual checks become error-prone.

## 8. Migrations Plan

- `[DONE]` Replace production reliance on `prisma db push` before private/non-discardable data ingestion.
- `[DONE]` Create committed Prisma migrations.
- `[DONE]` Document production `prisma migrate deploy`.
- `[DONE]` Add the committed additive GymForge score-correction migration.
- `[DONE]` Create and verify a current backup, deploy the committed migration with `prisma migrate deploy`, and confirm migration status is current.
- `[LATER]` Keep disposable/local-only schema workflows clearly separated from production.

## 9. Backup And Restore Plan

- `[DONE]` Document PostgreSQL backup process.
- `[DONE]` Ensure backup output paths are ignored by Git.
- `[DONE]` Document restore command.
- `[DONE]` Validate restore on a disposable database.
- `[LATER]` Repeat restore validation after meaningful schema or backup procedure changes.

## 10. Observability And Operations

- `[DONE]` Minimal audit logs exist for auth/session/security events.
- `[DONE]` Audit metadata is intentionally sanitized.
- `[DONE]` Local health and status scripts exist:
  - `health:local`
  - `status:prod`
  - `status:ports`
  - `logs:prod`
- `[DONE]` Audit retention policy and cleanup.
- `[LATER]` Safe redacted diagnostics if needed.
- `[DONE]` The bounded, read-only audit log UI is restricted to the global `OWNER` and renders only allowlisted safe fields.

## 11. Core, Available Applications, And Reserved Modules

### BielOS Core

BielOS Core is the private hub platform and workspace, not a reserved module. Its expansion is explicitly authorized, but future Core phases remain incomplete until implemented and validated.

- `[DONE]` Rebaseline Core architecture, security, project management, project access, sessions, safe operations, and safe audit visibility.
- `[DONE]` Existing Core models: `Project`, `ProjectAccess`, `Session`, `SecurityUnlock`, and `AuditLog`.
- `[DONE]` Core security, authorization, lifecycle, audit, session, and operations boundary is defined in `docs/modules/bielos-core.md`.
- `[DONE]` Scoped Core project registry and project management are implemented at `/core/projects`.
- `[DONE]` Project access management is implemented with explicit VIEWER, EDITOR, and OWNER levels.
- `[DONE]` `SecurityUnlock` design gate is complete; unresolved runtime semantics remain blocked.
- `[DONE]` Personal session management is implemented at `/core/security` with user-scoped revocation.
- `[DONE]` Core workspace and available applications are integrated in the typed hub registry.
- `[DONE]` Safe operations visibility uses a bounded database probe and honest unknown/manual states.
- `[DONE]` Owner-only audit visibility is implemented with a 50-row newest-first bound and safe display categories.
- `[DONE]` Complete the BielOS Core adversarial security/static-UI review and resolve all confirmed findings; authenticated visual smoke remains a follow-up.
- `[DONE]` Complete full validation, backup/migration deployment, production restart, and unauthenticated smoke checks.
- `[DONE]` Add disposable PostgreSQL integration coverage for Core authorization, mutations, access invariants, concurrency, session isolation, audit visibility, and operations reliability.
- `[DONE]` Run the Core database integration and concurrency suites in CI with one synthetic PostgreSQL service.
- `[BLOCKED]` Keep `SecurityUnlock` runtime changes blocked until its intended semantics are sufficiently defined.

### Available Applications

GymForge is already implemented and available inside the authenticated private hub. Preserve the completed history below; do not continue its optional feature roadmap.

- `[DONE]` Consolidated application and module index: `docs/modules/README.md`.
- `[DONE]` GymForge is available at `/gymforge` behind Cloudflare Access and BielOS internal authentication.
- `[BLOCKED]` GymForge expansion is frozen, including private invitations, public registration, import/export, photo proof/uploads, APIs, broad social features, and further scoring work.
- `[DONE]` GymForge gated competition planning revision.
- `[DONE]` GymForge MVP architecture document.
- `[DONE]` GymForge MVP foundation.
- `[DONE]` GymForge participant/admin read foundation.
- `[DONE]` GymForge admin-only participant management.
- `[DONE]` GymForge admin-only exercise catalog management.
- `[DONE]` GymForge attendance check-in foundation.
- `[DONE]` GymForge attendance timezone hardening.
- `[DONE]` GymForge workout entry foundation.
- `[DONE]` GymForge ranking and streak foundation.
- `[DONE]` GymForge competition foundation.
- `[DONE]` GymForge competition assignment and scoring design.
- `[DONE]` GymForge competition participant assignment and automatic scoring implementation.
- `[DONE]` GymForge competition lifecycle management.
- `[DONE]` GymForge UI usability pass and safe competition deletion.
- `[DONE]` GymForge admin attendance correction.
- `[DONE]` GymForge workout editing/deletion.
- `[DONE]` GymForge one-set workout integrity and transactional dependent-set deletion.
- `[DONE]` GymForge competition score-correction Phase 2 docs-only design.
- `[DONE]` GymForge competition score-correction Phase 3 additive model/migration and private-hub implementation.
- `[DONE]` Eight focused scoring cases plus secret scan, lint, typecheck, Prisma validation, and build pass before commit.

### Reserved Modules

Reserved modules remain planning-only and inert. They are not part of the active Core expansion.

- `[DONE]` L-vault planning document.
- `[DO NOT IMPLEMENT YET]` L-vault implementation.
- `[DONE]` root.ark public zero-knowledge planning revision.
- `[BLOCKED]` root.ark architecture phase before any implementation.
- `[DO NOT IMPLEMENT YET]` root.ark implementation.
- `[DONE]` H-vault planning document.
- `[DO NOT IMPLEMENT YET]` H-vault implementation.

## 12. Definition Of MVP Complete

BielOS MVP is complete when:

- `[DONE]` Local production stack starts reliably.
- `[DONE]` Local health checks pass.
- `[DONE]` Production Compose config validates.
- `[DONE]` App ports remain loopback-only.
- `[DONE]` Session cleanup runs.
- `[DONE]` CSRF protects current mutable routes.
- `[DONE]` Secret scan, lint, typecheck, build, and Prisma validation pass.
- `[DONE]` `biel.dev.br` works publicly through Cloudflare.
- `[DONE]` `hub.biel.dev.br` works privately through Cloudflare Access.
- `[DONE]` BielOS internal auth works after Cloudflare Access.
- `[DONE]` Prisma migrations replace production `db push`.
- `[DONE]` Backup and restore are documented and tested.
- `[DONE]` Hub application registry exists; private data handling is limited to implemented authenticated surfaces such as GymForge.
- `[BLOCKED]` Reserved modules remain inert, and GymForge expansion remains frozen while Core is the active path.

## 13. Recommended Phase Order

- `[DONE]` Phase 06.1: local production launch execution.
- `[DONE]` Phase 06.2: live Cloudflare smoke test.
- `[LATER]` Phase 06.3: fix real launch blockers only.
- `[DONE]` Phase 07.0: production Prisma migrations.
- `[DONE]` Phase 07.1: PostgreSQL backup procedure.
- `[DONE]` Phase 07.2: restore validation.
- `[DONE]` Phase 08.0: persistent login rate limiting.
- `[DONE]` Phase 08.1: audit retention and cleanup.
- `[DONE]` Phase 09.0: module shell registry only.
- `[DONE]` Phase 09.1: module security design template.
- `[DONE]` Phase 09.2: L-vault planning only.
- `[DONE]` Phase 09.3: root.ark planning only.
- `[DONE]` Phase 09.4: H-vault planning only.
- `[DONE]` Phase 09.5: GymForge planning only.
- `[DONE]` Phase 09.6: consolidate module planning docs.
- `[DONE]` Phase 09.3R: revise root.ark zero-knowledge planning.
- `[DONE]` Phase 09.5R: revise GymForge gated competition planning.
- `[LATER]` Phase 09.7: root.ark public zero-knowledge architecture.
- `[DONE]` Phase 09.8: GymForge MVP architecture.
- `[DONE]` Phase 09.9: GymForge MVP foundation.
- `[DONE]` Phase 09.10: GymForge participant/admin read foundation.
- `[DONE]` Phase 09.11: GymForge admin participant management.
- `[DONE]` Phase 09.12: GymForge admin exercise catalog management.
- `[DONE]` Phase 09.13: GymForge attendance check-in foundation.
- `[DONE]` Phase 09.14: GymForge attendance timezone hardening.
- `[DONE]` Phase 09.15: GymForge workout entry foundation.
- `[DONE]` Phase 09.16: GymForge ranking/streak foundation.
- `[DONE]` Phase 09.17: GymForge competition foundation.
- `[DONE]` Phase 09.18: GymForge competition assignment/scoring design.
- `[DONE]` Phase 09.19: BielOS language selector and Portuguese default.
- `[DONE]` Phase 09.20: sync GymForge docs and status copy.
- `[DONE]` Phase 09.21: GymForge competition assignment/scoring implementation.
- `[DONE]` Phase 09.22: GymForge competition lifecycle management.
- `[DONE]` Phase 09.23: GymForge UI usability pass and safe competition deletion.
- `[DONE]` Phase 09.25: GymForge admin attendance correction.
- `[DONE]` Phase 09.26: GymForge workout editing and deletion.
- `[DONE]` GymForge competition score-correction Phase 2: docs-only design.
- `[DONE]` GymForge competition score-correction Phase 3: additive migration, guarded OWNER/ADMIN actions, current-state score integration, private bilingual UI, redacted audit events, and tests.
- `[DONE]` Core Phase 0: rebaseline the roadmap around BielOS Core and freeze further GymForge expansion.
- `[DONE]` Core Phase 1: define BielOS Core security and data architecture.
- `[DONE]` Core Phase 2: Core project registry and project management.
- `[DONE]` Core Phase 3: Core project access management.
- `[DONE]` Core Phase 4: `SecurityUnlock` design-only boundary.
- `[DONE]` Core Phase 5: personal session management.
- `[DONE]` Core Phase 6: hub application registry integration.
- `[DONE]` Core Phase 7: safe operations visibility.
- `[DONE]` Core Phase 8: conditional owner-only audit visibility.
- `[DONE]` Core Phase 9: adversarial security/static-UI review with three low-severity fixes.
- `[DONE]` Core Phase 10: full validation and Compose configuration gate.
- `[DONE]` Core Phase 11: verified current PostgreSQL backup and committed migration deployment.
- `[DONE]` Core Phase 12: production restart and unauthenticated health/exposure smoke.
- `[DONE]` Core Phase 13: final plan-tree and operational status synchronization.
- `[DONE]` Core hardening follow-up: database-backed authorization, concurrency, session, audit, and operations verification plus CI integration.
- `[BLOCKED]` GymForge optional expansion and all reserved-module runtime work remain outside the active Core roadmap.
