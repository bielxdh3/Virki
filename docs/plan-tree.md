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
  - `POST /api/login`
  - `POST /api/logout`
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
- `[BLOCKED]` Audit log UI is blocked until authorization and retention rules are stronger.

## 11. Future Modules And Remaining Blocked Work

Do not implement new modules beyond inert shell registry entries until each module completes `docs/module-security-template.md`. GymForge is the exception: its MVP foundation is implemented, but its future work remains scoped by the blockers below.

- `[DONE]` Consolidated module planning index: `docs/modules/README.md`.
- `[DONE]` BielOS Core shell registry entry.
- `[DO NOT IMPLEMENT YET]` BielOS Core module expansion.
- `[DONE]` L-vault planning document.
- `[DO NOT IMPLEMENT YET]` L-vault implementation.
- `[DONE]` root.ark public zero-knowledge planning revision.
- `[BLOCKED]` root.ark architecture phase before implementation.
- `[DO NOT IMPLEMENT YET]` root.ark implementation.
- `[DONE]` H-vault planning document.
- `[DO NOT IMPLEMENT YET]` H-vault implementation.
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
- `[DO NOT IMPLEMENT YET]` GymForge workout editing/deletion, upload, invite acceptance, import/export, public registration, admin attendance correction, score correction, deletion of ACTIVE or assigned competitions, and broad social feed behavior.

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
- `[DONE]` Module shell registry exists without private data ingestion.
- `[BLOCKED]` No new real future modules are implemented prematurely.

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
- `[LATER]` Phase 09.24+: other real modules only after module-specific security and data design.
