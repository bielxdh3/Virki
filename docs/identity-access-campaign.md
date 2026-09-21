# BielOS Identity and Access Campaign

Status: `[CURRENT PUBLISHED CAMPAIGN]` — implementation and remote deployment are complete; authenticated human visual/behavior acceptance remains external.

## Current direct campaign snapshot — 2026-09-18

- Local and remote `main` are at accepted commit `06073a7db6284293eeedd2ba8e6eaca82e5af973`; exact-SHA CI run `35633568823` passed. No migration files were added; the canonical remote production stack was rebuilt/restarted and verified healthy.
- The worktree intentionally preserves inherited security/GymForge WIP alongside the campaign changes. Runtime-sensitive local validation was repeated with Node `22.20.0`; Docker/PostgreSQL-dependent gates remain environment-blocked.
- Current runtime dependency baseline is Next.js `16.3.5`, sharp `0.35.4`, and Nodemailer `10.0.10`; the production dependency audit is clean after omitting development dependencies. The accepted Prisma/deepmerge advisory remains tooling-only and is enforced by the exact tooling policy gate.
- Current local evidence includes `npm run secrets:scan`, `npm run lint`, `npm run typecheck`, `npm run prisma:validate`, `npm run test:core:unit` (97/97), `npm run test:public-site` (4/4), `npm run test:gymforge-scoring` (8/8), `npm run test:production-revision` (17/17), and `npm run build`; exact-SHA CI and remote runtime gates are complete, while authenticated human smoke remains external.

Historical technical evidence is retained below. Current exact-SHA evidence is GitHub Actions run `35633568823` for `06073a7db6284293eeedd2ba8e6eaca82e5af973`, which passed all configured jobs.

## Post-closeout live-smoke repair — 2026-08-18

The latest historical human smoke confirmed OWNER administrative credential setup, offline recovery-code acknowledgement, and normal timed/manual elevation. It also confirmed the former UI scope-availability defect blocked `PROJECT_OWNER_ACCESS_CHANGE` and `CORE_PROJECT_ARCHIVE` project smoke, while repetitive `ACCESS_JWT_VALID` events made the OWNER audit view low-signal. Those machine corrections were committed at `76a9a7b59ba7dc9a4c594be986d47ffcb71b60ce`; exact-SHA CI run `32263676937` was green, and the canonical remote stack was rebuilt at that historical SHA. Do not claim current authenticated OWNER/MEMBER browser smoke.

The published campaign adds routine global-OWNER project participant/access changes without elevation, keeps ADMIN elevation and higher-risk archive elevation, adds administrative credential recovery with one-time offline codes, and matures the owner audit surface with retained-history cursor pagination, safe taxonomy/filtering, detail disclosure, retention visibility, and bounded sanitized export. Exact-SHA CI passed; authenticated human smoke and live production evidence remain pending.

The bounded resume checklist is only: as OWNER, grant/change/revoke disposable Project A MEMBER access without elevation and verify Project B denial/no leak plus last-owner protection; acquire `CORE_PROJECT_ARCHIVE` only for the archive flow and verify read-only behavior; verify MEMBER admin/audit/session restrictions; and perform normal logout. Keep public registration and live Intake disabled, Cloudflare Access before BielOS authentication, GymForge expansion frozen, reserved modules inert, `SecurityUnlock` blocked, and AIP separate.

The dependency audit exception is tooling-only technical debt. The production dependency gate uses a clean `npm ci --omit=dev --omit=peer --omit=optional` tree and must remain green with Prisma CLI, `@prisma/config`, and `deepmerge-ts` absent while `@prisma/client` and its generated client remain available. The full tooling gate accepts only the exact GHSA-ggr8-5vv4-36mx path through Prisma `6.19.3`, `@prisma/config` `6.19.3`, and `deepmerge-ts` `7.1.5`; any advisory, path, count, version, severity, or metadata drift fails closed, and a clean audit signals removal of the exception. This does not claim the GHSA is globally fixed or complete human OWNER/MEMBER smoke.

## Binding boundaries

- `biel.dev.br` is public; `hub.biel.dev.br` remains private.
- Cloudflare Access stays before BielOS internal authentication; origin JWT enforcement and loopback-only ports remain required.
- The public site stays database-free. Public intake uses a separately isolated capability and never imports the private database package.
- GymForge remains available and feature-frozen. AIP remains separate. root.ark, L-vault, and H-vault remain non-runtime surfaces.
- BielOS Core is not a requestable module. Catalog visibility, runtime availability, and entitlement are separate facts.
- Only global `OWNER` manages accounts, global access, module grants, participants, and critical permissions.
- Public registration and live Intake remain disabled pending repeat of the affected authenticated OWNER/MEMBER browser ceremony after this repair.

## Data flows and trust boundaries

1. Public browser → same-origin `/apply` → isolated intake handler → restricted intake capability → pending application/outbox records.
2. Provider-neutral email transport → one-time challenge links/codes → verified application or authentication ceremony.
3. Private browser → Cloudflare Access → hub → BielOS session → server authorization → Prisma transaction.
4. Owner review → per-module decisions → pending activation → one-time activation → active user and explicit grants.
5. Authenticated user → module catalog/request services → persisted grant/request state; runtime routing remains independent.
6. Owner critical action → normal authorization + CSRF + separate admin credential + email factor → versioned session-bound `SecurityElevation` → guarded transaction; legacy `SecurityUnlock` rows remain non-authoritative.

## Lifecycle states

- Application: `PENDING_EMAIL`, `EMAIL_VERIFIED`, `IN_REVIEW`, `PARTIALLY_APPROVED`, `APPROVED`, `REJECTED`, `EXPIRED`, `ACTIVATED`.
- Module decision: `REQUESTED`, `APPROVED`, `REJECTED`, `BLOCKED`, `EXPIRED`, `REVOKED`.
- Account: pending activation, active, blocked, inactive; nullable password is never the lifecycle state.
- Access: permanent or temporary with explicit expiry; expired state fails closed.
- Email delivery: queued, processing, sent, retryable failure, terminal failure; delivery failure never authorizes a challenge.
- Elevation: challenge pending, active, expired, revoked, consumed/invalidated; legacy `APPROVED` rows are non-authoritative.

## Meta dependency ledger

| Meta task | Boundary | Depends on | Exit evidence |
| --- | --- | --- | --- |
| 1 | Baseline, reusable skill, threat model, ledger | — | docs/router validation |
| 2 | Additive identity/access schema and data invariants | 1 | migration + DB/concurrency tests |
| 3 | Provider-neutral outbox and deterministic transport | 2 | delivery/idempotency tests |
| 4 | `/apply` and isolated intake | 2, 3 | handler + isolation tests |
| 5 | Owner review and activation | 2–4 | lifecycle/concurrency tests |
| 6 | Module/feature requests and grants | 2, 5 | visibility/cooldown/IDOR tests |
| 7 | 2FA, devices, ordinary recovery | 2, 3 | factor/replay/isolation tests |
| 8 | Admin credential and `SecurityUnlock` v1 | 2, 3, 5, 7 | protected-action/concurrency tests |
| 9 | Integrated UI, audit, notifications, operations | 4–8 | server/UI/redaction/accessibility tests |
| 10 | Adversarial gate, docs, rollout, publication | 1–9 | exact local evidence and clean synchronized state |

Only one task may own a migration chain at a time. Integration proceeds in this order and preserves newer compatible repository work.

## Rollout gates and rollback limits

Production enablement requires a real email transport, restricted intake credential, owner administrative password, owner second factor, acknowledged offline admin recovery codes, current migrated backup with restore evidence, public routing, and an authorized production smoke. Until then `/apply` is unavailable or feature-gated and intake is not publicly reachable.

Schema rollback is additive-only: code can be rolled back before dependent writes, but destructive down-migrations and data reconstruction are not assumed safe. Preserve backups and document any forward-only migration limit.

## Acceptance matrix

| Area | Must be true before enabled |
| --- | --- |
| Public intake | database-free public build, strict origin/content checks, bounded input, generic responses, cooldown and abuse controls, restricted capability |
| Verification/activation | hashed one-time material, expiry/reissue/replay denial, verified email before owner review, atomic activation |
| Access | public-only catalog visibility, declared feature permissions, explicit temporary/permanent grants, fail-closed expiry, IDOR isolation |
| 2FA/devices | email or encrypted TOTP factor, one-time recovery codes, no session before new-device verification, own-device/session scope |
| Elevation | separate admin password, email factor, versioned scope/session binding, immediate revoke, no legacy-row authority |
| Operations | truthful safe status only; no secrets, raw provider errors, or private catalog leakage |
| Validation | focused and real transaction tests, secret scan, lint, typecheck, Prisma validation, build, Compose/image, backup/restore, diff and clean-tree checks |

## Current implementation notes

- Migrations are additive through `20260805120000_add_remembered_browser_grant`; production intake remains disabled until the real gates are satisfied. The remembered-browser migration adds nullable grant timestamps so existing trusted-device rows fail closed without remembered-login authority.
- Account security, recovery, trusted devices, module access, owner review, administrative elevation, and truthful operations status are implemented behind Cloudflare, CSRF, session, and feature boundaries.
- `BIELOS_FINAL_TECHNICAL_CLOSEOUT_READY_FOR_HUMAN_SMOKE`: the tooling exception contract, production dependency/image boundary, exact-SHA CI, Node 22 build, runtime smoke, loopback ports, Cloudflare Access ordering, and local production rebuild are complete at `76a9a7b59ba7dc9a4c594be986d47ffcb71b60ce`; only the real OWNER/MEMBER browser ceremony remains. Cloudflare Access stays first, BielOS internal authentication second; loopback-only ports remain required, public registration and live Intake stay disabled, GymForge expansion is frozen, reserved modules are inert, and AIP remains separate.
