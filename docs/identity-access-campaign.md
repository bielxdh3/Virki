# BielOS Identity and Access Campaign

Status: `[CURRENT]` — implementation is disabled by default until the production gates are real.

Baseline: `677c9622029e4a2e63d5fb10ce79eed7a5b3b157` (`main`, clean worktree).

## Binding boundaries

- `biel.dev.br` is public; `hub.biel.dev.br` remains private.
- Cloudflare Access stays before BielOS internal authentication; origin JWT enforcement and loopback-only ports remain required.
- The public site stays database-free. Public intake uses a separately isolated capability and never imports the private database package.
- GymForge remains available and feature-frozen. AIP remains separate. root.ark, L-vault, and H-vault remain non-runtime surfaces.
- BielOS Core is not a requestable module. Catalog visibility, runtime availability, and entitlement are separate facts.
- Only global `OWNER` manages accounts, global access, module grants, participants, and critical permissions.
- Public applications, email-dependent behavior, and production intake remain disabled until their exact enablement gates are satisfied.

## Data flows and trust boundaries

1. Public browser → same-origin `/apply` → isolated intake handler → restricted intake capability → pending application/outbox records.
2. Provider-neutral email transport → one-time challenge links/codes → verified application or authentication ceremony.
3. Private browser → Cloudflare Access → hub → BielOS session → server authorization → Prisma transaction.
4. Owner review → per-module decisions → pending activation → one-time activation → active user and explicit grants.
5. Authenticated user → module catalog/request services → persisted grant/request state; runtime routing remains independent.
6. Owner critical action → normal authorization + CSRF + separate admin credential + email factor → versioned session-bound `SecurityUnlock` elevation → guarded transaction.

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

- Migrations are additive through `20260801140000_security_ui_keys`; production intake remains disabled until the real gates are satisfied.
- Account security, recovery, trusted devices, module access, owner review, administrative elevation, and truthful operations status are implemented behind Cloudflare, CSRF, session, and feature boundaries.
- Docker/PostgreSQL was unavailable in this environment, so migration deployment, restricted-role enforcement, contention suites, backup/restore, Compose/image validation, and production smoke remain manual gates.
