# BielOS Core Security And Data Design

## Implementation Status

Core project registry, project management, and project access administration are implemented in the private hub at `/core/projects`. Personal session management is implemented at `/core/security`. Read scope follows this document; mutations require Cloudflare Access, BielOS authentication, CSRF, bounded validation, generic errors, and sanitized audits. Access changes use serializable transactions, prevent duplicate rows and role escalation, and retain the last active project owner. Session queries are user-scoped and omit token material; users may revoke only their own other sessions, with an explicit confirmation for the all-other action. Permanent project deletion remains unavailable.

The hub uses a typed application registry that separates Core workspace surfaces, the available GymForge application, and inert reserved modules. Registry links do not weaken the authentication boundary or create reserved-module routes.

The hub operations panel separates request-time checks, configured architecture, and external manual validation. It verifies only the current hub render, authenticated session, and a timeout-bounded minimal database query. Container health, public routes, Cloudflare ordering, ports, and migration state remain manual checks; no Docker socket, raw logs, environment values, or external network dependency is introduced.

## Identity

- Status: Core expansion authorized; this document is the runtime gate for project, access, session, operations, and audit surfaces.
- Boundary: Cloudflare Access is the outer private-hub gate and BielOS internal authentication is the second gate. Core authorization never replaces either layer.
- Global roles: `OWNER`, `ADMIN`, and `MEMBER` come from the active authenticated BielOS user.
- Inactive users receive no Core access even if a `ProjectAccess` row remains.
- Authorization failures use HTTP `403` where access is forbidden and generic redirects/results for invalid mutations. Responses must not reveal whether a hidden project or user exists.

## Project Authorization

Authorization is evaluated in this order:

1. Require Cloudflare Access when configured, a valid BielOS session, and an active user.
2. Global `OWNER` and `ADMIN` may view every Core project, including archived projects.
3. An active `MEMBER` may view a `PUBLIC` project without an explicit access row. `PUBLIC` means visible to authenticated BielOS users; it does not create a public internet route.
4. An active `MEMBER` needs an explicit `ProjectAccess` row for `INTERNAL` or `SENSITIVE` projects.
5. `ProjectAccess` grants the project capability represented by `VIEWER`, `EDITOR`, or `OWNER`. It does not grant global administration or permission to manage access when the user is globally a `MEMBER`.
6. A future `SecurityUnlock` may add a narrower gate for sensitive actions, but absence of that workflow must never widen access.

Descriptions are returned only with projects the requester is authorized to view. Lists use selected fields and bounded queries.

## Project Access Administration

- Global `OWNER` may create, change, and revoke `VIEWER`, `EDITOR`, and `OWNER` access.
- Global `ADMIN` may create, change, and revoke only `VIEWER` and `EDITOR` access. An admin cannot create, demote, or revoke a project `OWNER` row.
- Global `MEMBER` cannot administer access, even when their project access level is `OWNER`.
- Project creation transactionally creates an `OWNER` access row for the creating global owner or admin.
- A project must retain at least one active project `OWNER`; the last such row cannot be demoted or revoked.
- Duplicate `(userId, projectId)` rows are rejected by the existing unique constraint and handled transactionally by the application.
- Only active users and existing, non-archived projects may receive new access.
- A caller cannot grant a level above the authority allowed by their global role.

## Core Data

The first Core runtime phases use the existing models:

- `Project`: project metadata, visibility, lifecycle status, and timestamps.
- `ProjectAccess`: one access level per user and project.
- `Session`: hashed session token, creation, expiration, and revocation state.
- `SecurityUnlock`: reserved model whose runtime semantics remain blocked below.
- `AuditLog`: bounded, sanitized security and Core activity records.

No schema change is required for the initial project, access, session, operations, or bounded audit surfaces. Core data remains in PostgreSQL under Prisma migrations and the existing backup/restore process.

## Project Lifecycle

- Create: global `OWNER` or `ADMIN`; validate all fields; create the first project-owner access row in the same transaction.
- Edit: global `OWNER` or `ADMIN`; allow name, slug, description, visibility, and status for non-archived projects.
- Activate or pause: explicit status transition by global `OWNER` or `ADMIN`.
- Archive: explicit action by global `OWNER` or `ADMIN`; archive is terminal in the initial runtime and preserves access and history.
- Delete: permanent deletion is blocked in the initial Core runtime. Prefer retention and archive.
- Visibility: `PUBLIC`, `INTERNAL`, and `SENSITIVE` follow the authorization rules above. Changing visibility never creates a public route.
- Slugs: lowercase ASCII letters, digits, and single hyphens; no leading, trailing, or repeated hyphen; globally unique; length bounded by the server.
- Retention: archived projects, access history represented by current rows, and related audits remain until a later deletion/retention design is approved.

Project status values are `PLANNED`, `RESERVED`, `ACTIVE`, `PAUSED`, and `ARCHIVED`. Archived projects are read-only and visually distinct.

## SecurityUnlock Boundary

The existing model does not define how a challenge is issued or verified, who may approve it, whether approval is one-time or reusable, how denial is attributed, how recovery differs from login, or how consumption is recorded. `challengeHash`, `approvedAt`, and `expiresAt` alone are insufficient to implement a safe workflow.

Runtime use is therefore blocked. A future design must define challenge entropy and delivery, verification, request/approval separation, expiration, one-time consumption, project and purpose scope, denial/revocation, recovery rules, concurrency, rate limits, and audit events. An unlock may only be an additional scoped gate; it can never replace Cloudflare Access, BielOS authentication, user activity checks, or project authorization.

The dedicated gate and unresolved decision set are recorded in `docs/security-unlock.md`.

## Sessions

- Users may see only their own sessions.
- Safe display fields are creation time, expiry time, revocation state, and whether the row is the current session.
- Raw session tokens, token hashes, cookies, IPs, headers, and user agents are never selected for UI display.
- A user may revoke their own other sessions or all other sessions. Current-session revocation is omitted unless a later explicit confirmed flow is designed.
- Global administrators do not gain broad session visibility.
- Every revocation requires CSRF and a server-side `userId` condition. Existing cleanup behavior remains intact.

## Audit Contract

Core event types are allowlisted for project create/update/archive, access grant/change/revoke, and personal session revocation. Conditional audit viewing is read-only and owner-only.

Audit metadata may contain only bounded enum values, aggregate counts, generic action scope, and stable hashed resource references. It must not contain names, slugs, descriptions, emails, raw identifiers, form values, request bodies, passwords, secrets, cookies, tokens, token hashes, JWTs, headers, IPs, environment values, database URLs, logs, or unrestricted free text.

The viewer, if its later gate passes, exposes only event type, result, safe resource category, creation time, and generic actor state (`user` or `system`). It does not render raw metadata or arbitrary messages. Queries are newest-first and strictly bounded. Existing audit retention remains authoritative.

## Safe Operations Visibility

The private hub may display only facts it can determine safely and cheaply:

- the current hub request and authenticated session are valid;
- a bounded database probe succeeds or fails;
- configured architecture labels such as public site, private hub, and layered access, without environment values;
- migration state only when safely available without making page rendering depend on an external command.

It must not read the Docker socket, claim container health without checking it, render raw logs, expose environment values or database URLs, reveal private Cloudflare identifiers, or make external network calls during normal page rendering. Unknown or failed checks are shown as `unknown`, while external deployment checks remain documented manual operations. `/api/health` stays minimal and unauthenticated for local health checks.

## UI And API Constraints

- Core surfaces remain inside the authenticated private hub and are available in PT-BR and English.
- Project and session lists use compact rows/cards, small empty states, stable native drawers, accessible labels, and visible focus states.
- Admin controls are separated from member workspace views. Danger actions remain collapsed and require explicit intent.
- Every mutation is a server action or existing private route with server-side authorization and CSRF validation.
- No public Core administration API, project site, import/export, upload, or module runtime is added.
- Errors are generic and redirects are restricted to known local paths.

## Threat Model And Failure Modes

Primary threats are IDOR, role escalation, crafted enum values, duplicate access races, last-owner removal, CSRF, session token leakage, audit-data leakage, unbounded queries, stale authorization after user deactivation, and misleading operations telemetry.

- Database unavailable: reads fail safely; mutations do not claim success; transaction boundaries prevent partial multi-row writes.
- Backup unavailable: no durable migration or destructive operation proceeds.
- Cloudflare Access unavailable or invalid when required: return `403` before Core data access.
- BielOS session missing, invalid, expired, revoked, or inactive: redirect to login or reject the mutation.
- Audit write failure: retain the existing fail-soft policy without logging private values.
- Concurrent access changes: use a serializable transaction with bounded retry for owner-count and privilege invariants.

## Backup, Import, And Export

Core project and access rows are covered by the existing PostgreSQL backup and restore process. No Core-specific file storage is introduced. Import and export are blocked until a separate format, authorization, redaction, conflict, backup, and transaction design exists. Sessions, token hashes, unlock challenges, and audit logs must never be included in a project export.

## Validation Gate

Runtime phases require secret scan, lint, typecheck, Prisma validation, production build, focused authorization tests where practical, and adversarial review of IDOR, CSRF, role escalation, query bounds, archive behavior, and audit redaction. Schema changes require a committed migration and verified backup before durable deployment.
