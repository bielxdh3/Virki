# Roadmap

## Master Finish Everything campaign — current local truth (2026-09-18)

The direct Codex campaign is implementation-complete for its authorized scope and published at `a9f867f6d06eeae71e00f5fae910978382260468`; `main` and `origin/main` match and exact-SHA CI run `35419764845` passed. Prompt Arena parity, Core identity/access/recovery/audit maturation, current Hub surfaces, and approved platform capabilities are complete. Remaining gate is authenticated human visual/interaction smoke.

Use [master-finish-everything-ledger.md](master-finish-everything-ledger.md) as the current disposition ledger. GymForge expansion and reserved modules remain frozen by approved product boundaries; `SecurityUnlock` remains non-authoritative and blocked. The next user-only gate is explicit publication authorization after the human smoke and external environment gates are satisfied.

## Current Platform State: BielOS Core

BielOS Core is the private hub platform and workspace, distinct from applications and reserved modules. Its project-detail and identity/access source surfaces are implemented behind the existing Cloudflare Access-first, BielOS internal-auth, CSRF, session/elevation, authorization, and audit boundaries. The current campaign is published at `a9f867f6d06eeae71e00f5fae910978382260468`; the local production stack is converged and authenticated browser smoke remains the human gate. Public registration and live Intake remain disabled.

Core identity/access surfaces include the accepted shell/navigation and trusted-device states plus the corresponding source implementation. The historical technical closeout for `33f540a4b396aa8a55fa65ad9f950b0c36712aae` and run `31821995102` remains dated evidence. The latest human smoke confirmed OWNER credential setup, offline recovery-code acknowledgement, and normal timed/manual elevation, but the former UI scope defect blocked `PROJECT_OWNER_ACCESS_CHANGE` and `CORE_PROJECT_ARCHIVE` project smoke and `ACCESS_JWT_VALID` reduced audit signal. Phase 1/2 repairs are present locally; affected human smoke must be repeated, and no current authenticated OWNER/MEMBER smoke or final closeout claim is made.

The Core security and architecture gate is complete in `docs/modules/bielos-core.md`. Core projects, access, personal sessions, safe operations visibility, retained-history owner-only audit investigation, recovery, capability cards, and the typed hub registry are implemented. Project and session reads revalidate persisted identity state; project access mutations use serializable per-project locking; and the operations panel distinguishes verified local checks, configured architecture, and external manual validation.

Core login limiting now requires a dedicated production HMAC key, never derives it from the database target, and keeps only a synthetic development/test fallback. Real login-route tests cover Access and CSRF denial, generic failure, five-attempt throttling, successful session/cookie behavior, sanitized audits, normalization, inactive users, unavailable configuration, and concurrent requests. Lifecycle tests cover exact window reset, retention, stale-bucket clearing, independent identifiers, and dummy-verification paths. Same-identifier password verification remains inside the transaction to preserve the strict cap; advisory-lock waits are bounded to five seconds and the transaction remains bounded to 15 seconds.

Cloudflare Access diagnostic coverage was completed in `4705e9df46812967aa86ae780c732d56e17a719a` with typed fixed categories, generic fallbacks, non-disclosure tests, and normal unit/CI integration. Public login/logout redirects were corrected in `e8ad193bca55abab87a16440d879ed534b86c761`, then hardened in `d634a454138e7f59aa364a3764efce16a99bf2e3` with literal destinations, HTTPS-only production configuration, fail-closed invalid configuration, pre-mutation login validation, safe logout cookie clearing, and proxy `503` behavior.

Protected-origin commit `70f577329f36471876fcc184ef713e25d8b98b1f` added early denial for missing required Access assertions. Runtime correction `00c29fd79b94338fe39545044e282f430450e5e2` separated the framework event from environment injection and added deployed-invocation regression coverage. Runtime correction `e559152b8f402f07f86c3eb29c56e601cf5bca44` ensures a present assertion reaches full JOSE validation before BielOS session routing rather than being treated as sufficient proof.

Historical Core gate records include secret scan, lint, typecheck, Prisma validation, public discovery, Core unit/database/concurrency tests, build, production image, and production Compose validation for the existing private Core surfaces. Current runtime-sensitive validation was repeated with Node `22.20.0`; Docker/PostgreSQL-backed gates, exact-SHA CI, and authenticated human smoke remain external. `SecurityUnlock` remains design-only and blocked.

Historical authenticated OWNER and MEMBER production browser smoke covered the existing private Core surfaces through Cloudflare Access first and BielOS login second. It does not close the identity/access rollout-readiness gates or enable public registration/live Intake; no GymForge or reserved-module behavior changed.

The current bounded phase is post-smoke repair readiness: complete proportional local checks and repeat only the affected OWNER/MEMBER scope, project, audit, restriction, and logout smoke. This is not an implementation-complete or unapproved production mutation phase.

BielOS is the hub, registry, navigation surface, identity/security boundary, and Core policy layer. A future application or module may be embedded, separately deployed, locally external, or remotely external; it is not required to share the hub Next.js runtime or container. Any external integration requires an explicit versioned contract, independent operation, explicit authentication and authorization, least-privilege capabilities, failure isolation, privacy classification, compatibility rules, and explicit user approval where needed. Redirect origin alone is never trust, and a shared database is not the default integration boundary. This is architectural direction only; no external integration exists.

## Current Application Classification

- BielOS Core: implemented private platform/workspace with project-detail, identity/access, recovery, audit, capability, and operations surfaces behind the existing layered boundaries; published at `a9f867f6d06eeae71e00f5fae910978382260468` with exact-SHA CI passed. Authenticated human smoke remains open.
- GymForge: available integrated private-hub application at `/gymforge`; implemented capabilities are preserved and further feature expansion is frozen.
- L-vault, root.ark, and H-vault: reserved planning-only modules; runtime remains inert.

GymForge invitations, public registration, import/export, photo proof/uploads, APIs, broad social features, and further scoring work are not active roadmap items.

AIP remains a separate repository. Any future BielOS integration requires an explicitly authorized contract phase and must not import AIP implementation code directly.

## Historical Roadmap Record

The entries below preserve prior planning and completed delivery history. Any earlier statement that Core expansion is blocked or active, GymForge is merely planned, or a new GymForge phase is next is superseded by the current platform state above.

## Phase 1: BielOS Core

- Create the monorepo structure.
- Build public landing page for `biel.dev.br`.
- Build private hub shell for `hub.biel.dev.br`.
- Add Prisma schema for users, projects, access, sessions, and security unlocks.
- Add Docker Compose for application and PostgreSQL.
- Keep future modules as reserved folders and dashboard cards only.

## Phase 2: Access Boundary

- Implement real authentication.
- Add session lifecycle and revocation.
- Integrate Cloudflare Access assumptions at the edge.
- Add authorization checks for sensitive modules.

## Phase 3: Core Operations

- Add project management workflows.
- Add audit-friendly security unlock flow.
- Add backup and restore routines.
- Add basic observability without leaking private data.

## Phase 4: Modules

- Redesign the private hub shell into a cleaner personal workspace before module implementation.
- Implement L-vault.
- Implement root.ark.
- Implement H-vault.
- Implement GymForge.

Each module should be started only after Core authentication and authorization are stable.

Phase 04 redesigned the hub shell only. At that time, L-vault, root.ark, H-vault, and GymForge were reserved and not implemented as module applications.

Phase 04.1 fixed hub sidebar section navigation using real dashboard anchors. Future modules remain unimplemented.

Phase 04.2 polished the hub visual shell. Auth, Cloudflare, Docker, Prisma, and future modules were intentionally unchanged.

Phase 04.3 reduced artificial dashboard styling and copy. Future modules remain unimplemented, and auth, Cloudflare, Docker, and Prisma were intentionally unchanged.

Phase 05 added minimal safe audit logs for auth and security events. Future modules remain unimplemented.

Phase 05.R bound production debug ports to loopback, removed dead Session request-context fields, and documented the migration plan. Future modules remain unimplemented.

Phase 05.1 added optional origin-side Cloudflare Access JWT validation preparation for the hub. Future modules remain unimplemented, and BielOS internal authentication remains required.

Phase 05.1R hardened denied Access origin validation to return HTTP 403 and added a safe hub health endpoint for local and Docker health checks.

Phase 05.2 added root linting and a basic committed-secret scan to CI. Future modules remain unimplemented, and runtime auth, Cloudflare, and Docker port behavior remain unchanged.

Phase 05.2R aligned the root Node engine and CI Node version with the lint tooling requirements.

Phase 05.2S bound development Compose host-published app and database ports to loopback.

Phase 05.3 added explicit CSRF protection for mutable hub POST routes. Future modules remain unimplemented, and Cloudflare Access, internal auth, and Docker port behavior remain unchanged.

Phase 05.4 added an automatic production Compose session cleanup worker. Future modules remain unimplemented, and hub app behavior, Cloudflare Tunnel behavior, and Docker app port bindings remain unchanged.

Phase 07.0 added the initial committed Prisma migration and production `prisma migrate deploy` scripts. Future modules remain unimplemented, and private/non-discardable data ingestion still waits for backup and restore validation.

Phase 07.1 documented the PostgreSQL backup procedure and kept backup output paths ignored by Git. Future modules remain unimplemented, and private/non-discardable data ingestion still waits for restore validation.

Phase 09.0 added only an inert private hub module shell registry. L-vault, root.ark, H-vault, GymForge, and real BielOS Core expansion remain unimplemented until each has its own security and data design.

Phase 09.1 added the module security design template. Real module implementation remains blocked until the target module completes that template.

Phase 09.2 added the L-vault planning document only. L-vault upload, storage, encryption, import/export, UI, routes, APIs, schema, migrations, and private data ingestion remain blocked.

Phase 09.3 added the root.ark planning document only. Archive storage, upload, import/export, indexing/search, UI, routes, APIs, schema, migrations, and private data ingestion remain blocked.

Phase 09.4 added the H-vault planning document only. Health/sensitive storage, upload, import/export, UI, routes, APIs, schema, migrations, and private data ingestion remain blocked.

Phase 09.5 added the GymForge planning document only. Workout tracking, body metrics, upload, import/export, UI, routes, APIs, schema, migrations, and private data ingestion remain blocked.

Phase 09.6 consolidated module planning documents under `docs/modules/README.md`. Real module implementation remains blocked until module-specific design is complete.

Phase 09.3R revised root.ark planning toward a public zero-knowledge compartment model. Implementation remains blocked until a dedicated architecture phase covers capability links, encrypted blob storage, metadata minimization, key lifecycle, revocation, deletion, and public abuse controls.

Phase 09.5R revised GymForge planning toward a gated social gym competition model for invited or admin-created participants. Implementation remains blocked until a dedicated architecture or MVP phase covers gated entry, attendance, streaks, photo proof, workout logging, exercise catalog, competitions, group visibility, retention, deletion, and abuse controls.

Phase 09.8 documented the GymForge MVP architecture for gated entry, participant/admin roles, exercise catalog, attendance, streaks, future photo proof, workout notes, exercise logs, group ranking, visibility, retention, audit events, and validation. GymForge implementation remains blocked until a dedicated implementation phase.

Phase 09.9 added the GymForge MVP foundation: Prisma models, migration, and an authenticated hub placeholder route. Check-in creation, workout entry, uploads, import/export, public registration, and participant management remain blocked for later scoped phases.

Phase 09.10 added read-only GymForge participant/admin foundation data on the authenticated hub route. It shows aggregate counts and the linked viewer participant status without adding forms, APIs, uploads, check-ins, workout entry, or public registration.

Phase 09.11 added admin-only GymForge participant management inside the authenticated hub route. OWNER and ADMIN users can create unlinked participants and disable or archive participants with CSRF protection and sanitized audit events. Public registration, invite acceptance, uploads, check-ins, workout entry, and APIs remain blocked.

Phase 09.12 added admin-only GymForge exercise catalog management inside the authenticated hub route. OWNER and ADMIN users can view latest catalog entries, create exercises, and deactivate or archive exercises with CSRF protection and sanitized audit events. Check-ins, workout entry, uploads, public registration, invite acceptance, and APIs remain blocked.

Phase 09.13 added participant attendance check-ins inside the authenticated hub route. Only users linked to an ACTIVE GymForge participant can check in, one streak-counting attendance is allowed per participant per local day, notes are capped, and audit metadata stays sanitized. Photo proof, workout entry, invite acceptance, public registration, admin correction, and APIs remain blocked.

Phase 09.14 hardened GymForge attendance date calculation with an explicit `America/Sao_Paulo` MVP timezone policy shared by the page and server action. Effective attendance dates are canonical UTC dates for stable uniqueness and future streak computation. No user location inference, workout entry, photo upload, invite acceptance, or public registration was added.

Phase 09.15 added GymForge workout entry foundation for users linked to an ACTIVE participant. The authenticated hub route can create one workout with one active exercise set per submission and show the viewer's latest workouts. Workout editing, deletion, uploads, invite acceptance, public registration, APIs, and broad social views remain blocked.

Phase 09.16 added read-only GymForge ranking and streak foundation inside the authenticated hub route. Ranking uses attendance records only, includes ACTIVE participants, computes current streaks server-side from GymForge effective dates, and shows display name, attendance count, streak, and latest check-in date without exposing workout details or notes.

Phase 09.17 added GymForge competition foundation inside the authenticated hub route. OWNER and ADMIN users can create competition metadata with CSRF protection and sanitized audit events, while authenticated hub users can view safe read-only competition fields. Participant assignment, automatic scoring, editing, deletion, uploads, invite acceptance, public registration, APIs, and broad social features remain blocked.

Phase 09.18 documented GymForge competition assignment and scoring design only. It defines explicit participant assignment, participant scope, attendance-count and streak scoring, tie breakers, date range behavior using the fixed `America/Sao_Paulo` GymForge policy, disabled/archived participant handling, admin override limits, visibility rules, future audit events, and validation requirements. Runtime assignment, automatic scoring, UI, APIs, server actions, schema changes, and migrations remain blocked.

Phase 09.19 added a BielOS language selector for the public site, hub shell, login page, and current GymForge UI. The default locale is `pt-BR`; supported values are limited to `pt-BR` and `en` in the non-sensitive `bielos_locale` cookie. Runtime auth, Cloudflare behavior, Docker, Prisma, and module data flows were unchanged.

Phase 09.20 synchronized GymForge documentation and visible status copy with the current implementation. GymForge is no longer described as entirely blocked or schema-only: its private hub MVP foundation includes participant/admin read data, admin participant management, admin exercise catalog management, attendance check-ins, explicit `America/Sao_Paulo` attendance dates, workout entry foundation, ranking/streak foundation, and competition metadata foundation. Photo upload, public registration, invite acceptance, import/export, workout editing/deletion, admin attendance correction, competition participant assignment implementation, and automatic competition scoring implementation remain blocked.

Phase 09.21 implemented GymForge competition participant assignment and automatic scoring inside the authenticated hub route. OWNER and ADMIN users can assign ACTIVE participants to competitions with CSRF protection and sanitized audit events. Authenticated hub users can view read-only deterministic competition rankings based on assigned active participants, qualifying attendance dates, explicit competition date ranges, and supported scoring rules. Photo upload, public registration, invite acceptance, import/export, workout editing/deletion, admin attendance correction, competition editing/deletion, APIs, and broad social feed behavior remain blocked.

Phase 09.22 added GymForge competition lifecycle management inside the authenticated hub route. OWNER and ADMIN users can update existing competition metadata, status, date range, and scoring rule, and can archive competitions with CSRF protection and sanitized audit events. Participant assignment and read-only automatic scoring behavior were preserved. Photo upload, public registration, invite acceptance, import/export, workout editing/deletion, admin attendance correction, competition deletion, APIs, and broad social feed behavior remain blocked.

Phase 09.23 improved the GymForge competition UI into clearer dashboard panels for user scoring and admin management, and added admin-only safe competition deletion. OWNER and ADMIN users can permanently delete only non-ACTIVE competitions with zero participant assignments, with CSRF protection, explicit confirmation, and sanitized audit events. Active or assigned competitions must be archived or retained. Photo upload, public registration, invite acceptance, import/export, workout editing/deletion, admin attendance correction, APIs, and broad social feed behavior remain blocked.

Phase 09.25 added GymForge admin attendance correction inside the authenticated hub route. OWNER and ADMIN users can create a streak-counting attendance correction for a selected active participant/date and remove incorrect attendance rows from a compact admin drawer, with CSRF protection, duplicate participant/date prevention, the fixed `America/Sao_Paulo` effective-date policy, and sanitized audit events. Corrections update existing ranking and competition scoring because both derive from attendance rows. Photo upload, public registration, invite acceptance, import/export, workout editing/deletion, APIs, and broad social feed behavior remain blocked.

Phase 09.26 added GymForge workout editing and deletion inside the authenticated hub route. Participants can edit or delete only their own workout entries, while OWNER and ADMIN users can edit or delete any participant workout. Mutations require CSRF, deletion requires explicit confirmation, child workout sets are updated transactionally, and sanitized audit events exclude notes and raw form values. Attendance records, competition assignments, and current attendance-derived scoring are unchanged.

Current GymForge MVP integrity hardening intentionally keeps workout creation/editing to exactly one set. Updates fail safely before mutation when a stored workout unexpectedly has zero or multiple sets, while explicit deletion transactionally removes every dependent set before deleting the workout. Upload/photo proof, public registration, invite acceptance until Phase 4, import/export, unsafe competition deletion, a public API, and broad social feed behavior remain blocked until scoped phases implement them.

GymForge competition score-correction Phase 2 is `[DONE]` as a docs-only design. It preserves deterministic current-state base scoring, adds planned append-only additive correction/revocation history without mutating attendance, workout, assignment, or competition source rows, defines OWNER/ADMIN status and CSRF gates, blocks assignment removal while active corrections exist, separates base/aggregate adjustment/final score, fixes stable tie breakers, limits participant visibility, specifies hashed/redacted audits, and requires restrictive retention and destructive-rollback safeguards.

GymForge competition score-correction Phase 3 is `[DONE]`. It adds the additive model/migration, separate current automatic base plus summed active adjustments, negative final scores, deterministic hidden-id tie fallback, OWNER/ADMIN create/revoke gates, UUID idempotency, CSRF, generic errors, bounded serializable retries, lifecycle guards, restrictive deletion, bilingual private UI, and hashed-reference-only create/revoke audits. Eight focused scoring cases and all required repository validations pass.

The committed additive migration was applied to production with `prisma migrate deploy` after a current custom-format PostgreSQL backup was created and verified. Migration status is current. After the first correction write, a pre-Phase-3 application rollback is unsafe because assignment, reactivation, and `DRAFT` guards live in the new runtime; recovery requires a forward fix or verified restore. Actor relations use `SET NULL`, while `revokedAt` preserves revocation after revoker-account removal.

GymForge expansion is now frozen. Private invitations, public registration, import/export, photo proof/uploads, APIs, broad social features, and further scoring work are not active follow-up phases. The existing authenticated GymForge application remains available and its completed delivery history above is preserved.
