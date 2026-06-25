# Roadmap

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
