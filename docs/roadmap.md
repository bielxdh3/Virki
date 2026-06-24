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

Phase 04 redesigned the hub shell only. L-vault, root.ark, H-vault, and GymForge remain reserved and are not implemented as module applications yet.

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
