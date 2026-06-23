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
