# Architecture

BielOS is organized as a monorepo with two initial Next.js applications and shared packages.

## Surfaces

- Public site: `biel.dev.br`
- Private hub: `hub.biel.dev.br`

The public site must stay generic. It should not reveal private module data, internal paths, local ports, stack internals, private logs, or operational details.

## Applications

`apps/public-site` contains the public operating-system-style landing screen.

`apps/hub` contains the private desktop/dashboard, BielOS Core workspace, and integrated private applications. Cloudflare Access is the outer boundary and BielOS internal authentication is the second boundary.

## Packages

- `packages/ui`: shared module metadata and reusable UI contracts.
- `packages/auth`: internal authentication, sessions, CSRF, Cloudflare Access validation, and sanitized audit primitives.
- `packages/database`: Prisma schema and database client boundary.
- `packages/config`: environment-driven configuration.
- `packages/types`: shared TypeScript types.

## Data

PostgreSQL is the primary database. Prisma owns the application schema. Database connection details must come from environment variables.

## Deployment Shape

The initial deployment target is Docker Compose on the user's primary Windows PC. The project should later move to Linux without path rewrites or hardcoded machine details.

Cloudflare Tunnel and Cloudflare Access provide the external boundary for the private hub. Host-published application ports remain loopback-only.

## Core And Applications

BielOS Core owns the deployed project, access, personal session, safe operations, and owner-only audit surfaces. GymForge is an available application linked from the hub; its feature expansion is frozen. L-vault, root.ark, and H-vault remain reserved and inert.

The Core authorization and data contract is documented in `docs/modules/bielos-core.md`.

`packages/ui` owns the small typed hub registry. It classifies Core surfaces, available applications, and reserved modules without introducing a plugin runtime or placeholder routes.

The Core operations panel performs only local, bounded application checks. It does not inspect Docker, read raw logs or environment values, or make external requests while rendering. Deployment and edge status remain separate manual validation.

The production Compose stack runs the public site, private hub, PostgreSQL, Cloudflare Tunnel, and session-cleanup worker. App ports remain published only on `127.0.0.1`; Cloudflare Access remains the first hub boundary and BielOS authentication remains the second.
