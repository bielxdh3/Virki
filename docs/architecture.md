# Architecture

BielOS is organized as a monorepo with two initial Next.js applications and shared packages.

## Surfaces

- Public site: `biel.dev.br`
- Private hub: `hub.biel.dev.br`

The public site must stay generic. It should not reveal private module data, internal paths, local ports, stack internals, private logs, or operational details.

## Applications

`apps/public-site` contains the public operating-system-style landing screen.

`apps/hub` contains the private desktop/dashboard shell. Authentication is represented by a placeholder screen in this MVP and must be completed before real private use.

## Packages

- `packages/ui`: shared module metadata and reusable UI contracts.
- `packages/auth`: authentication boundary placeholders.
- `packages/database`: Prisma schema and database client boundary.
- `packages/config`: environment-driven configuration.
- `packages/types`: shared TypeScript types.

## Data

PostgreSQL is the primary database. Prisma owns the application schema. Database connection details must come from environment variables.

## Deployment Shape

The initial deployment target is Docker Compose on the user's primary Windows PC. The project should later move to Linux without path rewrites or hardcoded machine details.

Cloudflare Tunnel and Cloudflare Access are planned as the external access boundary.
