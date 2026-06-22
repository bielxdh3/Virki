# BielOS

BielOS is a personal operating-system-style hub for projects, tools, archives, automation, and technical labs.

The project starts as a local Windows-friendly monorepo and is designed to move cleanly to a dedicated Linux machine through Docker, PostgreSQL, and environment-based configuration.

## Apps

- `apps/public-site`: public landing screen for `biel.dev.br`.
- `apps/hub`: private hub shell for `hub.biel.dev.br`.

## Reserved Modules

- `modules/lvault`: reserved for L-vault.
- `modules/rootark`: reserved for root.ark.
- `modules/hvault`: reserved for H-vault.
- `modules/gymforge`: reserved for GymForge.

These modules are placeholders only. They are not implemented as full applications yet.

## Packages

- `packages/ui`: shared UI primitives and module metadata.
- `packages/auth`: authentication placeholders and contracts.
- `packages/database`: Prisma schema and database client boundary.
- `packages/config`: environment helpers.
- `packages/types`: shared TypeScript types.

## Local Setup

1. Install dependencies:

   ```bash
   npm install
   ```

2. Copy `.env.example` to a private `.env` file and replace placeholder values.

3. Start PostgreSQL and the application services:

   ```bash
   docker compose -f infra/docker-compose.yml up --build
   ```

4. For direct local development without Docker:

   ```bash
   npm run dev
   ```

## Security Baseline

- Real secrets must stay out of Git.
- Public pages must not expose private hub data, internal ports, stack internals, logs, or local paths.
- Authentication is intentionally shallow in this first core scaffold and must be completed before private use.
- Cloudflare Tunnel and Cloudflare Access are planned integration layers, not hardcoded assumptions.
