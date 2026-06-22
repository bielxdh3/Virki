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

## CI and Validation

GitHub Actions runs the Phase 01 validation pipeline on pushes and pull requests to `main` using Node.js 22.

The CI workflow runs:

```bash
npm ci
npm run typecheck
npm run prisma:validate
npm run build
```

## Internal Authentication

The private hub uses internal email and password authentication backed by the `User` and `Session` database models. Passwords are hashed with Argon2id, and session cookies store only an opaque session token while the database stores only its hash.

To prepare a local OWNER account, set `BIELOS_OWNER_EMAIL` and `BIELOS_OWNER_PASSWORD` in a private `.env` file, apply the Prisma schema to your local database, then run:

```bash
npm run seed:owner
```

See `docs/auth.md` for the auth architecture and current security limits.

## Security Baseline

- Real secrets must stay out of Git.
- Public pages must not expose private hub data, internal ports, stack internals, logs, or local paths.
- Authentication is intentionally shallow in this first core scaffold and must be completed before private use.
- Cloudflare Tunnel and Cloudflare Access are planned integration layers, not hardcoded assumptions.
