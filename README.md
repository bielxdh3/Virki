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

Use Node.js `22.13.0` or newer within Node 22. The lint tooling requires Node `22.13+`, and CI currently uses Node `22.20.0`.

1. Install dependencies:

   ```bash
   npm install
   ```

2. Copy `.env.example` to a private `.env` file and replace placeholder values.

3. Start PostgreSQL and the application services:

   ```bash
   docker compose -f infra/docker-compose.yml up --build
   ```

   Development Docker ports bind to `127.0.0.1` only. They are for local browser access and should not expose BielOS to LAN/WAN by default.

4. For direct local development without Docker:

   ```bash
   npm run dev
   ```

## CI and Validation

GitHub Actions runs validation on pushes and pull requests to `main` using Node.js `22.20.0`.

The CI workflow runs:

```bash
npm ci
npm run secrets:scan
npm run lint
npm run typecheck
npm run prisma:validate
npm run build
```

## Internal Authentication

The private hub uses internal email and password authentication backed by the `User` and `Session` database models. Passwords are hashed with Argon2id, and session cookies store only an opaque session token while the database stores only its hash.

To prepare a local OWNER account, set `BIELOS_OWNER_EMAIL` and `BIELOS_OWNER_PASSWORD` in a private `.env` file, apply Prisma migrations to your local database, then run:

```bash
npm run prisma:migrate:deploy
npm run seed:owner
```

See `docs/auth.md` for the auth architecture and current security limits.

## Production Readiness

Use `infra/docker-compose.prod.yml` and `infra/Dockerfile.prod` for production-style builds. The development compose file runs `next dev` and must not be exposed.

Production requires a private `.env` file and the Cloudflare Tunnel/Access boundary described in `docs/production.md`.

## Operations

Use the root operation scripts for the local production stack:

```bash
npm run start:prod
npm run stop:prod
npm run restart:prod
npm run status:prod
npm run logs:prod
npm run health:local
```

See `docs/operations.md` for beginner-friendly start, stop, status, logs, health check, and troubleshooting steps.

## Security Baseline

- Real secrets must stay out of Git.
- Public pages must not expose private hub data, internal ports, stack internals, logs, or local paths.
- The hub remains private behind Cloudflare Access and BielOS internal auth.
- Production database changes use committed Prisma migrations, not `prisma db push`.
