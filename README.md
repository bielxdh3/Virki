<div align="center">

# BielOS

**A personal operating-system-style hub for projects, tools, archives, automation, and technical labs.**

[![Status](https://img.shields.io/badge/status-active%20development-orange)](#project-status)
[![Version](https://img.shields.io/badge/version-0.1.0-blue)](#project-status)
[![Runtime](https://img.shields.io/badge/Node.js-22.13%2B-339933)](#requirements)
[![Stack](https://img.shields.io/badge/stack-Next.js%20%2B%20PostgreSQL-black)](#architecture)
[![Access](https://img.shields.io/badge/access-private%20hub-blueviolet)](#security-boundary)

BielOS organizes public presence, private administration, project modules, infrastructure, and operational tooling behind one coherent system boundary.

</div>

> [!IMPORTANT]
> BielOS is a private personal system, not a general-purpose public platform. Public pages and private hub services have different trust boundaries and must remain separated in code, infrastructure, data, and deployment.

## System map

```text
                              Internet
                                 │
                       ┌─────────▼─────────┐
                       │ Cloudflare edge   │
                       │ DNS · Tunnel      │
                       │ Access boundary   │
                       └──────┬───────┬────┘
                              │       │
                       public │       │ authenticated
                              │       │
                 ┌────────────▼─┐   ┌─▼────────────────┐
                 │ Public site  │   │ Private hub      │
                 │ biel.dev.br  │   │ hub.biel.dev.br  │
                 └──────────────┘   └──────┬───────────┘
                                           │
                             ┌─────────────▼──────────────┐
                             │      BielOS core           │
                             │ auth · projects · modules  │
                             │ audit · operations · UI    │
                             └──────┬─────────────┬───────┘
                                    │             │
                         persistent │             │ module boundaries
                                    │             │
                          ┌─────────▼──────┐  ┌──▼─────────────────┐
                          │ PostgreSQL     │  │ Root.ark · L-vault │
                          │ Prisma models  │  │ H-vault · GymForge │
                          └────────────────┘  └────────────────────┘
```

The public site is intentionally narrow. The private hub combines an internal authentication layer with Cloudflare Access rather than relying on one control alone.

## What BielOS is

BielOS is the control plane for Biel's personal technical ecosystem. It is designed to bring together:

- a minimal public site;
- a private authenticated hub;
- project and module navigation;
- operational status and revision visibility;
- shared UI, configuration, types, authentication, and database boundaries;
- future integration points for independent projects without silently merging their trust models.

## Project status

Current foundations include:

- [x] public landing application;
- [x] private hub shell;
- [x] internal email and password authentication;
- [x] Argon2id password hashing;
- [x] opaque session tokens with database-side hashes;
- [x] Prisma-managed PostgreSQL models and migrations;
- [x] owner-account seeding workflow;
- [x] Cloudflare Access integration boundary;
- [x] development and production-style Docker configurations;
- [x] revision-aware production operations;
- [x] secret scanning, linting, type checking, tests, and builds;
- [x] audit and session-maintenance tooling.

L-vault, root.ark, and H-vault remain reserved project boundaries and navigation targets. They must not be described as fully integrated applications until their designs are implemented and reviewed. GymForge is an implemented private-hub application; further expansion remains frozen.

## Architecture

| Layer | Responsibility | Current technology |
|---|---|---|
| Public application | Minimal public presence | Next.js |
| Private hub | Authenticated administration and modules | Next.js |
| Intake boundary | Narrow inbound service path | Node.js/TypeScript workspace |
| Authentication | Passwords, sessions, access policy, administration | Argon2id + opaque sessions |
| Database | Identity, sessions, projects, operational data | PostgreSQL + Prisma |
| Shared packages | UI, auth, database, config, and types | npm workspaces |
| Deployment | Reproducible application and database services | Docker Compose |
| Edge boundary | Private routing and access enforcement | Cloudflare Tunnel + Access |

## Repository map

```text
BielOS/
├── apps/
│   ├── public-site/          Public landing experience
│   ├── hub/                  Private authenticated hub
│   └── intake/               Restricted inbound service boundary
├── packages/
│   ├── ui/                   Shared interface primitives
│   ├── auth/                 Authentication and authorization logic
│   ├── database/             Prisma schema and database client
│   ├── config/               Environment configuration helpers
│   └── types/                Shared TypeScript contracts
├── modules/
│   ├── lvault/               Reserved L-vault boundary
│   ├── rootark/              Reserved Root.ark boundary
│   ├── hvault/               Reserved H-vault boundary
│   └── gymforge/             Implemented private GymForge boundary
├── infra/                    Docker and production infrastructure
├── scripts/                  Validation and operational tooling
├── docs/                     Architecture, auth, operations, and production docs
└── README.md
```

## Requirements

- Node.js `22.13.0` or newer within Node 22;
- npm 10 or newer;
- Docker and Docker Compose for the containerized workflow;
- PostgreSQL;
- private environment values for database, authentication, owner bootstrap, and Cloudflare integration.

CI currently validates with Node.js `22.20.0`.

## Quick start

### 1. Install dependencies

```bash
npm install
```

### 2. Configure the local environment

Copy `.env.example` to `.env` and replace every placeholder with private local values.

> [!CAUTION]
> Never commit `.env`, passwords, session secrets, Cloudflare credentials, database URLs, logs, database exports, or runtime backups.

### 3. Start with Docker

```bash
docker compose -f infra/docker-compose.yml up --build
```

Development ports bind to `127.0.0.1` only. This makes them available to the local browser without intentionally exposing the stack to the LAN or internet.

### 4. Or run direct development

```bash
npm run dev
```

## Owner account bootstrap

Set the following values in the private `.env` file:

```text
BIELOS_OWNER_EMAIL=...
BIELOS_OWNER_PASSWORD=...
```

Then prepare the database and create or update the owner account:

```bash
npm run prisma:migrate:deploy
npm run seed:owner
```

Read [docs/auth.md](docs/auth.md) for the authentication architecture and current security limits.

## Development and production are different

```text
Development
└─ next dev · local ports · local iteration

Production (remote server only)
└─ SSH preflight · exact archive · built images · revision checks
   └─ Cloudflare Tunnel + Access
      └─ BielOS internal authentication
```

> [!WARNING]
> `infra/docker-compose.yml` runs development services and must not be exposed as a production deployment. The development PC must never start the real BielOS production Compose stack; use the guarded remote commands below.

## Operations

| Command | Purpose |
|---|---|
| `npm run preflight:prod` | Verify the canonical SSH/Docker production host |
| `npm run deploy:prod` | Transfer and deploy the exact clean `main` revision remotely |
| `npm run start:prod` | Start remote production |
| `npm run stop:prod` | Stop remote production without deleting volumes |
| `npm run restart:prod` | Rebuild and restart remote production |
| `npm run status:prod` | Show remote service status |
| `npm run revision:prod` | Verify remote image revision labels |
| `npm run health:prod` | Check remote loopback health endpoints |
| `npm run logs:prod` | Report sanitized remote log availability |
| `npm run health:local` | Run disposable local health checks only |
| `npm run audit:recent` | Inspect recent audit activity |
| `npm run audit:cleanup` | Apply audit-retention cleanup |
| `npm run sessions:cleanup` | Remove expired sessions |

Production commands require a clean `main` whose full revision matches `origin/main`, and each remote mutation repeats the SSH preflight. The revision is attached to built images so the running stack can be tied back to source.

Read [docs/operations.md](docs/operations.md) and [docs/production.md](docs/production.md) before operating the production-style stack.

## Validation

The primary CI path runs:

```bash
npm ci
npm run secrets:scan
npm run lint
npm run typecheck
npm run prisma:validate
npm run build
```

Additional focused suites cover core unit logic, database behavior, concurrency, backup and restore, production runtime, revision safety, intake database roles, public-site discovery, and selected module behavior.

Useful commands include:

```bash
npm run test:core
npm run test:backup:restore
npm run test:production:runtime
npm run test:production-revision
```

## Security boundary

BielOS uses defense in depth rather than treating any single layer as sufficient.

- public pages must not expose hub data, internal routes, stack details, logs, ports, or local paths;
- the private hub sits behind Cloudflare Access and BielOS internal authentication;
- passwords are hashed with Argon2id;
- browser cookies contain opaque tokens, while the database stores only token hashes;
- production database changes use committed Prisma migrations, not `prisma db push`;
- production operations verify the repository revision before building and starting;
- development ports stay bound to loopback by default;
- each future module integration requires its own data, permission, and failure boundary;
- reserved module directories are not permission to copy private project data into this repository.

## Roadmap

- [x] **UI/UX rebaseline:** Prompt Arena parity source lock, semantic shell tokens, appearance controls, compact navigation, accessibility hooks, reduced motion, and responsive mapping are implemented locally. Evidence: [parity matrix](docs/ui-ux-prompt-arena-parity.md).
- [x] **Minimal-first information density:** Core administration, module requests, health, recovery, activity, automation, and audit surfaces use compact labels and progressive disclosure; human visual acceptance remains a separate gate.
- [x] **Intuition-first text compression:** compact navigation and removal of decorative numbering are implemented. See [docs/ui-ux-intuition-first.md](docs/ui-ux-intuition-first.md).
- [x] Port Prompt Arena shell/navigation, semantic tokens, typography, appearance controls, component patterns, accessibility, reduced motion, and responsive behavior locally before independent polish.
- [x] Migrate the current Hub surfaces to the shared parity system through the shell/token/component mapping while preserving legacy route/security boundaries; authenticated visual acceptance is still pending.
- [x] Mature operational health, audit, and recovery surfaces with bounded capability contracts, pagination, filters, safe detail, and export.
- [x] Define explicit contracts for independent project modules (Capability Contract v1).
- [ ] Integrate Root.ark only after a separate architecture and security review
- [ ] Integrate L-vault without weakening its local-data boundary
- [ ] Add H-vault through an isolated module contract; preserve GymForge's implemented private-hub behavior and expansion freeze
- [x] Strengthen backup, restore, and disaster-recovery evidence through the documented disposable PostgreSQL backup/restore validation contract; repeat validation remains a release gate after meaningful procedure or schema changes.
- [x] Keep the public site intentionally minimal while the private system grows; the public-site suite covers canonical routes and keeps private data out of the surface.

## Documentation

- [UI/UX Prompt Arena parity roadmap](docs/ui-ux-prompt-arena-roadmap.md)
- [UI/UX intuition-first compression rule](docs/ui-ux-intuition-first.md)
- [Authentication](docs/auth.md)
- [Production deployment](docs/production.md)
- [Operations](docs/operations.md)

## Disclaimer

BielOS is a private personal system under active development. Repository access, a successful build, or a running container does not by itself mean a deployment is safe to expose or ready to operate without review.
