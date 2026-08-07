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

The reserved project modules exist as integration boundaries and navigation targets. They must not be described as fully integrated applications until that work is implemented and reviewed.

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
│   └── gymforge/             Reserved GymForge boundary
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

Production-style
└─ built images · committed migrations · revision checks
   └─ Cloudflare Tunnel + Access
      └─ BielOS internal authentication
```

> [!WARNING]
> `infra/docker-compose.yml` runs development services and must not be exposed as a production deployment. Use the production files and documented access boundary for production-style operation.

## Operations

| Command | Purpose |
|---|---|
| `npm run start:prod` | Validate and start the local production stack |
| `npm run stop:prod` | Stop production services |
| `npm run restart:prod` | Validate and restart production services |
| `npm run status:prod` | Show service status |
| `npm run revision:prod` | Verify the deployed source revision |
| `npm run logs:prod` | Follow recent production logs |
| `npm run health:local` | Run local health checks |
| `npm run audit:recent` | Inspect recent audit activity |
| `npm run audit:cleanup` | Apply audit-retention cleanup |
| `npm run sessions:cleanup` | Remove expired sessions |

Production start and restart require a clean `main` whose full revision matches `origin/main`. The revision is attached to built images so the running stack can be tied back to source.

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

- [ ] Expand the private core dashboard and project management views
- [ ] Mature operational health, audit, and recovery surfaces
- [ ] Define explicit contracts for independent project modules
- [ ] Integrate Root.ark only after a separate architecture and security review
- [ ] Integrate L-vault without weakening its local-data boundary
- [ ] Add H-vault and GymForge through isolated module contracts
- [ ] Strengthen backup, restore, and disaster-recovery evidence
- [ ] Keep the public site intentionally minimal while the private system grows

## Documentation

- [Authentication](docs/auth.md)
- [Production deployment](docs/production.md)
- [Operations](docs/operations.md)

## Disclaimer

BielOS is a private personal system under active development. Repository access, a successful build, or a running container does not by itself mean a deployment is safe to expose or ready to operate without review.