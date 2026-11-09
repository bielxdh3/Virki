<p align="center">
  <img src="apps/public-site/public/virki-mark.svg" alt="Virki" width="96" height="96" />
</p>

# Virki

![Private repository](https://img.shields.io/badge/repository-private-64748B)
![OIDC](https://img.shields.io/badge/identity-OIDC-7C3AED)
![Node.js](https://img.shields.io/badge/runtime-Node.js%2022-339933)
![PostgreSQL](https://img.shields.io/badge/database-PostgreSQL-4169E1)

Virki provides identity, authentication and SSO, security, project entry access, and audit for external projects. It authenticates users and controls entry; each project owns its own experience and permissions.

## Surfaces

- `biel.dev.br` — minimal public page and portal entry.
- `portal.biel.dev.br` — authenticated USER portal with a **Projetos** landing page and OIDC endpoints. The USER portal is not the ADMIN Hub; the current implementation lists only enabled projects with active grants.
- `hub.biel.dev.br` — ADMIN control plane behind Cloudflare Access and Virki authentication.

The ADMIN navigation is Contas, Acessos, Segurança, Auditoria, and Conexões. Stored roles are ADMIN and USER. Project access is granted explicitly to users; Virki has no project roles.

## Architecture at a glance

```text
                     Production routes (conceptual)

  Public internet
        |
        v
  Cloudflare Tunnel
        |
        +-- Public hostname --------> Public site (loopback)
        |                                |
        |                              Entrar
        |                                |
        +-- USER hostname  <-------------+
        |       |
        |       v
        |    USER portal (apps/hub, NOT the ADMIN dashboard)
        |       +-- / : Projetos (currently: enabled + granted only)
        |       +-- /account/security : user account security
        |       +-- private OIDC path proxy ---> OIDC issuer
        |
        +-- ADMIN hostname --> Cloudflare Access --> ADMIN Hub
                                                     + Virki ADMIN session

      USER portal + ADMIN Hub share an application service;
      they are distinct host/access surfaces, not a user redirect.

      Hub application + OIDC issuer + private background workers
                              |
                              v
                       PostgreSQL / Prisma
                users · sessions · grants · audit
                    protected OIDC artifacts

  External projects use OIDC authorization code + PKCE.
  Project sessions and app-internal permissions stay in each project.
```

The production public site and Hub bind to loopback; the OIDC issuer and database have no host-published ports. The USER portal does **not** require the ADMIN Cloudflare Access assertion. The ADMIN hostname requires **both** Cloudflare Access and a Virki ADMIN session. The issuer is reachable through the portal's internal OIDC proxy, not a directly exposed port.

This is a **diagram of the currently configured routing and implemented portal**, not proof that a production deployment has passed acceptance. Details: [architecture](docs/architecture.md), [security](docs/security.md), and [deployment](docs/deployment.md).

### Project visibility — intended behavior (not yet implemented)

After entering from the public site and authenticating on `portal.biel.dev.br`, a USER should land on the **Projetos** section. The intended catalog distinguishes **visibility** (whether a project is listed) from **authorization** (whether entry is granted):

| State | USER portal behavior |
|---|---|
| **Visible + authorized** | List the project with **Acessar**; the backend still verifies the active grant before OIDC authorization. |
| **Visible + unauthorized** | List the project as **Sem acesso**, without an actionable launch link or authorization. |
| **Hidden** | Do not list the project or disclose its details to the USER, even if the project exists. |

```text
      Intended USER project catalog (NOT IMPLEMENTED)
                          |
                    Project hidden?
                     /          \
                   Yes          No
                    |            |
               Not listed    Active grant?
                               /       \
                             Yes       No
                              |         |
                           Acessar   Sem acesso
```

**Implementation status:** `apps/hub/src/app/page.tsx` currently queries only enabled connections with active `UserProjectGrant` records. `ProjectConnection` has an `enabled` flag but no independent public/hidden visibility setting in the Prisma schema. Therefore the visible-but-unauthorized and hidden classifications are **requirements, not shipped UI or database features**. This README change does not implement them or relax authorization. The ADMIN Hub at `hub.biel.dev.br` remains a separate, protected surface.

## Local development

Requirements: Node.js 22.13 or later within Node 22, npm 10 or later, Docker Compose, and PostgreSQL.

1. Install with `npm ci`.
2. Copy `.env.example` to `.env` and set private local values. Use a separate development database.
3. Start the development stack:

   ```bash
   docker compose -f infra/docker-compose.yml up --build
   ```

   Development service ports bind to loopback. The OIDC issuer is reachable only inside the Compose network.

`npm run dev` starts the public site, hub, and issuer directly when a development database and environment are already available.

## OIDC integration

Register each external project through **Hub → Conexões** with its canonical HTTPS origin and exact redirect URI list. Grant users entry through **Hub → Acessos**. See [docs/sso-integration.md](docs/sso-integration.md) for the supported protocol and client requirements.

## Production operations

Production is a gated **native Linux / SSH** workflow, not a development-server command. Operations require independently verified host identity, an accepted exact source SHA and CI/CodeQL evidence, remote-only protected configuration, and backup/migration safeguards. **Do not deploy just because code has merged or this README describes the architecture.**

| Command | Purpose |
|---|---|
| `npm run preflight:prod` | Verify accepted source and operator prerequisites before contacting production. |
| `npm run backup:prod` | Run the guarded backup/restore validation. |
| `npm run deploy:prod` | Deploy only after all exact-source and host/migration gates pass. |
| `npm run health:prod` | Verify service health and access boundaries after an accepted release. |

The complete command reference, remote configuration, recovery, maintenance, first-install and data-safety requirements are in [Operations](docs/operations.md) and [Deployment](docs/deployment.md). Dated README status notes are preserved in [the October 2026 archive](docs/validation/readme-october-2026-status-snapshot.md).

## Validation

```bash
npm run secrets:scan
npm run lint
npm run typecheck
npm run prisma:validate
npm run test:unit
npm run test:public-site
npm run test:migration
npm run test:backup:restore
npm run test:production:runtime
npm run test:production-revision
npm run build
```

`test:backup:restore` is an opt-in local Windows Docker Desktop Linux test.
Set `VIRKI_BACKUP_VALIDATION_LOCAL_DOCKER=1` before running; see
[the disposable PostgreSQL validation guide](docs/offline-pg-disposable-recovery.md)
for environment restrictions and cleanup behavior.

CI also checks production dependencies, the Docker image boundary, Compose configuration, and exact revision labels. Successful main pushes build, smoke-test, and retain runtime and migration images for both supported Linux architectures for 14 days. See [docs/architecture.md](docs/architecture.md), [docs/security.md](docs/security.md), and [docs/operations.md](docs/operations.md).
