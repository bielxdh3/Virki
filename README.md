# BielOS

BielOS provides identity, authentication and SSO, security, project entry access, and audit for external projects. It authenticates users and controls entry; each project owns its own experience and permissions.

## Surfaces

- `biel.dev.br` — minimal public page and portal entry.
- `portal.biel.dev.br` — authenticated USER portal and OIDC issuer. Users see only projects granted to them.
- `hub.biel.dev.br` — ADMIN control plane behind Cloudflare Access and BielOS authentication.

The ADMIN navigation is Contas, Acessos, Segurança, Auditoria, and Conexões. Stored roles are ADMIN and USER. Project access is granted explicitly to users; BielOS has no project roles.

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

The next canonical production host is native Linux reached over SSH. The previous host is unavailable and the native Linux host has not been verified; do not deploy until its identity and existing BielOS data are confirmed. The scripts reject WSL, require a pre-provisioned host marker, and never create that marker during first contact. Operator connection values live in the ignored `.production.operator.json` file or `BIELOS_PRODUCTION_*` environment variables. Run the SSH preflight only when the native Linux host is available.

| Command | Purpose |
|---|---|
| `npm run preflight:prod` | Require eight stable SSH probes, the expected native Linux host, its pre-provisioned identity marker, private remote environment files, and Docker Compose. |
| `npm run deploy:prod` | Require clean `main` at `origin/main` and green exact-SHA CI, then backup, restore-test migrations, enter maintenance, migrate, start, and health-check. |
| `npm run backup:prod` | Create a backup outside source releases and validate all committed migrations against a restored copy. |
| `npm run status:prod` | Show BielOS service status. |
| `npm run revision:prod` | Verify running service image revisions. |
| `npm run health:prod` | Check public and hub health, portal OIDC discovery, Hub denial without Access, and loopback bindings. |
| `npm run logs:prod` | Return sanitized log availability only. |
| `node scripts/production-remote.mjs start-tunnel` | Start the Cloudflare Tunnel connector after application health checks pass. |
| `node scripts/production-remote.mjs maintenance-on` | Stop routed app, worker, and Tunnel services while preserving PostgreSQL and named data. |
| `node scripts/production-remote.mjs maintenance-off` | Resume services only when the source and migration status are verified. |

Production secrets stay on the remote Linux host in private `.env`, `.env.oidc`, and `.env.oidc-data` files; deployment transfers the accepted Git archive and the matching images produced by exact-SHA CI, never an environment file. Compose runs those preloaded revision-tagged images without rebuilding or pulling them. The main `.env` is used for interpolation, the issuer signing and cookie keys go only to the issuer, and the OIDC data-encryption key goes only to the Hub and issuer. Each remote operation requires a clean accepted `main` revision with green exact-SHA CI. Never use `prisma db push`, remove production volumes, weaken ADMIN Cloudflare Access, or touch deManage. See [docs/deployment.md](docs/deployment.md) and [docs/operations.md](docs/operations.md).

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

CI also checks production dependencies, the Docker image boundary, Compose configuration, and exact revision labels. Successful main pushes build, smoke-test, and retain runtime and migration images for both supported Linux architectures for 14 days. See [docs/architecture.md](docs/architecture.md), [docs/security.md](docs/security.md), and [docs/operations.md](docs/operations.md).
