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

Production runs only on the configured remote Windows host. Operator connection values live in the ignored `.production.operator.json` file or `BIELOS_PRODUCTION_*` environment variables. Run the SSH preflight before changing production.

| Command | Purpose |
|---|---|
| `npm run preflight:prod` | Verify SSH stability, production identity, and remote Docker. |
| `npm run deploy:prod` | Back up, restore-verify, migrate, deploy, and verify the exact clean `main` revision. |
| `npm run backup:prod` | Create and restore-verify a production backup against the current migration plan. |
| `npm run status:prod` | Show BielOS service status. |
| `npm run revision:prod` | Verify running service image revisions. |
| `npm run health:prod` | Check public, portal OIDC, ADMIN boundary, and loopback health. |
| `npm run logs:prod` | Return sanitized log availability only. |

Production changes require exact-SHA CI success. Never use `prisma db push`, delete production volumes, weaken ADMIN Cloudflare Access, or touch deManage. See [docs/deployment.md](docs/deployment.md) and [docs/operations.md](docs/operations.md).

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

CI also checks production dependencies, the Docker image boundary, Compose configuration, and the exact revision label. See [docs/architecture.md](docs/architecture.md), [docs/security.md](docs/security.md), and [docs/operations.md](docs/operations.md).
