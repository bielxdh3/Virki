# BielOS contributor guide

BielOS has five responsibilities: identity, authentication and SSO, security, project entry access, and audit. It authenticates people and decides whether a person may enter an external project. Project behavior and permissions stay with that project.

## Surfaces

- `biel.dev.br` is a minimal public page with a portal entry.
- `portal.biel.dev.br` is the authenticated USER portal and OIDC issuer surface. A user sees only enabled projects with an active explicit grant.
- `hub.biel.dev.br` is the ADMIN control plane. Cloudflare Access is the outer boundary; BielOS authentication and authorization are the inner boundary.
- The administration navigation contains only Contas, Acessos, Segurança, Auditoria, and Conexões.

## Identity and authorization

- Stored roles are `ADMIN` and `USER` only. Unauthenticated requests are untrusted and denied by default.
- There are no BielOS project roles. Access is an explicit USER-to-project grant.
- Projects are external OIDC relying parties. BielOS does not host their experiences or manage their internal permissions.
- Do not add a project unless an ADMIN registers its canonical origin, exact redirect URI allowlist, and client credentials.
- Recheck account, project, and grant state when authorizing. Client supplied roles or grants are never authoritative.

## Security and data

- Preserve password hashes, MFA/TOTP, recovery, account security metadata, and compatible authentication/security audit history.
- Keep host-only session cookies. Never share the central session with a project or across subdomains.
- Require CSRF protection, rate limits, replay protection, generic authentication failures, safe logout, and server-side authorization for sensitive actions.
- OIDC uses Authorization Code with PKCE S256, exact redirect matching, short-lived one-time codes, client binding, and state/nonce validation.
- Never print or commit secrets, tokens, private keys, database URLs with passwords, dumps, backups, or raw security logs.
- Admin security changes require fresh proof where the action policy specifies it.

## Implementation and interface

- Keep the public page, USER portal, and ADMIN control plane small and direct.
- Keep each surface limited to identity, authentication, security, project entry, and audit; projects own their application experiences and internal authorization.
- Preserve keyboard access, visible focus, labels, contrast, responsive behavior, and correct skip-link placement.
- Keep focused tests for authorization, grants, OIDC, MFA, audit redaction, migrations, and production boundaries.

## Production operations

- Local use is limited to development, builds, and disposable validation databases. Production runs only on the configured remote native Linux host; Windows and WSL are not production targets.
- Production host values come from the ignored `.production.operator.json` file or `BIELOS_PRODUCTION_*` environment variables. Never add machine-specific host, path, or Cloudflare values to tracked files.
- Run `npm run preflight:prod` before any production mutation. Require stable SSH probes, the expected host, remote Docker, the production identity marker, and the exact accepted revision. Do not use a local or WSL fallback.
- Deploy only a clean `main` revision matching `origin/main` after exact-SHA CI is green.
- Before a database change, create a production backup outside the repository, restore it to a disposable database, and validate the migration plan against that restore. Apply committed Prisma migrations; never use `prisma db push` in production.
- Preserve persistent volumes. Do not delete Docker volumes, expose database ports, weaken Cloudflare Access, or change router/firewall settings.
- Keep deManage isolated. Do not inspect its data or change its containers, networks, volumes, or services.
- Cloudflare DNS, Tunnel, and Access settings are external state. Verify the public portal route and ensure the ADMIN host remains protected without imposing its Access policy on the USER portal.

## Documentation and validation

Keep documentation limited to current architecture, security, operations, SSO integration, and deployment. Remove obsolete product language rather than retaining it as a roadmap or tombstone.

For relevant code changes run the focused tests plus:

```bash
npm run secrets:scan
npm run lint
npm run typecheck
npm run prisma:validate
npm run build
git diff --check
```

Validate Docker Compose and production runtime behavior when those areas change. Report any checks that could not run and why.
