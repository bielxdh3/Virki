# Virki historical README status (October 2026)

> [!NOTE]
> Dated notes preserved verbatim from the original `main` README blob `0f88071f13639073d7832fa6389f327723b37220`. These are **historical observations**, not current CI status or deployment authorization. Operational source of truth: [Operations](../operations.md), [Deployment](../deployment.md), [Security](../security.md).

**October 2026 source status:** [PR #51](https://github.com/bielxdh3/Virki/pull/51), [PR #52](https://github.com/bielxdh3/Virki/pull/52), and [PR #53](https://github.com/bielxdh3/Virki/pull/53) are merged into `main`. They add authentication/OIDC and database safeguards, structured audit records and ADMIN investigation filters, and login, invitation, and recovery-flow improvements. Local integrated regression evidence covers these changes, but does not substitute for hosted CI or a verified production deployment.

**Validation boundary (2026-10-19):** the recorded `main` CI run following these merges failed. The native Linux production host is still unverified; the operations gate below remains in force. Do not infer a successful deployment from merged PRs.

## Historical production-operations wording

This previous README wording is retained as context; follow the current [Operations](../operations.md) runbook for any approved action.

## Production operations

The next canonical production host is native Linux reached over SSH. The previous host is unavailable and the native Linux host has not been verified; do not deploy until its identity and existing Virki data are confirmed. The scripts reject WSL, require a pre-provisioned host marker, and never create that marker during first contact. Operator connection values live in the ignored `.production.operator.json` file or `VIRKI_PRODUCTION_*` environment variables. Run the SSH preflight only when the native Linux host is available.

| Command | Purpose |
|---|---|
| `npm run preflight:prod` | Require eight stable SSH probes, the expected native Linux host, its pre-provisioned identity marker, private remote environment files, and Docker Compose. |
| `npm run deploy:prod` | Require clean `main` at `origin/main` and green exact-SHA CI, then backup, restore-test migrations, enter maintenance, migrate, start, and health-check. |
| `npm run backup:prod` | Create a backup outside source releases and validate all committed migrations against a restored copy. |
| `npm run status:prod` | Show Virki service status. |
| `npm run revision:prod` | Verify running service image revisions. |
| `npm run health:prod` | Check public and hub health, portal OIDC discovery, Hub denial without Access, and loopback bindings. |
| `npm run logs:prod` | Return sanitized log availability only. |
| `node scripts/production-remote.mjs start-tunnel` | Start the Cloudflare Tunnel connector after application health checks pass. |
| `node scripts/production-remote.mjs maintenance-on` | Stop routed app, worker, and Tunnel services while preserving PostgreSQL and named data. |
| `node scripts/production-remote.mjs maintenance-off` | Resume services only when the source and migration status are verified. |

Production secrets stay on the remote Linux host in private `.env`, `.env.oidc`, and `.env.oidc-data` files; deployment transfers the accepted Git archive and the matching images produced by exact-SHA CI, never an environment file. Compose runs those preloaded revision-tagged images without rebuilding or pulling them. The main `.env` is used for interpolation, the issuer signing and cookie keys go only to the issuer, and the OIDC data-encryption key goes only to the Hub and issuer. Each remote operation requires a clean accepted `main` revision with green exact-SHA CI. Never use `prisma db push`, remove production volumes, weaken ADMIN Cloudflare Access, or touch deManage. See [docs/deployment.md](docs/deployment.md) and [docs/operations.md](docs/operations.md).
