# Operations

This guide is for running BielOS locally in production mode without memorizing Docker commands.

## Before Starting

Make sure Docker Desktop is running.

For local Node.js commands, use Node `22.13.0` or newer within Node 22. The lint tooling added in Phase 05.2 depends on packages that do not support early Node 22 releases.

Make sure the private `.env` file exists in the repository root. This file must stay local. Never commit it.

The `.env` file contains private values such as:

- PostgreSQL password
- OWNER seed email and password
- Cloudflare Tunnel token

## Commands

Start BielOS in production mode:

```bash
npm run start:prod
```

Stop BielOS:

```bash
npm run stop:prod
```

Restart BielOS:

```bash
npm run restart:prod
```

Show container status:

```bash
npm run status:prod
```

Show published port bindings:

```bash
npm run status:ports
```

Development and production app ports should show loopback bindings only:

```text
127.0.0.1:3000->3000
127.0.0.1:3001->3001
```

Show useful logs:

```bash
npm run logs:prod
```

Run local health checks:

```bash
npm run health:local
```

Use `docs/deployment-verification.md` for the first production launch checklist and live Cloudflare smoke test.

The health check verifies:

- `http://127.0.0.1:3000`
- `http://127.0.0.1:3001/api/health`

These addresses are for local debugging only. They are not the remote ingress path.

The hub health endpoint returns only minimal liveness status. It does not require Cloudflare Access JWT validation, so local Docker health checks keep working when `CLOUDFLARE_ACCESS_JWT_REQUIRED=true`.

## Services

- `public-site`: the public BielOS site for `biel.dev.br`.
- `hub`: the private BielOS hub for `hub.biel.dev.br`.
- `session-cleanup`: the production worker that periodically removes expired or revoked hub sessions.
- `postgres`: the PostgreSQL database used by the hub.
- `cloudflared`: the Cloudflare Tunnel connector that exposes BielOS through Cloudflare without opening router ports.

Cloudflare Tunnel does not depend on the host-published `127.0.0.1` debug ports. When `cloudflared` runs inside Docker, it reaches the apps through Docker service names:

- `http://public-site:3000`
- `http://hub:3001`

## Expected Remote Flow

The expected remote flow is:

1. `https://biel.dev.br` loads the public site.
2. `https://hub.biel.dev.br` shows Cloudflare Access first.
3. After Cloudflare Access, BielOS shows the internal login.
4. After BielOS login, the hub dashboard loads.

## Troubleshooting

### Docker Is Not Running

Open Docker Desktop and wait until it says Docker is running. Then run:

```bash
npm run status:prod
```

If Docker is still unavailable, restart Docker Desktop.

### `biel.dev.br` Shows 502

Check container status:

```bash
npm run status:prod
```

Check logs:

```bash
npm run logs:prod
```

In the Cloudflare dashboard, confirm the Docker route uses the service name:

```text
biel.dev.br -> http://public-site:3000
www.biel.dev.br -> http://public-site:3000
```

Do not use `localhost` when `cloudflared` runs inside Docker.

If `biel.dev.br` still returns 502, confirm the dashboard route is not using `localhost` and then run:

```bash
npm run status:ports
```

### `hub.biel.dev.br` Skips Cloudflare Access

Check Cloudflare Access in the Cloudflare dashboard.

The hub hostname must be protected:

```text
hub.biel.dev.br
```

Access should only allow the owner's email or an approved identity group.

The Docker route should be:

```text
hub.biel.dev.br -> http://hub:3001
```

Do not expose port `3001` directly to the internet. Direct access to port `3001` bypasses Cloudflare Access.

### Login Fails

Confirm the OWNER user was seeded:

```bash
docker compose --env-file .env -f infra/docker-compose.prod.yml -f infra/docker-compose.cloudflare.yml exec -T hub npm run seed:owner
```

If the database was recreated, apply committed migrations first:

```bash
docker compose --env-file .env -f infra/docker-compose.prod.yml -f infra/docker-compose.cloudflare.yml exec -T hub npm run prisma:migrate:deploy
```

Then seed the OWNER user again.

Confirm the email and password are the values in your private local `.env` file.

If a login or logout POST returns HTTP `403` while the page itself loads normally, reload the form and try again. Hub POST routes require a short-lived CSRF token, and tokens generated before a hub restart may no longer validate.

### Session Cleanup

Production Compose starts a `session-cleanup` worker with no published ports. It uses the same private database configuration as the hub and runs `npm run sessions:cleanup --workspace @bielos/auth` every hour by default.

To change the interval, set this non-secret value in the private local `.env` file:

```bash
SESSION_CLEANUP_INTERVAL_SECONDS=3600
```

The cleanup log prints only the number of inactive sessions removed. It must not print session tokens, cookies, raw IPs, JWTs, or Cloudflare values.

### Health Check Fails

Run:

```bash
npm run status:prod
```

If containers are not running, start them:

```bash
npm run start:prod
```

If containers are running but health still fails, inspect logs:

```bash
npm run logs:prod
```

The hub health check should use `/api/health`, not `/login`. `/login` can correctly return HTTP `403` when origin-side Cloudflare Access JWT validation is enabled and the request does not include a valid Access assertion.

### Local Validation Checks

Before pushing a phase, run the same core checks used by CI when feasible:

```bash
npm run secrets:scan
npm run lint
npm run typecheck
npm run prisma:validate
npm run build
```

The secret scan is intentionally safe to run locally. It scans tracked repository files plus new non-ignored files and reports only file paths, line numbers, and rule ids.

For CSRF changes, also verify locally when feasible that the login and logout forms contain a hidden CSRF field, valid form submissions work, and missing-token POSTs return HTTP `403`.

## Security Notes

Development and production debug ports are bound to `127.0.0.1` only. On a public Linux server or VPS, also block inbound internet access to ports `3000` and `3001` with the host firewall as defense in depth.

Never commit:

- `.env`
- Cloudflare Tunnel token
- Cloudflare account ID
- real tunnel ID
- tunnel credentials JSON
- screenshots containing secrets
- database dumps
- backup archives

The repository should contain only examples, placeholders, and documentation.
