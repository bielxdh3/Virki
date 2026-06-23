# Production

Phase 02.2 adds a production deployment foundation. Phase 03.1 documents the confirmed Docker-based remote deployment path through Cloudflare Tunnel and Cloudflare Access.

## Development vs Production Compose

Development:

```bash
docker compose -f infra/docker-compose.yml up --build
```

The development compose file runs `npm run dev`. It is intended only for local development.

Production:

```bash
docker compose --env-file .env -f infra/docker-compose.prod.yml up --build
```

The production compose file builds with `infra/Dockerfile.prod` and starts the Next.js apps with production `next start` commands.

Production host-published debug ports are bound to loopback only:

- `127.0.0.1:${PUBLIC_SITE_PORT:-3000}:3000`
- `127.0.0.1:${HUB_PORT:-3001}:3001`

These bindings preserve local health checks while avoiding exposure on all host interfaces. Cloudflare Tunnel does not use these host-published ports when it runs inside Docker.

## Simple Production Validation

Run the production compose path:

```bash
docker compose --env-file .env -f infra/docker-compose.prod.yml up --build
```

Then validate the basic behavior:

- Confirm the public site loads on `http://127.0.0.1:3000`.
- Confirm the hub health endpoint returns minimal status data on `http://127.0.0.1:3001/api/health`.
- Confirm the hub redirects unauthenticated users from `http://127.0.0.1:3001` to `/login` when Access JWT validation is disabled for local development.
- Confirm `npm run status:ports` shows `127.0.0.1` port bindings, not `0.0.0.0`.
- Run `npm run prisma:push` and `npm run seed:owner` with a private `.env` file configured.
- Confirm login works with the seeded OWNER account.

## Do Not Expose `next dev`

`next dev` is not a production server. It is optimized for local feedback, verbose errors, source maps, file watching, and development behavior.

Only the production compose path should be used for a machine that is reachable beyond local development.

## Required Environment Variables

Production compose requires a private `.env` file. Do not commit it.

Required values:

- `DATABASE_URL`
- `POSTGRES_PASSWORD`
- `NEXT_PUBLIC_HUB_URL`

Recommended values:

- `POSTGRES_DB`
- `POSTGRES_USER`
- `PUBLIC_SITE_PORT`
- `HUB_PORT`
- `BIELOS_OWNER_EMAIL`
- `BIELOS_OWNER_PASSWORD`
- `CLOUDFLARE_ACCESS_JWT_REQUIRED`
- `CLOUDFLARE_ACCESS_AUDIENCE`
- `CLOUDFLARE_TEAM_DOMAIN`

## Cookie Security

The hub session cookie is `HttpOnly` and `SameSite=Lax`.

When `NODE_ENV=production`, the cookie is also marked `Secure`. That means browser delivery requires HTTPS in production.

## Cloudflare Status

Cloudflare Tunnel and Cloudflare Access are prepared through templates and documented for the confirmed Docker deployment path. Real Cloudflare credentials and dashboard configuration stay outside the repository.

Do not add Cloudflare account IDs, tunnel IDs, tokens, or Access policies to Git. Configure those later through private environment variables and external Cloudflare configuration.

Remote exposure must use the production compose file plus the Cloudflare compose override:

```bash
docker compose --env-file .env -f infra/docker-compose.prod.yml -f infra/docker-compose.cloudflare.yml up --build
```

When `cloudflared` runs inside Docker, Cloudflare public hostname routes must use Docker service names:

- `biel.dev.br` -> `http://public-site:3000`
- `www.biel.dev.br` -> `http://public-site:3000`
- `hub.biel.dev.br` -> `http://hub:3001`

Do not use `localhost` in the Cloudflare dashboard for the Docker production path. Use `localhost` only if `cloudflared` is intentionally running directly on Windows outside Docker.

`hub.biel.dev.br` must remain protected by Cloudflare Access. Cloudflare Access is not a replacement for BielOS internal authentication, and BielOS internal authentication is not a replacement for Cloudflare Access. Both layers are required for the hub.

Exposing host port `3001` directly to the internet bypasses Cloudflare Access. If BielOS moves to a public Linux server or VPS, keep Docker ports bound to `127.0.0.1` and also block inbound internet access to `3000` and `3001` with the host firewall.

For hardened production, enable origin-side Access JWT validation in the private `.env` file:

```bash
CLOUDFLARE_ACCESS_JWT_REQUIRED=true
CLOUDFLARE_ACCESS_AUDIENCE=<Access application AUD tag>
CLOUDFLARE_TEAM_DOMAIN=https://<team-name>.cloudflareaccess.com
```

Keep `CLOUDFLARE_ACCESS_JWT_REQUIRED=false` for local development outside Cloudflare Access. Never commit real Access values.

When origin-side Access JWT validation is enabled, denied hub page requests return HTTP `403` and render the Access unavailable screen. Docker and local health checks use `GET /api/health`, which stays minimal and does not require the Cloudflare Access JWT header.

`infra/Dockerfile.prod` is shared by both Next.js apps. Its default command starts the hub only as a manual fallback; production compose overrides `command` for both `public-site` and `hub`.

## Current Production Blockers

- Cloudflare Access JWT validation must be enabled with real private environment values and tested before treating the origin as production hardened.
- No explicit CSRF tokens beyond `SameSite=Lax`.
- Login rate limiting is in-memory and not distributed.
- No backup and restore procedure validated through Docker.
- No TLS termination configured in this repository.
- Secret scanning and linting are not yet wired into CI.
