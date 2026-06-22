# Production

Phase 02.2 adds a production deployment foundation. It does not configure Cloudflare Tunnel, Cloudflare Access, DNS, or public domains yet.

## Development vs Production Compose

Development:

```bash
docker compose -f infra/docker-compose.yml up --build
```

The development compose file runs `npm run dev`. It is intended only for local development.

Production:

```bash
docker compose -f infra/docker-compose.prod.yml up --build
```

The production compose file builds with `infra/Dockerfile.prod` and starts the Next.js apps with production `next start` commands.

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

## Cookie Security

The hub session cookie is `HttpOnly` and `SameSite=Lax`.

When `NODE_ENV=production`, the cookie is also marked `Secure`. That means browser delivery requires HTTPS in production.

## Cloudflare Status

Cloudflare Tunnel and Cloudflare Access are still not configured in this repository.

Do not add Cloudflare account IDs, tunnel IDs, tokens, or Access policies to Git. Configure those later through private environment variables and external Cloudflare configuration.

## Current Production Blockers

- No Cloudflare Access boundary yet.
- No explicit CSRF tokens beyond `SameSite=Lax`.
- Login rate limiting is in-memory and not distributed.
- No login/logout audit log.
- No backup and restore procedure validated through Docker.
- No TLS termination configured in this repository.
