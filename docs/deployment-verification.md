# First Production Launch Checklist

Use this checklist for the first production launch and later smoke tests. Do not paste `.env` contents, Cloudflare tokens, JWTs, cookies, database URLs with passwords, private keys, or raw logs into issues or docs.

## Before Start

- Confirm the private `.env` file exists locally in the repository root.
- Confirm the private `.env` defines these names without printing their values:
  - `DATABASE_URL`
  - `POSTGRES_PASSWORD`
  - `NEXT_PUBLIC_HUB_URL`
  - `CLOUDFLARE_TUNNEL_TOKEN`
  - `CLOUDFLARE_ACCESS_JWT_REQUIRED`
  - `BIELOS_OWNER_EMAIL`
  - `BIELOS_OWNER_PASSWORD`
- Confirm no real `.env`, tunnel token, credentials JSON, Cloudflare account ID, Cloudflare secret, database dump, or backup archive is committed.

## Start And Local Smoke Test

Start the production stack with the Cloudflare override:

```bash
npm run start:prod
```

Inspect status and local health:

```bash
npm run status:prod
npm run status:ports
npm run health:local
```

- Confirm `npm run status:ports` shows loopback bindings only:
  - `127.0.0.1:3000->3000`
  - `127.0.0.1:3001->3001`
- Confirm `postgres`, `public-site`, `hub`, `cloudflared`, and `session-cleanup` are running.
- Confirm `session-cleanup` has no published ports.
- Confirm `cloudflared` has no published ports.
- Confirm `npm run health:local` checks:
  - `http://127.0.0.1:3000`
  - `http://127.0.0.1:3001/api/health`
- Confirm `http://127.0.0.1:3001/login` reaches the hub login only when `CLOUDFLARE_ACCESS_JWT_REQUIRED=false` for local development.
- If `CLOUDFLARE_ACCESS_JWT_REQUIRED=true`, direct local hub page requests without a valid Access assertion should return HTTP `403`; `GET /api/health` should still return minimal health data.

## Cloudflare Smoke Test

- Confirm `https://biel.dev.br` loads the public site.
- Confirm `https://www.biel.dev.br` loads or redirects correctly.
- Confirm `https://hub.biel.dev.br` shows Cloudflare Access before BielOS.
- Confirm Cloudflare Access only allows the owner's email or approved identity group.
- Confirm BielOS internal login appears after Cloudflare Access.
- Confirm BielOS internal login works with the seeded OWNER user.
- Confirm logout clears the BielOS session and returns to `/login`.

## Cloudflare Routing

When `cloudflared` runs inside Docker, public hostname routes must use Docker service names:

- `biel.dev.br` -> `http://public-site:3000`
- `www.biel.dev.br` -> `http://public-site:3000`
- `hub.biel.dev.br` -> `http://hub:3001`

Do not use `localhost` for the Docker production path.

If `cloudflared` runs directly on Windows outside Docker, local routes may use:

- `biel.dev.br` -> `http://localhost:3000`
- `www.biel.dev.br` -> `http://localhost:3000`
- `hub.biel.dev.br` -> `http://localhost:3001`

The preferred BielOS production path is Docker.

## Safe Diagnostics

- Use `npm run logs:prod` only for local inspection. Summarize service status or non-sensitive errors; do not copy secrets, tokens, cookies, JWTs, raw headers, raw IPs, or database URLs.
- If `biel.dev.br` returns `502`, confirm `cloudflared` is running and the Cloudflare public hostname routes use Docker service names.
- If `hub.biel.dev.br` skips Cloudflare Access, stop and fix the Cloudflare Access application policy before using the hub remotely.
- If local health fails, confirm `hub` healthcheck uses `/api/health`, not `/login`.
- If login fails after a database reset, apply migrations and seed the OWNER user from private local values.

## Rollback

Stop the production stack safely:

```bash
npm run stop:prod
```

Cloudflare Tunnel does not depend on host-published ports. In Docker mode, it reaches `http://public-site:3000` and `http://hub:3001` on the Docker network. Remote hub exposure must remain behind Cloudflare Access, and direct internet access to port `3001` must stay blocked.

## Remaining Limitations

- Origin-side Cloudflare Access JWT validation is optional and depends on private environment configuration.
- Login rate limiting is local/in-memory and not distributed.
- CSRF protection currently covers the login and logout write flows.
- Backup and restore procedures still need production validation.
- Host firewall rules for public Linux/VPS deployment still need environment-specific validation.
