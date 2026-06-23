# Deployment Verification

Use this checklist after starting the production stack with the Cloudflare compose override.

Start the stack with:

```bash
npm run start:prod
```

Inspect it with:

```bash
npm run status:prod
npm run logs:prod
npm run health:local
```

## Stack

- Confirm the production Docker Compose stack is running.
- Confirm the `cloudflared` container is connected.
- Confirm `postgres`, `public-site`, and `hub` are healthy.
- Confirm no real `.env`, tunnel token, credentials JSON, Cloudflare account ID, or Cloudflare secret is committed.

## Remote Routes

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

## Local Behavior

- `http://localhost:3000` reaches the public site on the host machine.
- `http://localhost:3001` reaches the hub login on the host machine.
- Local host access is useful for validation, but remote hub exposure must remain behind Cloudflare Access.

## Remaining Limitations

- The app does not yet validate Cloudflare Access JWTs at the origin.
- Login rate limiting is local/in-memory and not distributed.
- CSRF protection currently relies on cookie posture and limited write flows.
- Backup and restore procedures still need production validation.
