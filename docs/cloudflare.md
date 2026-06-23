# Cloudflare

Phase 03 prepares BielOS for Cloudflare Tunnel and Cloudflare Access. Phase 03.1 documents the confirmed Docker-based remote deployment path. The repository still does not contain a real tunnel token, account ID, tunnel ID, Access policy export, DNS export, or credentials file.

## Purpose

Cloudflare Tunnel will provide the remote ingress path for BielOS without opening router ports to the public internet.

Cloudflare Access will protect the private hub before requests reach the hub container. BielOS internal authentication remains active behind Access as a second layer.

Phase 05.1 adds optional origin-side JWT validation so the hub can also verify the Access token that Cloudflare injects into the `cf-access-jwt-assertion` request header.

## Hostname Model

- `biel.dev.br`: public site. This should remain public unless intentionally changed.
- `hub.biel.dev.br`: private hub. This must be protected by Cloudflare Access before exposure.

Expected Tunnel routing when `cloudflared` runs inside Docker:

- `biel.dev.br` -> `http://public-site:3000`
- `www.biel.dev.br` -> `http://public-site:3000`
- `hub.biel.dev.br` -> `http://hub:3001`
- unmatched hostnames -> `404`

Do not use `localhost` in the Cloudflare dashboard for this Docker-based production path. Inside the `cloudflared` container, `localhost` points to the `cloudflared` container itself, not the Next.js app containers.

If `cloudflared` is run directly on Windows instead of inside Docker, routes may use:

- `biel.dev.br` -> `http://localhost:3000`
- `www.biel.dev.br` -> `http://localhost:3000`
- `hub.biel.dev.br` -> `http://localhost:3001`

The preferred production path for BielOS is Docker.

## Repository Boundary

The repository may contain templates and documentation only.

Never commit:

- Cloudflare API tokens
- Tunnel tokens
- Account IDs
- Real tunnel IDs
- Tunnel credentials JSON files
- Access policies with private identifiers
- Dashboard screenshots containing secrets or private identifiers

## Files

- `infra/cloudflare/config.example.yml`: local-management Tunnel configuration template.
- `infra/docker-compose.cloudflare.yml`: compose override for a remotely managed Tunnel using `CLOUDFLARE_TUNNEL_TOKEN` from a private `.env` file.
- `docs/cloudflare-access-checklist.md`: manual dashboard checklist.

## Compose Usage

After `infra/docker-compose.prod.yml` is configured and working, start Cloudflare through the override:

```bash
docker compose --env-file .env -f infra/docker-compose.prod.yml -f infra/docker-compose.cloudflare.yml up --build
```

The `cloudflared` service exposes no local ports. It connects outbound to Cloudflare using `TUNNEL_TOKEN`, mapped from the private `CLOUDFLARE_TUNNEL_TOKEN` value in `.env`.

The tunnel token must only be stored in the private local `.env` file. Never commit it, print it into logs, or paste it into repository documentation.

## Origin JWT Validation

Cloudflare Access JWT validation is controlled by local environment variables:

```bash
CLOUDFLARE_ACCESS_JWT_REQUIRED=false
CLOUDFLARE_ACCESS_AUDIENCE=
CLOUDFLARE_TEAM_DOMAIN=
```

For production, set the values only in the private `.env` file:

- `CLOUDFLARE_ACCESS_JWT_REQUIRED=true`
- `CLOUDFLARE_ACCESS_AUDIENCE`: the Application Audience (AUD) tag from the Access application.
- `CLOUDFLARE_TEAM_DOMAIN`: the team domain, for example `https://<team-name>.cloudflareaccess.com`.

When enabled, the hub fetches public keys from `<team-domain>/cdn-cgi/access/certs` and verifies signature, issuer, audience, and expiration before the BielOS internal auth flow.

Do not commit real Access audience values, team identifiers if treated as private, Cloudflare tokens, or dashboard exports.

This validation does not replace Cloudflare Access at the edge and does not replace BielOS internal login. It is an additional origin-side check.

## Validation Checklist

1. Start production compose with the Cloudflare override.
2. Visit `biel.dev.br` and confirm the public site loads.
3. Visit `www.biel.dev.br` and confirm it loads or redirects correctly.
4. Visit `hub.biel.dev.br` and confirm Cloudflare Access appears first.
5. Authenticate through Cloudflare Access.
6. Confirm the BielOS internal login appears second.
7. Log in with the seeded OWNER user.
8. Confirm logout clears the BielOS session and returns to `/login`.
9. If `CLOUDFLARE_ACCESS_JWT_REQUIRED=true`, confirm direct local requests without the Access header are rejected by the hub.

## Current Status

The confirmed remote exposure model is:

1. Cloudflare Tunnel reaches the Docker network through the `cloudflared` compose service.
2. `biel.dev.br` and `www.biel.dev.br` route to the public site.
3. `hub.biel.dev.br` is protected by Cloudflare Access at the edge.
4. BielOS internal login remains the second authentication layer after Access.
5. Optional origin JWT validation can be enabled after the Access audience and team domain are configured privately.
