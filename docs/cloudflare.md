# Cloudflare

Phase 03 prepares BielOS for Cloudflare Tunnel and Cloudflare Access. It does not configure a real tunnel, Access policy, DNS record, token, account ID, tunnel ID, or credentials file.

## Purpose

Cloudflare Tunnel will provide the remote ingress path for BielOS without opening router ports to the public internet.

Cloudflare Access will protect the private hub before requests reach the hub container. BielOS internal authentication remains active behind Access as a second layer.

## Hostname Model

- `biel.dev.br`: public site. This should remain public unless intentionally changed.
- `hub.biel.dev.br`: private hub. This must be protected by Cloudflare Access before exposure.

Expected Tunnel routing:

- `biel.dev.br` -> `http://public-site:3000`
- `hub.biel.dev.br` -> `http://hub:3001`
- unmatched hostnames -> `404`

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
docker compose -f infra/docker-compose.prod.yml -f infra/docker-compose.cloudflare.yml up --build
```

The `cloudflared` service exposes no local ports. It connects outbound to Cloudflare using `TUNNEL_TOKEN`, mapped from the private `CLOUDFLARE_TUNNEL_TOKEN` value in `.env`.

## Validation Checklist

1. Start production compose with the Cloudflare override.
2. Visit `biel.dev.br` and confirm the public site loads.
3. Visit `hub.biel.dev.br` and confirm Cloudflare Access appears first.
4. Authenticate through Cloudflare Access.
5. Confirm the BielOS internal login appears second.
6. Log in with the seeded OWNER user.
7. Confirm logout clears the BielOS session and returns to `/login`.

## Current Status

Remote exposure remains blocked until Cloudflare Tunnel and Cloudflare Access are manually configured and tested.
