# Cloudflare Access Checklist

Use this checklist in the Cloudflare dashboard. Do not commit dashboard exports, screenshots with secrets, tokens, account IDs, tunnel IDs, or credentials files.

## Tunnel

- Create or select a Cloudflare Tunnel for BielOS.
- Use `bielos` as the tunnel name unless you intentionally choose another name.
- Store the generated tunnel token only in a private local `.env` file as `CLOUDFLARE_TUNNEL_TOKEN`.
- Do not commit the token.

## Public Hostnames

- Add `biel.dev.br` as a public hostname.
- Point `biel.dev.br` to the local service `http://public-site:3000`.
- Add `hub.biel.dev.br` as a public hostname.
- Point `hub.biel.dev.br` to the local service `http://hub:3001`.

## Access Application

- Create a self-hosted Access application for `hub.biel.dev.br`.
- Allow only the user's email or chosen identity provider group.
- Deny everyone else.
- Keep `biel.dev.br` public unless intentionally changed.
- Enable Access before exposing the hub publicly.

## Validation

- Confirm `biel.dev.br` loads without Cloudflare Access.
- Confirm `hub.biel.dev.br` shows Cloudflare Access before BielOS.
- Authenticate through Cloudflare Access.
- Confirm BielOS internal login still appears after Access.
- Log in with the seeded OWNER user.
- Confirm logout clears the BielOS session.

## Required Security Posture

Cloudflare Access is required for `hub.biel.dev.br`, but it is not a replacement for BielOS internal authentication.

BielOS internal authentication is required, but it is not a replacement for Cloudflare Access.

Both layers are required for the private hub.
