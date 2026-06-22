# Security

Security is a first-class requirement for BielOS.

## Current MVP Rules

- Do not commit real secrets.
- Do not create or commit a real `.env` file.
- Do not commit Cloudflare tokens, Gmail data, Google Takeout exports, logs, IP addresses, local private paths, database dumps, or backup archives.
- Keep public pages generic and free of private operational details.
- Use environment variables for all deployment-specific configuration.

## Authentication

The first scaffold includes only a login screen placeholder and auth package contracts. Real authentication must be implemented before the hub contains private data.

Planned layers:

- Application session management.
- Password or passphrase verification using strong hashing.
- Session token hashing at rest.
- Cloudflare Access as an outer boundary for the private hub.
- Security unlock flow for sensitive modules.

## Database

The schema stores session tokens as hashes and includes a separate security unlock model. IP addresses should not be stored directly; if needed, store a salted hash or avoid persistence.

## Public Surface

The public site can show the BielOS name, short description, public cards, generic status, and an enter button. It must not expose private modules beyond approved generic references.

## Production Exposure Blockers

Do not expose the development server or `infra/docker-compose.yml` outside local development.

Before exposing BielOS beyond a local trusted network:

- Use `infra/docker-compose.prod.yml`, not the development compose file.
- Serve through HTTPS so production session cookies marked `Secure` are sent by browsers.
- Configure an external boundary such as Cloudflare Access.
- Keep the private `.env` file outside Git.
- Validate database backup and restore procedures.
- Add persistent or edge-level rate limiting before multi-user or internet-facing use.
- Add explicit CSRF protection before broader write workflows are implemented.
