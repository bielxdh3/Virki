# Architecture

## Responsibility

BielOS owns identity, authentication and SSO, security, project entry decisions, and audit. Projects are external relying applications and own their internal sessions and permissions.

## Request surfaces

| Host | Surface | Access |
|---|---|---|
| `biel.dev.br` | Minimal public page with portal entry | Public |
| `portal.biel.dev.br` | USER portal and OIDC endpoints | Public OIDC metadata and protocol endpoints; account pages require a BielOS session |
| `hub.biel.dev.br` | ADMIN control plane | Cloudflare Access JWT plus active BielOS ADMIN session |

The portal displays only enabled external connections with an active grant for the current USER. The admin routes are `/admin/accounts`, `/admin/access`, `/admin/security`, `/admin/audit`, and `/admin/connections`. `/admin` redirects to the account list.

## Runtime components

- `apps/public-site` serves the minimal public page.
- `apps/hub` serves the USER portal, authentication and account-security pages, and ADMIN control plane. Host routing selects the surface; unknown hosts are rejected.
- `apps/issuer` runs `oidc-provider` on the private Compose network. The portal host rewrites standard OIDC paths from the hub to the issuer. The issuer has no host-published port.
- `packages/auth` owns password/session, MFA, recovery, authorization policy, audit, and protected secret helpers.
- `packages/database` owns the Prisma schema and committed migrations.
- `session-cleanup` and `email-worker` are private production workers.

## Authorization model

Stored roles are ADMIN and USER. Anonymous traffic is untrusted. A project connection stores its name, canonical HTTPS origin, OIDC client identity, encrypted secret, exact redirect URI allowlist, enabled state, and timestamps. `UserProjectGrant` records explicit entry grants. The issuer rechecks the account, connection, and grant before completing authorization.

No project experience, internal project roles, or project permissions are represented in BielOS.

## Persistence

The data model retains user credentials, MFA and recovery records, sessions, trusted-device records, account-recovery records, administrative credentials/elevations, sanitized audit entries, external OIDC connections, explicit grants, and encrypted OIDC transient artifacts. OIDC database identifiers are hashed; protocol payloads and client secrets are encrypted.

Production database changes use committed Prisma migrations. A clean `0_init` baseline initializes a new database. The one-time production rebaseline accepts only the exact documented fifteen-row legacy transition history, and only after a verified restore passes migration-history, identity, recovery-outbox, migration-status, and resulting-schema checks. Any other history fails closed; routine deploys do not rewrite migration history.
