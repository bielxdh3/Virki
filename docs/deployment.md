# Deployment and migration

## Network layout

Cloudflare Tunnel routes `biel.dev.br` to the public site and both `portal.biel.dev.br` and `hub.biel.dev.br` to the hub application. Host routing and internal rewrites keep the OIDC issuer private. The issuer and PostgreSQL have no host-published ports. The public site and hub bind to loopback on the host.

Cloudflare Access must protect the ADMIN hostname. The USER portal must remain reachable without an ADMIN-only Access policy. The example Tunnel configuration documents the route; it does not prove the live Cloudflare state. Verify DNS, Tunnel routing, and Access policies after deployment. Never weaken the ADMIN boundary to make the portal route work.

## Exact-source deployment

Production is remote-only. The guarded script requires the clean `main` SHA to equal `origin/main`, runs SSH preflight before each remote mutation, installs only a Git archive, and verifies every running application image against that exact revision. CI must be green for the deployed SHA.

Before changing data, deployment creates a production backup, restores it in a disposable PostgreSQL container, and runs the planned migration/reconciliation against that restored database. The clone has no host-published port and its temporary volume is removed after the check. If backup, restore, host, source, data precondition, or migration-plan verification fails, production migration stops.

## Production schema convergence

The first rebaseline migration maps the single unambiguous historical administrative identity to ADMIN and ordinary accounts to USER. It blocks when the historical privilege state is ambiguous. It preserves credentials, TOTP, recovery records, account-security metadata, and compatible auth/security audit data. It revokes sessions, remembered-device trust, pending challenges, and temporary elevations. The verified backup is retained outside the repository.

After that migration is deployed and verified, the repository is reduced to a clean `0_init` baseline generated from the final Prisma schema. On a fresh database the baseline creates the schema normally. On the existing production database, the guarded baseline procedure verifies the restored schema, marks `0_init` applied using Prisma, removes only the known completed historical migration records in a transaction, and requires `prisma migrate status` to report the baseline current. This reconciliation is tested on the restored copy before production bookkeeping changes.

Do not delete applied migration history without the restore-and-status procedure. Do not use `prisma db push`, manually drop application tables outside the committed migration, remove production volumes, or modify deManage.

## Post-deployment checks

Verify:

- the expected exact revision on public site, hub, issuer, and private workers;
- public page and hub health;
- direct-origin portal OIDC discovery, issuer value, Authorization Code, and PKCE S256 support;
- ADMIN route denial without a Cloudflare Access JWT;
- loopback-only public-site and hub host ports;
- final Prisma migration status and expected account role counts;
- the deManage container count is unchanged and no deManage resource was touched;
- the external portal hostname reaches OIDC discovery through Cloudflare;
- the live ADMIN hostname remains behind Cloudflare Access.

The final two external checks require the production operator's Cloudflare/DNS state. Report them as manual gates unless observed successfully.
