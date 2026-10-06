# Operations

## Local setup

Use Node 22 and npm 10 or later. Copy `.env.example` to `.env`, use a disposable development database, and start:

```bash
npm ci
docker compose -f infra/docker-compose.yml up --build
```

Use `npm run dev` only when PostgreSQL and development environment values are already available. Do not point local commands at production.

## Native Linux production target

The next canonical production host is native Linux over SSH. The previous host is unavailable, and the new host and existing data have not been verified. Local preparation is allowed, but production commands must wait until a native Linux host and its database identity are available. WSL is rejected by preflight and is not an accepted production target.

The operator configuration is `.production.operator.json` (ignored by Git) or these environment variables:

```text
BIELOS_PRODUCTION_SSH_ALIAS
BIELOS_PRODUCTION_HOST
BIELOS_PRODUCTION_PORT
BIELOS_PRODUCTION_ROOT
```

Use a trusted SSH alias with a pinned host key. The alias must resolve to the configured host and port. SSH requires `BatchMode=yes` and `StrictHostKeyChecking=yes`; an unknown or changed host key fails closed. `BIELOS_PRODUCTION_ROOT` must be an absolute POSIX path without spaces or shell metacharacters.

Before the first script contact, an operator must provision the host root and the following paths, owned by the SSH account with mode `0700`:

```text
.deploy-tmp/
releases/
backups/
```

The operator must also create `.bielos-production-host`, owned by the SSH account with mode `0600`, with exactly these four newline-terminated entries and no other lines:

```text
role=production
protocol=2
hostname=<output of hostname -s>
path=<absolute configured production root>
```

The host marker is a pre-provisioned identity check. Preflight and deployment only read it; neither creates nor repairs it. Preflight checks the host marker, native Linux kernel, eight stable SSH probes, Docker Engine and Compose, disk availability, and the presence and permissions of the private environment files. It counts deManage container names for visibility only; BielOS operations do not inspect or change their data, containers, networks, volumes, or services.

Provision `.env`, `.env.oidc`, and `.env.oidc-data` on the Linux host, owned by the SSH account with mode `0600`. Keep `.env.oidc` limited to `BIELOS_OIDC_SIGNING_JWKS`, `BIELOS_OIDC_COOKIE_KEY`, and the public issuer URL if configured. Keep `.env.oidc-data` limited to the required 32-byte `BIELOS_OIDC_ADAPTER_KEY` and, only during the bounded rotation overlap, the optional 32-byte `BIELOS_OIDC_ADAPTER_KEY_PREVIOUS`. The main `.env` holds database, application, email, Cloudflare Access, and Tunnel settings for Compose interpolation. Compose does not attach that broad file to app containers: issuer signing material goes only to the issuer, OIDC data-encryption keys go only to the Hub and issuer, and the Tunnel token goes only to the Tunnel connector. The deploy process never reads a local `.env`, transfers an environment file, or generates replacement OIDC signing keys. Set `BIELOS_PORTAL_URL` explicitly in the remote `.env` when public entry and recovery-email links should point to the USER portal. Production Compose leaves that link unset by default; `BIELOS_PORTAL_HOSTNAME` configures the portal surface independently. Missing or unsafe remote files stop the operation.

## Exact-source gate

Every remote operation requires a clean local checkout of `main` whose `origin` URL exactly matches the canonical HTTPS remote `https://github.com/bielxdh3/BielOS.git` and whose full commit SHA matches `origin/main`. The CI query is pinned to `bielxdh3/BielOS` and must find a successful latest `push` run of the `CI` workflow for the same SHA and branch. Pull-request runs, another commit's green run, an in-progress run, a failed run, or a missing result do not pass the gate. No production SSH or SCP begins until the source and CI gates pass.

The deploy command creates a `git archive` from that exact commit with Git replacement objects disabled, checks the Git tree for symlinks, release markers, and reserved secret and backup paths, computes its SHA-256, and transfers that archive to `.deploy-tmp`. It uses the same successful CI run ID to download the tested runtime and migrator images for the host's native `linux/amd64` or `linux/arm64` platform, checks the compressed artifact's SHA-256 locally and remotely, verifies the loaded image revision labels, and removes the transferred image archive. Production Compose uses those revision-tagged images with pulling disabled, so the production host does not rebuild application images. It never transfers local ignored or untracked files. The remote host rejects links and unsupported source archive entry types before extraction, then checks reserved paths before writing a release marker. It retains immutable releases under `releases/<sha>` and keeps `current` on the active release until the final backup and migration validation pass. It atomically points `current` to the accepted release before starting its services. Remote environment files remain outside the archive and are linked into each release. Older release directories are retained for operator recovery; the deployment does not recursively clear the production root.

## Useful commands

| Command | Purpose |
|---|---|
| `npm run preflight:prod` | Verify the native Linux target, stable SSH identity, pre-provisioned marker, remote private files, Docker and Compose. |
| `npm run deploy:prod` | Stage the accepted source, verify backup and migration on a restore, migrate under maintenance, then health-check the release. |
| `npm run backup:prod` | Create a custom-format PostgreSQL backup outside releases and test the current committed migrations against its restored copy. |
| `npm run backup:inventory -- --directory <absolute-path>` | Read-only fixture or approved-directory inventory: list retained files, report the current verification marker, and alert below 15% free space. It cannot delete files; use disposable fixtures for validation. |
| `npm run start:prod` | Start the accepted release when migration status is current. |
| `npm run stop:prod` | Stop BielOS services without removing persistent volumes. |
| `npm run restart:prod` | Recreate services from the accepted preloaded images after migration status passes. |
| `npm run status:prod` | Show container status. |
| `npm run revision:prod` | Verify application image revision labels. |
| `npm run status:ports` | Verify application ports bind only to loopback. |
| `npm run health:prod` | Check public and hub health, portal OIDC discovery, and denial of Hub access without Cloudflare Access. |
| `npm run logs:prod` | Return only sanitized log-line availability; log contents are withheld. |
| `node scripts/production-remote.mjs start-tunnel` | Start the Cloudflare Tunnel connector after the routed applications are healthy. |
| `node scripts/production-remote.mjs maintenance-on` | Stop public, Hub, OIDC, worker, and Tunnel services while leaving PostgreSQL and its persistent volume available. |
| `node scripts/production-remote.mjs maintenance-off` | Resume services only if the accepted source and migration status are current. |
| `npm run audit:recent` | Return a sanitized count of recent audit rows. |
| `npm run audit:cleanup` | Run audit retention cleanup. |
| `npm run sessions:cleanup` | Remove expired sessions. |

The remote operator wrapper requires the same exact-source and exact-SHA CI checks for read and write commands. State-changing commands take an exclusive `flock` on a mode-`0600` lock under the pre-provisioned production root, so deploy, source installation, activation, maintenance, backups, and service operations run one at a time. A deploy transfers its archive first, then stages that source and completes backup validation, migration, activation, and health checks under one remote lock. Preflight confirms `flock` is available. Starting an accepted source whose release is not already active fails before it stops the Tunnel or application services. Maintenance commands stop or resume the Cloudflare Tunnel connector with the app; they do not alter Cloudflare DNS, Tunnel routes, or Access policies.

## Deployment, migrations, and recovery

The deploy sequence loads the runtime and migrator images built and smoke-tested by exact-SHA CI, validates their revision labels, then enters maintenance and stops application writers and the Tunnel connector while PostgreSQL remains running. It creates a production backup under the pre-provisioned `backups/` directory and restores that same snapshot into a disposable PostgreSQL container on a dedicated transient internal Docker network. The clone accepts only a clean `0_init` history with applied names present in the release, or the exact legacy history of fourteen named migrations plus `20260922090000_total_identity_security_rebaseline`. For that exact legacy state, it resolves `0_init` as applied, then atomically removes the fifteen old rows only after verifying the exact sixteen-row set, complete status, and absence of rolled-back or unfinished rows. Every unknown, duplicate, failed, incomplete, or divergent history fails closed. The clone then receives committed migrations with `prisma migrate deploy`, is checked with `prisma migrate status`, and must match the committed Prisma datamodel. Only the restore container and migration runner join the network; it is isolated from the live production Compose network and has no published port or outbound route. The clone uses a randomly generated ephemeral password. It also confirms that ADMIN/USER counts and the encrypted `ACCOUNT_RECOVERY` outbox payload, status, retry count, and delivery-attempt metadata survive migration unchanged. The tagged clone containers and network must be confirmed absent after validation; uncertain or incomplete cleanup leaves the system in maintenance. A missing ADMIN, failed restore, failed migration, schema/data invariant change, or non-current status stops before production migration.

After the restore and migration checks pass, deployment applies the same committed Prisma migration files to production using `prisma migrate deploy`, checks identity and recovery-outbox invariants again, and starts the accepted application release. The Tunnel connector starts only after image revisions, loopback bindings, public and Hub health, portal OIDC discovery, and unauthenticated Hub denial have passed. Any startup or post-maintenance failure stops the routed application services and Tunnel connector while leaving PostgreSQL and its persistent volume running.

After the verified restore passes migration-history, schema, identity, recovery-outbox, status, and cleanup checks, the live step may repeat the exact transition-to-baseline reconciliation while maintenance is active and the verified backup is still protected. Routine deploys do not rewrite migration history. If a failure occurs after maintenance begins, the script leaves routed services stopped. Do not bypass the migration-status gate or remove the maintenance marker manually. Inspect the preserved backup and migration result, then resume only after the committed migration status and data invariants are verified. The scripts never call `prisma db push`, delete persistent volumes, or alter Cloudflare configuration.

Cloudflare Tunnel routes must send `biel.dev.br` to the public site and `portal.biel.dev.br` and `hub.biel.dev.br` to the Hub application's host router. Cloudflare Access protects only the ADMIN hostname. The example Tunnel configuration documents the desired routes; it does not prove public DNS, Tunnel, or Access state. Verify the public portal route and protected Hub boundary manually after a future deployment. Never impose the Hub Access policy on the USER portal.

## Identity recovery and rate-limit tradeoffs

An active ADMIN can recover the separate administrative credential from the Hub security page using the ADMIN's current BielOS account password and one unused administrative recovery code. A successful recovery rotates the set of ten codes and revokes pending and active security elevations. It does not reset the normal BielOS password, reactivate a disabled account, or authorize one ADMIN to approve their own account recovery. Cross-account recovery requires a different active ADMIN.

The remembered-browser grant lasts at most seven days after strong verification. It can avoid another email/TOTP login ceremony on that recognized browser, but it does not issue a Cloudflare Access assertion, create an ADMIN session by itself, or satisfy action-scoped security elevation. Hub page and mutation guards continue to require valid Cloudflare Access and an active BielOS ADMIN session; protected changes still require the elevation their policy specifies. A trusted device can be revoked, and account recovery/deactivation revokes its remembered grants.

Login and recovery counters are persisted as keyed hashes. The default login limiter uses five attempts per role-scoped identifier and fifteen-minute window, an account bucket of twenty attempts, and a trusted-source bucket of thirty; successful authentication refunds the source reservation. Recovery also has source and address counters and a one-minute per-account request cooldown. These limits reduce guessing and mail abuse, but a source-address cap can affect unrelated people behind the same NAT or corporate proxy. Operators should first verify that trusted proxy forwarding is configured correctly; do not raise limits or accept untrusted forwarded addresses as a workaround.

Recovery responses remain generic, but the request path is not guaranteed to have constant response time: an eligible account performs serialized account-state checks, creates a recovery record, queues mail, and writes audit data, while an unknown or ineligible account exits earlier. There is no artificial sleep to equalize those paths. Treat timing as a residual account-enumeration risk; do not claim that generic copy alone eliminates it. Keep public confirmation text generic, monitor aggregate abuse without logging submitted emails or codes, and evaluate any future timing mitigation against abuse and availability behavior.

If there is only one ADMIN, use the in-product administrative-credential recovery only when that ADMIN can still authenticate with the normal account password and has an unused recovery code. If the sole ADMIN cannot access the account, email, password, or recovery codes, the current application has no operator break-glass endpoint. Stop privileged operations and follow [the sole-ADMIN break-glass procedure](admin-account-break-glass.md); never promote an account, replace a password hash, bypass Access, or edit live identity rows by ad hoc SQL.

## Email delivery guarantees

The outbox claims work with a five-minute processing lease, records interrupted and failed attempts, fences stale workers during finalization, and applies retry backoff after the transport attempt completes. It stops retrying after five attempts. There is no lease heartbeat, and the SMTP socket timeout is an inactivity timeout rather than a total-send deadline. A continuously progressing SMTP send that exceeds the five-minute lease can therefore overlap with a later worker reclaiming the message. SMTP is at-least-once: a provider can accept a message immediately before a connection/process failure prevents BielOS from recording success, so a later retry can duplicate that email; overlapping workers can also send concurrently in the lease-expiry case. Neither transporter shutdown nor an application wait timeout can prove that the remote provider did not accept a message. Do not describe this path as exactly-once delivery or claim the lease prevents all concurrent duplicate sends. Failed transport details are reduced to a fixed error code; secrets and message bodies stay out of logs.

## Dependency-integrity gate

As of 2026-10-06, the PR lockfile resolves `prisma@6.19.3` to `@prisma/config@6.19.3`, whose package metadata requires exactly `deepmerge-ts@7.1.5`. The root override forces `8.0.2` to avoid GHSA-ggr8-5vv4-36mx, whose patched range begins at 8.0.0, but this violates the declared exact dependency and `npm ls @prisma/config deepmerge-ts --all` fails with `ELSPROBLEMS`. `npm audit` reporting zero advisories does not establish dependency-tree integrity or API compatibility. Registry metadata on this date lists `6.19.3` as the last stable Prisma 6 release; moving to Prisma 7 is a major upgrade and has not been validated here. Do not remove the override to restore vulnerable 7.x or claim the override is supported. Keep publication blocked until an upstream-compatible Prisma/config release or a separately reviewed and fully validated migration resolves both constraints. The affected package is Prisma tooling; the production dependency audit is a separate result and does not clear this tooling gate.

The dependency selections elsewhere in the PR are not all security claims: `prisma` and `@prisma/client` are both pinned to `6.19.3`; `typescript@5.9.3` is inside the installed `typescript-eslint@8.71.0` peer range (`>=4.8.4 <6.1.0`), whereas the mainline `7.0.2` is outside it; Next `16.3.8` declares support for React/React DOM `^19`, and the lockfile keeps both at `19.2.7`. One unresolved alignment remains: `oidc-provider@9.12.2` is paired with `@types/oidc-provider@8.8.1`, although `@types/oidc-provider@9.12.1` is published. Compilation alone does not prove that the older declarations accurately model the v9 runtime; this PR does not record a reason for the downgrade, so do not present that pair as independently validated compatibility.

## CodeQL evidence retention

The CodeQL workflow analyzes the exact Git revision without trying to upload alerts to GitHub Code Scanning, then stores the SARIF output as a GitHub Actions artifact for fourteen days. This preserves inspectable analysis output while repository Code Scanning upload is unavailable; it does not populate GitHub code-scanning alerts. The exact-SHA CodeQL workflow result remains part of the release gate. An artifact that has expired must be regenerated from the same accepted revision; it must not be replaced by results from a different SHA.

## Validation boundaries

CI checks the Linux control script syntax and runs mocked production-control tests. The migration and backup/restore validations use disposable Docker databases; they do not contact or alter production. These checks do not prove the configured production host identity, existing production data, live Docker state, or Cloudflare routing and Access policy. The operator must verify those host-specific conditions through the guarded preflight and post-deployment gates when the native Linux target is available.
