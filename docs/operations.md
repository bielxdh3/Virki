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

Provision `.env`, `.env.oidc`, and `.env.oidc-data` on the Linux host, owned by the SSH account with mode `0600`. Keep `.env.oidc` limited to `BIELOS_OIDC_SIGNING_JWKS`, `BIELOS_OIDC_COOKIE_KEY`, and the public issuer URL if configured. Keep `.env.oidc-data` limited to the 32-byte `BIELOS_OIDC_ADAPTER_KEY`. The main `.env` holds database, application, email, Cloudflare Access, and Tunnel settings for Compose interpolation. Compose does not attach that broad file to app containers: issuer signing material goes only to the issuer, the OIDC data key goes only to the Hub and issuer, and the Tunnel token goes only to the Tunnel connector. The deploy process never reads a local `.env`, transfers an environment file, or generates replacement OIDC signing keys. Set `BIELOS_PORTAL_URL` explicitly in the remote `.env` when public entry and recovery-email links should point to the USER portal. Production Compose leaves that link unset by default; `BIELOS_PORTAL_HOSTNAME` configures the portal surface independently. Missing or unsafe remote files stop the operation.

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

## Validation boundaries

CI checks the Linux control script syntax and runs mocked production-control tests. The migration and backup/restore validations use disposable Docker databases; they do not contact or alter production. These checks do not prove the configured production host identity, existing production data, live Docker state, or Cloudflare routing and Access policy. The operator must verify those host-specific conditions through the guarded preflight and post-deployment gates when the native Linux target is available.
