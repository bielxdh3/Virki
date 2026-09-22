# Operations

## Local setup

Use Node 22 and npm 10 or later. Copy `.env.example` to `.env`, use a disposable development database, and start:

```bash
npm ci
docker compose -f infra/docker-compose.yml up --build
```

Use `npm run dev` only when PostgreSQL and development environment values are already available. Do not point local commands at production.

## Production operator configuration

The production scripts read `.production.operator.json` (ignored by Git) or these environment variables:

```text
BIELOS_PRODUCTION_SSH_ALIAS
BIELOS_PRODUCTION_HOST
BIELOS_PRODUCTION_PORT
BIELOS_PRODUCTION_ROOT
```

Use the trusted SSH configuration and the already-established production root. Do not place actual operator values in tracked files, examples, logs, or command output. Production secrets remain on the remote host in its private environment files.

## Guarded deployment

1. Run `npm run preflight:prod`; require 8/8 stable SSH probes, the expected host, remote Windows PowerShell/Docker, and the production identity guard.
2. Require a clean `main` whose SHA matches `origin/main` and has green exact-SHA CI.
3. `npm run deploy:prod` transfers a Git archive, preserves private environment and backup files, builds the accepted revision, and provisions private OIDC signing configuration if none exists.
4. It creates a custom PostgreSQL backup outside the source tree, restores it into a disposable isolated PostgreSQL container, and runs the migration plan against that restored copy.
5. Only if restore and migration validation pass does it mutate production. It then verifies service image revisions, loopback bindings, database migration state, public health, the portal discovery document, and the ADMIN Access boundary.

The OIDC signing environment is generated once and retained across deployments. Key rotation is a deliberate operator change, not part of routine deployment.

## Useful commands

| Command | Purpose |
|---|---|
| `npm run preflight:prod` | SSH and remote Docker preflight |
| `npm run deploy:prod` | Backup, restore verification, migration, deployment, and checks |
| `npm run backup:prod` | Backup plus migration-plan restore verification |
| `npm run status:prod` | Container state |
| `npm run revision:prod` | Running source revision labels |
| `npm run health:prod` | Direct-origin health and security smoke |
| `npm run logs:prod` | Sanitized count of available log lines |
| `npm run audit:recent` | Sanitized count of recent audit rows |
| `npm run sessions:cleanup` | Expired-session cleanup |

Remote actions repeat SSH preflight. Do not run `prisma db push`, remove volumes, expose PostgreSQL, or change router/firewall rules. Never touch deManage.

## Backups and recovery

Backups are custom-format PostgreSQL dumps stored under the configured production root, outside the repository. The deployment gate verifies the dump by restoring it to a disposable database and applying the current migration/baseline plan. The verification marker is bound to the accepted source SHA, backup hash, plan, and a short age window.

The clone is attached only to the private BielOS Compose network, has no host-published port, and is removed after verification. Its disposable data volume is removed with the clone. The production data volume is never removed by these scripts.

Keep and protect production backups according to the operator's retention policy. A verified backup is necessary before destructive schema work; it is not a substitute for periodic restore drills.
