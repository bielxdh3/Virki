# Operations

## Local setup

Use Node 22 and npm 10 or later. Copy `.env.example` to `.env`, use a disposable development database, and start:

```bash
npm ci
docker compose -f infra/docker-compose.yml up --build
```

Use `npm run dev` only when PostgreSQL and development environment values are already available. Do not point local commands at production.

## Native Linux production target

Production runs on the configured native Linux host over SSH. Windows and WSL are not production targets. Keep host, root, and Cloudflare-specific settings in the ignored operator configuration; before each production operation, verify the exact accepted source, host marker, protected environment metadata, Docker state, resource isolation, and the operation's own state guards. A fresh-install operation is only for an empty Virki target and its separate database resources; it does not imply that another active installation may be stopped or replaced.

The operator configuration is `.production.operator.json` (ignored by Git) or these environment variables:

```text
VIRKI_PRODUCTION_SSH_ALIAS
VIRKI_PRODUCTION_HOST
VIRKI_PRODUCTION_PORT
VIRKI_PRODUCTION_ROOT
```

Use a trusted SSH alias with a pinned host key. The alias must resolve to the configured host and port. SSH requires `BatchMode=yes` and `StrictHostKeyChecking=yes`; an unknown or changed host key fails closed. `VIRKI_PRODUCTION_ROOT` must be an absolute POSIX path without spaces or shell metacharacters.

Before the first script contact, an operator must provision the host root and the following paths, owned by the SSH account with mode `0700`:

```text
.deploy-tmp/
releases/
backups/
```

The operator must also create `.virki-production-host`, owned by the SSH account with mode `0600`, with exactly these four newline-terminated entries and no other lines:

```text
role=production
protocol=2
hostname=<output of hostname -s>
path=<absolute configured production root>
```

The host marker is a pre-provisioned identity check. Preflight and deployment only read it; neither creates nor repairs it. Preflight checks the host marker, native Linux kernel, eight stable SSH probes, Docker Engine and Compose, disk availability, and the presence and permissions of the private environment files. It counts deManage container names for visibility only; Virki operations do not inspect or change their data, containers, networks, volumes, or services.

Provision `.env`, `.env.oidc`, and `.env.oidc-data` on the Linux host, owned by the SSH account with mode `0600`. Keep `.env.oidc` limited to `VIRKI_OIDC_SIGNING_JWKS`, `VIRKI_OIDC_COOKIE_KEY`, and the public issuer URL if configured. Keep `.env.oidc-data` limited to the required 32-byte `VIRKI_OIDC_ADAPTER_KEY` and, only during the bounded rotation overlap, the optional 32-byte `VIRKI_OIDC_ADAPTER_KEY_PREVIOUS`. The main `.env` holds database, application, email, Cloudflare Access, and Tunnel settings for Compose interpolation. Compose does not attach that broad file to app containers: issuer signing material goes only to the issuer, OIDC data-encryption keys go only to the Hub and issuer, and the Tunnel token goes only to the Tunnel connector. The deploy process never reads a local `.env`, transfers an environment file, or generates replacement OIDC signing keys. Set `VIRKI_PORTAL_URL` explicitly in the remote `.env` when public entry and recovery-email links should point to the USER portal. Production Compose leaves that link unset by default; `VIRKI_PORTAL_HOSTNAME` configures the portal surface independently. Missing or unsafe remote files stop the operation.

## Exact-source gate

Deployment, `production-remote.mjs`, and standalone `npm run preflight:prod` require a clean local `main` checkout whose `origin` URL exactly matches the canonical HTTPS remote `https://github.com/bielxdh3/Virki.git` and whose full commit SHA matches `origin/main`. Their static-analysis gate is `OWNER_APPROVED_EXACT_SHA_CODEQL_SARIF_GATE`: successful completed PUSH runs of `CI` and `CodeQL` for the exact SHA and branch, plus retrieval and re-evaluation of SARIF from the immutable private GHCR evidence digest logged by that exact CodeQL run with the current reviewed policy. The policy must pass without an unreviewed violation, and the private GHCR image and exact-run digest log must remain available. Pull-request runs, another commit's green run, pending/failed/missing results, unavailable/tampered GHCR evidence, or policy violations fail closed. If evidence is unavailable, rerun the workflows for that same accepted SHA; do not substitute another SHA. GitHub Code Scanning publication is not enabled under current private-repository capability and is not required by the owner's approved policy. No claim is made that GitHub Code Scanning alerts are populated. See [deployment gates](deployment.md#source-and-ci-gate).

The deploy command creates a `git archive` from that exact commit with Git replacement objects disabled, checks the Git tree for symlinks, release markers, and reserved secret and backup paths, computes its SHA-256, and transfers that archive to `.deploy-tmp`. It retrieves a small per-platform GHCR provenance manifest by the immutable digest recorded in that exact successful CI run log, verifies SHA/run/platform/digest and its hash on both ends, then authenticates with the production-only `read:packages` credential, pulls private images by digest, and checks source/revision labels and platform before retagging the local Compose names. A short-lived private Docker credential directory is removed immediately. Compose remains `pull_policy: never`, and production does not build application images. It never transfers local ignored or untracked files. The remote host rejects links and unsupported source archive entry types before extraction, then checks reserved paths before writing a release marker. It retains immutable releases under `releases/<sha>` and keeps `current` on the active release until the final backup and migration validation pass. It atomically points `current` to the accepted release before starting its services. Remote environment files remain outside the archive and are linked into each release. Older release directories are retained for operator recovery; the deployment does not recursively clear the production root.

## Useful commands

| Command | Purpose |
|---|---|
| `npm run preflight:prod` | Verify the native Linux target, stable SSH identity, pre-provisioned marker, remote private-file metadata, Docker/Compose, disk, `flock`, and report the deManage container-name count. |
| `npm run first-install:prod` | Initialize only a verified empty Virki project and its new PostgreSQL volume from accepted exact-SHA CI images. |
| `npm run first-install:recover:prod` | Recover only the exact retained partial first install after database, container, network, volume, source, backup, restore, and checkpoint checks pass. |
| `npm run stage:prod` | Start the accepted Virki application on private loopback staging ports `13000` and `13001`, with the Tunnel connector stopped. |
| `npm run first-admin:prod` | Prompt over a protected SSH TTY to create the first ADMIN in the verified virgin Virki database. |
| `npm run deploy:prod` | Stage the accepted source, verify backup and migration on a restore, migrate under maintenance, then health-check the release. |
| `npm run backup:prod` | Create a custom-format PostgreSQL backup outside releases and test the current committed migrations against its restored copy. |
| `npm run backup:inventory -- --directory <absolute-path>` | Read-only fixture or approved-directory inventory: list retained files, report the current verification marker, and alert below 15% free space. It cannot delete files; use disposable fixtures for validation. |
| `npm run start:prod` | Start the accepted release when migration status is current. |
| `npm run stop:prod` | Stop Virki services without removing persistent volumes. |
| `npm run restart:prod` | Recreate services from the accepted preloaded images after migration status passes. |
| `npm run status:prod` | Show container status. |
| `npm run revision:prod` | Verify application image revision labels. |
| `npm run status:ports` | Verify application ports bind only to loopback. |
| `npm run health:prod` | Check public and hub health, portal OIDC discovery, and denial of Hub access without Cloudflare Access. |
| `npm run logs:prod` | Return only sanitized log-line availability; log contents are withheld. |
| `node scripts/production-remote.mjs start-tunnel` | Start the Cloudflare Tunnel connector after the routed applications are healthy. |
| `node scripts/production-remote.mjs maintenance-on` | Stop public, Hub, OIDC, worker, and Tunnel services while leaving PostgreSQL and its persistent volume available. |
| `node scripts/production-remote.mjs maintenance-off` | Resume only with the current verified backup and schema, plus a VERIFIED migration integrity checkpoint if live migrations began. |
| `npm run audit:recent` | Return a sanitized count of recent audit rows. |
| `npm run audit:cleanup` | Run audit retention cleanup. |
| `npm run sessions:cleanup` | Remove expired sessions. |

The remote operator wrapper enforces exact-source and the full exact-SHA CI/CodeQL/SARIF-artifact gate for its read and write commands. Standalone preflight applies that same gate before contacting SSH. State-changing commands take an exclusive `flock` on a mode-`0600` lock under the pre-provisioned production root, so deploy, source installation, activation, maintenance, backups, and service operations run one at a time. A deploy transfers its archive first, then stages that source and completes backup validation, migration, activation, and health checks under one remote lock. Preflight confirms `flock` is available. Starting an accepted source whose release is not already active fails before it stops the Tunnel or application services. Maintenance commands stop or resume the Cloudflare Tunnel connector with the app; they do not alter Cloudflare DNS, Tunnel routes, or Access policies.

## Deployment, migrations, and recovery

The deploy sequence pulls the runtime and migrator images by verified private GHCR digests after exact-SHA CI smoke tests, validates their revision labels, then enters maintenance and stops application writers and the Tunnel connector while PostgreSQL remains running. It creates a production backup under the pre-provisioned `backups/` directory and restores that same snapshot into a disposable PostgreSQL container on a dedicated transient internal Docker network. The clone accepts only a clean `0_init` history with applied names present in the release, or the exact legacy history of fourteen named migrations plus `20260922090000_total_identity_security_rebaseline`. For that exact legacy state, it resolves `0_init` as applied, then atomically removes the fifteen old rows only after verifying the exact sixteen-row set, complete status, and absence of rolled-back or unfinished rows. Every unknown, duplicate, failed, incomplete, or divergent history fails closed. The clone then receives committed migrations with `prisma migrate deploy`, is checked with `prisma migrate status`, and must match the committed Prisma datamodel. Only the restore container and migration runner join the network; it is isolated from the live production Compose network and has no published port or outbound route. The clone uses a randomly generated ephemeral password. It also confirms that ADMIN/USER counts and the encrypted `ACCOUNT_RECOVERY` outbox payload, status, retry count, and delivery-attempt metadata survive migration unchanged. The tagged clone containers and network must be confirmed absent after validation; uncertain or incomplete cleanup leaves the system in maintenance. A missing ADMIN, failed restore, failed migration, schema/data invariant change, or non-current status stops before production migration.

After the restore and migration checks pass, deployment applies the same committed Prisma migration files to production using `prisma migrate deploy`, checks identity and recovery-outbox invariants again, and starts the accepted application release. The Tunnel connector starts only after image revisions, loopback bindings, public and Hub health, portal OIDC discovery, and unauthenticated Hub denial have passed. Any startup or post-maintenance failure stops the routed application services and Tunnel connector while leaving PostgreSQL and its persistent volume running.

After the verified restore passes migration-history, schema, identity, recovery-outbox, status, and cleanup checks, the live step may repeat the exact transition-to-baseline reconciliation while maintenance is active and the verified backup is still protected. Routine deploys do not rewrite migration history. **Before the first live migration or database-role change**, the remote runner persists and syncs `.virki-migration-integrity-guard` with the exact revision, verified backup name and SHA-256, **immutable original pre-migration backup name/SHA-256**, ADMIN/USER count baseline, and recovery-outbox snapshot digest. Only successful live migration-status, schema/role checks, and matching post-migration invariants promote its state from `PREPARED` to `VERIFIED`. `maintenance-off` rejects pending, corrupt, symlinked, mismatched or unverified checkpoints; `start`, `restart`, `start-tunnel`, `install-source` and repeat deployments cannot bypass a surviving checkpoint. After verified application health, the guard and maintenance markers are durably cleared **before** starting the public Tunnel, avoiding public automatic restart with stale maintenance state.

A plain `maintenance-on` still invalidates any previously verified backup when maintenance first begins. Repeating `maintenance-on` while already in maintenance preserves the current backup verification, but `maintenance-off` **always** requires a recent verified backup even when no migration occurred. For a lengthy maintenance window after a **VERIFIED** migration, `backup-verify` stops routed writers, checks the original pre-migration backup SHA-256 and current data invariants, restores/validates a **new** disposable backup, and atomically rebinds the checkpoint to the newly verified backup; the immutable original backup identity is retained and required for every subsequent renewal. An interrupted renewal is repeatable only while this original backup and current data invariants still match. A **PREPARED**/failed migration cannot renew its checkpoint or use `maintenance-off`. If a migration or invariant fails, **do not** remove the guard or maintenance marker, retry a deploy, or rely on schema-current alone. The guard intentionally has no automatic reset: operators must investigate in an isolated restored PostgreSQL environment, preserve the exact original backup, and obtain independently reviewed restoration/reconciliation evidence before any specifically authorized recovery implementation. Until then the release is **NO-GO**, routed services remain stopped, and production data is preserved. The scripts never call `prisma db push`, delete persistent volumes, or alter Cloudflare configuration.

Cloudflare Tunnel routes must send `biel.dev.br` to the public site and `portal.biel.dev.br` and `hub.biel.dev.br` to the Hub application's host router. Cloudflare Access protects only the ADMIN hostname. The example Tunnel configuration documents the desired routes; it does not prove public DNS, Tunnel, or Access state. Verify the public portal route and protected Hub boundary manually after a future deployment. Never impose the Hub Access policy on the USER portal.

## Identity recovery and rate-limit tradeoffs

An active ADMIN can recover the separate administrative credential from the Hub security page using the ADMIN's current Virki account password and one unused administrative recovery code. A successful recovery rotates the set of ten codes and revokes pending and active security elevations. It does not reset the normal Virki password, reactivate a disabled account, or authorize one ADMIN to approve their own account recovery. Cross-account recovery requires a different active ADMIN.

The remembered-browser grant lasts at most seven days after strong verification. It can avoid another email/TOTP login ceremony on that recognized browser, but it does not issue a Cloudflare Access assertion, create an ADMIN session by itself, or satisfy action-scoped security elevation. Hub page and mutation guards continue to require valid Cloudflare Access and an active Virki ADMIN session; protected changes still require the elevation their policy specifies. A trusted device can be revoked, and account recovery/deactivation revokes its remembered grants.

Login and recovery counters are persisted as keyed hashes. The default login limiter uses five attempts per role-scoped identifier and fifteen-minute window, an account bucket of twenty attempts, and a trusted-source bucket of thirty; successful authentication refunds the source reservation. Recovery also has source and address counters and a one-minute per-account request cooldown. These limits reduce guessing and mail abuse, but a source-address cap can affect unrelated people behind the same NAT or corporate proxy. Operators should first verify that trusted proxy forwarding is configured correctly; do not raise limits or accept untrusted forwarded addresses as a workaround.

Recovery responses remain generic, but the request path is not guaranteed to have constant response time: an eligible account performs serialized account-state checks, creates a recovery record, queues mail, and writes audit data, while an unknown or ineligible account exits earlier. There is no artificial sleep to equalize those paths. Treat timing as a residual account-enumeration risk; do not claim that generic copy alone eliminates it. Keep public confirmation text generic, monitor aggregate abuse without logging submitted emails or codes, and evaluate any future timing mitigation against abuse and availability behavior.

If there is only one ADMIN, that account can use the in-product administrative-credential recovery only while it can still authenticate with the normal account password and has an unused recovery code. If the sole ADMIN cannot access the account, email, password, or recovery codes, the application has no operator break-glass endpoint. This is a real `HARDENING_POST_DEPLOY` recovery gap, not a general deployment blocker: the migration guard requires at least one ADMIN and preserves ADMIN/USER counts, but does not require multiple ADMIN accounts or supply offline recovery. If an actual lockout occurs, stop privileged operations and follow [the sole-ADMIN break-glass procedure](admin-account-break-glass.md); never promote an account, replace a password hash, bypass Access, or edit live identity rows by ad hoc SQL.

## Email delivery guarantees

The outbox claims work with a five-minute processing lease, records interrupted and failed attempts, fences stale workers during finalization, and applies retry backoff after the transport attempt completes. It stops retrying after five attempts. There is no lease heartbeat, and the SMTP socket timeout is an inactivity timeout rather than a total-send deadline. A continuously progressing SMTP send that exceeds the five-minute lease can therefore overlap with a later worker reclaiming the message. SMTP is at-least-once: a provider can accept a message immediately before a connection/process failure prevents Virki from recording success, so a later retry can duplicate that email; overlapping workers can also send concurrently in the lease-expiry case. Neither transporter shutdown nor an application wait timeout can prove that the remote provider did not accept a message. Do not describe this path as exactly-once delivery or claim the lease prevents all concurrent duplicate sends. Failed transport details are reduced to a fixed error code; secrets and message bodies stay out of logs.

## Dependency-tree policy and compatibility reservations

At pre-change baseline `main` SHA `85d224d27027fc3c65ce9c15aeaafb85cbeaf759` (2026-10-07), the lockfile resolves `prisma`, `@prisma/client`, and `@prisma/config` to `6.19.3`. `@prisma/config` declares `deepmerge-ts@7.1.5`, while the root override intentionally resolves `deepmerge-ts@8.0.2` to avoid the reviewed GHSA-ggr8-5vv4-36mx advisory. This declared-versus-overridden version difference remains a compatibility reservation; do not remove the security override or claim that every upstream API compatibility case is proven.

The exact-SHA [CI run 37628498128](https://github.com/bielxdh3/Virki/actions/runs/37628498128), including the [Prisma tooling job](https://github.com/bielxdh3/Virki/actions/runs/37628498128/job/112816357610), passed the `Verify Prisma dependency tree` step, which runs `npm ls @prisma/config deepmerge-ts --all`, plus the tooling audit and policy tests, production dependency audit, validation, authenticated browser E2E, and both production image/migrator smoke jobs. Therefore the earlier statement that this command fails with `ELSPROBLEMS` and that publication must remain blocked is stale for this baseline SHA. These checks establish that the pinned dependency-tree policy passes and exercise the CI-supported paths; they do not prove every possible upstream API interaction. Classify the remaining mismatch as a bounded compatibility reservation, not a deployment blocker absent a concrete failing behavior. Reassess it when Prisma/config versions change or a relevant compatibility failure appears.

The dependency selections elsewhere are not all independent compatibility claims: `typescript@5.9.3` is inside the installed `typescript-eslint@8.71.0` peer range (`>=4.8.4 <6.1.0`), whereas `7.0.2` is outside it; Next `16.3.8` declares support for React/React DOM `^19`, and the lockfile keeps both at `19.2.7`. A separate version alignment remains: the runtime is `oidc-provider@9.12.2`, while `apps/issuer` declares `@types/oidc-provider@^8.8.0` and the lockfile resolves `8.8.1`. Exact-SHA typecheck and authenticated browser E2E passed, but do not prove every declaration/runtime API interaction. Treat this as a bounded compatibility reservation, not a deployment blocker absent a concrete failing behavior; do not present the pair as fully validated.

## CodeQL evidence retention

The CodeQL workflow analyzes the exact Git revision with `upload: never`, enforces `scripts/codeql-sarif-policy.mjs`, and stores SARIF as a private GHCR OCI image with a run-bound digest recorded in the successful GitHub Actions log. The owner-approved production gate requires successful exact-SHA PUSH CI and CodeQL, a passing reviewed SARIF policy with no unreviewed violation, and retrieval by digest of private GHCR evidence from that exact CodeQL run. The deployment/preflight gate performs that retrieval and re-evaluation; absent or tampered GHCR evidence blocks until the workflows are rerun for the same accepted SHA. The evidence is copied out of a stopped OCI container and independently re-evaluated before host contact. This does not populate GitHub Code Scanning alerts, and publication is not required by current owner policy. Keep the policy fail-closed; never substitute SARIF from another SHA, run or unverified registry tag.

## Validation boundaries

CI checks the Linux control script syntax and runs mocked production-control tests. The migration and backup/restore validations use disposable Docker databases; they do not contact or alter production. These checks do not prove the configured production host identity, existing production data, live Docker state, or Cloudflare routing and Access policy. The operator must verify those host-specific conditions through the guarded preflight and post-deployment gates when the native Linux target is available.

## Private GHCR transport readiness

The owner has provisioned `virki-runtime`, `virki-migrator` and `virki-evidence` as private packages linked to this repository. Bootstrap images are non-deployable. The proposed `main` workflow builds, tests and pushes the actual runtime/migrator images; CodeQL and image-provenance evidence uses `virki-evidence`, not quota-limited Actions artifact uploads. The successful workflow log records each evidence image's immutable digest, bound to SHA/run/kind/platform, and the production gate re-evaluates SARIF and manifests retrieved by that digest. A mutable tag or a passing PR check alone cannot authorize deployment. The native Linux host still needs a protected read-only GHCR credential before private staging; no public Cloudflare cutover is part of this branch. Historical Actions image artifacts were deleted only as specifically approved, and the two most recent Virki rollback image artifacts remain retained.
