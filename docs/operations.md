# Operations

This guide is for operating the canonical BielOS production host through the trusted `servidor` SSH path. The development PC is never a BielOS production host.

## Before Starting

Make sure the trusted Windows OpenSSH path to the production server is available. Do not start the real production Compose stack on the development PC.

For local Node.js commands, use Node `22.13.0` or newer within Node 22. The lint tooling added in Phase 05.2 depends on packages that do not support early Node 22 releases.

The private `.env` file is authoritative on the production server. It may exist locally for development and migration, but must stay uncommitted.

The `.env` file contains private values such as:

- PostgreSQL password
- OWNER seed email and password
- Cloudflare Tunnel token

## Commands

Run the required remote SSH/Docker preflight:

```bash
npm run preflight:prod
```

Deploy the exact clean `main` revision to the server:

```bash
npm run deploy:prod
```

Start or restart remote BielOS production:

```bash
npm run start:prod
npm run restart:prod
```

Stop remote BielOS production without deleting persistent volumes:

```bash
npm run stop:prod
```

Before `deploy:prod`, `start:prod`, or `restart:prod`, run `git fetch origin`. The wrapper fails closed unless the active branch is `main`, tracked/staged/untracked source is clean, and local `HEAD` exactly equals `origin/main`. It does not pull, reset, clean, or change branches. Every remote action repeats the SSH preflight.

Verify that all running BielOS-built services use the current revision:

```bash
npm run revision:prod
```

The verifier checks only `org.opencontainers.image.revision` on the BielOS-built `public-site`, `hub`, `intake`, `session-cleanup`, and `email-worker` services. It emits fixed match/missing/malformed/mismatch categories and never prints container IDs, image IDs, raw inspect data, environment values, or an unexpected label value.

Show remote container status, loopback bindings, health, revision, or sanitized log availability:

```bash
npm run status:prod
npm run status:ports
npm run health:prod
npm run revision:prod
npm run logs:prod
```

Run local health checks only for disposable development validation:

```bash
npm run health:local
```

Use `docs/deployment-verification.md` for the remote production acceptance checklist and live Cloudflare smoke test.

The canonical production directory is `C:\BielOS`, isolated from deManage. The server-side runner requires the production-host marker, clean exact-archive source markers, and exact image revision labels before it starts or restarts the real stack.

The health check verifies:

- `http://127.0.0.1:3000`
- `http://127.0.0.1:3001/api/health`

These addresses are checked on the remote server over SSH. They are not the public ingress path.

The hub health endpoint returns only minimal liveness status. It does not require Cloudflare Access JWT validation, so local Docker health checks keep working when `CLOUDFLARE_ACCESS_JWT_REQUIRED=true`.

## Services

- `public-site`: the public BielOS site for `biel.dev.br`.
- `hub`: the private BielOS hub for `hub.biel.dev.br`.
- `intake`: the isolated public application service; it receives only the restricted intake database URL and remains disabled until rollout gates pass.
- `session-cleanup`: the production worker that periodically removes expired or revoked hub sessions.
- `email-worker`: the private worker that delivers the durable email outbox through the configured SMTP adapter.
- `postgres`: the PostgreSQL database used by the hub.
- `cloudflared`: the Cloudflare Tunnel connector that exposes BielOS through Cloudflare without opening router ports.

Cloudflare Tunnel does not depend on the host-published `127.0.0.1` debug ports. When `cloudflared` runs inside Docker, it reaches the apps through Docker service names:

- `http://public-site:3000`
- `http://hub:3001`

## Expected Remote Flow

The expected remote flow is:

1. `https://biel.dev.br` loads the public site.
2. `https://hub.biel.dev.br` shows Cloudflare Access first.
3. After Cloudflare Access, BielOS shows the internal login.
4. After BielOS login, the hub dashboard loads.

## Troubleshooting

### Remote Docker Is Not Running

Run the guarded server preflight:

```bash
npm run preflight:prod
```

If remote Docker is still unavailable, stop and repair the server outside this deployment flow. Do not start a local production stack as a fallback.

### `biel.dev.br` Shows 502

Check container status:

```bash
npm run status:prod
```

Check logs:

```bash
npm run logs:prod
```

In the Cloudflare dashboard, confirm the Docker route uses the service name:

```text
biel.dev.br -> http://public-site:3000
www.biel.dev.br -> http://public-site:3000
```

Do not use `localhost` when `cloudflared` runs inside Docker.

If `biel.dev.br` still returns 502, confirm the dashboard route is not using `localhost` and then run:

```bash
npm run status:ports
```

### `hub.biel.dev.br` Skips Cloudflare Access

Check Cloudflare Access in the Cloudflare dashboard.

The hub hostname must be protected:

```text
hub.biel.dev.br
```

Access should only allow the owner's email or an approved identity group.

The Docker route should be:

```text
hub.biel.dev.br -> http://hub:3001
```

Do not expose port `3001` directly to the internet. Direct access to port `3001` bypasses Cloudflare Access.

### Login Fails

Confirm the OWNER user was seeded:

```bash
npm run seed:owner
```

If the database was recreated, apply reviewed committed migrations from a separate tooling-capable operator environment against the private remote `DATABASE_URL`; never run them inside the runtime container or against the local production volume.

Then seed the OWNER user again.

Confirm the email and password are the values in the private server `.env` file.

If a login or logout POST returns HTTP `403` while the page itself loads normally, reload the form and try again. Hub POST routes require a short-lived CSRF token, and tokens generated before a hub restart may no longer validate.

### Session Cleanup

Production Compose starts `session-cleanup` and `email-worker` workers with no published ports. They use the same private database configuration as the hub; `session-cleanup` runs `npm run sessions:cleanup --workspace @bielos/auth` every hour by default, while `email-worker` polls the durable outbox with bounded retries.

To change the interval, set this non-secret value in the private server `.env` file:

```bash
SESSION_CLEANUP_INTERVAL_SECONDS=3600
```

The cleanup log prints only the number of inactive sessions removed. It must not print session tokens, cookies, raw IPs, JWTs, or Cloudflare values.

### Core health, activity, automation, and recovery

Authenticated Core exposes `/core/health`, `/core/activity`, `/core/automation`, and `/core/recovery`. These pages are read-only capability consumers. Health and recovery cards show source and freshness; `unknown` and `unavailable` are not treated as success. Activity stays empty until a module declares an authorized `events.read` provider. Automation recipes remain blocked until a declared provider and bounded scheduler exist. No protected module data is copied into Core.

### Audit Log Cleanup

Production cleanup also runs audit log retention cleanup on the same interval. The default retention is `180` days.

To change it, set this non-secret value in the private local `.env` file:

```bash
AUDIT_LOG_RETENTION_DAYS=180
```

Manual cleanup:

```bash
npm run audit:cleanup
```

The cleanup deletes only audit rows older than the retention window and prints only a deleted-row count. It must not print audit contents, metadata, identifiers, raw headers, raw IPs, cookies, JWTs, tokens, or private values.

### Database Backups

Use `docs/database.md` for the PostgreSQL backup procedure.

Backups are private operational artifacts. Keep them out of Git, do not paste their contents into logs or chat, and verify restore only on a disposable database.

### Health Check Fails

Run:

```bash
npm run status:prod
```

If containers are not running, start them:

```bash
npm run start:prod
```

If containers are running but health still fails, inspect logs:

```bash
npm run logs:prod
```

The hub health check should use `/api/health`, not `/login`. `/login` can correctly return HTTP `403` when origin-side Cloudflare Access JWT validation is enabled and the request does not include a valid Access assertion.

### Local Validation Checks

Before pushing a phase, run the same core checks used by CI when feasible:

```bash
npm run secrets:scan
npm run lint
npm run typecheck
npm run prisma:validate
npm run test:core
npm run build
```

Focused database commands are also available:

```bash
npm run test:core:db:integration
npm run test:core:concurrency
```

Without `CORE_TEST_DATABASE_URL`, these commands create an isolated PostgreSQL Compose project on a random loopback port, apply committed migrations, run synthetic fixtures, and remove the service and volume. The runner refuses production mode, non-test database/user identities, and non-allowlisted hosts. Do not point it at durable data and do not replace migration deployment with `db push`.

Production requires a dedicated non-empty `BIELOS_RATE_LIMIT_HASH_SECRET` for login-identifier HMACs. Confirm only that the private variable exists; never print its value. Development and test may use the built-in synthetic fallback, while production fails closed and never derives the key from `DATABASE_URL`.

Do not run a production restart when that private variable is absent. Configure it interactively, validate Compose without printing resolved environment values, and then restart. A synthetic placeholder is sufficient only for CI or local Compose syntax validation.

The secret scan is intentionally safe to run locally. It scans tracked repository files plus new non-ignored files and reports only file paths, line numbers, and rule ids.

For CSRF changes, inventory login, logout, Core project lifecycle/access, personal session, and existing GymForge mutation forms. Verify locally when feasible that each form carries the CSRF field, valid submissions work, and missing-token mutations return HTTP `403` without changing state.

Remote CI evidence must identify the exact commit SHA and completed workflow result. Do not infer success from local validation or create a dummy commit merely to trigger CI. If the GitHub run cannot be inspected safely, report exactly: `CI remoto não confirmado.`

Authenticated OWNER/MEMBER browser smoke must use an existing safe browser session and disposable identities through Cloudflare Access and BielOS login. Do not request credentials, extract cookies or tokens, reset passwords, or weaken either boundary. If no safe authenticated session is available, preserve the manual checklist in `docs/deployment-verification.md` and report the smoke as incomplete.

The redirect-hardening campaign reviewed commits `4705e9df46812967aa86ae780c732d56e17a719a`, `e8ad193bca55abab87a16440d879ed534b86c761`, `d634a454138e7f59aa364a3764efce16a99bf2e3`, `70f577329f36471876fcc184ef713e25d8b98b1f`, `00c29fd79b94338fe39545044e282f430450e5e2`, and `e559152b8f402f07f86c3eb29c56e601cf5bca44`. Access diagnostics are typed and non-disclosing in the normal unit path. Login, logout, and proxy redirects use the configured public origin, allow only `/` and `/login`, require HTTPS in production, and fail closed without an internal-origin fallback. Missing required assertions are denied early; present assertions reach full JOSE validation before BielOS session routing. The deployed proxy wrapper keeps the framework event separate from runtime environment configuration.

The Core gate includes secret scan, lint, typecheck, Prisma validation, public discovery, unit, database integration and concurrency tests, build, production image, and Compose validation. Production builds now require a clean pushed `main` revision and store the exact full SHA in the immutable OCI image label. The local verifier requires the running BielOS-built service labels to match that intended revision. This attestation remains local operational and CI evidence; no public application surface exposes the private repository revision.

Historical OWNER and MEMBER production smoke passed through Cloudflare Access first and BielOS login second. It is not current evidence for the published repair, so only the affected flows must be repeated. Existing GymForge behavior remains frozen and reserved modules remain inert. Exact-SHA CI run `35673141210` passed for the accepted remote revision `0c1fc27cff56f3ad0065ff4099c310d7b929d24e`.

This deployment runs on local Windows with Docker Desktop and Cloudflare Tunnel. Public Linux/VPS host-firewall validation is not applicable to the current environment; application listeners remain bound to loopback and the tunnel remains the ingress path. A future migration to a public Linux/VPS host must add host-firewall rules that block direct inbound application-port access.

Diagnostic reports should summarize pass/fail state and non-sensitive errors only. Do not include raw command logs when they could expose environment values, private identifiers, headers, IPs, cookies, JWTs, tokens, or database URLs.

## Security Notes

Development and production debug ports are bound to `127.0.0.1` only. On a public Linux server or VPS, also block inbound internet access to ports `3000` and `3001` with the host firewall as defense in depth.

Never commit:

- `.env`
- Cloudflare Tunnel token
- Cloudflare account ID
- real tunnel ID
- tunnel credentials JSON
- screenshots containing secrets
- database dumps
- backup archives

The repository should contain only examples, placeholders, and documentation.
