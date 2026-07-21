# First Production Launch Checklist

Use this checklist for the first production launch and later smoke tests. Do not paste `.env` contents, Cloudflare tokens, JWTs, cookies, database URLs with passwords, private keys, or raw logs into issues or docs.

## Before Start

- Run `git fetch origin` and confirm the active branch is `main`.
- Confirm local `HEAD` equals `origin/main` and the tracked, staged, and non-ignored untracked worktree is clean. `start:prod` and `restart:prod` fail closed otherwise.
- Confirm the private `.env` file exists locally in the repository root.
- Confirm the private `.env` defines these names without printing their values:
  - `DATABASE_URL`
  - `BIELOS_RATE_LIMIT_HASH_SECRET`
  - `POSTGRES_PASSWORD`
  - `NEXT_PUBLIC_HUB_URL`
  - `CLOUDFLARE_TUNNEL_TOKEN`
  - `CLOUDFLARE_ACCESS_JWT_REQUIRED`
  - `BIELOS_OWNER_EMAIL`
  - `BIELOS_OWNER_PASSWORD`
- Confirm no real `.env`, tunnel token, credentials JSON, Cloudflare account ID, Cloudflare secret, database dump, or backup archive is committed.

## Start And Local Smoke Test

Start the production stack with the Cloudflare override:

```bash
npm run start:prod
```

Inspect status and local health:

```bash
npm run status:prod
npm run status:ports
npm run health:local
npm run revision:prod
```

- Confirm `npm run status:ports` shows loopback bindings only:
  - `127.0.0.1:3000->3000`
  - `127.0.0.1:3001->3001`
- Confirm `postgres`, `public-site`, `hub`, `cloudflared`, and `session-cleanup` are running.
- Confirm `session-cleanup` has no published ports.
- Confirm `cloudflared` has no published ports.
- Confirm `npm run revision:prod` reports `match` for `public-site`, `hub`, and `session-cleanup` against the current full Git revision.
- Confirm `npm run health:local` checks:
  - `http://127.0.0.1:3000`
  - `http://127.0.0.1:3001/api/health`
- Confirm `http://127.0.0.1:3001/login` reaches the hub login only when `CLOUDFLARE_ACCESS_JWT_REQUIRED=false` for local development.
- If `CLOUDFLARE_ACCESS_JWT_REQUIRED=true`, direct local hub page requests without a valid Access assertion should return HTTP `403`; `GET /api/health` should still return minimal health data.

## Cloudflare Smoke Test

- Confirm `https://biel.dev.br` loads the public site.
- Confirm `https://www.biel.dev.br` loads or redirects correctly.
- Confirm `https://hub.biel.dev.br` shows Cloudflare Access before BielOS.
- Confirm Cloudflare Access only allows the owner's email or approved identity group.
- Confirm BielOS internal login appears after Cloudflare Access.
- Confirm BielOS internal login works with the seeded OWNER user.
- Confirm logout clears the BielOS session and returns to `/login`.

## Cloudflare Routing

When `cloudflared` runs inside Docker, public hostname routes must use Docker service names:

- `biel.dev.br` -> `http://public-site:3000`
- `www.biel.dev.br` -> `http://public-site:3000`
- `hub.biel.dev.br` -> `http://hub:3001`

Do not use `localhost` for the Docker production path.

If `cloudflared` runs directly on Windows outside Docker, local routes may use:

- `biel.dev.br` -> `http://localhost:3000`
- `www.biel.dev.br` -> `http://localhost:3000`
- `hub.biel.dev.br` -> `http://localhost:3001`

The preferred BielOS production path is Docker.

## Authenticated BielOS Core Smoke

Use only existing disposable test identities. Do not reset a real user's password, copy session material, weaken Cloudflare Access, or create an authentication bypass.

| Identity | Route | Action | Expected result | Cleanup |
| --- | --- | --- | --- | --- |
| Fresh browser | `/` on the private hub | Open the hub without an existing Access session | Cloudflare Access appears before BielOS login | Close the fresh session |
| Disposable `OWNER` | `/` | Sign in, switch PT-BR/English, open Core links and GymForge | Hub and both locales render; GymForge opens; reserved modules remain inert | Restore preferred locale and sign out when finished |
| Disposable `OWNER` | `/core/projects` | Create a uniquely named disposable project, edit visibility/status, then archive it | Generic validation is stable; archive succeeds; permanent delete is absent | Leave the test project archived because permanent deletion is intentionally unavailable |
| Disposable `OWNER` | `/core/projects` | Grant a disposable `MEMBER` `VIEWER`, change to `EDITOR`, grant `OWNER` if intended, test last-owner protection, then revoke | Authority and last-owner rules hold; Project A access does not reveal Project B | Revoke the disposable member's access where allowed |
| Disposable `OWNER` | `/core/security` | Inspect sessions, revoke another disposable own session if one exists, and use all-other revocation only when safe | Current session is marked and preserved; no token/hash or cross-user rows appear | Sign in again only if a disposable test session was intentionally revoked |
| Disposable `OWNER` | `/core/security#audit` | Inspect newest project/access/session events | At most 50 safe rows appear; no raw metadata, messages, emails, or identifiers appear | No data cleanup required beyond the disposable project/access actions |
| Disposable `OWNER` | `/#ops` | Inspect live, configured, and manual groups | Database/request/session evidence is truthful; container/external checks remain manual; no raw error appears | No cleanup required |
| Disposable `MEMBER` | `/core/projects` | Open lists and direct URLs for granted, public, and ungranted restricted projects | Only public or explicitly granted projects appear; restricted direct URLs fail without description/status leakage | OWNER removes the disposable grant afterward |
| Disposable `MEMBER` | `/core/projects` and `/core/security` | Attempt admin controls/audit access and inspect sessions | Project mutation/access controls and owner audit are unavailable; only the member's sessions appear | Sign out |

Authenticated OWNER and MEMBER smoke has been executed through the real Cloudflare Access and BielOS login flow. Disposable MEMBER credentials, sessions, grants, account state, and browser profiles were removed after verification.

## Safe Diagnostics

- Use `npm run logs:prod` only for local inspection. Summarize service status or non-sensitive errors; do not copy secrets, tokens, cookies, JWTs, raw headers, raw IPs, or database URLs.
- If `biel.dev.br` returns `502`, confirm `cloudflared` is running and the Cloudflare public hostname routes use Docker service names.
- If `hub.biel.dev.br` skips Cloudflare Access, stop and fix the Cloudflare Access application policy before using the hub remotely.
- If local health fails, confirm `hub` healthcheck uses `/api/health`, not `/login`.
- If login fails after a database reset, apply migrations and seed the OWNER user from private local values.

## Rollback

Stop the production stack safely:

```bash
npm run stop:prod
```

Cloudflare Tunnel does not depend on host-published ports. In Docker mode, it reaches `http://public-site:3000` and `http://hub:3001` on the Docker network. Remote hub exposure must remain behind Cloudflare Access, and direct internet access to port `3001` must stay blocked.

## Current Verification State And Remaining Limitations

- Login rate limiting is persisted in PostgreSQL, requires a dedicated private HMAC key in production, serializes same-identifier updates with a transaction-scoped advisory lock, caps attempts at five, and stores only a keyed hash of the normalized identifier plus bounded attempt/window state.
- Real login-route and limiter-lifecycle tests cover Access/CSRF denial, generic failure/success, cookie attributes, sanitized audits, exact window reset, retention, independent identifiers, strict concurrency, and bounded lock timeout.
- CSRF protection covers login, logout, Core project lifecycle and access management, personal session management, and existing mutable GymForge flows.
- A current PostgreSQL backup was created and verified before the committed migrations were deployed with `prisma migrate deploy`; restore was validated against a disposable target.
- The latest complete gate passed 52 unit, 48 aggregate database, 36 integration, and 12 concurrency tests plus secret scan, lint, typecheck, Prisma validation, build, production image build, production Compose validation, production restart, local/public health checks, Cloudflare-first hub routing, and loopback port checks.
- Diagnostic commit `4705e9df46812967aa86ae780c732d56e17a719a` supplies typed non-disclosing Access categories in the normal test path. Redirect correction commit `e8ad193bca55abab87a16440d879ed534b86c761` routes login success/failure and logout to the configured public origin. Hardening commit `d634a454138e7f59aa364a3764efce16a99bf2e3` limits destinations, requires HTTPS in production, removes production fallback, validates login configuration before mutable auth work, preserves logout cookie clearing, and makes proxy misconfiguration fail with a generic `503`.
- Protected-origin commit `70f577329f36471876fcc184ef713e25d8b98b1f` adds early denial for missing required Access assertions. Runtime correction commit `00c29fd79b94338fe39545044e282f430450e5e2` separates the framework event from environment injection and adds a regression test for the deployed invocation shape.
- Production revision attestation uses the immutable OCI label `org.opencontainers.image.revision`. The production wrapper requires clean pushed `main` source, CI verifies exact label equality, and local verification fails when any required BielOS-built service is absent or differs. The revision is not exposed by public HTML, discovery metadata, health routes, login responses, headers, audit logs, or user-facing errors.
- `CI remoto não confirmado.` GitHub CLI authentication was unavailable for exact workflow evidence.
- The dedicated limiter key is configured only in the ignored private environment. The current runtime was rebuilt and deployed without schema changes; migrations remain current and all expected services are healthy or running.
- Local/public health, Cloudflare-first routing, direct-origin login, logout, and protected-page `403`, public login/logout redirects, and loopback-only port checks passed. This is a local Windows/Docker Desktop deployment through Cloudflare Tunnel, so public Linux/VPS host-firewall validation is not applicable.
- Production browser redirects stayed on the public HTTPS hub origin: successful login reached `/`, one synthetic invalid login reached `/login?error=1` with a generic result, and logout returned `303` to `/login` while ending the BielOS session. BielOS logout did not claim to end the separate Cloudflare Access session.
- Authenticated OWNER production browser smoke passed through Cloudflare Access first and BielOS login second. Project create/edit/archive, duplicate and bounded failures, one deployed CSRF `403`, personal-session revocation, audit, operations, locale, GymForge integration, reserved-module inactivity, login failure handling, and normal logout were verified with disposable data and isolated profiles; temporary profiles were removed.
- Authenticated MEMBER production smoke passed after explicit Authorization B. One disposable MEMBER was provisioned privately without a tracked command or permanent surface, authenticated through Access then BielOS, and verified for baseline denial, VIEWER/EDITOR visibility, global-role mutation denial, revocation, Project A/B IDOR isolation, personal-session isolation, owner-audit denial, sanitized operations, one generic invalid login followed by successful login, and logout. Cleanup removed the account credential, sessions, grants, temporary profiles, and provisioning mechanism; both synthetic projects were archived and required audit history was preserved.
- Origin-side Cloudflare Access JWT validation depends on private environment configuration. Keep it enabled where required; never disable it merely to make a smoke test pass.
- If BielOS is later migrated to a public Linux/VPS host, that new host must block direct inbound access to application ports. This is a future migration condition, not a pending limitation of the current Windows/Docker Desktop deployment.
