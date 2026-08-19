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
- Confirm `postgres`, `public-site`, `hub`, `cloudflared`, `session-cleanup`, and `email-worker` are running.
- Confirm `intake` is running without a host-published port and remains disabled: `GET /api/catalog` returns `503` and `POST /api/apply` cannot create an application or queue an email.
- Confirm `session-cleanup` has no published ports.
- Confirm `email-worker` has no published ports.
- Confirm `cloudflared` has no published ports.
- Confirm `npm run revision:prod` reports `match` for `public-site`, `hub`, `intake`, `session-cleanup`, and `email-worker` against the current full Git revision.
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

The table is the bounded resume checklist for the affected post-smoke flows. Historical OWNER/MEMBER smoke is retained as historical evidence only. The latest human smoke confirmed OWNER credential setup, offline recovery-code acknowledgement, and normal timed/manual elevation, but the then-current UI scope availability defect blocked project archive/access smoke and repetitive `ACCESS_JWT_VALID` events reduced audit signal. Repeat only the affected checklist after the local repair; do not claim current authenticated OWNER/MEMBER smoke completion.

## Intake Rollout Status

The Core browser smoke above does not validate public intake. No valid end-to-end application submission, email verification, owner review, activation, or production email delivery smoke is claimed here. An invalid `/api/apply` request returning HTTP `400` is only a rejection test and is not rollout evidence. Keep `BIELOS_INTAKE_ENABLED=false` and public registration disabled.

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

`BIELOS_POST_SMOKE_REPAIR_LOCALLY_COMPLETE_AWAITING_HUMAN_SMOKE` is the current status. Phase 1/2 source corrections are present and locally validated in the uncommitted worktree: implemented elevation scopes are available to the OWNER UI, Core pages use the shared dock, and OWNER audit activity has a bounded relevant/infrastructure filter with `ACCESS_JWT_VALID` success noise omitted by default. The current local `HEAD` remains `afb74455573179b9cd915d2076032af9fae23a4b`; the worktree is uncommitted, `origin/main` remains that pre-existing SHA, and no push, new remote CI run, or deployment was authorized or performed.

The latest human smoke is the authority for the remaining resume gate: OWNER administrative credential setup, offline recovery-code acknowledgement, and normal timed/manual elevation worked; the former UI scope defect blocked `PROJECT_OWNER_ACCESS_CHANGE` and `CORE_PROJECT_ARCHIVE` project smoke, while `ACCESS_JWT_VALID` reduced audit signal. Current human smoke must be repeated after this patch; do not claim `BIELOS_CLOSEOUT_COMPLETE` or current authenticated OWNER/MEMBER browser smoke.

Resume only the affected flows: acquire `PROJECT_OWNER_ACCESS_CHANGE`; grant, change, and revoke disposable Project A MEMBER access while verifying Project B denial/no leak and last-owner protection; acquire `CORE_PROJECT_ARCHIVE`; archive and verify read-only behavior; verify MEMBER admin/audit/session restrictions; then perform normal logout. Keep Cloudflare Access first, BielOS internal authentication second, public registration and live Intake disabled, GymForge expansion frozen, reserved modules inert, `SecurityUnlock` blocked, and AIP separate.

Historical technical/runtime/CI/Cloudflare evidence remains historical and must not be attributed to this uncommitted worktree. Current local validation completed under Node `24.14.1`, but the declared Node 22 engine mismatch remains a release limitation; those checks must be repeated under Node 22 rather than silently treated as supported.

Local validation completed under Node `24.14.1` (`node --version`): `npm run secrets:scan`, `npm run lint`, `npm run typecheck --workspaces --if-present`, `npm run prisma:validate`, `npm run test:core` (79 unit + 66 database), `npm run test:core:concurrency` (12), `npm run test:public-site` (4), `npm run test:gymforge-scoring` (8), `npm run test:production-revision` (13), and `npm run build`. The declared engine remains Node `>=22.13.0 <23`; Node 22 was unavailable, so this is unsupported-runtime evidence and must be repeated under Node 22 before release.
