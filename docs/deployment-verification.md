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

`BIELOS_MASTER_FINISH_EVERYTHING_READY_FOR_PUBLICATION_AUTH` is the current local campaign status. The worktree is intentionally uncommitted and contains the Core UI/capability/audit/recovery implementation plus preserved security WIP. Local HEAD and `origin/main` are `4be92f85a3573feb184da2bf770d0497a22f6a6`; no push, merge, deployment, migration, Cloudflare change, or production mutation was authorized or performed.

The local code gate is exhausted for the scoped roadmap. Remaining gates are an authenticated human visual/interaction smoke, remote CI after publication, and environment-backed Docker/database/backup/runtime evidence. Keep Cloudflare Access first, BielOS internal authentication second, public registration and live Intake disabled, GymForge expansion frozen, reserved modules inert, `SecurityUnlock` blocked, and AIP separate. Do not claim current production or authenticated browser smoke completion from local source checks alone.

Validation was repeated with the declared Node 22 runtime through `npx --yes node@22.20.0` where the command is runtime-sensitive; the host default remains Node `24.14.1`. The supported-runtime unit, public-site, GymForge scoring, production revision, lint/typecheck/Prisma/build checks pass. Docker-backed database, backup/restore, runtime-image, and intake-role checks remain blocked by the unavailable Docker daemon, missing runtime image, or missing `CORE_TEST_DATABASE_URL`; these are exact environment prerequisites, not code failures. The production dependency tree audit passes after omitting development dependencies; the remaining raw `npm audit` finding is the accepted Prisma tooling-only `deepmerge-ts` advisory documented in `docs/production.md`.

Read-only GitHub inspection on 2026-09-18 shows the latest completed CI run (`33825713090`) passed for the current base SHA `4be92f85a3573feb184da2bf770d0497a22f6a6a`. The campaign worktree remains unpushed, so that remote result does not validate the local dirty diff.
