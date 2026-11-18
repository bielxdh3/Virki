# Local physical email-worker HOL/CAS regression (Windows Docker Desktop)

This is a **separate local gate** for the mandatory two-worker PostgreSQL
HOL/CAS regression while GitHub Actions is unavailable. It does **not** change
or bypass the GitHub-hosted `scripts/integration/worker-hol-ci.sh` gate and
does not constitute a hosted CI attestation.

## Run

Use a clean, isolated Virki worktree on Windows and a **Node 22 / npm 10**
toolchain. Docker Desktop must be running in Linux mode and accessible to the
current unprivileged user. Do not run in an elevated shell or on the production
host. The runner rejects inherited database connection strings, Docker
contexts, mail transport/SMTP configuration and Node preloads.

```powershell
cd E:\Virki\.worktrees\virki-local-worker-hol-w37-20261110
node --version  # must show v22.x
npm ci
npm run test:integration:email-worker:hol:local:contract
npm run test:integration:email-worker:hol:local
```

The physical command is equivalent to
`node scripts/integration/local-worker-hol-disposable.mjs`, **not** the
GitHub-only shell script or generic `test:integration`. It requires no
`GITHUB_ACTIONS`, `RUNNER_ENVIRONMENT`, GitHub tokens, production database,
Cloudflare tunnel or real SMTP credentials. Never synthesize GitHub-runner
environment variables to run the CI-only script locally.

## Security boundary and evidence

The physical launcher:

1. Verifies the installed Docker CLI's Docker Inc Authenticode signature and
   uses only the fixed Docker Desktop Linux named pipe. The daemon must identify
   itself as Linux/amd64; ambient contexts and credentials are rejected.
2. Pins the PostgreSQL 17 OCI digest and checks both local image ID and
   RepoDigests before launching exactly one uniquely named, owner-labelled
   disposable container with `--rm`, `--tmpfs`, restricted PIDs/memory, and
   a Docker-assigned **127.0.0.1-only** port. No Docker data volume is used.
3. Generates independent ephemeral bootstrap, migrator, audit, runtime and
   worker-role passwords, and uses the reviewed PostgreSQL role initializer.
   Migrates only its own randomly named
   `virki_email_worker_hol_<12-hex>` database.
4. Uses a separate bootstrap-role **observer** to check PostgreSQL major
   version, nonprivileged worker role and that both outbox/delivery-attempt
   tables contain **zero rows** before the worker starts. Then runs the
   existing `scripts/integration/worker-hol.mjs` with an allowlisted test
   environment and deterministic in-memory email transport (no SMTP).
5. Accepts only the existing exact two-test TAP contract, zero FAIL/SKIP,
   and **also** requires verified owner-ID container cleanup before printing
   `LOCAL_EMAIL_WORKER_HOL_PHYSICAL_PASS`. If Docker operation or cleanup
   ownership becomes uncertain, it fails closed and leaves a durable
   `RECONCILIATION_REQUIRED` receipt, not a false PASS.

The owner-only receipt is written under
`%USERPROFILE%\.virki-private-local-hol\email-hol-<UUID>.jsonl`;
no generated password or connection URL is recorded there. Each attempt uses
an independent UUID. Do not delete unrelated containers or force cleanup of
uncertain ownership; reconcile the recorded immutable ID.

## Non-equivalence to hosted CI

The standalone physical local proof checks genuine database concurrency and
head-of-line behavior; the separate contract command uses **mocked Docker**
for negative cases and is not itself proof. The local run does not prove the
GitHub-hosted runner, CI service security, image publication, real SMTP
delivery, Cloudflare configuration or deployment. Fetching the digest-pinned
PostgreSQL image and `npm ci` may require network access during setup; the
worker test itself needs only loopback to its private disposable database.
