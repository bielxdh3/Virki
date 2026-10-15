# GitHub one-click production approval (Virki)

This is the same **approval-pointer plus host pull-agent** pattern used for deManage, but it is an independent Virki deployment system. It does not use deManage credentials, services, network, volume, or approval branch.

## What the GitHub button does

The **Authorize Virki production release** workflow appears under **Actions** once its PR is merged. Only the repository owner can run it on main. It requires a successful exact-commit main-push CI, CodeQL, both published CPU-architecture images, and private GHCR packages. It writes `production.json` to a separate `production` branch. This is a **request**, not a deployment.

A separate agent on the native Linux production operator host polls that pointer. It only operates if `VIRKI_AUTOMATED_DEPLOY_ENABLED=true`, a first-install marker and active Virki release exist, the pinned SSH host is reachable, and deManage containers are running. The agent fast-forwards its **clean, dedicated** `main` operator checkout to the exact approved revision, verifies the official production preflight (including GHCR evidence and reviewed SARIF), runs `npm run deploy:prod`, checks `npm run health:prod` and compares deManage container names. It records success only after these checks.

If a deployment is interrupted or fails, the agent stores `attempted` or `failed` and **never retries automatically**. A human must investigate production maintenance, backup integrity, schema state and health before resetting the owner-only state. Do not remove or edit the state to defeat this protection.

## One-time provisioning (not automated and not yet completed)

1. Complete the safe first-install recovery or first install of Virki using the repository's existing **guarded** commands. The status observed on October 14 had a partially prepared `/srv/virki`, a stopped Virki PostgreSQL container, no `current` link and no first-install marker. Do not use `deploy:prod` as a replacement for `first-install:recover:prod`. Use dedicated staging ports, complete the interactive first-ADMIN creation, and prove portal DNS, tunnel, Cloudflare Access, OIDC and SMTP before cutover. Old the legacy identity deployment may only be stopped after safety checks; deManage must remain operational throughout.
2. Provision a **separate**, owner-only `0600` **read:packages** GHCR token directly at the already-established Virki production secret path (see `docs/deployment.md`). Do not copy deManage credentials or use the desktop's broad GitHub login token. Confirm access to `virki-runtime`, `virki-migrator` and `virki-evidence` **by immutable digest**.
3. Provision a clean, dedicated operator `main` checkout on the trusted Linux host (separate from `/srv/virki/releases`), Node 22, npm 10, GitHub CLI, Docker, SSH, and read-only private GitHub repo+Actions credentials for `gh api` and `git fetch`. Configure the ignored `.production.operator.json` or equivalent environment to pin SSH alias, hostname, port and production root. Pin the SSH host key; no password-based fallback.
4. Store `GH_TOKEN` securely in a root- or owner-protected systemd EnvironmentFile readable only by the agent. Put the separate agent state at an absolute `virki-approval-state.json` filename in a private, owner-only `0700` directory; set `VIRKI_APPROVAL_STATE_FILE` accordingly. It must not be inside the tracked repository, deManage directories or Docker volumes.
5. Run the agent manually in a **disabled or read-only configuration first** and verify it refuses. After first install and public cutover are independently verified, set `VIRKI_AUTOMATED_DEPLOY_ENABLED=true`. Configure an owner-only systemd timer with a **nonblocking `flock`** around `node scripts/production-approval-agent.mjs`, e.g. every five minutes. Do not make a timer active until the first install, scoped credentials, environment-file permissions, SSH pinning and safe retry behavior have been tested.
6. Run one explicitly approved GitHub production workflow on the intended `main` SHA. Inspect its successful output and the host agent logs. Confirm source revision, backup/restore evidence, migrations, health endpoints, portal discovery, Cloudflare ADMIN Access, public HTTPS and deManage availability before calling the release deployed.

## Scope and limits

- The workflow cannot reach the server on its own; there is **no hosted-runner SSH access, self-hosted GitHub runner, or automatic deployment** until the pull agent is provisioned.
- The operator agent verifies the **current HEAD** of `main` only. To deploy a previous revision, use a separately reviewed rollback plan, not a changed pointer.
- GitHub checks and GHCR package visibility are only *approval gates*. The existing `npm run preflight:prod` and deployment scripts remain the authority for SARIF, provenance, backup/restore, migration, SSH and health validation.
- The automation does not perform first installation, establish new ADMIN credentials, alter Cloudflare DNS/Access, delete the legacy identity deployment or deManage containers, or bypass safety controls.
- Do not report deployment success based only on the approval workflow. The definitive result is the host's verified revision and the post-deploy checks.
