# Manual deployment over SSH — the simple path

SSH already encrypts the transport. **For an owner-operated, image-only staging update**, use the installed Docker/Compose tools. No custom SSH protocol, GHCR, release server, or new daemon is needed.

This procedure is **staging-only**, for a previously tested image whose change needs **no database migration**. It does **not** bypass production CI/approval, backup/restore, schema-migration, or Cloudflare Access requirements. Do not use it for a new first install or a schema-changing release.

## 1. Prepare the image (skip if the exact image is already on staging)

From a clean checkout at the intended revision, with local Docker available:

```powershell
$rev = (git rev-parse HEAD).Trim()
$portalHost = "portal-pr88-temp-20261102.biel.dev.br" # replace with the verified staging Portal hostname
if (-not (Select-String -LiteralPath infra/Dockerfile.prod -Pattern '^ARG VIRKI_PORTAL_HOSTNAME=' -Quiet)) { throw "OIDC build-host support missing: first include PR #109." }
$image = "virki-manual:$rev"
docker build --platform linux/amd64 --target production --build-arg "VIRKI_BUILD_REVISION=$rev" --build-arg "VIRKI_PORTAL_HOSTNAME=$portalHost" -t $image -f infra/Dockerfile.prod .
$localId = (docker image inspect --format '{{.Id}}' $image).Trim()
docker save -o runtime.tar $image
$hash = (Get-FileHash .\runtime.tar -Algorithm SHA256).Hash.ToLowerInvariant()
```

**Build prerequisite:** use a checkout containing PR #109, which validates the compiled OIDC routes. The Portal hostname must match the existing staging HTTPS ingress. A production-host build can start in staging while its authorization endpoints route incorrectly; do not proceed if the guard fails.

Use a **preconfigured SSH alias with a verified, pinned server host key** (example: `stage-vm`). Do not disable host-key checking. Transfer the TAR only if the remote image ID is missing:

```powershell
scp -o StrictHostKeyChecking=yes .\runtime.tar stage-vm:~/runtime.tar
"$hash  runtime.tar" | ssh stage-vm 'sha256sum -c -'
if ($LASTEXITCODE -ne 0) { throw "Remote TAR SHA-256 mismatch; image not loaded." }
ssh stage-vm 'sudo docker load -i ~/runtime.tar'
$remoteId = (ssh stage-vm "sudo docker image inspect --format={{.Id}} $image").Trim()
if ($remoteId -ne $localId) { throw "Remote Docker image ID mismatch; stop." }
```

**Stop** unless both commands succeed and the image has the expected Linux/amd64 revision and non-root runtime user. Never send `.env`, DB dumps, private keys or auth tokens.

## 2. Change only the Hub in isolated staging

Keep the preexisting, trusted Compose YAML and private `.env` on the VM; do **not** replace them or change the shared image setting for other services. Record the old Hub image ID and all non-Hub container IDs first. If a prior attempt/overlay marker is present, reconcile it **before** trying another revision; never blindly retry after an interrupted SSH response.

For a new, authorized staging attempt, the essential operation is only:

```powershell
$override = "services:`n  hub:`n    image: $image`n"
$override | ssh stage-vm 'sudo docker compose --project-name virki-manual-staging --env-file /usr/local/share/virki-manual-staging/.env -f /usr/local/share/virki-manual-staging/infra/docker-compose.prod.yml -f - up -d --no-deps --no-build --pull never --force-recreate --wait hub'
```

The server-side operator must serialize the update, durably mark an attempt **before** changing the Hub, and preserve that marker if the command is interrupted. This prevents an old full-deployment receipt from falsely describing a newer Hub. Do not run `compose down`, `--remove-orphans`, the migrator, or a full staging `apply`. **Only the Hub can restart.** Keep the old Docker image for a reviewed rollback; do not assume that a failed health check rolled back automatically.

## 3. Confirm the result

```powershell
ssh stage-vm 'sudo docker ps --filter label=com.docker.compose.project=virki-manual-staging --format={{.Names}}:{{.Status}}'
ssh stage-vm 'sudo docker inspect --format={{.Image}}:{{.State.Health.Status}} virki-manual-staging-hub-1'
```

Require the exact new Hub image ID, Hub health `healthy`, and unchanged identities for PostgreSQL, issuer, public site, cleanup and email workers. Then verify real external HTTPS/OIDC/Access login separately. An interrupted command means **inspect first, never retry blindly**. A DB-changing release needs an independently verified backup/restore and a separate migration procedure; SSH encryption alone does not make migrations safe.

## 4. Authenticated staging acceptance (separately authorized)

First have the owner sign into the existing staging Hub via Cloudflare Access and complete ADMIN e-mail MFA. Without bypassing security elevation, use the **existing** `/admin/accounts` UI to invite a disposable USER (the user accepts the e-mail invitation), `/admin/connections` to register an HTTPS OIDC relying party with an exact callback URL, and `/admin/access` to grant that active USER access to that connection. **Creating any of these three resources requires specific owner approval; this guide does not authorize it.** Store the one-time OIDC client secret only in the relying party's own private configuration, never in logs or Git.

The repository's existing `examples/oidc-node-rp` supplies a tested PKCE client; its `.env.example` documents the HTTPS callback and separate RP database. Once the user, client and grant exist, use that RP to verify the authorization-code+S256 PKCE login, one code-to-token exchange, issuer/JWKS/nonce validation and rejection of an invalid redirect URI. Do not claim staging PKCE passed from CI fixtures alone; authenticated browser evidence is still required.
