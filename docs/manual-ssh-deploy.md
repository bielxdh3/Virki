# Manual deployment over SSH — the simple path

SSH already encrypts the transport. **For an owner-operated, image-only staging update**, use the installed Docker/Compose tools. No custom SSH protocol, GHCR, release server, or new daemon is needed.

This procedure is **staging-only**, for a previously tested image whose change needs **no database migration**. It does **not** bypass production CI/approval, backup/restore, schema-migration, or Cloudflare Access requirements. Do not use it for a new first install or a schema-changing release.

## 1. Prepare the image (skip if the exact image is already on staging)

From a clean checkout at the intended revision, with local Docker available:

```powershell
$rev = (git rev-parse HEAD).Trim()
$portalHost = "portal.staging.example.test" # the actual staging Portal hostname
$image = "virki-manual:$rev"
docker build --platform linux/amd64 --target production --build-arg "VIRKI_BUILD_REVISION=$rev" --build-arg "VIRKI_PORTAL_HOSTNAME=$portalHost" -t $image -f infra/Dockerfile.prod .
docker image inspect --format '{{.Id}}' $image
docker save -o runtime.tar $image
(Get-FileHash .\runtime.tar -Algorithm SHA256).Hash.ToLowerInvariant()
```

**Build prerequisite:** the Dockerfile must support `VIRKI_PORTAL_HOSTNAME` and check the compiled OIDC host-qualified routes (fix in PR #109). The value must equal the existing staging Portal hostname and its trusted HTTPS ingress; otherwise stop. A production-host build can start in staging while its authorization endpoints route incorrectly.

Use a **preconfigured SSH alias with a verified, pinned server host key** (example: `stage-vm`). Do not disable host-key checking. Transfer the TAR only if the remote image ID is missing:

```powershell
scp -o StrictHostKeyChecking=yes .\runtime.tar stage-vm:~/runtime.tar
ssh stage-vm 'sha256sum ~/runtime.tar'
ssh stage-vm 'sudo docker load -i ~/runtime.tar'
ssh stage-vm "sudo docker image inspect --format={{.Id}} $image"
```

**Stop** unless the remote TAR SHA-256 equals the local one and the loaded Docker image ID matches the locally inspected ID, with the expected Linux/amd64 revision and non-root runtime user. Never send `.env`, DB dumps, private keys or auth tokens.

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
