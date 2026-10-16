#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

action=${1:-}
root=${2:-}
revision=${3:-}
archive_hash=${4:-}
archive_id=${5:-}
image_hash=${6:-}
image_id=${7:-}

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

[[ "$root" =~ ^/([A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+$ ]] || fail 'Production root is invalid.'
[[ "$root" != '/' && ! "$root" =~ (^|/)\.\.?(/|$) ]] || fail 'Production root is invalid.'

allowed_actions=' install-source cleanup-deploy-staging first-install first-install-recovery first-admin-rescue-prepare first-admin-rescue deploy stage first-admin-bootstrap start restart start-tunnel stop maintenance-on maintenance-off status ports revision health logs backup-verify migration-status audit-recent audit-cleanup sessions-cleanup config '
[[ "$allowed_actions" == *" $action "* ]] || fail 'Production action is not allowed.'

if [[ "$action" == cleanup-deploy-staging ]]; then
  archive_id=$archive_hash
  archive_hash=
fi

readonly release_dir="$root/releases"
readonly current_link="$root/current"
readonly lock_path="$root/.virki-operations.lock"
source_dir=
readonly temp_dir="$root/.deploy-tmp"
readonly backup_dir="$root/backups"
readonly marker_path="$root/.virki-production-host"
readonly revision_path="$root/.virki-deploy-revision"
readonly source_state_path="$root/.virki-source-state"
readonly verification_path="$root/.virki-migration-verification"
readonly recovery_path="$root/.virki-first-install-recovery"
readonly maintenance_path="$root/.virki-maintenance"
readonly first_install_path="$root/.virki-first-install"
readonly first_install_volume='virki-prod_virki_postgres_data'
# Exceptional one-time bridge for the proven October 2026 no-ADMIN install.
# This is NOT a generic permission to bypass an existing ADMIN requirement.
readonly first_admin_rescue_predecessor='cbd065f2c560fdbc1f32c4c1c4804c352cf84494'
readonly migration_schema='packages/database/prisma/schema.prisma'
readonly migration_directory='packages/database/prisma/migrations'
readonly transition_migration_name='20260922090000_total_identity_security_rebaseline'
readonly migration_status_args=(--profile migration run --rm --no-deps migrate npm run prisma:migrate:status --workspace @virki/database)
readonly application_services=(public-site hub oidc-issuer session-cleanup email-worker)
readonly state_changing_actions=' install-source cleanup-deploy-staging first-install first-install-recovery first-admin-rescue-prepare first-admin-rescue stage first-admin-bootstrap deploy start restart start-tunnel stop maintenance-on maintenance-off backup-verify audit-cleanup sessions-cleanup '
readonly -a legacy_transition_migrations=(
  20260624190000_initial_schema
  20260624203000_add_login_rate_limit
  20260625160000_add_gymforge_foundation
  20260625173000_add_gymforge_competition_assignments
  20260714100000_add_gymforge_score_corrections
  20260801090000_identity_access_foundation
  20260801100000_add_intake_dedupe_controls
  20260801110000_add_partial_application_state
  20260801120000_account_security_verification
  20260801130000_administrative_elevation
  20260801140000_security_ui_keys
  20260802090000_restrict_intake_database_access
  20260802100000_fix_intake_security_functions
  20260805120000_add_remembered_browser_grant
)
state_lock_fd=
first_install_database_started=false
recovery_prior_revision=
recovery_archive_hash=
recovery_phase=
recovery_database_state=

verify_linux_host() {
  [[ "$(uname -s)" == Linux ]] || fail 'Production SSH target is not Linux.'
  local kernel
  kernel=$(tr '[:upper:]' '[:lower:]' < /proc/sys/kernel/osrelease)
  [[ "$kernel" != *microsoft* && "$kernel" != *wsl* ]] || fail 'WSL is not an accepted production host.'
}

verify_host() {
  verify_linux_host
  [[ -d "$root" && ! -L "$root" && "$(readlink -f -- "$root")" == "$root" ]] || fail 'Pre-provisioned production root does not match.'
  [[ "$(stat -c '%a' -- "$root")" == 700 && "$(stat -c '%u' -- "$root")" == "$(id -u)" ]] || fail 'Production root permissions are unsafe.'
  for directory in "$temp_dir" "$release_dir" "$backup_dir"; do
    [[ -d "$directory" && ! -L "$directory" ]] || fail 'Pre-provisioned production directories are missing or unsafe.'
    [[ "$(stat -c '%a' -- "$directory")" == 700 ]] || fail 'Production directory permissions are unsafe.'
    [[ "$(stat -c '%u' -- "$directory")" == "$(id -u)" ]] || fail 'Production directory owner does not match the SSH account.'
  done
  [[ -f "$marker_path" && ! -L "$marker_path" && "$(stat -c '%a' -- "$marker_path")" == 600 && "$(stat -c '%u' -- "$marker_path")" == "$(id -u)" && "$(wc -l < "$marker_path")" -eq 4 ]] || fail 'Pre-provisioned production identity marker is missing or invalid.'
  local host
  host=$(hostname -s)
  grep -Fxq 'role=production' "$marker_path" || fail 'Production identity marker mismatch.'
  grep -Fxq 'protocol=2' "$marker_path" || fail 'Production identity marker mismatch.'
  grep -Fxq "hostname=$host" "$marker_path" || fail 'Production identity marker mismatch.'
  grep -Fxq "path=$root" "$marker_path" || fail 'Production identity marker mismatch.'
  for name in .env .env.oidc .env.oidc-data; do
    local file="$root/$name"
    [[ -f "$file" && ! -L "$file" && "$(stat -c '%a' -- "$file")" == 600 ]] || fail 'Remote production secret files are missing or have unsafe permissions.'
    [[ "$(stat -c '%u' -- "$file")" == "$(id -u)" ]] || fail 'Remote production secret file owner does not match the SSH account.'
  done
  if [[ -e "$current_link" || -L "$current_link" ]]; then
    [[ -L "$current_link" ]] || fail 'Production source path is not a managed release link.'
    local current_target
    current_target=$(readlink -f -- "$current_link")
    [[ "$current_target" == "$release_dir"/* ]] || fail 'Production source link escaped the release directory.'
  fi
}

verify_cleanup_target() {
  [[ "$(uname -s)" == Linux ]] || return 1
  local kernel host
  kernel=$(tr '[:upper:]' '[:lower:]' < /proc/sys/kernel/osrelease) || return 1
  [[ "$kernel" != *microsoft* && "$kernel" != *wsl* ]] || return 1
  [[ -d "$root" && ! -L "$root" && "$(readlink -f -- "$root")" == "$root" ]] || return 1
  [[ "$(stat -c '%a' -- "$root")" == 700 && "$(stat -c '%u' -- "$root")" == "$(id -u)" ]] || return 1
  [[ -d "$temp_dir" && ! -L "$temp_dir" && "$(stat -c '%a' -- "$temp_dir")" == 700 && "$(stat -c '%u' -- "$temp_dir")" == "$(id -u)" ]] || return 1
  [[ -f "$marker_path" && ! -L "$marker_path" && "$(stat -c '%a' -- "$marker_path")" == 600 && "$(stat -c '%u' -- "$marker_path")" == "$(id -u)" && "$(wc -l < "$marker_path")" -eq 4 ]] || return 1
  host=$(hostname -s) || return 1
  grep -Fxq 'role=production' "$marker_path" || return 1
  grep -Fxq 'protocol=2' "$marker_path" || return 1
  grep -Fxq "hostname=$host" "$marker_path" || return 1
  grep -Fxq "path=$root" "$marker_path" || return 1
}

acquire_state_lock() {
  if [[ -e "$lock_path" || -L "$lock_path" ]]; then
    [[ -f "$lock_path" && ! -L "$lock_path" && "$(stat -c '%a' -- "$lock_path")" == 600 && "$(stat -c '%u' -- "$lock_path")" == "$(id -u)" ]] || fail 'Production operation lock file is unsafe.'
  fi
  exec {state_lock_fd}>>"$lock_path"
  [[ -f "$lock_path" && ! -L "$lock_path" && "$(stat -c '%a' -- "$lock_path")" == 600 && "$(stat -c '%u' -- "$lock_path")" == "$(id -u)" ]] || fail 'Production operation lock file is unsafe.'
  flock -n "$state_lock_fd" || fail 'Another production state change is already running.'
}

verify_revision() {
  [[ "$revision" =~ ^[0-9a-f]{40}$ ]] || fail 'Expected production revision is invalid.'
  [[ -f "$revision_path" && ! -L "$revision_path" && "$(cat -- "$revision_path")" == "$revision" ]] || fail 'Requested revision does not match the production source marker.'
  local release="$release_dir/$revision" archive_hash
  [[ -d "$release" && ! -L "$release" ]] || fail 'Accepted production release is missing or unsafe.'
  source_dir=$release
  [[ -f "$source_state_path" && ! -L "$source_state_path" ]] || fail 'Production source state marker is missing.'
  grep -Fxq 'source=verified-archive' "$source_state_path" || fail 'Production source state is invalid.'
  grep -Fxq 'branch=main' "$source_state_path" || fail 'Production source state is invalid.'
  grep -Fxq 'clean=true' "$source_state_path" || fail 'Production source state is invalid.'
  grep -Fxq 'ci=success' "$source_state_path" || fail 'Production source state is invalid.'
  grep -Fxq "revision=$revision" "$source_state_path" || fail 'Production source state does not match the requested revision.'
  archive_hash=$(awk -F= '$1 == "archive_sha256" { print substr($0, index($0, "=") + 1) }' "$source_state_path")
  [[ "$archive_hash" =~ ^[0-9a-f]{64}$ ]] || fail 'Production source archive marker is invalid.'
  grep -Fxq "revision=$revision" "$release/.virki-release" || fail 'Production release marker is invalid.'
  grep -Fxq "archive_sha256=$archive_hash" "$release/.virki-release" || fail 'Production release marker does not match its archive.'
  [[ -d "$source_dir" && -f "$source_dir/infra/docker-compose.prod.yml" && -f "$source_dir/infra/docker-compose.cloudflare.yml" ]] || fail 'Accepted production source is incomplete.'
  [[ -L "$source_dir/.env" && "$(readlink -- "$source_dir/.env")" == "$root/.env" ]] || fail 'Production source does not use the remote environment file.'
  [[ -L "$source_dir/.env.oidc" && "$(readlink -- "$source_dir/.env.oidc")" == "$root/.env.oidc" ]] || fail 'Production source does not use the remote OIDC environment file.'
  [[ -L "$source_dir/.env.oidc-data" && "$(readlink -- "$source_dir/.env.oidc-data")" == "$root/.env.oidc-data" ]] || fail 'Production source does not use the remote OIDC data-key file.'
}

assert_active_source() {
  [[ -L "$current_link" && "$(readlink -f -- "$current_link")" == "$source_dir" ]] || fail 'Active production source does not match the requested revision.'
}

verify_source_archive() {
  [[ "$revision" =~ ^[0-9a-f]{40}$ && "$archive_hash" =~ ^[0-9a-f]{64}$ && "$archive_id" =~ ^[0-9a-f]{24}$ ]] || fail 'Source archive identity is invalid.'
  local archive="$temp_dir/source-$revision-$archive_id.tar"
  [[ -f "$archive" && ! -L "$archive" ]] || fail 'Verified source archive is missing.'
  [[ "$(sha256sum -- "$archive" | awk '{print $1}')" == "$archive_hash" ]] || fail 'Source archive checksum does not match.'
  local listing entry
  listing=$(tar --list --verbose --quoting-style=c --file "$archive") || fail 'Source archive entries could not be inspected.'
  while IFS= read -r entry; do
    case "${entry:0:1}" in
      -|d) ;;
      *) fail 'Source archive contains a link or unsupported filesystem entry.' ;;
    esac
  done <<< "$listing"
}

verify_image_manifest() {
  [[ "$revision" =~ ^[0-9a-f]{40}$ && "$image_hash" =~ ^[0-9a-f]{64}$ && "$image_id" =~ ^[0-9a-f]{24}$ ]] || fail 'GHCR provenance identity is invalid.'
  local manifest="$temp_dir/images-$revision-$image_id.manifest"
  [[ -f "$manifest" && ! -L "$manifest" && "$(wc -c < "$manifest")" -le 512 ]] || fail 'Verified GHCR provenance manifest is missing or unsafe.'
  [[ "$(sha256sum -- "$manifest" | awk '{print $1}')" == "$image_hash" ]] || fail 'GHCR provenance manifest checksum does not match.'
  local -a fields=()
  mapfile -t fields < "$manifest"
  ((${#fields[@]} == 5)) || fail 'GHCR provenance manifest has an unexpected field count.'
  [[ "${fields[0]}" == "revision=$revision" && "${fields[1]}" =~ ^run_id=[1-9][0-9]*$ ]] || fail 'GHCR provenance source identity is invalid.'
  case "$(uname -m)" in
    x86_64) [[ "${fields[2]}" == 'platform=linux/amd64' ]] || fail 'GHCR provenance architecture mismatch.' ;;
    aarch64|arm64) [[ "${fields[2]}" == 'platform=linux/arm64' ]] || fail 'GHCR provenance architecture mismatch.' ;;
    *) fail 'Unsupported GHCR production architecture.' ;;
  esac
  [[ "${fields[3]}" =~ ^runtime_digest=sha256:[0-9a-f]{64}$ && "${fields[4]}" =~ ^migrator_digest=sha256:[0-9a-f]{64}$ ]] || fail 'GHCR provenance digest is invalid.'
}

load_production_images() {
  verify_image_manifest
  local manifest="$temp_dir/images-$revision-$image_id.manifest" auth_dir token="$root/.ghcr-read-token" image digest observed expected_platform role
  local -a fields=()
  mapfile -t fields < "$manifest"
  [[ -f "$token" && ! -L "$token" && "$(stat -c '%a' -- "$token")" == 600 && "$(stat -c '%u' -- "$token")" == "$(id -u)" ]] || fail 'Private GHCR read-only credential is missing or unsafe.'
  expected_platform=${fields[2]#platform=}
  auth_dir=$(mktemp -d "$temp_dir/.ghcr-auth.XXXXXXXX") || fail 'Could not allocate isolated registry credential directory.'
  (
    export DOCKER_CONFIG="$auth_dir"
    # Docker may create contexts/ and other files below this isolated directory.
    trap 'rm -rf -- "$auth_dir"' EXIT
    docker login ghcr.io --username bielxdh3 --password-stdin < "$token" >/dev/null 2>&1 || fail 'Private GHCR login failed.'
    for role in runtime migrator; do
      case "$role" in
        runtime) image='ghcr.io/bielxdh3/virki-runtime'; digest=${fields[3]#runtime_digest=} ;;
        migrator) image='ghcr.io/bielxdh3/virki-migrator'; digest=${fields[4]#migrator_digest=} ;;
      esac
      docker pull "$image@$digest" >/dev/null 2>&1 || fail 'Exact-digest GHCR image pull failed.'
      observed=$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}|{{index .Config.Labels "org.opencontainers.image.source"}}|{{.Os}}/{{.Architecture}}' "$image@$digest") || fail 'Exact-digest GHCR image identity could not be inspected.'
      [[ "$observed" == "$revision|https://github.com/bielxdh3/Virki|$expected_platform" ]] || fail 'GHCR image labels or architecture differ from accepted CI evidence.'
    done
    # Check both images before changing either accepted local alias.
    docker image tag "ghcr.io/bielxdh3/virki-runtime@${fields[3]#runtime_digest=}" "virki-production-ci:$revision" || fail 'Could not stage verified runtime image alias.'
    docker image tag "ghcr.io/bielxdh3/virki-migrator@${fields[4]#migrator_digest=}" "virki-migrator-ci:$revision" || fail 'Could not stage verified migrator image alias.'
  ) || fail 'Private GHCR image verification or credential cleanup failed.'
  rm -- "$manifest" || fail 'Verified GHCR provenance manifest could not be removed.'
}

compose_args() {
  printf '%s\0' \
    --progress quiet \
    --project-name virki-prod \
    --project-directory "$source_dir/infra" \
    --env-file "$root/.env" \
    -f "$source_dir/infra/docker-compose.prod.yml" \
    -f "$source_dir/infra/docker-compose.cloudflare.yml"
}

compose() {
  local -a args=()
  mapfile -d '' -t args < <(compose_args)
  docker compose "${args[@]}" "$@"
}

compose_with_override() {
  local override=$1
  shift
  local -a args=()
  mapfile -d '' -t args < <(compose_args)
  args+=(-f "$override")
  docker compose "${args[@]}" "$@"
}

assert_revisions() {
  local service container observed
  for service in public-site hub oidc-issuer session-cleanup email-worker; do
    local -a containers=()
    mapfile -t containers < <(compose ps -q "$service")
    ((${#containers[@]} == 1)) || fail "Production service $service is not running exactly once."
    container=${containers[0]}
    observed=$(docker inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$container")
    [[ "$observed" == "$revision" ]] || fail "Production service $service revision does not match the accepted source."
  done
  printf 'Production service revisions match %s.\n' "$revision"
}

assert_loopback_ports() {
  local service port binding
  for service in public-site hub; do
    port=3000
    [[ "$service" == hub ]] && port=3001
    binding=$(compose port "$service" "$port")
    local expected_port=${PUBLIC_SITE_PORT:-3000}
    [[ "$service" == hub ]] && expected_port=${HUB_PORT:-3001}
    [[ "$binding" == "127.0.0.1:$expected_port" ]] || fail "Production service $service is not bound to its expected loopback port."
    printf '%s port is loopback-bound.\n' "$service"
  done
}

verify_fresh_install_target() {
  local path entry source_marker_present=false revision_marker_present=false
  [[ ! -e "$current_link" && ! -L "$current_link" ]] || fail 'First install refused because a current release is already active.'
  [[ ! -e "$first_install_path" && ! -L "$first_install_path" ]] || fail 'First install has already been initialized or its marker path is occupied.'
  [[ ! -e "$maintenance_path" && ! -L "$maintenance_path" && ! -e "$verification_path" && ! -L "$verification_path" ]] || fail 'First install refused because production state markers already exist.'

  for path in "$source_state_path" "$revision_path"; do
    if [[ -e "$path" || -L "$path" ]]; then
      [[ -f "$path" && ! -L "$path" ]] || fail 'First install refused because a source state marker is unsafe.'
      [[ "$path" == "$source_state_path" ]] && source_marker_present=true
      [[ "$path" == "$revision_path" ]] && revision_marker_present=true
    fi
  done
  [[ "$source_marker_present" == "$revision_marker_present" ]] || fail 'First install refused because source state is incomplete.'
  for entry in "$release_dir"/*; do
    [[ -e "$entry" || -L "$entry" ]] || continue
    # A previously staged and verified exact revision may be reused safely.
    if [[ "$source_marker_present" == true && "$entry" == "$release_dir/$revision" && -d "$entry" && ! -L "$entry" ]]; then
      continue
    fi
    fail 'First install refused because an unrelated release already exists.'
  done
  [[ "$source_marker_present" == false ]] || verify_revision

  local backup_entry
  backup_entry=$(find "$backup_dir" -mindepth 1 -maxdepth 1 -print -quit) || fail 'First install could not inspect the backup directory.'
  [[ -z "$backup_entry" ]] || fail 'First install refused because the backup directory is not empty.'

  local project_containers project_volumes project_networks
  project_containers=$(docker ps --all --quiet --filter 'label=com.docker.compose.project=virki-prod') || fail 'First install could not inspect Virki project containers.'
  [[ -z "$project_containers" ]] || fail 'First install refused because Virki project containers already exist.'
  project_volumes=$(docker volume ls --filter 'name=virki-prod_virki_postgres_data' --format '{{.Name}}') || fail 'First install could not inspect the Virki PostgreSQL volume.'
  [[ -z "$project_volumes" ]] || fail 'First install refused because the Virki PostgreSQL volume already exists.'
  project_networks=$(docker network ls --filter 'name=virki-prod_default' --format '{{.Name}}') || fail 'First install could not inspect the Virki project network.'
  [[ -z "$project_networks" ]] || fail 'First install refused because the Virki project network already exists.'
}

verify_first_install_recovery_project() {
  local expected_revision=$1 alternate_revision=${2:-} container_id container_identity mounts mount_count consumers volume network members role_script alternate_role_script role_mounts_valid=false
  local state status exit_code running health
  local -a containers=()
  mapfile -t containers < <(docker ps --all --no-trunc --quiet --filter 'label=com.docker.compose.project=virki-prod') || fail 'First-install recovery could not inspect Virki containers.'
  ((${#containers[@]} == 1)) || fail 'First-install recovery requires exactly the existing Virki PostgreSQL container.'
  container_id=${containers[0]}
  [[ "$container_id" =~ ^[0-9a-f]{64}$ ]] || fail 'First-install PostgreSQL container identity is invalid.'
  container_identity=$(docker inspect --format '{{index .Config.Labels "com.docker.compose.project"}}|{{index .Config.Labels "com.docker.compose.service"}}|{{.Config.Image}}|{{.State.Status}}|{{.State.ExitCode}}|{{.State.Running}}' "$container_id") || fail 'First-install PostgreSQL container could not be inspected.'
  [[ "$container_identity" == 'virki-prod|postgres|postgres:17-alpine@sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24|running|0|true' || "$container_identity" == 'virki-prod|postgres|postgres:17-alpine@sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24|exited|0|false' ]] || fail 'First-install recovery PostgreSQL identity or stopped state does not match the approved partial install.'
  IFS='|' read -r _ _ _ status exit_code running <<< "$container_identity"
  if [[ "$running" == true ]]; then
    health=$(docker inspect --format '{{.State.Health.Status}}' "$container_id") || fail 'First-install PostgreSQL health could not be inspected.'
    [[ "$status" == running && "$health" == healthy ]] || fail 'First-install recovery requires its running PostgreSQL container to be healthy.'
  else
    [[ "$status" == exited && "$exit_code" == 0 ]] || fail 'First-install recovery only accepts its cleanly stopped PostgreSQL container.'
  fi

  mount_count=$(docker inspect --format '{{len .Mounts}}' "$container_id") || fail 'First-install PostgreSQL mount count could not be inspected.'
  [[ "$mount_count" == 2 ]] || fail 'First-install recovery refused because the PostgreSQL container has an unexpected mount.'
  mounts=$(docker inspect --format '{{range .Mounts}}{{.Type}}|{{.Name}}|{{.Source}}|{{.Destination}}|{{.RW}};{{end}}' "$container_id") || fail 'First-install PostgreSQL mounts could not be inspected.'
  role_script="$release_dir/$expected_revision/infra/postgres-init/10-virki-database-roles.sh"
  [[ "$mounts" == *"bind||$role_script|/docker-entrypoint-initdb.d/10-virki-database-roles.sh|false;"* ]] && role_mounts_valid=true
  if [[ -n "$alternate_revision" ]]; then
    alternate_role_script="$release_dir/$alternate_revision/infra/postgres-init/10-virki-database-roles.sh"
    [[ "$mounts" == *"bind||$alternate_role_script|/docker-entrypoint-initdb.d/10-virki-database-roles.sh|false;"* ]] && role_mounts_valid=true
  fi
  [[ "$role_mounts_valid" == true && "$mounts" == *"volume|$first_install_volume|/var/lib/docker/volumes/$first_install_volume/_data|/var/lib/postgresql/data|true;"* ]] || fail 'First-install recovery PostgreSQL mounts do not match the exact Virki release and database volume.'
  consumers=$(docker ps --all --no-trunc --quiet --filter "volume=$first_install_volume") || fail 'First-install PostgreSQL volume consumers could not be inspected.'
  [[ "$consumers" == "$container_id" ]] || fail 'First-install recovery refused because another container uses the PostgreSQL volume.'

  volume=$(docker volume inspect --format '{{.Name}}|{{index .Labels "com.docker.compose.project"}}|{{index .Labels "com.docker.compose.volume"}}' "$first_install_volume") || fail 'First-install PostgreSQL volume could not be inspected.'
  [[ "$volume" == "$first_install_volume|virki-prod|virki_postgres_data" ]] || fail 'First-install PostgreSQL volume labels do not match the isolated Virki project.'
  network=$(docker network inspect --format '{{.Name}}|{{index .Labels "com.docker.compose.project"}}' virki-prod_default) || fail 'First-install Virki network could not be inspected.'
  [[ "$network" == 'virki-prod_default|virki-prod' ]] || fail 'First-install Virki network labels do not match the isolated project.'
  members=$(docker network inspect --format '{{range .Containers}}{{.Name}}|{{end}}' virki-prod_default) || fail 'First-install Virki network members could not be inspected.'
  if [[ "$running" == true ]]; then
    [[ "$members" == 'virki-prod-postgres-1|' ]] || fail 'First-install recovery refused because another container uses the Virki network.'
  else
    [[ -z "$members" || "$members" == 'virki-prod-postgres-1|' ]] || fail 'First-install recovery refused because another container uses the Virki network.'
  fi
}

verify_first_install_recovery_release() {
  local release_revision=$1 expected_hash=$2 release_marker
  release_marker="$release_dir/$release_revision/.virki-release"
  [[ -d "$release_dir/$release_revision" && ! -L "$release_dir/$release_revision" ]] || fail 'First-install recovery release is missing or unsafe.'
  [[ -f "$release_marker" && ! -L "$release_marker" && "$(stat -c '%a' -- "$release_marker")" == 600 && "$(stat -c '%u' -- "$release_marker")" == "$(id -u)" && "$(wc -l < "$release_marker")" -eq 2 ]] || fail 'First-install recovery release marker is missing or unsafe.'
  grep -Fxq "revision=$release_revision" "$release_marker" && grep -Fxq "archive_sha256=$expected_hash" "$release_marker" || fail 'First-install recovery release marker does not match its source state.'
  [[ -L "$release_dir/$release_revision/.env" && "$(readlink -- "$release_dir/$release_revision/.env")" == "$root/.env" ]] || fail 'First-install recovery release does not use the protected production environment.'
  [[ -L "$release_dir/$release_revision/.env.oidc" && "$(readlink -- "$release_dir/$release_revision/.env.oidc")" == "$root/.env.oidc" ]] || fail 'First-install recovery release does not use the protected OIDC environment.'
  [[ -L "$release_dir/$release_revision/.env.oidc-data" && "$(readlink -- "$release_dir/$release_revision/.env.oidc-data")" == "$root/.env.oidc-data" ]] || fail 'First-install recovery release does not use the protected OIDC data-key file.'
}

write_first_install_recovery_marker() {
  local phase=$1 marker_tmp="$recovery_path.tmp.$$"
  [[ "$phase" == prepared || "$phase" == database-verified ]] || fail 'First-install recovery checkpoint phase is invalid.'
  [[ "$recovery_prior_revision" =~ ^[0-9a-f]{40}$ && "$revision" =~ ^[0-9a-f]{40}$ && "$recovery_archive_hash" =~ ^[0-9a-f]{64}$ ]] || fail 'First-install recovery checkpoint identity is invalid.'
  if [[ -e "$recovery_path" || -L "$recovery_path" ]]; then
    [[ -f "$recovery_path" && ! -L "$recovery_path" && "$(stat -c '%a' -- "$recovery_path")" == 600 && "$(stat -c '%u' -- "$recovery_path")" == "$(id -u)" ]] || fail 'First-install recovery checkpoint is unsafe.'
  fi
  [[ ! -e "$marker_tmp" && ! -L "$marker_tmp" ]] || fail 'First-install recovery checkpoint temporary path is already occupied.'
  {
    printf 'prior_revision=%s\n' "$recovery_prior_revision"
    printf 'revision=%s\n' "$revision"
    printf 'archive_sha256=%s\n' "$recovery_archive_hash"
    printf 'phase=%s\n' "$phase"
  } > "$marker_tmp"
  chmod 600 -- "$marker_tmp"
  mv -fT -- "$marker_tmp" "$recovery_path" || fail 'First-install recovery checkpoint could not be updated atomically.'
}

verify_first_install_recovery_target() {
  local path= entry= source_revision= source_hash= state_hash= prior_hash= prior_release_marker= current_target= accepted_release_present=false progress_present=false
  local -a releases=() root_entries=() checkpoint_lines=()
  [[ ! -e "$first_install_path" && ! -L "$first_install_path" ]] || fail 'First-install recovery refused because its completion marker already exists.'
  [[ ! -e "$maintenance_path" && ! -L "$maintenance_path" ]] || fail 'First-install recovery refused because maintenance is active.'
  verify_first_install_recovery_backups
  [[ -f "$source_state_path" && ! -L "$source_state_path" && -f "$revision_path" && ! -L "$revision_path" ]] || fail 'First-install recovery requires the exact retained partial-install source markers.'
  [[ "$(stat -c '%a' -- "$source_state_path")" == 600 && "$(stat -c '%a' -- "$revision_path")" == 600 && "$(stat -c '%u' -- "$source_state_path")" == "$(id -u)" && "$(stat -c '%u' -- "$revision_path")" == "$(id -u)" ]] || fail 'First-install recovery source marker permissions are unsafe.'
  source_revision=$(cat -- "$revision_path")
  if [[ -e "$recovery_path" || -L "$recovery_path" ]]; then
    [[ -f "$recovery_path" && ! -L "$recovery_path" && "$(stat -c '%a' -- "$recovery_path")" == 600 && "$(stat -c '%u' -- "$recovery_path")" == "$(id -u)" && "$(wc -l < "$recovery_path")" -eq 4 ]] || fail 'First-install recovery checkpoint is missing or unsafe.'
    mapfile -t checkpoint_lines < "$recovery_path"
    [[ "${checkpoint_lines[0]}" =~ ^prior_revision=([0-9a-f]{40})$ ]] || fail 'First-install recovery checkpoint has an invalid predecessor revision.'
    recovery_prior_revision=${BASH_REMATCH[1]}
    [[ "${checkpoint_lines[1]}" == "revision=$revision" && "${checkpoint_lines[2]}" =~ ^archive_sha256=([0-9a-f]{64})$ ]] || fail 'First-install recovery checkpoint does not match the accepted recovery source.'
    recovery_archive_hash=${BASH_REMATCH[1]}
    [[ "${checkpoint_lines[3]}" =~ ^phase=(prepared|database-verified)$ ]] || fail 'First-install recovery checkpoint phase is invalid.'
    recovery_phase=${BASH_REMATCH[1]}
    progress_present=true
  else
    recovery_prior_revision=$source_revision
    recovery_archive_hash=$archive_hash
    recovery_phase=prepared
    [[ "$recovery_archive_hash" =~ ^[0-9a-f]{64}$ ]] || fail 'First-install recovery source archive identity is invalid.'
  fi
  [[ "$recovery_prior_revision" =~ ^[0-9a-f]{40}$ && "$recovery_prior_revision" != "$revision" ]] || fail 'First-install recovery source revision is invalid or already matches the requested revision.'
  [[ "$source_revision" == "$recovery_prior_revision" || "$source_revision" == "$revision" ]] || fail 'First-install recovery source markers do not match the recorded transaction.'
  [[ "$(wc -l < "$source_state_path")" -eq 6 ]] || fail 'First-install recovery source marker has an unexpected shape.'
  grep -Fxq 'source=verified-archive' "$source_state_path" && grep -Fxq 'branch=main' "$source_state_path" && grep -Fxq 'clean=true' "$source_state_path" && grep -Fxq 'ci=success' "$source_state_path" || fail 'First-install recovery source marker does not identify an accepted source.'
  if [[ "$source_revision" == "$recovery_prior_revision" ]]; then
    grep -Fxq "revision=$recovery_prior_revision" "$source_state_path" || fail 'First-install recovery predecessor source marker is inconsistent.'
    state_hash=$(awk -F= '$1 == "archive_sha256" { print substr($0, index($0, "=") + 1) }' "$source_state_path")
    [[ "$state_hash" =~ ^[0-9a-f]{64}$ ]] || fail 'First-install recovery predecessor source archive marker is invalid.'
  else
    grep -Fxq "revision=$revision" "$source_state_path" || fail 'First-install recovery accepted source marker is inconsistent.'
    source_hash=$(awk -F= '$1 == "archive_sha256" { print substr($0, index($0, "=") + 1) }' "$source_state_path")
    [[ "$source_hash" == "$recovery_archive_hash" ]] || fail 'First-install recovery accepted archive marker differs from its checkpoint.'
  fi
  prior_release_marker="$release_dir/$recovery_prior_revision/.virki-release"
  [[ -f "$prior_release_marker" && ! -L "$prior_release_marker" ]] || fail 'First-install recovery predecessor release marker is missing or unsafe.'
  prior_hash=$(awk -F= '$1 == "archive_sha256" { print substr($0, index($0, "=") + 1) }' "$prior_release_marker")
  [[ "$prior_hash" =~ ^[0-9a-f]{64}$ ]] || fail 'First-install recovery predecessor archive marker is invalid.'
  verify_first_install_recovery_release "$recovery_prior_revision" "$prior_hash"
  [[ "$source_revision" != "$recovery_prior_revision" || "$state_hash" == "$prior_hash" ]] || fail 'First-install recovery predecessor source and release markers differ.'
  if [[ -d "$release_dir/$revision" || -L "$release_dir/$revision" ]]; then
    verify_first_install_recovery_release "$revision" "$recovery_archive_hash"
    accepted_release_present=true
  fi
  [[ "$source_revision" != "$revision" || "$accepted_release_present" == true ]] || fail 'First-install recovery accepted release is missing.'
  if [[ -e "$current_link" || -L "$current_link" ]]; then
    [[ "$progress_present" == true && -L "$current_link" && "$accepted_release_present" == true ]] || fail 'First-install recovery refused because a current release is active.'
    current_target=$(readlink -f -- "$current_link") || fail 'First-install recovery current release link is invalid.'
    [[ "$current_target" == "$release_dir/$revision" ]] || fail 'First-install recovery current release does not match its checkpoint.'
  fi
  mapfile -t releases < <(find "$release_dir" -mindepth 1 -maxdepth 1 -type d -printf '%f\n') || fail 'First-install recovery release inventory failed.'
  if [[ "$accepted_release_present" == true ]]; then
    [[ ${#releases[@]} -eq 2 && " ${releases[*]} " == *" $recovery_prior_revision "* && " ${releases[*]} " == *" $revision "* ]] || fail 'First-install recovery refused because the release directory contains unexpected entries.'
  else
    [[ ${#releases[@]} -eq 1 && "${releases[0]}" == "$recovery_prior_revision" ]] || fail 'First-install recovery refused because the release directory contains unexpected entries.'
  fi
  entry=$(find "$release_dir" -mindepth 1 -maxdepth 1 ! -type d -print -quit) || fail 'First-install recovery release inventory failed.'
  [[ -z "$entry" ]] || fail 'First-install recovery refused because the release directory contains a non-directory entry.'
  mapfile -t root_entries < <(find "$root" -mindepth 1 -maxdepth 1 ! -name '.*' -printf '%f\n') || fail 'First-install recovery production-root inventory failed.'
  for entry in "${root_entries[@]}"; do
    case "$entry" in
      backups|releases|.deploy-tmp) ;;
      current)
        [[ "$progress_present" == true && "$accepted_release_present" == true ]] || fail 'First-install recovery refused because a current release exists without a verified checkpoint.'
        ;;
      *) fail 'First-install recovery refused because the production root contains an unexpected entry.' ;;
    esac
  done

  for path in "$root"/.[!.]*; do
    [[ -e "$path" || -L "$path" ]] || continue
    case "${path##*/}" in
      .env|.env.oidc|.env.oidc-data|.ghcr-read-token|.virki-production-host|.virki-deploy-revision|.virki-source-state|.virki-migration-verification|.virki-first-install-recovery|.virki-operations.lock|.deploy-tmp) ;;
      .env.pre-external-reuse.*)
        [[ -f "$path" && ! -L "$path" && "$(stat -c '%a' -- "$path")" == 600 && "$(stat -c '%u' -- "$path")" == "$(id -u)" ]] || fail 'First-install recovery found an unsafe protected backup file.'
        ;;
      *) fail 'First-install recovery refused because the production root contains an unexpected hidden entry.' ;;
    esac
  done
  verify_first_install_recovery_project "$recovery_prior_revision" "$revision"
  if [[ "$progress_present" == false ]]; then
    verify_source_archive
    verify_image_manifest
    write_first_install_recovery_marker prepared
  fi
  printf 'Verified the exact retained partial first-install target and its exclusive Virki PostgreSQL resources.\n'
}

verify_first_install_marker() {
  [[ -f "$first_install_path" && ! -L "$first_install_path" && "$(stat -c '%a' -- "$first_install_path")" == 600 && "$(stat -c '%u' -- "$first_install_path")" == "$(id -u)" ]] || fail 'Virki first-install marker is missing or unsafe.'
  local -a lines=()
  mapfile -t lines < "$first_install_path"
  [[ ${#lines[@]} -eq 4 && "${lines[0]}" == "revision=$revision" && "${lines[1]}" == 'compose_project=virki-prod' && "${lines[2]}" == "database_volume=$first_install_volume" && "${lines[3]}" == 'migrations=verified' ]] || fail 'Virki first-install marker does not match the accepted source and isolated database.'
}

verify_first_install_volume() {
  local metadata
  metadata=$(docker volume inspect --format '{{.Name}}|{{index .Labels "com.docker.compose.project"}}|{{index .Labels "com.docker.compose.volume"}}' "$first_install_volume") || fail 'Virki PostgreSQL volume could not be verified.'
  [[ "$metadata" == "$first_install_volume|virki-prod|virki_postgres_data" ]] || fail 'Virki PostgreSQL volume identity does not match the isolated project.'
}

wait_for_virki_postgres() {
  local attempt container health output
  for ((attempt = 0; attempt < 60; attempt += 1)); do
    output=$(compose ps -q postgres) || fail 'Virki PostgreSQL container could not be inspected.'
    mapfile -t containers <<< "$output"
    if ((${#containers[@]} == 1)) && [[ -n "${containers[0]}" ]]; then
      container=${containers[0]}
      health=$(docker inspect --format '{{.State.Running}}|{{.State.Status}}|{{.State.Health.Status}}' "$container") || fail 'Virki PostgreSQL health state could not be inspected.'
      [[ "$health" == 'true|running|healthy' ]] && return 0
      [[ "$health" != *'|unhealthy' ]] || fail 'Fresh Virki PostgreSQL did not become healthy.'
    fi
    sleep 2
  done
  fail 'Fresh Virki PostgreSQL did not become healthy within the bounded wait.'
}

verify_first_install_role_contract() {
  local container=${1:-} role_attributes privileges sql
  sql="SELECT CASE WHEN count(*) = 3 AND bool_and(rolcanlogin AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication AND NOT rolbypassrls AND NOT rolinherit) THEN 'valid' ELSE 'invalid' END FROM pg_roles WHERE rolname IN ('virki_runtime', 'virki_migrator', 'virki_audit_maintenance')"
  role_attributes=$(if [[ -n "$container" ]]; then clone_query "$container" "$sql"; else database_query "$sql"; fi)
  [[ "$role_attributes" == valid ]] || fail 'Fresh Virki database role attributes do not match the least-privilege contract.'
  sql="SELECT CASE WHEN has_table_privilege('virki_runtime', 'public.\"User\"', 'INSERT') AND NOT has_database_privilege('virki_runtime', current_database(), 'CREATE') AND NOT has_schema_privilege('virki_runtime', 'public', 'CREATE') AND NOT has_table_privilege('virki_runtime', 'public.\"AuditLog\"', 'UPDATE') AND NOT has_table_privilege('virki_runtime', 'public.\"AuditLog\"', 'DELETE') AND (SELECT pg_get_userbyid(relowner) = 'virki_migrator' FROM pg_class WHERE oid = 'public.\"User\"'::regclass) AND has_table_privilege('virki_audit_maintenance', 'public.\"AuditLog\"', 'DELETE') AND has_column_privilege('virki_audit_maintenance', 'public.\"AuditLog\"', 'createdAt', 'SELECT') AND NOT has_table_privilege('virki_audit_maintenance', 'public.\"AuditLog\"', 'SELECT') THEN 'valid' ELSE 'invalid' END"
  privileges=$(if [[ -n "$container" ]]; then clone_query "$container" "$sql"; else database_query "$sql"; fi)
  [[ "$privileges" == valid ]] || fail 'Fresh Virki database grants do not match the least-privilege contract.'
}

apply_first_install_database_roles() {
  local role_script="$source_dir/infra/postgres-init/10-virki-database-roles.sh"
  [[ -f "$role_script" && ! -L "$role_script" && "$(stat -c '%a' -- "$role_script")" == 644 ]] || fail 'Accepted Virki PostgreSQL role initializer is missing or unsafe.'
  compose exec -T postgres sh -s < "$role_script" >/dev/null 2>&1 || fail 'Virki database role initialization could not be applied to the accepted PostgreSQL cluster.'
}

verify_migrator_tcp_authentication() {
  local result
  result=$(migrator_network_authentication_result) || fail 'Virki migrator network authentication probe could not be run safely.'
  [[ "$result" == AUTH=PASS ]] || fail 'Virki migrator could not authenticate to PostgreSQL over the isolated Docker network.'
  printf 'Virki migrator authenticated over the isolated Docker network with the configured database credential.\n'
}

migrator_network_authentication_result() {
  local result probe
  probe=$(cat <<'JS'
let client;
function classify(error) {
  const message = String(error?.message ?? "").toLowerCase();
  if (error?.code === "P1000" || /password authentication failed|authentication failed|invalid credentials/u.test(message)) return "CREDENTIALS_REJECTED";
  if (error?.code === "P1010" || /no pg_hba\.conf entry/u.test(message)) return "ACCESS_RULE_REJECTED";
  if (error?.code === "P1001" || /econnrefused|connection refused|timed out|connect timeout/u.test(message)) return "TCP_UNAVAILABLE";
  return "UNCLASSIFIED";
}
try {
  const url = new URL(process.env.MIGRATION_DATABASE_URL);
  if (url.protocol !== "postgresql:" || url.username !== "virki_migrator" || url.hostname !== "postgres" || url.port !== "5432" || url.pathname !== "/virki") {
    process.stdout.write("AUTH=FAIL:TARGET_MISMATCH");
  } else {
    const { PrismaClient } = await import("@prisma/client");
    client = new PrismaClient({ datasources: { db: { url: process.env.MIGRATION_DATABASE_URL } }, log: [] });
    const rows = await client.$queryRaw`SELECT current_user AS role, current_database() AS database`;
    process.stdout.write(rows.length === 1 && rows[0].role === "virki_migrator" && rows[0].database === "virki" ? "AUTH=PASS" : "AUTH=WRONG_ROLE");
  }
} catch (error) {
  process.stdout.write(`AUTH=FAIL:${classify(error)}`);
} finally {
  if (client) await client.$disconnect().catch(() => {});
}
JS
)
  result=$(compose --profile migration run --rm --no-deps --entrypoint node migrate --input-type=module -e "$probe" 2>/dev/null) || fail 'Virki migrator network authentication probe could not be run safely.'
  [[ "$result" == AUTH=PASS || "$result" == AUTH=WRONG_ROLE || "$result" =~ ^AUTH=FAIL:(TARGET_MISMATCH|CREDENTIALS_REJECTED|ACCESS_RULE_REJECTED|TCP_UNAVAILABLE|UNCLASSIFIED)$ ]] || fail 'Virki migrator network authentication probe returned an unexpected status.'
  printf '%s\n' "$result"
}

report_first_install_migrator_pre_reconcile_state() {
  local result role_state
  result=$(migrator_network_authentication_result) || fail 'Pre-recovery migrator authentication state could not be classified safely.'
  if [[ "$result" == AUTH=PASS ]]; then
    printf 'Pre-recovery migrator diagnosis: configured credentials already authenticated over the Docker network.\n'
    return 0
  fi
  role_state=$(database_query "SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'virki_migrator') THEN 'role-absent' WHEN NOT (SELECT rolcanlogin FROM pg_roles WHERE rolname = 'virki_migrator') THEN 'role-no-login' WHEN NOT (SELECT rolpassword IS NOT NULL FROM pg_authid WHERE rolname = 'virki_migrator') THEN 'role-without-password' ELSE 'login-role-has-persisted-credential' END")
  case "$result|$role_state" in
    AUTH=FAIL:CREDENTIALS_REJECTED\|login-role-has-persisted-credential)
      printf 'Pre-recovery migrator diagnosis: configured credential was rejected by PostgreSQL for an existing LOGIN role; the persisted role credential differed from the configured connection credential.\n'
      ;;
    AUTH=FAIL:CREDENTIALS_REJECTED\|role-no-login)
      printf 'Pre-recovery migrator diagnosis: the persisted virki_migrator role did not allow LOGIN.\n'
      ;;
    AUTH=FAIL:CREDENTIALS_REJECTED\|role-absent)
      printf 'Pre-recovery migrator diagnosis: the persisted virki_migrator role was absent.\n'
      ;;
    AUTH=FAIL:CREDENTIALS_REJECTED\|role-without-password)
      printf 'Pre-recovery migrator diagnosis: the persisted virki_migrator role had no password credential.\n'
      ;;
    *)
      printf 'Pre-recovery migrator diagnosis: network authentication failed with a non-credential status; role metadata=%s.\n' "$role_state"
      ;;
  esac
}

write_first_install_marker() {
  local temporary="$first_install_path.tmp.$$"
  [[ ! -e "$first_install_path" && ! -L "$first_install_path" && ! -e "$temporary" && ! -L "$temporary" ]] || fail 'Virki first-install marker path is already occupied.'
  {
    printf 'revision=%s\n' "$revision"
    printf 'compose_project=virki-prod\n'
    printf 'database_volume=%s\n' "$first_install_volume"
    printf 'migrations=verified\n'
  } > "$temporary" || fail 'Virki first-install marker could not be written.'
  chmod 600 -- "$temporary" || fail 'Virki first-install marker permissions could not be set.'
  ln -- "$temporary" "$first_install_path" || fail 'Virki first-install marker could not be created without overwriting existing state.'
  rm -- "$temporary" || fail 'Temporary Virki first-install marker could not be removed.'
  verify_first_install_marker
}

assert_staging_ports_available() {
  local port listeners
  for port in 13000 13001; do
    listeners=$(ss -H -ltn "sport = :$port") || fail 'Staging listener ports could not be inspected.'
    [[ -z "$listeners" ]] || fail 'Virki staging loopback port is already occupied.'
  done
}

assert_tunnel_stopped() {
  local running
  running=$(docker ps --filter 'label=com.docker.compose.project=virki-prod' --filter 'label=com.docker.compose.service=cloudflared' --quiet) || fail 'Virki Tunnel state could not be inspected.'
  [[ -z "$running" ]] || fail 'Virki staging requires its Cloudflare Tunnel connector to remain stopped.'
}

stop_stage_after_failure() {
  local original_status=$1
  trap - EXIT
  set +e
  compose stop "${application_services[@]}" >/dev/null 2>&1
  printf '%s\n' 'Virki staging health check failed; only Virki application services were stopped. Database volume and Tunnel state were preserved.' >&2
  exit "$original_status"
}

is_valid_dns_hostname() {
  local hostname=$1
  [[ "${#hostname}" -le 253 && "$hostname" =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$ ]]
}

assert_health() {
  local public_response hub_response discovery_response access_response
  local public_status hub_status discovery_status access_status
  local public_binding hub_binding portal_hostname hub_hostname oidc_issuer
  public_binding=$(compose port public-site 3000)
  hub_binding=$(compose port hub 3001)
  [[ "$public_binding" =~ ^127\.0\.0\.1:[0-9]+$ && "$hub_binding" =~ ^127\.0\.0\.1:[0-9]+$ ]] || fail 'Production application port binding is not loopback-only.'
  portal_hostname=$(compose exec -T hub node -e 'process.stdout.write(process.env.VIRKI_PORTAL_HOSTNAME ?? "")') || fail 'Configured portal host could not be read.'
  hub_hostname=$(compose exec -T hub node -e 'process.stdout.write(process.env.VIRKI_HUB_HOSTNAME ?? "")') || fail 'Configured Hub host could not be read.'
  oidc_issuer=$(compose exec -T oidc-issuer node -e 'process.stdout.write(process.env.VIRKI_OIDC_ISSUER ?? "")') || fail 'Configured OIDC issuer could not be read.'
  is_valid_dns_hostname "$portal_hostname" && is_valid_dns_hostname "$hub_hostname" && [[ "$oidc_issuer" == "https://$portal_hostname" ]] || fail 'Configured application hosts or OIDC issuer are invalid.'
  public_response=$(curl --silent --show-error --max-time 10 --dump-header - --output /dev/null --write-out $'\nVIRKI_STATUS:%{http_code}' "http://$public_binding") || fail 'Public site health request failed.'
  hub_response=$(curl --silent --show-error --max-time 10 --dump-header - --output /dev/null --write-out $'\nVIRKI_STATUS:%{http_code}' --header "Host: $hub_hostname" "http://$hub_binding/api/health") || fail 'Hub health request failed.'
  discovery_response=$(curl --silent --show-error --max-time 10 --dump-header - --write-out $'\nVIRKI_STATUS:%{http_code}' --header "Host: $portal_hostname" "http://$hub_binding/.well-known/openid-configuration") || fail 'Portal OIDC discovery request failed.'
  access_response=$(curl --silent --show-error --max-time 10 --dump-header - --output /dev/null --write-out $'\nVIRKI_STATUS:%{http_code}' --header "Host: $hub_hostname" --header 'cf-access-jwt-assertion: forged-staging-probe' "http://$hub_binding/admin/accounts") || fail 'Hub Access boundary request failed.'
  public_status=${public_response##*$'\nVIRKI_STATUS:'}
  hub_status=${hub_response##*$'\nVIRKI_STATUS:'}
  discovery_status=${discovery_response##*$'\nVIRKI_STATUS:'}
  access_status=${access_response##*$'\nVIRKI_STATUS:'}
  [[ "$public_status" == 200 && "$hub_status" == 200 && "$access_status" == 403 ]] || fail 'Production health or ADMIN boundary check failed.'
  [[ "$discovery_status" == 200 ]] || fail 'Portal OIDC discovery request returned an unexpected status.'
  [[ "$discovery_response" == *"\"issuer\":\"$oidc_issuer\""* && "$discovery_response" == *'"S256"'* && "$discovery_response" == *'"code"'* ]] || fail 'Portal discovery profile does not match the expected OIDC issuer.'
  assert_production_response_headers "$public_response" 'no-referrer'
  assert_production_response_headers "$hub_response" 'strict-origin'
  # OIDC discovery is proxied from the issuer, whose stricter policy is
  # no-referrer (unlike the Hub's strict-origin policy). Preserve that
  # issuer-owned header and validate it exactly, never weaken the response.
  assert_production_response_headers "$discovery_response" 'no-referrer'
  assert_production_response_headers "$access_response" 'strict-origin'
  printf 'Public site, Hub health, portal OIDC discovery, security headers, cookie boundary, and unauthenticated ADMIN denial are healthy.\n'
}

assert_production_response_headers() {
  local response=$1 expected_referrer=$2 headers
  headers=${response%$'\nVIRKI_STATUS:'*}
  # curl's -D - output includes the JSON body; only the header section is trusted here.
  headers=${headers%%$'\r\n\r\n'*}
  headers=${headers%%$'\n\n'*}
  awk -F: -v expected_referrer="$expected_referrer" '
    function frame_ancestors_deny_only(policy,     directives, count, i, directive, found) {
      count = split(policy, directives, ";")
      found = 0
      for (i = 1; i <= count; i++) {
        directive = directives[i]
        sub(/^[[:space:]]+/, "", directive)
        sub(/[[:space:]]+$/, "", directive)
        if (directive ~ /^frame-ancestors([[:space:]]|$)/) {
          found++
          if (directive != sprintf("frame-ancestors %cnone%c", 39, 39)) return 0
        }
      }
      return found == 1
    }
    {
      key = tolower($1)
      value = substr($0, index($0, ":") + 1)
      sub(/^[[:space:]]+/, "", value)
      sub(/\r$/, "", value)
      if (key == "content-security-policy") { csp = value; csp_count++ }
      else if (key == "permissions-policy") { permissions = value; permissions_count++ }
      else if (key == "referrer-policy") { referrer = value; referrer_count++ }
      else if (key == "strict-transport-security") { hsts = value; hsts_count++ }
      else if (key == "x-content-type-options") { nosniff = value; nosniff_count++ }
      else if (key == "x-frame-options") { frame = value; frame_count++ }
    }
    END {
      exit !(frame_ancestors_deny_only(csp) && csp_count == 1 &&
        permissions == "camera=(), geolocation=(), microphone=()" && permissions_count == 1 &&
        referrer == expected_referrer && referrer_count == 1 &&
        hsts == "max-age=31536000" && hsts_count == 1 &&
        nosniff == "nosniff" && nosniff_count == 1 && frame == "DENY" && frame_count == 1)
    }
  ' <<< "$headers" || fail 'Virki staging response security headers are missing, duplicated, or invalid.'
  ! grep -Eiq '^set-cookie[[:space:]]*:' <<< "$headers" || fail 'Unauthenticated Virki staging response unexpectedly set a cookie.'
}

database_query() {
  local sql=$1
  compose exec -T postgres sh -lc 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -At -v ON_ERROR_STOP=1' <<< "$sql"
}

verify_empty_first_install_recovery_database() {
  local state
  state=$(database_query "SELECT CASE WHEN current_database() <> 'virki' OR NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'virki_bootstrap' AND rolsuper AND rolcreatedb AND rolcreaterole) OR EXISTS (SELECT 1 FROM pg_roles WHERE rolname !~ '^pg_' AND rolname NOT IN ('postgres', 'virki_bootstrap', 'virki_runtime', 'virki_migrator', 'virki_audit_maintenance')) OR EXISTS (SELECT 1 FROM pg_database WHERE datname NOT IN ('template0', 'template1', 'postgres', 'virki')) OR EXISTS (SELECT 1 FROM pg_namespace WHERE nspname NOT IN ('pg_catalog', 'information_schema', 'public') AND nspname NOT LIKE 'pg_toast%') OR EXISTS (SELECT 1 FROM pg_extension WHERE extname NOT IN ('plpgsql', 'pgcrypto')) THEN 'unexpected-state' WHEN NOT EXISTS (SELECT 1 FROM pg_class AS relation JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace WHERE namespace.nspname = 'public' AND relation.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')) AND NOT EXISTS (SELECT 1 FROM pg_extension WHERE extname NOT IN ('plpgsql', 'pgcrypto')) THEN 'empty-partial' WHEN EXISTS (SELECT 1 FROM pg_class AS relation JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace WHERE namespace.nspname = 'public' AND relation.relname = '_prisma_migrations' AND relation.relkind = 'r') THEN 'migrated-candidate' ELSE 'unexpected-state' END")
  case "$state" in
    empty-partial|migrated-candidate) recovery_database_state=$state ;;
    *) fail 'First-install recovery refused because the Virki database contains an unknown or partially migrated state.' ;;
  esac
  if [[ "$state" == empty-partial ]]; then printf 'Verified the partial Virki database contains no application schema or user data.\n'; fi
}

verify_first_install_recovery_has_no_application_rows() {
  local sql
  sql=$(cat <<'SQL'
DO $$
DECLARE candidate record; contains_rows boolean;
BEGIN
  FOR candidate IN
    SELECT tablename FROM pg_tables
    WHERE schemaname = 'public' AND tablename <> '_prisma_migrations'
  LOOP
    EXECUTE format('SELECT EXISTS (SELECT 1 FROM %I.%I LIMIT 1)', 'public', candidate.tablename)
      INTO contains_rows;
    IF contains_rows THEN
      RAISE EXCEPTION 'First-install recovery found application rows; manual review is required.';
    END IF;
  END LOOP;
END
$$;
SQL
)
  database_query "$sql" >/dev/null || fail 'First-install recovery refused because the migrated Virki database contains application rows.'
}

clone_query() {
  local container=$1 sql=$2
  docker exec -i "$container" psql -U virki_runtime -d virki_restore -At -v ON_ERROR_STOP=1 <<< "$sql"
}

clone_migration_query() {
  local container=$1 sql=$2
  [[ "${migrator_password:-}" =~ ^[a-f0-9]{64}$ ]] || fail 'Disposable migration role credential is unavailable.'
  local -x PGPASSWORD="$migrator_password"
  docker exec -i --env PGPASSWORD "$container" psql --host 127.0.0.1 -U virki_migrator -d virki_restore -At -v ON_ERROR_STOP=1 <<< "$sql"
}

current_migration_names() {
  local migration_root="$source_dir/$migration_directory"
  local migration_path migration_file migration_name legacy_name found_baseline=false
  local -a names=()
  [[ -d "$migration_root" && ! -L "$migration_root" ]] || fail 'Committed migration directory is missing or unsafe.'
  for migration_path in "$migration_root"/*; do
    [[ -d "$migration_path" ]] || continue
    [[ ! -L "$migration_path" ]] || fail 'Committed migration directory contains an unsafe link.'
    migration_file="$migration_path/migration.sql"
    [[ -f "$migration_file" && ! -L "$migration_file" ]] || fail 'Committed migration SQL is missing or unsafe.'
    migration_name=${migration_path##*/}
    [[ "$migration_name" =~ ^[A-Za-z0-9_]+$ ]] || fail 'Committed migration name is invalid.'
    [[ "$migration_name" != "$transition_migration_name" ]] || fail 'Baseline migration source still contains the retired transition migration.'
    for legacy_name in "${legacy_transition_migrations[@]}"; do
      [[ "$migration_name" != "$legacy_name" ]] || fail 'Baseline migration source still contains retired migration history.'
    done
    [[ "$migration_name" == 0_init ]] && found_baseline=true
    names+=("$migration_name")
  done
  [[ "$found_baseline" == true && ${#names[@]} -gt 0 ]] || fail 'Committed baseline migration is missing.'
  printf '%s\n' "${names[@]}"
}

migration_sql_name_list() {
  local name result='' separator=''
  for name in "$@"; do
    [[ "$name" =~ ^[A-Za-z0-9_]+$ ]] || fail 'Migration history allowlist contains an invalid name.'
    result+="$separator'$name'"
    separator=','
  done
  [[ -n "$result" ]] || fail 'Migration history allowlist is empty.'
  printf '%s\n' "$result"
}

migration_history_name_set() {
  local name result='' separator=''
  while IFS= read -r name; do
    [[ -n "$name" ]] || continue
    result+="$separator$name"
    separator=','
  done < <(printf '%s\n' "$@" | LC_ALL=C sort)
  printf '%s\n' "$result"
}

migration_history_names() {
  local container=$1 sql
  sql=$(cat <<'SQL'
SELECT COALESCE(string_agg("migration_name", ',' ORDER BY "migration_name" COLLATE "C"), '')
FROM "_prisma_migrations"
SQL
)
  if [[ -n "$container" ]]; then
    clone_migration_query "$container" "$sql"
  else
    database_query "$sql"
  fi
}

migration_history_summary() {
  local container=$1 legacy_names=$2 allowed_names=$3 sql
  sql=$(cat <<SQL
SELECT
  count(*)::text || '|' ||
  count(*) FILTER (WHERE "finished_at" IS NOT NULL AND "rolled_back_at" IS NULL)::text || '|' ||
  count(*) FILTER (WHERE "finished_at" IS NULL AND "rolled_back_at" IS NULL)::text || '|' ||
  count(*) FILTER (WHERE "rolled_back_at" IS NOT NULL)::text || '|' ||
  count(DISTINCT "migration_name")::text || '|' ||
  count(*) FILTER (WHERE "migration_name" = '0_init')::text || '|' ||
  count(*) FILTER (WHERE "migration_name" = '$transition_migration_name')::text || '|' ||
  count(*) FILTER (WHERE "migration_name" IN ($legacy_names))::text || '|' ||
  count(*) FILTER (WHERE "migration_name" IS NULL OR "migration_name" NOT IN ($allowed_names))::text
FROM "_prisma_migrations"
SQL
)
  if [[ -n "$container" ]]; then
    clone_migration_query "$container" "$sql"
  else
    database_query "$sql"
  fi
}

migration_history_is_clean_baseline() {
  local summary=$1 total applied unfinished rolled_back distinct baseline transition legacy unknown
  [[ "$summary" =~ ^([0-9]+)\|([0-9]+)\|([0-9]+)\|([0-9]+)\|([0-9]+)\|([0-9]+)\|([0-9]+)\|([0-9]+)\|([0-9]+)$ ]] || return 1
  total=${BASH_REMATCH[1]}
  applied=${BASH_REMATCH[2]}
  unfinished=${BASH_REMATCH[3]}
  rolled_back=${BASH_REMATCH[4]}
  distinct=${BASH_REMATCH[5]}
  baseline=${BASH_REMATCH[6]}
  transition=${BASH_REMATCH[7]}
  legacy=${BASH_REMATCH[8]}
  unknown=${BASH_REMATCH[9]}
  [[ "$total" -gt 0 && "$total" == "$applied" && "$unfinished" == 0 && "$rolled_back" == 0 && "$distinct" == "$total" && "$baseline" == 1 && "$transition" == 0 && "$legacy" == 0 && "$unknown" == 0 ]]
}

migration_history_is_current_prefix() {
  local history_names=$1 current_name expected
  shift
  local -a prefix=()
  for current_name in "$@"; do
    prefix+=("$current_name")
    expected=$(migration_history_name_set "${prefix[@]}")
    [[ "$history_names" == "$expected" ]] && return 0
  done
  return 1
}

run_migration_prisma() {
  local database_url=$1 override=$2 migration_container=$3 isolation_id=$4 operation=$5
  [[ "$operation" == resolve-baseline || "$operation" == verify-schema ]] || fail 'Migration administrative action is not allowlisted.'
  if [[ -n "$database_url" ]]; then
    local -x MIGRATION_DATABASE_URL="$database_url"
  else
    unset MIGRATION_DATABASE_URL
  fi
  if [[ -n "$override" ]]; then
    compose_with_override "$override" --profile migration run --rm --no-deps --name "$migration_container" --label "virki.restore.operation=$isolation_id" migrate npm run "prisma:migrate:$operation" --workspace @virki/database
  else
    compose --profile migration run --rm --no-deps migrate npm run "prisma:migrate:$operation" --workspace @virki/database
  fi
}

prune_legacy_migration_history() {
  local container=$1 expected_names=$2 sql
  sql=$(cat <<SQL
DO \$virki\$
DECLARE actual_names text;
BEGIN
  SELECT COALESCE(string_agg("migration_name", ',' ORDER BY "migration_name" COLLATE "C"), '')
    INTO actual_names
    FROM "_prisma_migrations";
  IF actual_names <> '$expected_names'
     OR (SELECT count(*) FROM "_prisma_migrations") <> 16
     OR (SELECT count(DISTINCT "migration_name") FROM "_prisma_migrations") <> 16
     OR (SELECT count(*) FILTER (WHERE "finished_at" IS NOT NULL AND "rolled_back_at" IS NULL) FROM "_prisma_migrations") <> 16
     OR EXISTS (SELECT 1 FROM "_prisma_migrations" WHERE "finished_at" IS NULL OR "rolled_back_at" IS NOT NULL) THEN
    RAISE EXCEPTION 'Unexpected migration history during verified baseline convergence';
  END IF;
  DELETE FROM "_prisma_migrations" WHERE "migration_name" <> '0_init';
  IF (SELECT count(*) FROM "_prisma_migrations") <> 1
     OR (SELECT count(*) FROM "_prisma_migrations" WHERE "migration_name" = '0_init' AND "finished_at" IS NOT NULL AND "rolled_back_at" IS NULL) <> 1 THEN
    RAISE EXCEPTION 'Migration history did not converge to the clean baseline';
  END IF;
END
\$virki\$;
SQL
)
  if [[ -n "$container" ]]; then
    clone_migration_query "$container" "$sql" >/dev/null
  else
    compose exec -T postgres sh -lc 'PGPASSWORD="$VIRKI_MIGRATOR_DB_PASSWORD" psql --host 127.0.0.1 -U virki_migrator -d "$POSTGRES_DB" -At -v ON_ERROR_STOP=1' <<< "$sql" >/dev/null
  fi
}

normalize_migration_history() {
  local database_url=$1 container=$2 override=$3 migration_container=$4 isolation_id=$5
  local current_names_output legacy_names_sql allowed_names_sql expected_legacy expected_resolved state names
  local -a current_names=() allowed_names=()
  current_names_output=$(current_migration_names | LC_ALL=C sort) || fail 'Committed migration inventory could not be verified.'
  mapfile -t current_names <<< "$current_names_output"
  allowed_names=("${current_names[@]}" "${legacy_transition_migrations[@]}" "$transition_migration_name")
  legacy_names_sql=$(migration_sql_name_list "${legacy_transition_migrations[@]}")
  allowed_names_sql=$(migration_sql_name_list "${allowed_names[@]}")
  expected_legacy=$(migration_history_name_set "${legacy_transition_migrations[@]}" "$transition_migration_name")
  expected_resolved=$(migration_history_name_set 0_init "${legacy_transition_migrations[@]}" "$transition_migration_name")

  state=$(migration_history_summary "$container" "$legacy_names_sql" "$allowed_names_sql")
  if migration_history_is_clean_baseline "$state"; then
    names=$(migration_history_names "$container")
    migration_history_is_current_prefix "$names" "${current_names[@]}" || fail 'Production migration history skips a committed migration.'
    return 0
  fi

  names=$(migration_history_names "$container")
  if [[ "$state" == '15|15|0|0|15|0|1|14|0' && "$names" == "$expected_legacy" ]]; then
    run_migration_prisma "$database_url" "$override" "$migration_container" "$isolation_id" resolve-baseline
    state=$(migration_history_summary "$container" "$legacy_names_sql" "$allowed_names_sql")
    names=$(migration_history_names "$container")
  fi

  [[ "$state" == '16|16|0|0|16|1|1|14|0' && "$names" == "$expected_resolved" ]] || fail 'Production migration history is not the exact supported baseline or transition state.'
  prune_legacy_migration_history "$container" "$expected_resolved"
  state=$(migration_history_summary "$container" "$legacy_names_sql" "$allowed_names_sql")
  names=$(migration_history_names "$container")
  [[ "$state" == '1|1|0|0|1|1|0|0|0' && "$names" == '0_init' ]] || fail 'Production migration history did not converge to the clean baseline.'
}

verify_migration_schema() {
  local database_url=$1 override=$2 migration_container=$3 isolation_id=$4
  run_migration_prisma "$database_url" "$override" "$migration_container" "$isolation_id" verify-schema >/dev/null 2>&1 || fail 'Restored or production database schema does not match the committed Prisma datamodel.'
}

identity_snapshot_sql='SELECT count(*) FILTER (WHERE "role"::text = '\''ADMIN'\'')::text || '\''|'\'' || count(*) FILTER (WHERE "role"::text = '\''USER'\'')::text || '\''|'\'' || count(*)::text FROM "User"'
recovery_snapshot_sql() {
  local snapshot_phase=${1:-after_migrations}
  local recovery_key_expression='"idempotencyKey"'
  if [[ "$snapshot_phase" == before_migrations ]]; then
    recovery_key_expression="CASE WHEN \"idempotencyKey\" ~ ('^account-recovery:[A-Za-z0-9_-]{32}' || chr(36)) THEN 'account-recovery-migrated:' || \"id\" ELSE \"idempotencyKey\" END"
  elif [[ "$snapshot_phase" != after_migrations ]]; then
    fail 'Recovery outbox snapshot phase is invalid.'
  fi

  cat <<SQL
SELECT jsonb_build_object(
  'messages', COALESCE((
    SELECT jsonb_agg(jsonb_build_array("id", $recovery_key_expression, "kind"::text, "recipientEmail", "locale", "payload", "status"::text, "attemptCount", "availableAt", "sentAt", "terminalFailedAt", "createdAt", "updatedAt") ORDER BY "id")
    FROM "EmailOutboxMessage"
    WHERE "kind"::text = 'ACCOUNT_RECOVERY'
  ), '[]'::jsonb),
  'attempts', COALESCE((
    SELECT jsonb_agg(jsonb_build_array(attempt."id", attempt."messageId", attempt."attempt", attempt."status"::text, attempt."errorCode", attempt."attemptedAt") ORDER BY attempt."id")
    FROM "EmailDeliveryAttempt" AS attempt
    JOIN "EmailOutboxMessage" AS message ON message."id" = attempt."messageId"
    WHERE message."kind"::text = 'ACCOUNT_RECOVERY'
  ), '[]'::jsonb)
)::text
SQL
}

recovery_snapshot() {
  local container=${1:-} snapshot_phase=${2:-after_migrations} query
  query=$(recovery_snapshot_sql "$snapshot_phase")
  if [[ -n "$container" ]]; then
    clone_query "$container" "$query" | sha256sum | awk '{print $1}'
  else
    database_query "$query" | sha256sum | awk '{print $1}'
  fi
}

identity_snapshot() {
  local container=${1:-}
  local counts
  if [[ -n "$container" ]]; then
    counts=$(clone_query "$container" "$identity_snapshot_sql")
  else
    counts=$(database_query "$identity_snapshot_sql")
  fi
  [[ "$counts" =~ ^([0-9]+)\|([0-9]+)\|([0-9]+)$ ]] || fail 'Production identity data could not be verified.'
  ((BASH_REMATCH[1] > 0 && BASH_REMATCH[3] > 0)) || fail 'Production database does not contain an ADMIN identity.'
  printf '%s\n' "$counts"
}

wait_for_clone() {
  local container=$1 attempt health
  for ((attempt = 0; attempt < 60; attempt += 1)); do
    health=$(docker inspect --format '{{.State.Health.Status}}' "$container" 2>/dev/null || true)
    [[ "$health" == healthy ]] && return 0
    sleep 1
  done
  fail 'Disposable PostgreSQL restore target did not become healthy.'
}

run_clone_migrations() {
  local database_url=$1 override=$2 migration_container=$3 isolation_id=$4 database_container=$5
  local -x MIGRATION_DATABASE_URL="$database_url"
  normalize_migration_history "$database_url" "$database_container" "$override" "$migration_container" "$isolation_id"
  compose_with_override "$override" --profile migration run --rm --no-deps --name "$migration_container" --label "virki.restore.operation=$isolation_id" migrate
  compose_with_override "$override" --profile migration run --rm --no-deps --name "$migration_container" --label "virki.restore.operation=$isolation_id" migrate npm run prisma:migrate:status --workspace @virki/database
  verify_migration_schema "$database_url" "$override" "$migration_container" "$isolation_id"
}

cleanup_clone() {
  local isolation_id=$1 override=$2 containers networks container_id network_id owned cleanup_failed=0
  containers=$(docker ps --all --quiet --filter "label=virki.restore.operation=$isolation_id") || {
    printf '%s\n' 'Could not list disposable restore containers during cleanup.' >&2
    cleanup_failed=1
    containers=
  }
  while IFS= read -r container_id; do
    [[ -n "$container_id" ]] || continue
    owned=$(docker inspect --format '{{index .Config.Labels "virki.restore.operation"}}' "$container_id") || {
      printf '%s\n' 'Could not inspect a disposable restore container during cleanup.' >&2
      cleanup_failed=1
      continue
    }
    if [[ "$owned" != "$isolation_id" ]]; then
      printf '%s\n' 'A restore container did not match its operation label.' >&2
      cleanup_failed=1
      continue
    fi
    docker rm --force --volumes "$container_id" >/dev/null || {
      printf '%s\n' 'Could not remove a disposable restore container and its anonymous volumes.' >&2
      cleanup_failed=1
    }
  done <<< "$containers"

  networks=$(docker network ls --quiet --filter "label=virki.restore.operation=$isolation_id") || {
    printf '%s\n' 'Could not list the disposable restore network during cleanup.' >&2
    cleanup_failed=1
    networks=
  }
  while IFS= read -r network_id; do
    [[ -n "$network_id" ]] || continue
    owned=$(docker network inspect --format '{{index .Labels "virki.restore.operation"}}' "$network_id") || {
      printf '%s\n' 'Could not inspect the disposable restore network during cleanup.' >&2
      cleanup_failed=1
      continue
    }
    if [[ "$owned" != "$isolation_id" ]]; then
      printf '%s\n' 'A restore network did not match its operation label.' >&2
      cleanup_failed=1
      continue
    fi
    docker network rm "$network_id" >/dev/null || {
      printf '%s\n' 'Could not remove the disposable restore network.' >&2
      cleanup_failed=1
    }
  done <<< "$networks"

  rm -f -- "$override" || {
    printf '%s\n' 'Could not remove the disposable restore Compose override.' >&2
    cleanup_failed=1
  }
  return "$cleanup_failed"
}

verify_clone_cleanup() {
  local isolation_id=$1 override=$2 containers networks
  containers=$(docker ps --all --filter "label=virki.restore.operation=$isolation_id" --format '{{.Names}}') || {
    printf '%s\n' 'Could not confirm disposable restore containers were removed.' >&2
    return 1
  }
  [[ -z "$containers" ]] || {
    printf '%s\n' 'Disposable restore containers remain after migration validation.' >&2
    return 1
  }
  networks=$(docker network ls --filter "label=virki.restore.operation=$isolation_id" --format '{{.Name}}') || {
    printf '%s\n' 'Could not confirm the disposable restore network was removed.' >&2
    return 1
  }
  [[ -z "$networks" ]] || {
    printf '%s\n' 'Disposable restore network remains after migration validation.' >&2
    return 1
  }
  [[ ! -e "$override" && ! -L "$override" ]] || {
    printf '%s\n' 'Disposable restore Compose override remains after migration validation.' >&2
    return 1
  }
}

cleanup_failed_backup_verification() {
  local original_status=$1 isolation_id=$2 override=$3 backup_path=$4 partial_backup_path=$5 verification_tmp=$6 backup_verified=$7 verification_path=$8 cleanup_failed=0
  trap - EXIT
  set +e
  cleanup_clone "$isolation_id" "$override" || cleanup_failed=1
  verify_clone_cleanup "$isolation_id" "$override" || cleanup_failed=1
  rm -f -- "$partial_backup_path" "$verification_tmp" || cleanup_failed=1
  if [[ "$backup_verified" != true ]]; then
    rm -f -- "$backup_path" "$verification_path" || cleanup_failed=1
  fi
  if ((cleanup_failed)); then
    printf '%s\n' 'Failure cleanup could not be confirmed; disposable restore resources or an unverified backup may remain.' >&2
    ((original_status != 0)) || original_status=1
  fi
  exit "$original_status"
}

create_verified_backup() {
  # A private subshell ensures backup cleanup never overrides deploy's EXIT guard.
  (
  local stamp isolation_id backup_path partial_backup_path container db_network alias database_url override migration_container bootstrap_password runtime_password migrator_password audit_maintenance_password verification_tmp backup_verified=false
  stamp="$(date -u +%Y%m%d-%H%M%S)-$(od -An -N3 -tx1 /dev/urandom | tr -d ' \n')"
  isolation_id=$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')
  [[ "$isolation_id" =~ ^[a-f0-9]{24}$ ]] || fail 'Could not create a unique restore isolation identifier.'
  backup_path="$backup_dir/virki-$stamp.dump"
  partial_backup_path="$backup_dir/.${backup_path##*/}.$$.partial"
  local -a postgres_ids=()
  mapfile -t postgres_ids < <(compose ps -q postgres)
  ((${#postgres_ids[@]} == 1)) || fail 'Production PostgreSQL service is not running exactly once.'
  container="virki-restore-$isolation_id"
  alias="$container"
  db_network="virki-restore-net-$isolation_id"
  migration_container="virki-restore-migrate-$isolation_id"
  override="$temp_dir/restore-$isolation_id.compose.yml"
  bootstrap_password=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
  runtime_password=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
  migrator_password=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
  audit_maintenance_password=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
  [[ "$bootstrap_password" =~ ^[a-f0-9]{64}$ && "$runtime_password" =~ ^[a-f0-9]{64}$ && "$migrator_password" =~ ^[a-f0-9]{64}$ && "$audit_maintenance_password" =~ ^[a-f0-9]{64}$ ]] || fail 'Could not create isolated PostgreSQL role credentials.'
  [[ "$bootstrap_password" != "$runtime_password" && "$bootstrap_password" != "$migrator_password" && "$runtime_password" != "$migrator_password" && "$audit_maintenance_password" != "$bootstrap_password" && "$audit_maintenance_password" != "$runtime_password" && "$audit_maintenance_password" != "$migrator_password" ]] || fail 'Isolated PostgreSQL role credentials are not distinct.'
  local -x POSTGRES_USER=virki_bootstrap POSTGRES_PASSWORD="$bootstrap_password" VIRKI_RUNTIME_DB_PASSWORD="$runtime_password" VIRKI_MIGRATOR_DB_PASSWORD="$migrator_password" VIRKI_AUDIT_MAINTENANCE_DB_PASSWORD="$audit_maintenance_password"
  database_url="postgresql://virki_migrator:$migrator_password@$alias:5432/virki_restore?schema=public"
  verification_tmp="$verification_path.tmp.$$"
  [[ ! -e "$backup_path" && ! -L "$backup_path" && ! -e "$partial_backup_path" && ! -L "$partial_backup_path" ]] || fail 'A production backup path already exists.'
  rm -f -- "$verification_path" "$verification_tmp"
  trap 'cleanup_failed_backup_verification "$?" "$isolation_id" "$override" "$backup_path" "$partial_backup_path" "$verification_tmp" "$backup_verified" "$verification_path"' EXIT
  compose exec -T postgres sh -lc 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" --format=custom --no-owner --no-privileges' > "$partial_backup_path" || fail 'Production PostgreSQL backup failed.'
  chmod 600 -- "$partial_backup_path"
  [[ -s "$partial_backup_path" ]] || fail 'Production PostgreSQL backup is empty.'

  docker network create --internal --label "virki.restore.operation=$isolation_id" "$db_network" >/dev/null || fail 'Isolated restore network could not be created.'
  {
    printf 'services:\n'
    printf '  migrate:\n'
    printf '    networks:\n'
    printf '      - restore\n'
    printf 'networks:\n'
    printf '  restore:\n'
    printf '    external: true\n'
    printf '    name: %s\n' "$db_network"
  } > "$override"
  chmod 600 -- "$override"
  docker run --detach --name "$container" --label "virki.restore.operation=$isolation_id" --network "$db_network" --network-alias "$alias" \
    --env POSTGRES_DB=virki_restore --env POSTGRES_USER --env POSTGRES_PASSWORD \
    --env VIRKI_RUNTIME_DB_PASSWORD --env VIRKI_MIGRATOR_DB_PASSWORD --env VIRKI_AUDIT_MAINTENANCE_DB_PASSWORD \
    --volume "$source_dir/infra/postgres-init/10-virki-database-roles.sh:/docker-entrypoint-initdb.d/10-virki-database-roles.sh:ro" \
    --health-cmd 'pg_isready -h 127.0.0.1 -U virki_bootstrap -d virki_restore' --health-interval 1s --health-timeout 3s --health-retries 60 \
    postgres:17-alpine@sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24 >/dev/null || fail 'Disposable PostgreSQL restore target could not start.'
  wait_for_clone "$container"
  docker exec --interactive --user postgres "$container" pg_restore --exit-on-error --clean --if-exists --no-owner --no-privileges -U virki_bootstrap -d virki_restore < "$partial_backup_path" >/dev/null
  docker exec --env VIRKI_RUNTIME_DB_PASSWORD --env VIRKI_MIGRATOR_DB_PASSWORD --env VIRKI_AUDIT_MAINTENANCE_DB_PASSWORD "$container" sh /docker-entrypoint-initdb.d/10-virki-database-roles.sh || fail 'Restored database role separation could not be applied.'

  local before_identity before_recovery after_identity after_recovery
  before_identity=$(identity_snapshot "$container")
  before_recovery=$(recovery_snapshot "$container" before_migrations)
  run_clone_migrations "$database_url" "$override" "$migration_container" "$isolation_id" "$container"
  after_identity=$(identity_snapshot "$container")
  after_recovery=$(recovery_snapshot "$container" after_migrations)
  [[ "$before_identity" == "$after_identity" ]] || fail 'Committed migrations changed ADMIN or USER counts in the restored copy.'
  [[ "$before_recovery" == "$after_recovery" ]] || fail 'Committed migrations changed encrypted recovery outbox payload or delivery-attempt metadata.'
  cleanup_clone "$isolation_id" "$override" || fail 'Disposable restore resources could not be removed.'
  verify_clone_cleanup "$isolation_id" "$override" || fail 'Disposable restore cleanup could not be confirmed.'

  mv -- "$partial_backup_path" "$backup_path"
  local backup_hash
  backup_hash=$(sha256sum -- "$backup_path" | awk '{print $1}')
  local verified_at
  verified_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  {
    printf 'revision=%s\n' "$revision"
    printf 'backup_name=%s\n' "${backup_path##*/}"
    printf 'backup_sha256=%s\n' "$backup_hash"
    printf 'verified_at=%s\n' "$verified_at"
  } > "$verification_tmp"
  chmod 600 -- "$verification_tmp"
  mv -f -- "$verification_tmp" "$verification_path"
  backup_verified=true
  trap - EXIT
  printf 'Remote production backup restored and all committed migrations validated outside the source tree.\n'
  )
}

run_first_install_recovery_clone_migrations() {
  local database_url=$1 override=$2 migration_container=$3 isolation_id=$4 database_container=$5
  local -x MIGRATION_DATABASE_URL="$database_url"
  compose_with_override "$override" --profile migration run --rm --no-deps --name "$migration_container" --label "virki.restore.operation=$isolation_id" migrate >/dev/null || fail 'Committed migrations failed against the restored partial-install backup.'
  compose_with_override "$override" --profile migration run --rm --no-deps --name "$migration_container" --label "virki.restore.operation=$isolation_id" migrate npm run prisma:migrate:status --workspace @virki/database >/dev/null || fail 'Restored partial-install migration status could not be verified.'
  verify_migration_schema "$database_url" "$override" "$migration_container" "$isolation_id"
  verify_first_install_role_contract "$database_container"
}

cleanup_first_install_recovery_fixture() {
  local original_status=$1 isolation_id=$2 override=$3 cleanup_failed=0
  trap - EXIT
  set +e
  cleanup_clone "$isolation_id" "$override" || cleanup_failed=1
  verify_clone_cleanup "$isolation_id" "$override" || cleanup_failed=1
  if ((cleanup_failed)); then
    printf '%s\n' 'First-install recovery could not confirm cleanup of its exact disposable restore fixture; the database backup was preserved.' >&2
    ((original_status != 0)) || original_status=1
  fi
  exit "$original_status"
}

create_first_install_recovery_backup() {
  local stamp isolation_id backup_path partial_backup_path container db_network alias database_url override migration_container
  local bootstrap_password runtime_password migrator_password audit_maintenance_password backup_hash verified_at verification_tmp
  if [[ -e "$verification_path" || -L "$verification_path" ]]; then
    assert_backup_verified
    printf 'Reusing the verified partial-install backup for the accepted recovery source.\n'
    return 0
  fi
  stamp="$(date -u +%Y%m%d-%H%M%S)-$(od -An -N3 -tx1 /dev/urandom | tr -d ' \n')"
  isolation_id=$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')
  [[ "$isolation_id" =~ ^[a-f0-9]{24}$ ]] || fail 'Could not create a unique first-install recovery identifier.'
  backup_path="$backup_dir/virki-$stamp.dump"
  partial_backup_path="$backup_dir/.${backup_path##*/}.$$.partial"
  container="virki-restore-$isolation_id"
  alias="$container"
  db_network="virki-restore-net-$isolation_id"
  migration_container="virki-restore-migrate-$isolation_id"
  override="$temp_dir/restore-$isolation_id.compose.yml"
  verification_tmp="$verification_path.tmp.$$"
  [[ ! -e "$backup_path" && ! -L "$backup_path" && ! -e "$partial_backup_path" && ! -L "$partial_backup_path" ]] || fail 'First-install recovery backup path is already occupied.'
  [[ ! -e "$override" && ! -L "$override" && ! -e "$verification_tmp" && ! -L "$verification_tmp" ]] || fail 'First-install recovery temporary path is already occupied.'
  [[ ! -e "$verification_path" && ! -L "$verification_path" ]] || fail 'First-install recovery found an existing migration-verification marker.'
  [[ -z "$(docker ps --all --filter "label=virki.restore.operation=$isolation_id" --format '{{.ID}}')" ]] || fail 'First-install recovery identifier collides with an existing restore container.'
  [[ -z "$(docker network ls --filter "label=virki.restore.operation=$isolation_id" --format '{{.ID}}')" ]] || fail 'First-install recovery identifier collides with an existing restore network.'

  bootstrap_password=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
  runtime_password=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
  migrator_password=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
  audit_maintenance_password=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
  [[ "$bootstrap_password" =~ ^[a-f0-9]{64}$ && "$runtime_password" =~ ^[a-f0-9]{64}$ && "$migrator_password" =~ ^[a-f0-9]{64}$ && "$audit_maintenance_password" =~ ^[a-f0-9]{64}$ ]] || fail 'Could not create isolated PostgreSQL recovery credentials.'
  [[ "$bootstrap_password" != "$runtime_password" && "$bootstrap_password" != "$migrator_password" && "$runtime_password" != "$migrator_password" && "$audit_maintenance_password" != "$bootstrap_password" && "$audit_maintenance_password" != "$runtime_password" && "$audit_maintenance_password" != "$migrator_password" ]] || fail 'Isolated PostgreSQL recovery credentials are not distinct.'
  local -x POSTGRES_USER=virki_bootstrap POSTGRES_PASSWORD="$bootstrap_password" VIRKI_RUNTIME_DB_PASSWORD="$runtime_password" VIRKI_MIGRATOR_DB_PASSWORD="$migrator_password" VIRKI_AUDIT_MAINTENANCE_DB_PASSWORD="$audit_maintenance_password"
  database_url="postgresql://virki_migrator:$migrator_password@$alias:5432/virki_restore?schema=public"
  trap 'cleanup_first_install_recovery_fixture "$?" "$isolation_id" "$override"' EXIT

  compose exec -T postgres sh -lc 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" --format=custom --no-owner --no-privileges' 2>/dev/null > "$partial_backup_path" || fail 'Partial Virki database backup could not be created.'
  chmod 600 -- "$partial_backup_path"
  [[ -s "$partial_backup_path" ]] || fail 'Partial Virki database backup is empty.'
  docker network create --internal --label "virki.restore.operation=$isolation_id" "$db_network" >/dev/null || fail 'Isolated first-install backup restore network could not be created.'
  local network_identity
  network_identity=$(docker network inspect --format '{{.Name}}|{{.Internal}}|{{index .Labels "virki.restore.operation"}}|{{len .Containers}}' "$db_network") || fail 'Isolated first-install backup restore network could not be verified.'
  [[ "$network_identity" == "$db_network|true|$isolation_id|0" ]] || fail 'First-install backup restore network does not match its isolated operation identity.'
  {
    printf 'services:\n'
    printf '  migrate:\n'
    printf '    networks:\n'
    printf '      - restore\n'
    printf 'networks:\n'
    printf '  restore:\n'
    printf '    external: true\n'
    printf '    name: %s\n' "$db_network"
  } > "$override"
  chmod 600 -- "$override"
  docker run --detach --name "$container" --label "virki.restore.operation=$isolation_id" --network "$db_network" --network-alias "$alias" \
    --tmpfs /var/lib/postgresql/data:rw,noexec,nosuid,nodev,size=512m \
    --env POSTGRES_DB=virki_restore --env POSTGRES_USER --env POSTGRES_PASSWORD \
    --env VIRKI_RUNTIME_DB_PASSWORD --env VIRKI_MIGRATOR_DB_PASSWORD --env VIRKI_AUDIT_MAINTENANCE_DB_PASSWORD \
    --volume "$source_dir/infra/postgres-init/10-virki-database-roles.sh:/docker-entrypoint-initdb.d/10-virki-database-roles.sh:ro" \
    --health-cmd 'pg_isready -h 127.0.0.1 -U virki_bootstrap -d virki_restore' --health-interval 1s --health-timeout 3s --health-retries 60 \
    postgres:17-alpine@sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24 >/dev/null || fail 'Disposable PostgreSQL backup restore target could not start.'
  local fixture_identity initializer_mount fixture_members
  fixture_identity=$(docker inspect --format '{{.Config.Image}}|{{.HostConfig.NetworkMode}}|{{index .HostConfig.Tmpfs "/var/lib/postgresql/data"}}|{{range $port, $bindings := .HostConfig.PortBindings}}{{range $bindings}}published{{end}}{{end}}|{{range $port, $bindings := .NetworkSettings.Ports}}{{range $bindings}}published{{end}}{{end}}' "$container") || fail 'Disposable PostgreSQL backup restore target metadata could not be inspected.'
  [[ "$fixture_identity" == "postgres:17-alpine@sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24|$db_network|rw,noexec,nosuid,nodev,size=512m||" ]] || fail 'Disposable PostgreSQL backup restore target must use the internal network, tmpfs, and no published host ports.'
  initializer_mount=$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/docker-entrypoint-initdb.d/10-virki-database-roles.sh"}}{{.RW}}{{end}}{{end}}' "$container") || fail 'Disposable PostgreSQL role initializer mount could not be inspected.'
  [[ "$initializer_mount" == false ]] || fail 'Disposable PostgreSQL role initializer must be mounted read-only.'
  fixture_members=$(docker network inspect --format '{{range .Containers}}{{.Name}}|{{end}}' "$db_network") || fail 'Disposable PostgreSQL restore network membership could not be inspected.'
  [[ "$fixture_members" == "$container|" ]] || fail 'Disposable PostgreSQL restore network has an unexpected member.'
  wait_for_clone "$container"
  docker exec --interactive --user postgres "$container" pg_restore --exit-on-error --clean --if-exists --no-owner --no-privileges -U virki_bootstrap -d virki_restore < "$partial_backup_path" >/dev/null 2>&1 || fail 'Partial Virki database backup could not be restored into the disposable validation database.'
  docker exec --env VIRKI_RUNTIME_DB_PASSWORD --env VIRKI_MIGRATOR_DB_PASSWORD --env VIRKI_AUDIT_MAINTENANCE_DB_PASSWORD "$container" sh /docker-entrypoint-initdb.d/10-virki-database-roles.sh >/dev/null 2>&1 || fail 'Database roles could not be reconciled on the restored partial-install copy.'
  local -x PGPASSWORD="$migrator_password"
  local recovered_role
  recovered_role=$(docker exec --env=PGPASSWORD "$container" psql --no-psqlrc --host 127.0.0.1 --username virki_migrator --dbname virki_restore --tuples-only --no-align --set ON_ERROR_STOP=1 --command 'SELECT current_user' 2>/dev/null) || fail 'Restored Virki migrator could not authenticate over TCP.'
  [[ "$recovered_role" == virki_migrator ]] || fail 'Restored Virki migrator TCP identity did not match its expected role.'
  run_first_install_recovery_clone_migrations "$database_url" "$override" "$migration_container" "$isolation_id" "$container"
  cleanup_clone "$isolation_id" "$override" || fail 'Disposable first-install recovery validation resources could not be removed.'
  verify_clone_cleanup "$isolation_id" "$override" || fail 'Disposable first-install recovery validation cleanup could not be confirmed.'

  mv -- "$partial_backup_path" "$backup_path"
  backup_hash=$(sha256sum -- "$backup_path" | awk '{print $1}')
  verified_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  {
    printf 'revision=%s\n' "$revision"
    printf 'backup_name=%s\n' "${backup_path##*/}"
    printf 'backup_sha256=%s\n' "$backup_hash"
    printf 'verified_at=%s\n' "$verified_at"
  } > "$verification_tmp"
  chmod 600 -- "$verification_tmp"
  ln -- "$verification_tmp" "$verification_path" || fail 'First-install recovery backup verification marker could not be created without overwriting existing state.'
  rm -- "$verification_tmp" || fail 'First-install recovery temporary backup marker could not be removed.'
  trap - EXIT
  printf 'Partial-install backup %s was restored and all committed migrations validated in a disposable PostgreSQL 17 database.\n' "${backup_path##*/}"
}

assert_backup_verified() {
  [[ -f "$verification_path" && ! -L "$verification_path" && "$(stat -c '%a' -- "$verification_path")" == 600 && "$(stat -c '%u' -- "$verification_path")" == "$(id -u)" ]] || fail 'Verified production backup marker is missing or unsafe.'
  local marked_revision backup_name backup_hash verified_at backup_path actual_hash verified_epoch now_epoch
  marked_revision=$(awk -F= '$1 == "revision" { print substr($0, index($0, "=") + 1) }' "$verification_path")
  backup_name=$(awk -F= '$1 == "backup_name" { print substr($0, index($0, "=") + 1) }' "$verification_path")
  backup_hash=$(awk -F= '$1 == "backup_sha256" { print substr($0, index($0, "=") + 1) }' "$verification_path")
  verified_at=$(awk -F= '$1 == "verified_at" { print substr($0, index($0, "=") + 1) }' "$verification_path")
  [[ "$marked_revision" == "$revision" && "$backup_name" =~ ^virki-[0-9]{8}-[0-9]{6}-[a-f0-9]{6}\.dump$ && "$backup_hash" =~ ^[a-f0-9]{64}$ ]] || fail 'Verified backup marker does not match this source revision.'
  backup_path="$backup_dir/$backup_name"
  [[ -f "$backup_path" && ! -L "$backup_path" && "$(stat -c '%a' -- "$backup_path")" == 600 && "$(stat -c '%u' -- "$backup_path")" == "$(id -u)" ]] || fail 'Verified production backup file is missing or unsafe.'
  actual_hash=$(sha256sum -- "$backup_path" | awk '{print $1}')
  [[ "$actual_hash" == "$backup_hash" ]] || fail 'Verified production backup changed after restore validation.'
  verified_epoch=$(date -u -d "$verified_at" +%s 2>/dev/null) || fail 'Verified backup timestamp is invalid.'
  now_epoch=$(date -u +%s)
  ((now_epoch - verified_epoch <= 86400 && verified_epoch <= now_epoch + 300)) || fail 'Verified backup is stale.'
}

# This bridge accepts only the one exact, previously recovered install that
# was observed to have zero accounts and two actorless, zero-change worker
# audits. Both the current revision and its first-install marker stay intact.
# The query checks every application table, including any future additions.
assert_first_admin_rescue_rows() {
  local sql
  sql=$(cat <<'SQL'
DO $$
DECLARE candidate record; contains_rows boolean;
BEGIN
  FOR candidate IN
    SELECT tablename FROM pg_tables
    WHERE schemaname = 'public' AND tablename NOT IN ('_prisma_migrations', 'AuditLog')
  LOOP
    EXECUTE format('SELECT EXISTS (SELECT 1 FROM %I.%I LIMIT 1)', 'public', candidate.tablename)
      INTO contains_rows;
    IF contains_rows THEN
      RAISE EXCEPTION 'Application records exist; first-ADMIN rescue is prohibited.';
    END IF;
  END LOOP;
  IF (SELECT count(*) FROM "AuditLog") <> 2 OR EXISTS (
    SELECT 1 FROM "AuditLog"
    WHERE "eventType"::text <> 'AUTH_SESSION_CLEANUP'
      OR "result"::text <> 'SUCCESS'
      OR "resource" IS DISTINCT FROM 'session'
      OR "message" IS DISTINCT FROM 'Inactive sessions cleaned up.'
      OR "actorUserId" IS NOT NULL
      OR "actorEmailHash" IS NOT NULL
      OR "metadata" IS DISTINCT FROM '{"source":"sessions-cleanup","deletedCount":0,"deletedRateLimitCount":0}'::jsonb
  ) THEN
    RAISE EXCEPTION 'Unexpected audit activity; first-ADMIN rescue is prohibited.';
  END IF;
END
$$;
SQL
)
  database_query "$sql" >/dev/null 2>&1 || fail 'First ADMIN rescue denied: application or audit state differs from the verified virgin-install exception.'
}

verify_first_admin_rescue_state() {
  # Local variables intentionally scope the existing production guard to the
  # PREDECESSOR. Never change on-disk revision or first-install markers here.
  local requested_revision=$revision
  [[ "$requested_revision" =~ ^[0-9a-f]{40}$ && "$requested_revision" != "$first_admin_rescue_predecessor" ]] || fail 'First ADMIN rescue target revision is invalid.'
  [[ ! -e "$maintenance_path" && ! -L "$maintenance_path" ]] || fail 'First ADMIN rescue cannot run in maintenance.'
  [[ ! -e "$HOME/.config/virki-approval/ENABLED" ]] || fail 'Disable the unattended approval agent before first ADMIN rescue.'
  local revision=$first_admin_rescue_predecessor
  local source_dir="$release_dir/$first_admin_rescue_predecessor"
  local -x VIRKI_PRODUCTION_IMAGE="virki-production-ci:$first_admin_rescue_predecessor"
  local -x VIRKI_MIGRATOR_IMAGE="virki-migrator-ci:$first_admin_rescue_predecessor"
  verify_revision
  assert_active_source
  verify_first_install_marker
  verify_first_install_volume
  assert_tunnel_stopped
  assert_backup_verified
  local project_service running_services
  running_services=$(docker ps --filter 'label=com.docker.compose.project=virki-prod' --format '{{.Label "com.docker.compose.service"}}') ||
    fail 'First ADMIN rescue could not inspect running Virki services.'
  while IFS= read -r project_service; do
    [[ -z "$project_service" || "$project_service" == 'postgres' ]] ||
      fail 'First ADMIN rescue requires every Virki application and Tunnel to be stopped.'
  done <<< "$running_services"
  wait_for_virki_postgres
  assert_first_admin_rescue_rows
}

assert_first_admin_rescue_prepared_image() {
  local expected="$revision" actual architecture
  [[ -d "$source_dir" && ! -L "$source_dir" ]] || fail 'Approved first ADMIN rescue source is not installed.'
  [[ -f "$source_dir/.virki-release" && ! -L "$source_dir/.virki-release" ]] || fail 'Approved first ADMIN rescue release marker is missing.'
  grep -Fxq "revision=$expected" "$source_dir/.virki-release" || fail 'Approved first ADMIN rescue release does not match source revision.'
  [[ -L "$source_dir/.env" && "$(readlink -- "$source_dir/.env")" == "$root/.env" &&
     -L "$source_dir/.env.oidc" && "$(readlink -- "$source_dir/.env.oidc")" == "$root/.env.oidc" &&
     -L "$source_dir/.env.oidc-data" && "$(readlink -- "$source_dir/.env.oidc-data")" == "$root/.env.oidc-data" ]] ||
     fail 'Approved first ADMIN rescue source is not bound to protected remote environment.'
  cmp -- "$source_dir/$migration_schema" "$release_dir/$first_admin_rescue_predecessor/$migration_schema" >/dev/null ||
    fail 'First ADMIN rescue forbids Prisma schema changes.'
  diff --brief --recursive -- "$source_dir/$migration_directory" "$release_dir/$first_admin_rescue_predecessor/$migration_directory" >/dev/null ||
    fail 'First ADMIN rescue forbids migration changes.'
  actual=$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}|{{index .Config.Labels "org.opencontainers.image.source"}}|{{.Os}}/{{.Architecture}}' "virki-production-ci:$expected") ||
    fail 'Verified first ADMIN rescue runtime image is unavailable.'
  architecture=$(docker info --format '{{.OSType}}/{{.Architecture}}') || fail 'First ADMIN rescue Docker platform is unavailable.'
  case "$architecture" in
    linux/x86_64|linux/amd64) architecture=linux/amd64 ;;
    linux/aarch64|linux/arm64) architecture=linux/arm64 ;;
    *) fail 'First ADMIN rescue target architecture is unsupported.' ;;
  esac
  [[ "$actual" == "$expected|https://github.com/bielxdh3/Virki|$architecture" ]] ||
    fail 'First ADMIN rescue runtime image identity or architecture is wrong.'
}

create_first_admin_rescue_snapshot() {
  # The previously clone-restored backup remains untouched. Additionally
  # capture the exact current virgin DB (including its two audit rows) before
  # invoking the one-time interactive ADMIN creation transaction.
  local id snapshot partial digest
  id="$(date -u +%Y%m%d-%H%M%S)-$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n')"
  [[ "$id" =~ ^[0-9]{8}-[0-9]{6}-[a-f0-9]{12}$ ]] || fail 'First ADMIN rescue snapshot identifier is invalid.'
  snapshot="$backup_dir/virki-first-admin-rescue-$id.dump"
  partial="$backup_dir/.virki-first-admin-rescue-$id.$$.partial"
  [[ ! -e "$snapshot" && ! -L "$snapshot" && ! -e "$partial" && ! -L "$partial" ]] ||
    fail 'First ADMIN rescue snapshot path is already occupied.'
  compose exec -T postgres sh -lc 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" --format=custom --no-owner --no-privileges' > "$partial" ||
    fail 'First ADMIN rescue snapshot failed; no account was created.'
  chmod 600 -- "$partial"
  [[ -s "$partial" ]] || fail 'First ADMIN rescue snapshot is empty.'
  compose exec -T postgres pg_restore --list < "$partial" >/dev/null ||
    fail 'First ADMIN rescue snapshot format could not be validated; no account was created.'
  mv --no-clobber -- "$partial" "$snapshot" || fail 'First ADMIN rescue snapshot could not be committed.'
  [[ ! -e "$partial" && -f "$snapshot" && ! -L "$snapshot" &&
     "$(stat -c '%a' -- "$snapshot")" == 600 && "$(stat -c '%u' -- "$snapshot")" == "$(id -u)" ]] ||
     fail 'First ADMIN rescue snapshot metadata is invalid.'
  digest=$(sha256sum -- "$snapshot" | awk '{print $1}')
  [[ "$digest" =~ ^[a-f0-9]{64}$ ]] || fail 'First ADMIN rescue snapshot SHA-256 is invalid.'
  printf 'A fresh pre-ADMIN database snapshot was preserved alongside the previously restored and verified backup.\n'
}

verify_first_install_recovery_backups() {
  local backup_name backup_count
  [[ -d "$backup_dir" && ! -L "$backup_dir" ]] || fail 'First-install recovery backup directory is missing or unsafe.'
  backup_count=$(find "$backup_dir" -mindepth 1 -maxdepth 1 -printf x | wc -c) || fail 'First-install recovery backup inventory failed.'
  if [[ -e "$verification_path" || -L "$verification_path" ]]; then
    assert_backup_verified
    backup_name=$(awk -F= '$1 == "backup_name" { print substr($0, index($0, "=") + 1) }' "$verification_path")
    [[ "$backup_count" == 1 && -f "$backup_dir/$backup_name" && ! -L "$backup_dir/$backup_name" ]] || fail 'First-install recovery backup directory contains unverified artifacts.'
  else
    [[ "$backup_count" == 0 ]] || fail 'First-install recovery backup directory contains unverified artifacts.'
  fi
}

run_migration_status() {
  compose "${migration_status_args[@]}" >/dev/null
  local count
  count=$(database_query 'SELECT count(*)::text FROM "_prisma_migrations" WHERE "finished_at" IS NOT NULL AND "rolled_back_at" IS NULL')
  [[ "$count" =~ ^[0-9]+$ ]] || fail 'Production migration history could not be read.'
  printf 'Prisma reports all %s committed migration records current.\n' "$count"
}

apply_production_migrations() {
  assert_backup_verified
  [[ -f "$maintenance_path" && ! -L "$maintenance_path" ]] || fail 'Production migration requires maintenance mode.'
  local before_identity before_recovery after_identity after_recovery
  compose up --detach --force-recreate postgres >/dev/null || fail 'Production PostgreSQL could not be restarted with the verified maintenance-role configuration.'
  compose exec -T postgres sh -lc 'for attempt in $(seq 1 60); do pg_isready -h 127.0.0.1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" >/dev/null 2>&1 && exit 0; sleep 1; done; exit 1' || fail 'Production PostgreSQL did not become ready after its protected restart.'
  compose exec -T postgres sh -s < "$source_dir/infra/postgres-init/10-virki-database-roles.sh" >/dev/null || fail 'Production database role transition could not be applied after backup verification.'
  before_identity=$(identity_snapshot)
  before_recovery=$(recovery_snapshot "" before_migrations)
  normalize_migration_history '' '' '' '' ''
  compose --profile migration run --rm --no-deps migrate
  run_migration_status
  verify_migration_schema '' '' '' ''
  after_identity=$(identity_snapshot)
  after_recovery=$(recovery_snapshot "" after_migrations)
  [[ "$before_identity" == "$after_identity" ]] || fail 'Production migration changed ADMIN or USER counts.'
  [[ "$before_recovery" == "$after_recovery" ]] || fail 'Production migration changed encrypted recovery outbox payload or delivery-attempt metadata.'
}

assert_no_maintenance() {
  [[ ! -e "$maintenance_path" && ! -L "$maintenance_path" ]] || fail 'Production maintenance is active; resume only through maintenance-off after recovery checks.'
}

maintenance_on() {
  rm -f -- "$verification_path"
  if [[ ! -f "$maintenance_path" ]]; then
    {
      printf 'revision=%s\n' "$revision"
      printf 'started_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    } > "$maintenance_path.tmp.$$"
    chmod 600 -- "$maintenance_path.tmp.$$"
    mv -f -- "$maintenance_path.tmp.$$" "$maintenance_path"
  fi
  trap 'stop_routed_services' EXIT
  compose stop cloudflared >/dev/null
  compose stop "${application_services[@]}" >/dev/null
  printf 'Virki application and Tunnel services are in maintenance; PostgreSQL and persistent data remain available.\n'
}

stop_routed_services() {
  local service
  for service in cloudflared "${application_services[@]}"; do
    compose stop "$service" >/dev/null 2>&1 || true
  done
}

stop_tunnel_on_failure() {
  compose stop cloudflared >/dev/null 2>&1 || true
}

assert_tunnel_running() {
  local -a containers=()
  mapfile -t containers < <(compose ps -q cloudflared)
  ((${#containers[@]} == 1)) || fail 'Cloudflare Tunnel connector is not running exactly once.'
  [[ "$(docker inspect --format '{{.State.Running}}' "${containers[0]}")" == true ]] || fail 'Cloudflare Tunnel connector is not running.'
}

resume_services() {
  [[ -f "$maintenance_path" && ! -L "$maintenance_path" ]] || fail 'Production maintenance is not active.'
  trap 'stop_routed_services' EXIT
  compose stop cloudflared >/dev/null 2>&1 || true
  run_migration_status
  verify_migration_schema '' '' '' ''
  activate_source
  compose up --detach --force-recreate "${application_services[@]}" >/dev/null
  assert_revisions
  assert_loopback_ports
  assert_health
  compose up --detach cloudflared >/dev/null
  assert_tunnel_running
  rm -f -- "$maintenance_path"
  trap - EXIT
}

install_source() {
  local preserve_live_markers=${1:-false}
  verify_source_archive
  local archive="$temp_dir/source-$revision-$archive_id.tar"
  local stage="$temp_dir/stage-$revision-$$"
  local release="$release_dir/$revision"
  if [[ -e "$release" || -L "$release" ]]; then
    [[ -d "$release" && ! -L "$release" ]] || fail 'Existing production release path is unsafe.'
    grep -Fxq "revision=$revision" "$release/.virki-release" || fail 'Existing production release does not match the requested revision.'
    grep -Fxq "archive_sha256=$archive_hash" "$release/.virki-release" || fail 'Existing production release has a different source archive.'
  else
    mkdir -m 700 -- "$stage"
    tar --extract --file "$archive" --directory "$stage" --no-same-owner --no-same-permissions
    [[ -f "$stage/scripts/production-server.sh" && -f "$stage/infra/docker-compose.prod.yml" && -f "$stage/infra/docker-compose.cloudflare.yml" ]] || fail 'Source archive is incomplete.'
    for reserved in .env .env.oidc .env.oidc-data backups releases current .virki-release .virki-production-host; do
      [[ ! -e "$stage/$reserved" && ! -L "$stage/$reserved" ]] || fail 'Source archive contains a reserved production path.'
    done
    [[ -z "$(find "$stage" -type l -print -quit)" ]] || fail 'Source archive contains a symbolic link.'
    ln -s "$root/.env" "$stage/.env"
    ln -s "$root/.env.oidc" "$stage/.env.oidc"
    ln -s "$root/.env.oidc-data" "$stage/.env.oidc-data"
    {
      printf 'revision=%s\n' "$revision"
      printf 'archive_sha256=%s\n' "$archive_hash"
    } > "$stage/.virki-release"
    chmod 600 -- "$stage/.virki-release"
    mv -- "$stage" "$release"
  fi
  local role_script="$release/infra/postgres-init/10-virki-database-roles.sh"
  [[ -f "$role_script" && ! -L "$role_script" ]] || fail 'PostgreSQL role initializer is missing or unsafe.'
  chmod 644 -- "$role_script"
  [[ "$(stat -c '%a' -- "$role_script")" == 644 ]] || fail 'PostgreSQL role initializer is not readable by the database container.'
  rm -f -- "$archive" || fail 'Verified source archive could not be removed after staging.'
  if [[ "$preserve_live_markers" == true ]]; then
    # A prepared, immutable rescue source is NOT an activated release.
    printf 'Verified first ADMIN rescue source %s staged without altering live production markers.\n' "$revision"
    return 0
  fi
  {
    printf 'revision=%s\n' "$revision"
    printf 'source=verified-archive\n'
    printf 'branch=main\n'
    printf 'clean=true\n'
    printf 'ci=success\n'
    printf 'archive_sha256=%s\n' "$archive_hash"
  } > "$source_state_path.tmp.$$"
  chmod 600 -- "$source_state_path.tmp.$$"
  mv -f -- "$source_state_path.tmp.$$" "$source_state_path"
  printf '%s\n' "$revision" > "$revision_path.tmp.$$"
  chmod 600 -- "$revision_path.tmp.$$"
  mv -f -- "$revision_path.tmp.$$" "$revision_path"
  printf 'Accepted source %s installed from its verified Git archive.\n' "$revision"
}

cleanup_deploy_staging() {
  local expected_revision=$1 staging_id=$2 cleanup_failed=0 path
  [[ "$expected_revision" =~ ^[0-9a-f]{40}$ && "$staging_id" =~ ^[a-f0-9]{24}$ ]] || {
    printf '%s\n' 'Deployment staging cleanup identity is invalid.' >&2
    return 1
  }
  for path in \
    "$temp_dir/source-$expected_revision-$staging_id.tar" \
    "$temp_dir/images-$expected_revision-$staging_id.manifest"; do
    if [[ -e "$path" || -L "$path" ]]; then
      if [[ -f "$path" && ! -L "$path" ]]; then
        rm -f -- "$path" || cleanup_failed=1
      else
        printf '%s\n' 'Deployment staging cleanup found an unsafe path.' >&2
        cleanup_failed=1
      fi
    fi
  done
  for path in \
    "$temp_dir/source-$expected_revision-$staging_id.tar" \
    "$temp_dir/images-$expected_revision-$staging_id.manifest"; do
    [[ ! -e "$path" && ! -L "$path" ]] || cleanup_failed=1
  done
  ((cleanup_failed == 0))
}

cleanup_failed_deploy() {
  local original_status=$1 cleanup_failed=0
  trap - EXIT
  set +e
  verify_cleanup_target && cleanup_deploy_staging "$revision" "$archive_id" || cleanup_failed=1
  if ((cleanup_failed)); then
    printf '%s\n' 'Deployment staging cleanup could not be confirmed.' >&2
    if ((original_status == 0)); then exit 1; fi
  fi
  exit "$original_status"
}

cleanup_failed_first_install() {
  local original_status=$1 cleanup_failed=0
  trap - EXIT
  set +e
  if [[ "$first_install_database_started" == true ]]; then
    compose stop postgres >/dev/null || cleanup_failed=1
  fi
  verify_cleanup_target && cleanup_deploy_staging "$revision" "$archive_id" || cleanup_failed=1
  if ((cleanup_failed)); then
    printf '%s\n' 'First-install failure cleanup could not be confirmed; any new Virki database volume was preserved.' >&2
    ((original_status != 0)) || original_status=1
  fi
  exit "$original_status"
}

activate_source() {
  local next_link="$root/.current-$revision-$$"
  ln -s "releases/$revision" "$next_link"
  mv -Tf -- "$next_link" "$current_link"
}

if [[ "$action" == cleanup-deploy-staging ]]; then
  verify_cleanup_target || fail 'Production staging cleanup target could not be verified.'
  acquire_state_lock
  cleanup_deploy_staging "$revision" "$archive_id" || fail 'Deployment staging cleanup could not be confirmed.'
  printf '%s\n' 'Failed deployment transfer staging was removed.'
  exit 0
fi
if [[ "$action" == first-install ]]; then
  trap 'cleanup_failed_first_install "$?"' EXIT
elif [[ "$action" == install-source || "$action" == deploy ]]; then
  trap 'cleanup_failed_deploy "$?"' EXIT
fi
verify_host
if [[ "$action" == install-source ]]; then
  acquire_state_lock
  install_source
  exit 0
fi
if [[ "$state_changing_actions" == *" $action "* ]]; then acquire_state_lock; fi
if [[ "$action" == first-admin-rescue-prepare ]]; then
  verify_first_admin_rescue_state
  verify_source_archive
  verify_image_manifest
  load_production_images
  install_source true
  source_dir="$release_dir/$revision"
  assert_first_admin_rescue_prepared_image
  verify_first_admin_rescue_state
  printf 'Verified first ADMIN rescue image prepared; live release, database and first-install markers unchanged.\n'
  exit 0
fi
if [[ "$action" == first-admin-rescue ]]; then
  [[ -t 0 && -t 1 ]] || fail 'First ADMIN rescue requires a trusted interactive terminal.'
  verify_first_admin_rescue_state
  source_dir="$release_dir/$revision"
  assert_first_admin_rescue_prepared_image
  export VIRKI_PRODUCTION_IMAGE="virki-production-ci:$revision"
  export VIRKI_MIGRATOR_IMAGE="virki-migrator-ci:$revision"
  create_first_admin_rescue_snapshot
  compose --profile bootstrap run --rm --no-deps --interactive --tty --env VIRKI_FIRST_INSTALL_BOOTSTRAP=enabled first-admin-bootstrap ||
    fail 'First ADMIN rescue failed; the original release and verified backup are preserved.'
  local_admin_count=$(database_query 'SELECT count(*)::text FROM "User" WHERE "role"::text = '\''ADMIN'\''') ||
    fail 'First ADMIN rescue could not verify its database result.'
  [[ "$local_admin_count" == 1 ]] || fail 'First ADMIN rescue did not create exactly one administrator.'
  printf 'Exactly one first ADMIN created; previous release remains active. The normal protected deploy is required next.\n'
  exit 0
fi
if [[ "$action" == deploy || "$action" == first-install || "$action" == first-install-recovery ]]; then
  if [[ "$action" == first-install ]]; then verify_fresh_install_target; fi
  if [[ "$action" == first-install-recovery ]]; then verify_first_install_recovery_target; fi
  load_production_images
  install_source
fi
verify_revision

export VIRKI_PRODUCTION_IMAGE="virki-production-ci:$revision"
export VIRKI_MIGRATOR_IMAGE="virki-migrator-ci:$revision"

case "$action" in
  first-install)
    compose config --quiet
    [[ ! -e "$first_install_path" && ! -L "$first_install_path" ]] || fail 'First install has already been initialized.'
    first_install_database_started=true
    compose up --detach postgres >/dev/null || fail 'Fresh Virki PostgreSQL could not be started.'
    wait_for_virki_postgres
    verify_first_install_volume
    apply_first_install_database_roles
    verify_migrator_tcp_authentication
    compose --profile migration run --rm --no-deps migrate >/dev/null || fail 'Committed Virki migrations could not be applied to the new database.'
    run_migration_status
    verify_migration_schema '' '' '' ''
    verify_first_install_role_contract
    activate_source
    write_first_install_marker
    trap - EXIT
    printf 'Fresh Virki database and committed migrations initialized in isolated volume %s; legacy services were not changed.\n' "$first_install_volume"
    ;;
  first-install-recovery)
    compose config --quiet
    verify_first_install_volume
    verify_first_install_recovery_project "$recovery_prior_revision" "$revision"
    compose up --detach postgres >/dev/null || fail 'Verified partial Virki PostgreSQL could not be started from the accepted recovery release.'
    wait_for_virki_postgres
    verify_first_install_volume
    verify_first_install_recovery_project "$revision"
    verify_empty_first_install_recovery_database
    if [[ "$recovery_phase" == database-verified ]]; then
      [[ "$recovery_database_state" == migrated-candidate ]] || fail 'First-install recovery checkpoint says migrations completed but the database is not fully migrated.'
      assert_backup_verified
    elif [[ "$recovery_database_state" == migrated-candidate ]]; then
      assert_backup_verified
      printf 'Recovery found migrations applied before the prior checkpoint; validating the completed database before resuming.\n'
    else
      [[ "$recovery_database_state" == empty-partial ]] || fail 'First-install recovery stopped because an earlier attempt left migrations without a verified completion checkpoint.'
      report_first_install_migrator_pre_reconcile_state
      create_first_install_recovery_backup
    fi
    apply_first_install_database_roles
    verify_migrator_tcp_authentication
    if [[ "$recovery_database_state" == empty-partial ]]; then
      compose --profile migration run --rm --no-deps migrate >/dev/null || fail 'Committed Virki migrations could not be applied to the recovered database.'
    fi
    run_migration_status
    verify_migration_schema '' '' '' ''
    verify_first_install_role_contract
    verify_first_install_recovery_has_no_application_rows
    write_first_install_recovery_marker database-verified
    activate_source
    write_first_install_marker
    printf 'Partial Virki first install recovered in place; the verified database volume and all predecessor services were preserved.\n'
    ;;
  stage)
    assert_no_maintenance
    assert_active_source
    verify_first_install_marker
    verify_first_install_volume
    assert_tunnel_stopped
    assert_staging_ports_available
    export PUBLIC_SITE_PORT=13000
    export HUB_PORT=13001
    trap 'stop_stage_after_failure "$?"' EXIT
    compose up --detach postgres >/dev/null || fail 'Virki staging PostgreSQL could not be started.'
    wait_for_virki_postgres
    compose up --detach "${application_services[@]}" >/dev/null || fail 'Virki staging application services could not be started.'
    assert_revisions
    assert_loopback_ports
    assert_health
    assert_tunnel_stopped
    trap - EXIT
    printf 'Virki staging is healthy on private loopback ports 13000 and 13001; Cloudflare Tunnel remains stopped.\n'
    ;;
  first-admin-bootstrap)
    assert_no_maintenance
    assert_active_source
    verify_first_install_marker
    verify_first_install_volume
    assert_tunnel_stopped
    compose --profile bootstrap run --rm --no-deps --interactive --tty --env VIRKI_FIRST_INSTALL_BOOTSTRAP=enabled first-admin-bootstrap
    ;;
  deploy)
    compose config --quiet
    maintenance_on
    create_verified_backup
    apply_production_migrations
    resume_services
    rm -f -- "$verification_path"
    printf 'Native Linux production deployment %s completed and health-checked.\n' "$revision"
    ;;
  start)
    assert_no_maintenance
    assert_active_source
    trap 'stop_routed_services' EXIT
    compose stop cloudflared >/dev/null 2>&1 || true
    compose up --detach postgres >/dev/null
    run_migration_status
    compose up --detach "${application_services[@]}" >/dev/null
    assert_revisions
    assert_loopback_ports
    assert_health
    compose up --detach cloudflared >/dev/null
    assert_tunnel_running
    trap - EXIT
    ;;
  restart)
    assert_no_maintenance
    assert_active_source
    trap 'stop_routed_services' EXIT
    compose stop cloudflared >/dev/null 2>&1 || true
    compose up --detach postgres >/dev/null
    run_migration_status
    compose up --detach --force-recreate "${application_services[@]}" >/dev/null
    assert_revisions
    assert_loopback_ports
    assert_health
    compose up --detach cloudflared >/dev/null
    assert_tunnel_running
    trap - EXIT
    ;;
  start-tunnel)
    assert_no_maintenance
    assert_active_source
    trap 'stop_tunnel_on_failure' EXIT
    compose stop cloudflared >/dev/null 2>&1 || true
    assert_revisions
    assert_loopback_ports
    assert_health
    compose up --detach cloudflared >/dev/null
    assert_tunnel_running
    trap - EXIT
    printf 'Cloudflare Tunnel connector started.\n'
    ;;
  stop)
    compose stop >/dev/null
    printf 'Virki services stopped; persistent volumes were preserved.\n'
    ;;
  maintenance-on)
    maintenance_on
    ;;
  maintenance-off)
    resume_services
    ;;
  status)
    compose ps
    ;;
  ports)
    assert_loopback_ports
    ;;
  revision)
    assert_revisions
    ;;
  health)
    assert_health
    ;;
  logs)
    local_lines=$(compose logs --tail=120 2>/dev/null | wc -l)
    printf 'Remote log lines available: %s (content withheld).\n' "$local_lines"
    ;;
  backup-verify)
    create_verified_backup
    ;;
  migration-status)
    run_migration_status
    ;;
  audit-recent)
    rows=$(compose exec -T hub npm run audit:recent --workspace @virki/auth | wc -l)
    printf 'Remote sanitized audit rows available: %s.\n' "$rows"
    ;;
  audit-cleanup)
    compose --profile maintenance run --rm audit-maintenance >/dev/null
    printf 'Remote audit cleanup completed.\n'
    ;;
  sessions-cleanup)
    compose exec -T hub npm run sessions:cleanup --workspace @virki/auth >/dev/null
    printf 'Remote session cleanup completed.\n'
    ;;
  config)
    compose config --no-env-resolution --quiet
    printf 'Remote Compose configuration is valid.\n'
    ;;
esac
