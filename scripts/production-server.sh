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

allowed_actions=' install-source cleanup-deploy-staging deploy start restart start-tunnel stop maintenance-on maintenance-off status ports revision health logs backup-verify migration-status audit-recent audit-cleanup sessions-cleanup config '
[[ "$allowed_actions" == *" $action "* ]] || fail 'Production action is not allowed.'

if [[ "$action" == cleanup-deploy-staging ]]; then
  archive_id=$archive_hash
  archive_hash=
fi

readonly release_dir="$root/releases"
readonly current_link="$root/current"
readonly lock_path="$root/.bielos-operations.lock"
source_dir=
readonly temp_dir="$root/.deploy-tmp"
readonly backup_dir="$root/backups"
readonly marker_path="$root/.bielos-production-host"
readonly revision_path="$root/.bielos-deploy-revision"
readonly source_state_path="$root/.bielos-source-state"
readonly verification_path="$root/.bielos-migration-verification"
readonly maintenance_path="$root/.bielos-maintenance"
readonly migration_schema='packages/database/prisma/schema.prisma'
readonly migration_directory='packages/database/prisma/migrations'
readonly transition_migration_name='20260922090000_total_identity_security_rebaseline'
readonly migration_status_args=(--profile migration run --rm --no-deps migrate npx prisma migrate status --schema "$migration_schema")
readonly application_services=(public-site hub oidc-issuer session-cleanup email-worker)
readonly state_changing_actions=' install-source cleanup-deploy-staging deploy start restart start-tunnel stop maintenance-on maintenance-off backup-verify audit-cleanup sessions-cleanup '
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
  grep -Fxq "revision=$revision" "$release/.bielos-release" || fail 'Production release marker is invalid.'
  grep -Fxq "archive_sha256=$archive_hash" "$release/.bielos-release" || fail 'Production release marker does not match its archive.'
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

verify_image_archive() {
  [[ "$revision" =~ ^[0-9a-f]{40}$ && "$image_hash" =~ ^[0-9a-f]{64}$ && "$image_id" =~ ^[0-9a-f]{24}$ ]] || fail 'Production image archive identity is invalid.'
  local archive="$temp_dir/images-$revision-$image_id.tar.gz"
  [[ -f "$archive" && ! -L "$archive" ]] || fail 'Verified production image archive is missing.'
  [[ "$(sha256sum -- "$archive" | awk '{print $1}')" == "$image_hash" ]] || fail 'Production image archive checksum does not match.'
  gzip --test -- "$archive" || fail 'Production image archive is corrupt.'
}

load_production_images() {
  verify_image_archive
  local archive="$temp_dir/images-$revision-$image_id.tar.gz" image observed
  docker load --input "$archive" >/dev/null || {
    rm -f -- "$archive" || printf '%s\n' 'Could not remove the rejected production image archive.' >&2
    fail 'Exact-revision production images could not be loaded.'
  }
  for image in "bielos-production-ci:$revision" "bielos-migrator-ci:$revision"; do
    observed=$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$image") || {
      rm -f -- "$archive" || printf '%s\n' 'Could not remove the rejected production image archive.' >&2
      fail 'Exact-revision production image is missing.'
    }
    if [[ "$observed" != "$revision" ]]; then
      rm -f -- "$archive" || printf '%s\n' 'Could not remove the rejected production image archive.' >&2
      fail 'Production image revision does not match the accepted source.'
    fi
  done
  rm -f -- "$archive" || fail 'Loaded production image archive could not be removed.'
}

compose_args() {
  printf '%s\0' \
    --progress quiet \
    --project-name bielos-prod \
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
    [[ "$binding" =~ ^127\.0\.0\.1: ]] || fail "Production service $service is not loopback-bound."
    printf '%s port is loopback-bound.\n' "$service"
  done
}

assert_health() {
  local public_status hub_status discovery access_status public_binding hub_binding
  public_binding=$(compose port public-site 3000)
  hub_binding=$(compose port hub 3001)
  [[ "$public_binding" =~ ^127\.0\.0\.1:[0-9]+$ && "$hub_binding" =~ ^127\.0\.0\.1:[0-9]+$ ]] || fail 'Production application port binding is not loopback-only.'
  public_status=$(curl --silent --show-error --max-time 10 --output /dev/null --write-out '%{http_code}' "http://$public_binding") || fail 'Public site health request failed.'
  hub_status=$(curl --silent --show-error --max-time 10 --output /dev/null --write-out '%{http_code}' "http://$hub_binding/api/health") || fail 'Hub health request failed.'
  discovery=$(curl --silent --show-error --max-time 10 --header 'Host: portal.biel.dev.br' "http://$hub_binding/.well-known/openid-configuration") || fail 'Portal OIDC discovery request failed.'
  access_status=$(curl --silent --show-error --max-time 10 --output /dev/null --write-out '%{http_code}' --header 'Host: hub.biel.dev.br' "http://$hub_binding/admin/accounts") || fail 'Hub Access boundary request failed.'
  [[ "$public_status" == 200 && "$hub_status" == 200 && "$access_status" == 403 ]] || fail 'Production health or ADMIN boundary check failed.'
  [[ "$discovery" == *'"issuer":"https://portal.biel.dev.br"'* && "$discovery" == *'"S256"'* && "$discovery" == *'"code"'* ]] || fail 'Portal discovery profile does not match the expected OIDC issuer.'
  printf 'Public site, hub health, portal OIDC discovery, and unauthenticated Hub denial are healthy.\n'
}

database_query() {
  local sql=$1
  compose exec -T postgres sh -lc 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -At -v ON_ERROR_STOP=1' <<< "$sql"
}

clone_query() {
  local container=$1 sql=$2
  docker exec -i "$container" psql -U bielos_restore -d bielos_restore -At -v ON_ERROR_STOP=1 <<< "$sql"
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
    clone_query "$container" "$sql"
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
    clone_query "$container" "$sql"
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
  local database_url=$1 override=$2 migration_container=$3 isolation_id=$4
  shift 4
  if [[ -n "$override" ]]; then
    local -x DATABASE_URL="$database_url"
    compose_with_override "$override" --profile migration run --rm --no-deps --name "$migration_container" --label "bielos.restore.operation=$isolation_id" migrate npx prisma "$@"
  else
    compose --profile migration run --rm --no-deps migrate npx prisma "$@"
  fi
}

prune_legacy_migration_history() {
  local container=$1 expected_names=$2 sql
  sql=$(cat <<SQL
DO \$bielos\$
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
\$bielos\$;
SQL
)
  if [[ -n "$container" ]]; then
    clone_query "$container" "$sql" >/dev/null
  else
    database_query "$sql" >/dev/null
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
    run_migration_prisma "$database_url" "$override" "$migration_container" "$isolation_id" migrate resolve --applied 0_init --schema "$migration_schema"
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
  run_migration_prisma "$database_url" "$override" "$migration_container" "$isolation_id" migrate diff --from-schema-datasource "$migration_schema" --to-schema-datamodel "$migration_schema" --exit-code >/dev/null 2>&1 || fail 'Restored or production database schema does not match the committed Prisma datamodel.'
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
  local -x DATABASE_URL="$database_url"
  normalize_migration_history "$database_url" "$database_container" "$override" "$migration_container" "$isolation_id"
  compose_with_override "$override" --profile migration run --rm --no-deps --name "$migration_container" --label "bielos.restore.operation=$isolation_id" migrate
  compose_with_override "$override" --profile migration run --rm --no-deps --name "$migration_container" --label "bielos.restore.operation=$isolation_id" migrate npx prisma migrate status --schema "$migration_schema"
  verify_migration_schema "$database_url" "$override" "$migration_container" "$isolation_id"
}

cleanup_clone() {
  local isolation_id=$1 override=$2 containers networks container_id network_id owned cleanup_failed=0
  containers=$(docker ps --all --quiet --filter "label=bielos.restore.operation=$isolation_id") || {
    printf '%s\n' 'Could not list disposable restore containers during cleanup.' >&2
    cleanup_failed=1
    containers=
  }
  while IFS= read -r container_id; do
    [[ -n "$container_id" ]] || continue
    owned=$(docker inspect --format '{{index .Config.Labels "bielos.restore.operation"}}' "$container_id") || {
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

  networks=$(docker network ls --quiet --filter "label=bielos.restore.operation=$isolation_id") || {
    printf '%s\n' 'Could not list the disposable restore network during cleanup.' >&2
    cleanup_failed=1
    networks=
  }
  while IFS= read -r network_id; do
    [[ -n "$network_id" ]] || continue
    owned=$(docker network inspect --format '{{index .Labels "bielos.restore.operation"}}' "$network_id") || {
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
  containers=$(docker ps --all --filter "label=bielos.restore.operation=$isolation_id" --format '{{.Names}}') || {
    printf '%s\n' 'Could not confirm disposable restore containers were removed.' >&2
    return 1
  }
  [[ -z "$containers" ]] || {
    printf '%s\n' 'Disposable restore containers remain after migration validation.' >&2
    return 1
  }
  networks=$(docker network ls --filter "label=bielos.restore.operation=$isolation_id" --format '{{.Name}}') || {
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
  local stamp isolation_id backup_path partial_backup_path container db_network alias database_url override migration_container password verification_tmp backup_verified=false
  stamp="$(date -u +%Y%m%d-%H%M%S)-$(od -An -N3 -tx1 /dev/urandom | tr -d ' \n')"
  isolation_id=$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')
  [[ "$isolation_id" =~ ^[a-f0-9]{24}$ ]] || fail 'Could not create a unique restore isolation identifier.'
  backup_path="$backup_dir/bielos-$stamp.dump"
  partial_backup_path="$backup_dir/.${backup_path##*/}.$$.partial"
  local -a postgres_ids=()
  mapfile -t postgres_ids < <(compose ps -q postgres)
  ((${#postgres_ids[@]} == 1)) || fail 'Production PostgreSQL service is not running exactly once.'
  container="bielos-restore-$isolation_id"
  alias="$container"
  db_network="bielos-restore-net-$isolation_id"
  migration_container="bielos-restore-migrate-$isolation_id"
  override="$temp_dir/restore-$isolation_id.compose.yml"
  password=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
  [[ "$password" =~ ^[a-f0-9]{64}$ ]] || fail 'Could not create an ephemeral restore database password.'
  local -x POSTGRES_PASSWORD="$password"
  database_url="postgresql://bielos_restore:$password@$alias:5432/bielos_restore?schema=public"
  verification_tmp="$verification_path.tmp.$$"
  [[ ! -e "$backup_path" && ! -L "$backup_path" && ! -e "$partial_backup_path" && ! -L "$partial_backup_path" ]] || fail 'A production backup path already exists.'
  rm -f -- "$verification_path" "$verification_tmp"
  trap 'cleanup_failed_backup_verification "$?" "$isolation_id" "$override" "$backup_path" "$partial_backup_path" "$verification_tmp" "$backup_verified" "$verification_path"' EXIT
  compose exec -T postgres sh -lc 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" --format=custom --no-owner --no-privileges' > "$partial_backup_path" || fail 'Production PostgreSQL backup failed.'
  chmod 600 -- "$partial_backup_path"
  [[ -s "$partial_backup_path" ]] || fail 'Production PostgreSQL backup is empty.'

  docker network create --internal --label "bielos.restore.operation=$isolation_id" "$db_network" >/dev/null || fail 'Isolated restore network could not be created.'
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
  docker run --detach --name "$container" --label "bielos.restore.operation=$isolation_id" --network "$db_network" --network-alias "$alias" \
    --env POSTGRES_DB=bielos_restore --env POSTGRES_USER=bielos_restore --env POSTGRES_PASSWORD \
    --health-cmd 'pg_isready -U bielos_restore -d bielos_restore' --health-interval 1s --health-timeout 3s --health-retries 60 \
    postgres:17-alpine@sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24 >/dev/null || fail 'Disposable PostgreSQL restore target could not start.'
  wait_for_clone "$container"
  docker exec --interactive --user postgres "$container" pg_restore --exit-on-error --clean --if-exists --no-owner --no-privileges -U bielos_restore -d bielos_restore < "$partial_backup_path" >/dev/null

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
}

assert_backup_verified() {
  [[ -f "$verification_path" && ! -L "$verification_path" ]] || fail 'Verified production backup marker is missing.'
  local marked_revision backup_name backup_hash verified_at backup_path actual_hash verified_epoch now_epoch
  marked_revision=$(awk -F= '$1 == "revision" { print substr($0, index($0, "=") + 1) }' "$verification_path")
  backup_name=$(awk -F= '$1 == "backup_name" { print substr($0, index($0, "=") + 1) }' "$verification_path")
  backup_hash=$(awk -F= '$1 == "backup_sha256" { print substr($0, index($0, "=") + 1) }' "$verification_path")
  verified_at=$(awk -F= '$1 == "verified_at" { print substr($0, index($0, "=") + 1) }' "$verification_path")
  [[ "$marked_revision" == "$revision" && "$backup_name" =~ ^bielos-[0-9]{8}-[0-9]{6}-[a-f0-9]{6}\.dump$ && "$backup_hash" =~ ^[a-f0-9]{64}$ ]] || fail 'Verified backup marker does not match this source revision.'
  backup_path="$backup_dir/$backup_name"
  [[ -f "$backup_path" && ! -L "$backup_path" ]] || fail 'Verified production backup file is missing.'
  actual_hash=$(sha256sum -- "$backup_path" | awk '{print $1}')
  [[ "$actual_hash" == "$backup_hash" ]] || fail 'Verified production backup changed after restore validation.'
  verified_epoch=$(date -u -d "$verified_at" +%s 2>/dev/null) || fail 'Verified backup timestamp is invalid.'
  now_epoch=$(date -u +%s)
  ((now_epoch - verified_epoch <= 86400 && verified_epoch <= now_epoch + 300)) || fail 'Verified backup is stale.'
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
  printf 'BielOS application and Tunnel services are in maintenance; PostgreSQL and persistent data remain available.\n'
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
  verify_source_archive
  local archive="$temp_dir/source-$revision-$archive_id.tar"
  local stage="$temp_dir/stage-$revision-$$"
  local release="$release_dir/$revision"
  if [[ -e "$release" || -L "$release" ]]; then
    [[ -d "$release" && ! -L "$release" ]] || fail 'Existing production release path is unsafe.'
    grep -Fxq "revision=$revision" "$release/.bielos-release" || fail 'Existing production release does not match the requested revision.'
    grep -Fxq "archive_sha256=$archive_hash" "$release/.bielos-release" || fail 'Existing production release has a different source archive.'
  else
    mkdir -m 700 -- "$stage"
    tar --extract --file "$archive" --directory "$stage" --no-same-owner --no-same-permissions
    [[ -f "$stage/scripts/production-server.sh" && -f "$stage/infra/docker-compose.prod.yml" && -f "$stage/infra/docker-compose.cloudflare.yml" ]] || fail 'Source archive is incomplete.'
    for reserved in .env .env.oidc .env.oidc-data backups releases current .bielos-release .bielos-production-host; do
      [[ ! -e "$stage/$reserved" && ! -L "$stage/$reserved" ]] || fail 'Source archive contains a reserved production path.'
    done
    [[ -z "$(find "$stage" -type l -print -quit)" ]] || fail 'Source archive contains a symbolic link.'
    ln -s "$root/.env" "$stage/.env"
    ln -s "$root/.env.oidc" "$stage/.env.oidc"
    ln -s "$root/.env.oidc-data" "$stage/.env.oidc-data"
    {
      printf 'revision=%s\n' "$revision"
      printf 'archive_sha256=%s\n' "$archive_hash"
    } > "$stage/.bielos-release"
    chmod 600 -- "$stage/.bielos-release"
    mv -- "$stage" "$release"
  fi
  rm -f -- "$archive" || fail 'Verified source archive could not be removed after staging.'
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
    "$temp_dir/images-$expected_revision-$staging_id.tar.gz"; do
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
    "$temp_dir/images-$expected_revision-$staging_id.tar.gz"; do
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
if [[ "$action" == install-source || "$action" == deploy ]]; then
  trap 'cleanup_failed_deploy "$?"' EXIT
fi
verify_host
if [[ "$action" == install-source ]]; then
  acquire_state_lock
  install_source
  exit 0
fi
if [[ "$state_changing_actions" == *" $action "* ]]; then acquire_state_lock; fi
if [[ "$action" == deploy ]]; then
  load_production_images
  install_source
fi
verify_revision

export BIELOS_PRODUCTION_IMAGE="bielos-production-ci:$revision"
export BIELOS_MIGRATOR_IMAGE="bielos-migrator-ci:$revision"

case "$action" in
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
    printf 'BielOS services stopped; persistent volumes were preserved.\n'
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
    rows=$(compose exec -T hub npm run audit:recent --workspace @bielos/auth | wc -l)
    printf 'Remote sanitized audit rows available: %s.\n' "$rows"
    ;;
  audit-cleanup)
    compose exec -T hub npm run audit:cleanup --workspace @bielos/auth >/dev/null
    printf 'Remote audit cleanup completed.\n'
    ;;
  sessions-cleanup)
    compose exec -T hub npm run sessions:cleanup --workspace @bielos/auth >/dev/null
    printf 'Remote session cleanup completed.\n'
    ;;
  config)
    compose config --no-env-resolution --quiet
    printf 'Remote Compose configuration is valid.\n'
    ;;
esac
