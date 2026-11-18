#!/usr/bin/env bash
# One-shot, mandatory HOL/CAS regression. Only run on a GitHub-hosted Linux
# runner: creates its OWN uniquely labelled Postgres tmpfs container and DB.
# No existing database is reset, cleaned or shared with another CI suite.
set -euo pipefail
umask 077

refuse() { printf 'Mandatory email worker HOL CI refused: %s\n' "$1" >&2; exit 1; }
[[ "${GITHUB_ACTIONS:-}" == true && "${CI:-}" == true &&
   "${RUNNER_OS:-}" == Linux && "${VIRKI_HOL_RUNNER_ENVIRONMENT:-}" == github-hosted &&
   "${GITHUB_REPOSITORY:-}" == bielxdh3/Virki ]] || refuse 'GitHub-hosted Linux identity is required'
[[ "${GITHUB_RUN_ID:-}" =~ ^[0-9]+$ && "${GITHUB_RUN_ATTEMPT:-}" =~ ^[0-9]+$ ]] || refuse 'CI run identity missing'
[[ -d "${GITHUB_WORKSPACE:-/nonexistent}" && -f "$GITHUB_WORKSPACE/scripts/integration/worker-hol.mjs" &&
   -f "$GITHUB_WORKSPACE/infra/postgres-init/10-virki-database-roles.sh" &&
   -f "$GITHUB_WORKSPACE/scripts/e2e/20-virki-e2e-runtime-test-role.sh" ]] || refuse 'Reviewed checkout unavailable'
[[ -x /usr/bin/docker && -S /var/run/docker.sock ]] || refuse 'Local Docker socket unavailable'
[[ "$(node --version)" == v22.* && "$(npm --version)" == 10.* ]] || refuse 'Node 22/npm 10 required'

docker_local() { /usr/bin/docker --host unix:///var/run/docker.sock "$@"; }
[[ "$(docker_local version --format '{{.Server.Os}}|{{.Server.Arch}}')" == linux\|amd64 ]] ||
  refuse 'The CI-local Linux/amd64 Docker engine was not verified'

owner="${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}-$(openssl rand -hex 6)"
container_name="virki-email-hol-${owner}"
database="virki_email_worker_hol_$(openssl rand -hex 6)"
bootstrap_password="$(openssl rand -hex 32)"
runtime_password="$(openssl rand -hex 32)"
migrator_password="$(openssl rand -hex 32)"
audit_password="$(openssl rand -hex 32)"
worker_password="$(openssl rand -hex 32)"
outbox_key="$(openssl rand -hex 32)"
for secret in "$bootstrap_password" "$runtime_password" "$migrator_password" "$audit_password" "$worker_password" "$outbox_key"; do
  printf '::add-mask::%s\n' "$secret"
done

container_id=''
creation_attempted=0
cleanup() {
  local status=$?
  trap - EXIT
  # Record intent BEFORE Docker run. Query the immutable random owner label,
  # NOT the mutable Docker name (which can be changed after launch). This also
  # finds a container when the Docker create ACK was lost.
  if [[ "$creation_attempted" == 1 ]]; then
    local found observed after by_id
    if ! found="$(docker_local ps --all --no-trunc --filter "label=virki.worker-hol.owner=${owner}" --format '{{.ID}}')"; then
      printf 'Cannot verify owned Docker resource cleanup.\n' >&2
      status=1
    elif [[ -n "$found" ]]; then
      if [[ ! "$found" =~ ^[a-f0-9]{64}$ ]] ||
         { [[ -n "$container_id" ]] && [[ "$found" != "$container_id" ]]; }; then
        printf 'Refusing cleanup: unexpected private container ID.\n' >&2
        status=1
      elif ! observed="$(docker_local inspect --format '{{index .Config.Labels "virki.worker-hol.owner"}}|{{index .Config.Labels "virki.worker-hol.kind"}}|{{.Id}}' "$found")"; then
        printf 'Cannot verify the Docker ownership labels.\n' >&2
        status=1
      elif [[ "$observed" != "${owner}|exclusive-test|${found}" ]]; then
        printf 'Refusing cleanup: private Docker ownership changed.\n' >&2
        status=1
      elif ! docker_local rm --force --volumes "$found" >/dev/null; then
        printf 'Could not delete the exact owned disposable database container.\n' >&2
        status=1
      elif ! after="$(docker_local ps --all --no-trunc --filter "label=virki.worker-hol.owner=${owner}" --format '{{.ID}}')" || [[ -n "$after" ]]; then
        printf 'Owned disposable PostgreSQL cleanup could not be confirmed.\n' >&2
        status=1
      fi
    fi
    # After Docker acknowledged the exact ID, verify that it is absent even
    # if its owner label were altered. A missing name alone is NEVER success.
    if [[ -n "$container_id" ]]; then
      if ! by_id="$(docker_local ps --all --no-trunc --filter "id=${container_id}" --format '{{.ID}}')" || [[ -n "$by_id" ]]; then
        printf 'Acknowledged disposable Docker ID still exists or cannot be checked.\n' >&2
        status=1
      fi
    fi
  fi
  exit "$status"
}
trap cleanup EXIT

# Same reviewed initialization and PG17 digest as the existing authenticated
# CI fixture, but in a NEW tmpfs-only container and a random database name.
creation_attempted=1
container_id="$(docker_local run --detach --rm \
  --name "$container_name" \
  --label "virki.worker-hol.owner=${owner}" --label virki.worker-hol.kind=exclusive-test \
  --pids-limit 256 \
  --publish 127.0.0.1::5432 \
  --tmpfs /var/lib/postgresql/data:rw,noexec,nosuid,nodev,size=512m \
  --health-cmd "pg_isready -h 127.0.0.1 -U virki_bootstrap -d ${database}" \
  --health-interval 1s --health-timeout 3s --health-retries 90 \
  --env "POSTGRES_DB=$database" --env POSTGRES_USER=virki_bootstrap \
  --env "POSTGRES_PASSWORD=$bootstrap_password" \
  --env "VIRKI_RUNTIME_DB_PASSWORD=$runtime_password" \
  --env "VIRKI_MIGRATOR_DB_PASSWORD=$migrator_password" \
  --env "VIRKI_AUDIT_MAINTENANCE_DB_PASSWORD=$audit_password" \
  --env "VIRKI_E2E_DATABASE_PASSWORD=$worker_password" \
  --mount "type=bind,source=$GITHUB_WORKSPACE/infra/postgres-init/10-virki-database-roles.sh,target=/docker-entrypoint-initdb.d/10-virki-database-roles.sh,readonly" \
  --mount "type=bind,source=$GITHUB_WORKSPACE/scripts/e2e/20-virki-e2e-runtime-test-role.sh,target=/docker-entrypoint-initdb.d/20-virki-e2e-runtime-test-role.sh,readonly" \
  postgres:17-alpine@sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24)"
[[ "$container_id" =~ ^[a-f0-9]{64}$ ]] || refuse 'Could not identify the private container'
for attempt in $(seq 1 90); do
  health="$(docker_local inspect --format '{{.State.Health.Status}}' "$container_id")"
  [[ "$health" == healthy ]] && break
  [[ "$health" != unhealthy ]] || refuse 'Fresh disposable PostgreSQL failed its health check'
  sleep 1
done
[[ "$(docker_local inspect --format '{{.State.Health.Status}}' "$container_id")" == healthy ]] ||
  refuse 'Fresh disposable PostgreSQL never became healthy'
mapped="$(docker_local port "$container_id" 5432/tcp)"
[[ "$mapped" =~ ^127\.0\.0\.1:([0-9]{2,5})$ ]] || refuse 'PostgreSQL published outside loopback'
port="${BASH_REMATCH[1]}"

base_url="postgresql://virki_runtime_test:${worker_password}@127.0.0.1:${port}/${database}?schema=public"
export MIGRATION_DATABASE_URL="postgresql://virki_migrator:${migrator_password}@127.0.0.1:${port}/${database}?schema=public"
export VIRKI_INTEGRATION_DATABASE_URL="$base_url"
export VIRKI_CORE_TEST_DATABASE_CONFIRM=disposable
export VIRKI_EMAIL_WORKER_DEDICATED_DB=confirmed
export VIRKI_EMAIL_OUTBOX_KEY="$outbox_key"
export NODE_ENV=test

cd "$GITHUB_WORKSPACE"
node packages/database/scripts/prisma-migrate.mjs deploy
# This script MUST fail unless both physical tests PASS with zero SKIP, even
# if the underlying Node test command incorrectly exits with code zero.
npm run test:integration:email-worker:hol
