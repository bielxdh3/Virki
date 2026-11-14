# PR #118 — segregated staging operator runbook

> **PREPARED, NOT EXECUTED.** These commands are for a separately authorized
> staging operator after exact-SHA SOURCE GO and hosted checks. They do not
> provision a host, authorize SMTP, change Cloudflare, deploy, or approve
> production. Never point them at production or deManage.

## 1. Preconditions and secret handling

The current local **runtime-code** candidate is
`2cb74f576039cac8d83fd2d1cc52e47f36184ad1`. It preserves the original
seven-commit candidate `6feb2da5ab9bd25ce1cc2f53c6a7c4fc4807bd1c` as an
ancestor and descends from the published PR source
`678d81af31fb6aa5f1ab4effcdee823a030c38ce`; it contains ten commits since
that published source. The final runbook, acceptance note and execution-ledger
updates are a documentation-only descendant of this runtime candidate;
no runtime source changes after `2cb74f5` are intended. The local branch is
unpublished and has no hosted checks. Any staging image must use the exact
final branch SHA after these documentation commits, not an earlier SHA. Do
not build or attest a release image until independent SOURCE review,
publication authorization and exact-SHA CI/CodeQL gates have completed.

The originally requested SOURCE interval `678d81a..6feb2da` remains included.
The later local commits add the signed staging-preflight, standalone-worker
resource policy, relay tenant/endpoint/account binding and non-interactive
database-role provisioning. Reviewing only the original interval is no longer
sufficient: authenticated independent SOURCE review must cover the complete
code diff `678d81a..2cb74f5`, including incremental `6feb2da..2cb74f5`. The
later documentation-only commit does not change that runtime-code review
range.

The operator must have an out-of-band approved staging context and Docker
daemon ID, project name, external network ID **and exact endpoint inventory**,
DB host/name/roles, immutable OCI digests with the exact source-revision/source
labels, relay tenant/endpoint/account, recipient policy, provider rate/message
caps, test inboxes, ingress/egress policy evidence, maintenance window and
named rollback owner. Compare these with the operator's production inventory;
a different string alone does not prove physical isolation. Any unexpected
network endpoint, image label or project resource is a hard stop.

All fenced `sh` blocks below are **Bash 4+** scripts for Linux with GNU
coreutils; do not execute them with `sh`, PowerShell or a Windows Docker
context. Keep the application/Docker operator shell separate from the
PostgreSQL-host rollback shell described in section 4.

The Hub and worker are separate Compose projects sharing only the explicitly
approved external staging network and the same staging outbox key. The Hub
must not receive SMTP credentials or the worker-only scoped role. A production
Compose base or the legacy layered override is not an acceptable substitute
for the independently approved Hub-only staging file.

The operator must also set `VIRKI_STAGING_APPROVED_SOURCE_SHA` to the exact
40-hex SHA approved by owner and independent reviewer. The same checkout must
be available on the staging PostgreSQL host for the two committed role scripts
used during physical restore; never substitute a newer branch or unverified
copy.

Inject the following required Compose variables from the approved staging
secret manager, never from the production `.env` or a committed file:

- `VIRKI_STAGING_COMPOSE_PROJECT`
- `VIRKI_STAGING_EMAIL_WORKER_NETWORK`
- `VIRKI_STAGING_EMAIL_WORKER_IMAGE` (exact repository plus
  `@sha256:<64 lowercase hex>`, already present on the host; no pull)
- `VIRKI_STAGING_HUB_COMPOSE_FILE`,
  `VIRKI_STAGING_HUB_COMPOSE_PROJECT`,
  `VIRKI_STAGING_HUB_IMAGE` (the separately approved Hub-only staging stack
  and its immutable, already-present image; never use the production base file)
- Exact comparison values copied from the verified signed approval/observation:
  `VIRKI_STAGING_APPROVED_PROJECT`, `VIRKI_STAGING_APPROVED_HUB_PROJECT`,
  `VIRKI_STAGING_APPROVED_IMAGE`, `VIRKI_STAGING_APPROVED_HUB_IMAGE`,
  `VIRKI_STAGING_APPROVED_OCI_DIGEST`, `VIRKI_STAGING_APPROVED_HUB_OCI_DIGEST`,
  `VIRKI_STAGING_APPROVED_HUB_COMPOSE_FILE_SHA256`,
  `VIRKI_STAGING_APPROVED_WORKER_RESOURCE_POLICY_ID`,
  `VIRKI_STAGING_APPROVED_WORKER_MEMORY_BYTES`,
  `VIRKI_STAGING_APPROVED_WORKER_CPU_NANO`,
  `VIRKI_STAGING_APPROVED_WORKER_PIDS_LIMIT`, and
  `VIRKI_STAGING_APPROVED_WORKER_INTERVAL_MS`, plus
  `VIRKI_STAGING_APPROVED_WORKER_RESOURCE_POLICY_EVIDENCE_REF`. These are
  comparison values, not secrets; copy them from the verified signed documents,
  never invent or recalculate them from an unsigned source.
- `VIRKI_STAGING_EMAIL_WORKER_DATABASE_URL` (dedicated
  `virki_email_worker` login on the isolated staging database)
- `VIRKI_STAGING_HUB_DATABASE_URL` (separate `virki_runtime` login to the
  same approved staging database)
- `VIRKI_STAGING_EMAIL_WORKER_MEMORY_LIMIT`,
  `VIRKI_STAGING_EMAIL_WORKER_CPUS_LIMIT` and
  `VIRKI_STAGING_EMAIL_WORKER_PIDS_LIMIT`, copied exactly from the signed
  resource policy (memory as an IEC unit, CPU with at most nine decimals, PID
  count as a positive integer)
- `VIRKI_STAGING_EMAIL_OUTBOX_KEY` (the same staging-only key used by the
  staging Hub, distinct from production)
- `VIRKI_STAGING_EMAIL_SMTP_HOST`, `VIRKI_STAGING_EMAIL_SMTP_PORT`,
  `VIRKI_STAGING_EMAIL_SMTP_SECURE`, `VIRKI_STAGING_EMAIL_SMTP_USER`,
  `VIRKI_STAGING_EMAIL_SMTP_PASSWORD`
- Non-secret relay identities copied from the signed approval/observation:
  `VIRKI_STAGING_APPROVED_SMTP_TENANT_ID`,
  `VIRKI_STAGING_APPROVED_SMTP_ENDPOINT_ID`, and
  `VIRKI_STAGING_APPROVED_SMTP_ACCOUNT_ID`. The verifier hashes the actual
  SMTP username and compares the endpoint/port/TLS mode and username hash to
  the signed approval and independent relay observation.
- `VIRKI_STAGING_EMAIL_FROM`,
  `VIRKI_STAGING_EMAIL_MIN_SEND_INTERVAL_MS`
- Optional `VIRKI_STAGING_EMAIL_REPLY_TO`.

The operator must also provide the signed inventory's exact database server
hostname, resolved server address, port and database name as
`VIRKI_STAGING_APPROVED_DB_HOST`,
`VIRKI_STAGING_APPROVED_DB_SERVER_ADDR`,
`VIRKI_STAGING_APPROVED_DB_PORT` and
`VIRKI_STAGING_APPROVED_DB_NAME`. These are comparison values, not secrets.

The Docker daemon stores container environment in inspectable metadata.
Restrict host/root and Docker-socket access to the named operator, keep shell
transcription and command-output capture disabled for secret-bearing commands,
and never print `docker compose config`, raw `docker inspect`, environment
blocks, SMTP headers, OTPs, recovery URLs or database URLs. The manifest has
no Docker secrets-file integration; environment injection is a documented
host-trust dependency, not encrypted-at-rest secret storage.

## 2. Read-only target and manifest preflight

Run on the **staging host** from the exact approved source checkout. This is
the only Compose file for the worker. Do not add `docker-compose.prod.yml`,
any base file, `--env-file`, `COMPOSE_FILE`, or an unapproved project.
Keep the target preflight, Hub start, worker start and both stop blocks in the
**same protected shell session** so the verified context, project, images,
network IDs and initial restart count cannot be lost or silently re-entered.

```sh
set -euo pipefail
[[ -n "${BASH_VERSION:-}" && "${BASH_VERSINFO[0]}" -ge 4 ]]
export COMPOSE_DISABLE_ENV_FILE=1

: "${VIRKI_STAGING_DOCKER_CONTEXT:?approved Docker context required}"
: "${VIRKI_STAGING_EXPECTED_DOCKER_ID:?independently witnessed daemon ID required}"
: "${VIRKI_STAGING_APPROVED_PROJECT:?owner-approved isolated project required}"
: "${VIRKI_STAGING_COMPOSE_PROJECT:?staging Compose project required}"
: "${VIRKI_STAGING_EMAIL_WORKER_NETWORK:?pre-existing staging network required}"
: "${VIRKI_STAGING_APPROVED_NETWORK_ID:?independently witnessed network ID required}"
: "${VIRKI_STAGING_APPROVED_NETWORK_POLICY:?signed network policy required}"
: "${VIRKI_STAGING_RESOURCE_POLICY_ID:?signed worker resource policy required}"
: "${VIRKI_STAGING_RESOURCE_POLICY_RECEIPT:?worker resource policy evidence required}"
: "${VIRKI_STAGING_APPROVED_WORKER_RESOURCE_POLICY_ID:?signed worker resource policy ID required}"
: "${VIRKI_STAGING_APPROVED_WORKER_MEMORY_BYTES:?signed worker memory bytes required}"
: "${VIRKI_STAGING_APPROVED_WORKER_CPU_NANO:?signed worker CPU nanocores required}"
: "${VIRKI_STAGING_APPROVED_WORKER_PIDS_LIMIT:?signed worker PID limit required}"
: "${VIRKI_STAGING_APPROVED_WORKER_INTERVAL_MS:?signed worker send interval required}"
: "${VIRKI_STAGING_APPROVED_WORKER_RESOURCE_POLICY_EVIDENCE_REF:?signed independent resource evidence reference required}"
: "${VIRKI_STAGING_EMAIL_WORKER_MEMORY_LIMIT:?signed worker memory limit required}"
: "${VIRKI_STAGING_EMAIL_WORKER_CPUS_LIMIT:?signed worker CPU limit required}"
: "${VIRKI_STAGING_EMAIL_WORKER_PIDS_LIMIT:?signed worker PID limit required}"
: "${VIRKI_STAGING_EMAIL_WORKER_DATABASE_URL:?isolated staging worker database URL required}"
: "${VIRKI_STAGING_HUB_COMPOSE_FILE:?approved Hub-only staging Compose file required}"
: "${VIRKI_STAGING_HUB_COMPOSE_FILE_SHA256:?signed Hub Compose file SHA-256 required}"
: "${VIRKI_STAGING_HUB_COMPOSE_PROJECT:?approved isolated Hub Compose project required}"
: "${VIRKI_STAGING_APPROVED_HUB_PROJECT:?signed Hub Compose project required}"
: "${VIRKI_STAGING_HUB_IMAGE:?immutable staging Hub image required}"
: "${VIRKI_STAGING_APPROVED_HUB_IMAGE:?owner-approved exact Hub image ref required}"
: "${VIRKI_STAGING_APPROVED_HUB_OCI_DIGEST:?signed Hub OCI digest required}"
: "${VIRKI_STAGING_APPROVED_HUB_COMPOSE_FILE_SHA256:?signed Hub Compose file hash required}"
: "${VIRKI_STAGING_HUB_DATABASE_URL:?isolated staging Hub database URL required}"
: "${VIRKI_STAGING_APPROVED_DB_HOST:?signed database hostname required}"
: "${VIRKI_STAGING_APPROVED_DB_SERVER_ADDR:?signed database server address required}"
: "${VIRKI_STAGING_APPROVED_DB_PORT:?signed database server port required}"
: "${VIRKI_STAGING_APPROVED_DB_NAME:?signed database name required}"
: "${VIRKI_STAGING_EMAIL_WORKER_IMAGE:?immutable staging image required}"
: "${VIRKI_STAGING_APPROVED_IMAGE:?owner-approved exact image ref required}"
: "${VIRKI_STAGING_APPROVED_OCI_DIGEST:?signed worker OCI digest required}"
: "${VIRKI_STAGING_APPROVED_SOURCE_SHA:?owner-approved exact source SHA required}"
command -v docker >/dev/null
command -v git >/dev/null
command -v jq >/dev/null
command -v awk >/dev/null
command -v node >/dev/null
command -v realpath >/dev/null
command -v grep >/dev/null
command -v sha256sum >/dev/null
command -v cut >/dev/null
command -v stat >/dev/null
command -v id >/dev/null
node -e 'if (Number(process.versions.node.split(".")[0]) < 22) process.exit(1)'

for name in COMPOSE_FILE COMPOSE_PROJECT_NAME DOCKER_HOST DOCKER_CONTEXT; do
  if [[ -n "${!name:-}" ]]; then
    printf 'BLOCK: unexpected override %s is set\n' "$name" >&2
    exit 1
  fi
done

ctx="$VIRKI_STAGING_DOCKER_CONTEXT"
project="$VIRKI_STAGING_COMPOSE_PROJECT"
network="$VIRKI_STAGING_EMAIL_WORKER_NETWORK"
image="$VIRKI_STAGING_EMAIL_WORKER_IMAGE"
file="infra/docker-compose.staging-email-worker-only.yml"
profile="staging-email-worker-manual"
if [[ "$VIRKI_STAGING_EMAIL_WORKER_MEMORY_LIMIT" =~ ^([1-9][0-9]*)([kKmMgGtT])?$ ]]; then
  memory_value="${BASH_REMATCH[1]}"
  memory_unit="${BASH_REMATCH[2],,}"
else
  printf 'BLOCK: worker memory limit must be a positive integer with optional K/M/G/T unit\n' >&2
  exit 1
fi
case "$memory_unit" in
  "") memory_factor=1 ;;
  k) memory_factor=1024 ;;
  m) memory_factor=1048576 ;;
  g) memory_factor=1073741824 ;;
  t) memory_factor=1099511627776 ;;
  *) exit 1 ;;
esac
(( 10#$memory_value <= 9007199254740991 / memory_factor ))
memory_bytes=$((10#$memory_value * memory_factor))
[[ "$VIRKI_STAGING_EMAIL_WORKER_PIDS_LIMIT" =~ ^[1-9][0-9]*$ ]]
[[ "$VIRKI_STAGING_EMAIL_WORKER_CPUS_LIMIT" =~ ^[0-9]+([.][0-9]{1,9})?$ ]]
[[ "$VIRKI_STAGING_APPROVED_WORKER_MEMORY_BYTES" =~ ^[1-9][0-9]*$ ]]
[[ "$VIRKI_STAGING_APPROVED_WORKER_CPU_NANO" =~ ^[1-9][0-9]*$ ]]
[[ "$VIRKI_STAGING_APPROVED_WORKER_PIDS_LIMIT" =~ ^[1-9][0-9]*$ ]]
[[ "$VIRKI_STAGING_APPROVED_WORKER_INTERVAL_MS" =~ ^[1-9][0-9]*$ ]]
(( 10#$VIRKI_STAGING_APPROVED_WORKER_INTERVAL_MS <= 60000 ))
[[ "$VIRKI_STAGING_EMAIL_MIN_SEND_INTERVAL_MS" == "$VIRKI_STAGING_APPROVED_WORKER_INTERVAL_MS" ]]
cpu_nanos="$(awk -v cpus="$VIRKI_STAGING_EMAIL_WORKER_CPUS_LIMIT" 'BEGIN { scaled = cpus * 1000000000; if (cpus <= 0 || scaled > 9007199254740991 || scaled != int(scaled)) exit 1; printf "%.0f", scaled }')"
[[ "$cpu_nanos" =~ ^[1-9][0-9]*$ ]]
[[ "$memory_bytes" == "$VIRKI_STAGING_APPROVED_WORKER_MEMORY_BYTES" ]]
[[ "$cpu_nanos" == "$VIRKI_STAGING_APPROVED_WORKER_CPU_NANO" ]]
[[ "$VIRKI_STAGING_EMAIL_WORKER_PIDS_LIMIT" == "$VIRKI_STAGING_APPROVED_WORKER_PIDS_LIMIT" ]]
[[ "$VIRKI_STAGING_RESOURCE_POLICY_ID" =~ ^[A-Za-z][A-Za-z0-9._-]{2,95}$ ]]
[[ "$VIRKI_STAGING_RESOURCE_POLICY_RECEIPT" =~ ^[A-Za-z][A-Za-z0-9._-]{2,95}$ ]]
[[ "$VIRKI_STAGING_RESOURCE_POLICY_ID" == "$VIRKI_STAGING_APPROVED_WORKER_RESOURCE_POLICY_ID" ]]
[[ "$VIRKI_STAGING_RESOURCE_POLICY_RECEIPT" == "$VIRKI_STAGING_APPROVED_WORKER_RESOURCE_POLICY_EVIDENCE_REF" ]]
[[ "$VIRKI_STAGING_APPROVED_DB_PORT" =~ ^[1-9][0-9]{0,4}$ ]]
(( 10#$VIRKI_STAGING_APPROVED_DB_PORT <= 65535 ))
[[ "$VIRKI_STAGING_APPROVED_DB_NAME" =~ ^[A-Za-z0-9_]+$ ]]
db_url_target="$(node -e '
  const url = new URL(process.env.VIRKI_STAGING_EMAIL_WORKER_DATABASE_URL);
  if (!["postgres:", "postgresql:"].includes(url.protocol) ||
      !url.hostname || !url.username || !url.password || !url.pathname) process.exit(1);
  const queryKeys = [...url.searchParams.keys()];
  if (url.hash || queryKeys.length !== 1 || queryKeys[0] !== "sslmode" ||
      url.searchParams.get("sslmode") !== "verify-full") process.exit(1);
  const host = url.hostname.replace(/^\[|\]$/gu, "").toLowerCase();
  const database = decodeURIComponent(url.pathname.replace(/^\//u, ""));
  const username = decodeURIComponent(url.username);
  if (!database || username !== "virki_email_worker") process.exit(1);
  process.stdout.write([host, url.port || "5432", database, username].join("|"));
')"
IFS='|' read -r worker_db_host worker_db_port worker_db_name worker_db_user <<<"$db_url_target"
[[ "$worker_db_host" == "${VIRKI_STAGING_APPROVED_DB_HOST,,}" ]]
[[ "$worker_db_port" == "$VIRKI_STAGING_APPROVED_DB_PORT" ]]
[[ "$worker_db_name" == "$VIRKI_STAGING_APPROVED_DB_NAME" ]]
[[ "$worker_db_user" == "virki_email_worker" ]]
unset db_url_target

[[ "$project" == "$VIRKI_STAGING_APPROVED_PROJECT" ]]
[[ "$project" =~ ^[a-z0-9][a-z0-9_-]{2,95}$ ]]
[[ "$project" != "virki-prod" && "$project" != demanage* ]]
[[ "$image" == "$VIRKI_STAGING_APPROVED_IMAGE" ]]
[[ "$VIRKI_STAGING_APPROVED_OCI_DIGEST" =~ ^sha256:[a-f0-9]{64}$ ]]
[[ "${image##*@}" == "$VIRKI_STAGING_APPROVED_OCI_DIGEST" ]]
[[ "$image" =~ @sha256:[a-f0-9]{64}$ ]]
[[ "$VIRKI_STAGING_APPROVED_SOURCE_SHA" =~ ^[a-f0-9]{40}$ ]]
actual_source_sha="$(git rev-parse HEAD)"
[[ "$actual_source_sha" == "$VIRKI_STAGING_APPROVED_SOURCE_SHA" ]]
[[ -z "$(git status --porcelain)" ]]

host_id="$(docker --context "$ctx" info --format '{{.ID}}|{{.OSType}}|{{.Architecture}}')"
[[ "$host_id" == "$VIRKI_STAGING_EXPECTED_DOCKER_ID|linux|amd64" ]]

image_metadata="$(docker --context "$ctx" image inspect "$image" \
  --format '{{.Id}}|{{index .Config.Labels "org.opencontainers.image.revision"}}|{{index .Config.Labels "org.opencontainers.image.source"}}')"
IFS='|' read -r image_id image_revision image_source <<<"$image_metadata"
repo_digests="$(docker --context "$ctx" image inspect "$image" --format '{{join .RepoDigests "\n"}}')"
grep -Fqx "$image" <<<"$repo_digests"
[[ "$image_id" == sha256:* ]]
[[ "$image_revision" == "$VIRKI_STAGING_APPROVED_SOURCE_SHA" ]]
[[ "$image_source" == "https://github.com/bielxdh3/Virki" ]]
unset image_metadata image_revision image_source

network_id="$(docker --context "$ctx" network inspect "$network" --format '{{.Id}}')"
[[ "$network_id" == "$VIRKI_STAGING_APPROVED_NETWORK_ID" ]]
network_policy="$(docker --context "$ctx" network inspect "$network" --format '{{.Internal}}|{{.Driver}}|{{.Scope}}')"
printf 'STAGING_NETWORK_POLICY=%s\n' "$network_policy"
[[ "$network_policy" == "$VIRKI_STAGING_APPROVED_NETWORK_POLICY" ]]
if [[ "${network_policy%%|*}" != "true" ]]; then
  : "${VIRKI_STAGING_EGRESS_POLICY_ID:?independent egress policy ID required for a non-internal network}"
  : "${VIRKI_STAGING_EGRESS_POLICY_RECEIPT:?independent egress policy evidence required}"
fi
docker --context "$ctx" network inspect "$network" \
  --format '{{range $id, $c := .Containers}}{{printf "%s\n" $c.Name}}{{end}}'
# If Internal is false, BLOCK unless an independently enforced host/firewall
# egress policy restricts the worker to the staging DB and approved SMTP relay.
# Prefer an internal network with a separately controlled staging relay.

# Capture the interpolated configuration only in memory. It contains secrets.
if ! config="$(docker --context "$ctx" compose --project-name "$project" \
  --profile "$profile" -f "$file" config --format json 2>/dev/null)"; then
  printf 'BLOCK: standalone worker Compose render failed\n' >&2
  exit 1
fi
printf '%s' "$config" | jq -e --arg project "$project" --arg image "$image" --arg network "$network" \
  --argjson memory "$memory_bytes" --argjson cpus "$VIRKI_STAGING_EMAIL_WORKER_CPUS_LIMIT" \
  --argjson pids "$VIRKI_STAGING_EMAIL_WORKER_PIDS_LIMIT" \
  --arg interval "$VIRKI_STAGING_EMAIL_MIN_SEND_INTERVAL_MS" '
  .services["email-worker"] as $w
  | .name == $project
    and (.services | keys == ["email-worker"])
    and $w.image == $image
    and (($w.command | if type == "array" then join(" ") else . end) == "npm run email:worker --workspace @virki/auth")
    and (($w.entrypoint // null) == null)
    and $w.restart == "no"
    and $w.pull_policy == "never"
    and $w.profiles == ["staging-email-worker-manual"]
    and $w.user == "node:node"
    and $w.read_only == true
    and $w.cap_drop == ["ALL"]
    and (($w.cap_add // []) | length == 0)
    and (($w.security_opt // []) | index("no-new-privileges:true") != null)
    and (($w.ports // []) | length == 0)
    and (($w.volumes // []) | length == 0)
    and (($w.depends_on // {}) | length == 0)
    and (($w.env_file // []) | length == 0)
    and (($w.build // null) == null)
    and (($w.privileged // false) == false)
    and (($w.devices // []) | length == 0)
    and (($w.device_cgroup_rules // []) | length == 0)
    and (($w.tmpfs // []) == ["/tmp:rw,noexec,nosuid,nodev,size=64m"])
    and (($w.network_mode // null) == null)
    and (($w.pid // null) == null)
    and (($w.ipc // null) == null)
    and (($w.uts // null) == null)
    and (($w.userns_mode // null) == null)
    and (($w.cgroup // null) == null)
    and (($w.container_name // null) == null)
    and (($w.healthcheck // null) == null)
    and (($w.mem_limit | tonumber) == $memory)
    and $w.cpus == $cpus
    and $w.pids_limit == $pids
    and (($w.networks // {}) | keys == ["staging-mail"])
    and ((.volumes // {}) | length == 0)
    and (.networks | keys == ["staging-mail"])
    and .networks["staging-mail"].external == true
    and .networks["staging-mail"].name == $network
    and ($w.environment | keys == ["DATABASE_URL","NODE_ENV","VIRKI_EMAIL_FROM",
      "VIRKI_EMAIL_MIN_SEND_INTERVAL_MS","VIRKI_EMAIL_OUTBOX_KEY","VIRKI_EMAIL_REPLY_TO",
      "VIRKI_EMAIL_SMTP_HOST","VIRKI_EMAIL_SMTP_PASSWORD","VIRKI_EMAIL_SMTP_PORT",
      "VIRKI_EMAIL_SMTP_SECURE","VIRKI_EMAIL_SMTP_USER","VIRKI_EMAIL_TRANSPORT",
      "VIRKI_EMAIL_WORKER_SCOPED_ROLE"])
    and $w.environment.NODE_ENV == "production"
    and $w.environment.VIRKI_EMAIL_WORKER_SCOPED_ROLE == "required"
    and $w.environment.VIRKI_EMAIL_TRANSPORT == "smtp"
    and $w.environment.VIRKI_EMAIL_MIN_SEND_INTERVAL_MS == $interval
    and (["DATABASE_URL","VIRKI_EMAIL_OUTBOX_KEY","VIRKI_EMAIL_SMTP_HOST",
      "VIRKI_EMAIL_SMTP_PORT","VIRKI_EMAIL_SMTP_SECURE","VIRKI_EMAIL_SMTP_USER",
      "VIRKI_EMAIL_SMTP_PASSWORD","VIRKI_EMAIL_FROM","VIRKI_EMAIL_MIN_SEND_INTERVAL_MS"]
      | all(.[]; $w.environment[.] != null and $w.environment[.] != ""))
    and $w.environment.VIRKI_EMAIL_SMTP_HOST == env.VIRKI_STAGING_EMAIL_SMTP_HOST
    and $w.environment.VIRKI_EMAIL_SMTP_PORT == env.VIRKI_STAGING_EMAIL_SMTP_PORT
    and $w.environment.VIRKI_EMAIL_SMTP_SECURE == env.VIRKI_STAGING_EMAIL_SMTP_SECURE
    and $w.environment.VIRKI_EMAIL_SMTP_USER == env.VIRKI_STAGING_EMAIL_SMTP_USER
    and $w.environment.VIRKI_EMAIL_SMTP_PASSWORD == env.VIRKI_STAGING_EMAIL_SMTP_PASSWORD
' >/dev/null
unset config

# The Hub is a separate staging project. It shares the same external network
# and outbox key, but uses virki_runtime and receives no SMTP credentials.
hub_file="$VIRKI_STAGING_HUB_COMPOSE_FILE"
hub_project="$VIRKI_STAGING_HUB_COMPOSE_PROJECT"
hub_image="$VIRKI_STAGING_HUB_IMAGE"
[[ "$hub_project" != "$project" ]]
[[ "$hub_project" == "$VIRKI_STAGING_APPROVED_HUB_PROJECT" ]]
[[ "$hub_project" =~ ^[a-z0-9][a-z0-9_-]{2,95}$ ]]
[[ "$hub_project" != "virki-prod" && "$hub_project" != demanage* ]]
[[ "$hub_file" == /* && -f "$hub_file" && ! -L "$hub_file" ]]
[[ "$(realpath -e "$hub_file")" == "$hub_file" ]]
[[ "$VIRKI_STAGING_HUB_COMPOSE_FILE_SHA256" =~ ^[a-f0-9]{64}$ ]]
[[ "$VIRKI_STAGING_HUB_COMPOSE_FILE_SHA256" == "$VIRKI_STAGING_APPROVED_HUB_COMPOSE_FILE_SHA256" ]]
hub_file_sha="$(sha256sum "$hub_file" | cut -d' ' -f1)"
[[ "$hub_file_sha" == "$VIRKI_STAGING_HUB_COMPOSE_FILE_SHA256" ]]
[[ "$hub_file" != *"/docker-compose.prod.yml" ]]
[[ "$hub_file" != *"/docker-compose.staging-email-worker.yml" ]]
[[ "$hub_image" == "$VIRKI_STAGING_APPROVED_HUB_IMAGE" ]]
[[ "$VIRKI_STAGING_APPROVED_HUB_OCI_DIGEST" =~ ^sha256:[a-f0-9]{64}$ ]]
[[ "${hub_image##*@}" == "$VIRKI_STAGING_APPROVED_HUB_OCI_DIGEST" ]]
[[ "$hub_image" =~ @sha256:[a-f0-9]{64}$ ]]
hub_image_metadata="$(docker --context "$ctx" image inspect "$hub_image" \
  --format '{{.Id}}|{{index .Config.Labels "org.opencontainers.image.revision"}}|{{index .Config.Labels "org.opencontainers.image.source"}}')"
IFS='|' read -r hub_image_id hub_image_revision hub_image_source <<<"$hub_image_metadata"
hub_repo_digests="$(docker --context "$ctx" image inspect "$hub_image" --format '{{join .RepoDigests "\n"}}')"
grep -Fqx "$hub_image" <<<"$hub_repo_digests"
[[ "$hub_image_id" == sha256:* ]]
[[ "$hub_image_revision" == "$VIRKI_STAGING_APPROVED_SOURCE_SHA" ]]
[[ "$hub_image_source" == "https://github.com/bielxdh3/Virki" ]]
unset hub_image_metadata hub_image_revision hub_image_source

# OCI labels and a local image ID are consistency checks, not build provenance.
# Before any staging activation, the independent operator must verify and
# retain the exact-final-SHA hosted CI and CodeQL runs, GHCR provenance for the
# immutable manifest digest/platform, and the host's runtime image ID/config
# hash. A missing or mismatched provenance receipt is a hard stop.

hub_db_target="$(node -e '
  const url = new URL(process.env.VIRKI_STAGING_HUB_DATABASE_URL);
  if (!["postgres:", "postgresql:"].includes(url.protocol) ||
      !url.hostname || !url.username || !url.password || !url.pathname) process.exit(1);
  const queryKeys = [...url.searchParams.keys()];
  if (url.hash || queryKeys.length !== 1 || queryKeys[0] !== "sslmode" ||
      url.searchParams.get("sslmode") !== "verify-full") process.exit(1);
  const host = url.hostname.replace(/^\[|\]$/gu, "").toLowerCase();
  const database = decodeURIComponent(url.pathname.replace(/^\//u, ""));
  if (!database) process.exit(1);
  process.stdout.write([host, url.port || "5432", database, decodeURIComponent(url.username)].join("|"));
')"
IFS='|' read -r hub_db_host hub_db_port hub_db_name hub_db_user <<<"$hub_db_target"
[[ "$hub_db_host" == "${VIRKI_STAGING_APPROVED_DB_HOST,,}" ]]
[[ "$hub_db_port" == "$VIRKI_STAGING_APPROVED_DB_PORT" ]]
[[ "$hub_db_name" == "$VIRKI_STAGING_APPROVED_DB_NAME" ]]
[[ "$hub_db_user" == "virki_runtime" ]]
unset hub_db_target
if ! hub_config="$(docker --context "$ctx" compose --project-name "$hub_project" \
  -f "$hub_file" config --format json 2>/dev/null)"; then
  printf 'BLOCK: approved Hub-only staging Compose render failed\n' >&2
  exit 1
fi
printf '%s' "$hub_config" | jq -e --arg project "$hub_project" --arg image "$hub_image" --arg network "$network" '
  .services.hub as $h
  | .networks as $networks
  | .name == $project
    and $h.image == $image
    and (($h.command | if type == "array" then join(" ") else . end) == "npm run start --workspace @virki/hub")
    and (($h.entrypoint // null) == null)
    and $h.pull_policy == "never"
    and $h.restart == "no"
    and $h.user == "node:node"
    and $h.read_only == true
    and $h.cap_drop == ["ALL"]
    and $h.security_opt == ["no-new-privileges:true"]
    and (($h.tmpfs // []) | sort == ["/app/apps/hub/.next/cache:rw,noexec,nosuid,nodev,size=128m", "/tmp:rw,noexec,nosuid,nodev,size=64m"])
    and (($h.ports // []) | length == 0)
    and (($h.volumes // []) | length == 0)
    and (($h.depends_on // {}) | length == 0)
    and (($h.cap_add // []) | length == 0)
    and (($h.devices // []) | length == 0)
    and (($h.device_cgroup_rules // []) | length == 0)
    and (($h.sysctls // {}) | length == 0)
    and (($h.group_add // []) | length == 0)
    and (($h.extra_hosts // []) | length == 0)
    and (($h.volumes_from // []) | length == 0)
    and (($h.secrets // []) | length == 0)
    and (($h.configs // []) | length == 0)
    and (($h.runtime // null) == null)
    and (($h.use_api_socket // false) == false)
    and (($h.privileged // false) == false)
    and (($h.network_mode // null) == null)
    and (($h.pid // null) == null)
    and (($h.ipc // null) == null)
    and (($h.uts // null) == null)
    and (($h.userns_mode // null) == null)
    and (($h.container_name // null) == null)
    and (($h.healthcheck // null) != null)
    and (($h.build // null) == null)
    and (($h.env_file // []) | length == 0)
    and $h.environment.DATABASE_URL == env.VIRKI_STAGING_HUB_DATABASE_URL
    and $h.environment.VIRKI_EMAIL_OUTBOX_KEY == env.VIRKI_STAGING_EMAIL_OUTBOX_KEY
    and $h.environment.NODE_ENV == "production"
    and $h.environment.VIRKI_HUB_PERIMETER_MODE == "native"
    and $h.environment.VIRKI_PASSKEYS_ENABLED == "false"
    and $h.environment.VIRKI_ADMIN_PASSKEYS_ENABLED == "false"
    and (($h.environment.VIRKI_PASSKEYS_LOCAL_TESTING // null) == null)
    and $h.environment.CLOUDFLARE_ACCESS_JWT_REQUIRED == "false"
    and (($h.environment.CLOUDFLARE_ACCESS_AUDIENCE // null) == null)
    and (($h.environment.CLOUDFLARE_TEAM_DOMAIN // null) == null)
    and (($h.environment.CLOUDFLARE_ACCESS_JWKS_URL // null) == null)
    and $h.environment.VIRKI_EMAIL_TRANSPORT == "smtp"
    and (($h.environment.VIRKI_EMAIL_WORKER_SCOPED_ROLE // null) == null)
    and ([$h.environment | keys[] | select(startswith("VIRKI_EMAIL_SMTP_"))] | length == 0)
    and (.services | keys == ["hub"])
    and (($h.networks // {}) | keys | length == 1)
    and (.networks | keys | length == 1)
    and ((.volumes // {}) | length == 0)
    and any($h.networks | keys[]; . as $key | $networks[$key].external == true and $networks[$key].name == $network)
' >/dev/null
unset hub_config
printf 'STAGING_HUB_ISOLATION_PREFLIGHT=PASS\n'

# First activation must not silently adopt/reconcile any resource left by a
# previous project using this supposedly fresh, isolated project identity.
existing_containers="$(docker --context "$ctx" ps -aq \
  --filter "label=com.docker.compose.project=$project")"
existing_volumes="$(docker --context "$ctx" volume ls -q \
  --filter "label=com.docker.compose.project=$project")"
existing_networks="$(docker --context "$ctx" network ls -q \
  --filter "label=com.docker.compose.project=$project")"
[[ -z "$existing_containers" && -z "$existing_volumes" && -z "$existing_networks" ]]
existing_worker_services="$(docker --context "$ctx" ps -aq \
  --filter "label=com.docker.compose.service=email-worker")"
[[ -z "$existing_worker_services" ]]
printf 'STAGING_WORKER_PREFLIGHT=PASS\n'
```

Also inspect the approved network's attached endpoint names and compare each
to the signed staging inventory. The network must contain only the approved
staging DB, Hub/relay and other named staging services; no production,
deManage, unknown or user-controlled endpoint. Compose declares an external
network but cannot enforce its isolation or egress policy. If the network is
shared or its policy is unknown, stop.

Use a protected `PGSERVICEFILE` and `PGPASSFILE` (mode 0600, private parent)
for database observation; never put a password-bearing URL in a command
argument:

```sh
set -euo pipefail
export PGSERVICEFILE=/run/virki-staging/pg_service.conf
export PGPASSFILE=/run/virki-staging/pgpass
service_dir="$(dirname "$PGSERVICEFILE")"
test ! -L "$service_dir"
test ! -L "$PGSERVICEFILE"
test ! -L "$PGPASSFILE"
test "$(realpath -e "$service_dir")" = "$service_dir"
test "$(dirname "$PGPASSFILE")" = "$service_dir"
test "$(stat -c '%u:%a' "$service_dir")" = "$(id -u):700"
test "$(stat -c '%u:%a' "$PGSERVICEFILE")" = "$(id -u):600"
test "$(stat -c '%u:%a' "$PGPASSFILE")" = "$(id -u):600"
test -f "$PGSERVICEFILE" && test -f "$PGPASSFILE"
test ! -L "$PGSERVICEFILE" && test ! -L "$PGPASSFILE"
[[ "$(realpath -e "$PGSERVICEFILE")" == "$PGSERVICEFILE" ]]
[[ "$(realpath -e "$PGPASSFILE")" == "$PGPASSFILE" ]]
test "$(stat -c '%h' "$PGSERVICEFILE")" = "1"
test "$(stat -c '%h' "$PGPASSFILE")" = "1"
service_file="$PGSERVICEFILE"
pass_file="$PGPASSFILE"
if grep -Eiq '^[[:space:]]*password[[:space:]]*=' "$PGSERVICEFILE"; then
  printf 'BLOCK: password material must be in the protected pass file, not the service file\n' >&2
  exit 1
fi
if grep -q '\*' "$PGPASSFILE"; then
  printf 'BLOCK: wildcard pgpass entries are not allowed\n' >&2
  exit 1
fi
require_service_tls() {
  local service="$1"
  awk -v section="[$service]" '
    $0 == section { if (found) bad=1; found=1; active=1; next }
    /^\[/ { if (active) active=0 }
    active && /^[[:space:]]*sslmode[[:space:]]*=/ {
      count++; value=$0; sub(/^[^=]*=/, "", value); gsub(/[[:space:]]/, "", value)
      if (value != "verify-full") bad=1
    }
    active && /^[[:space:]]*(password|passfile|hostaddr)[[:space:]]*=/ { bad=1 }
    END { exit !(found && count == 1 && !bad) }
  ' "$PGSERVICEFILE"
}
require_service_tls virki-staging-worker
require_service_tls virki-staging-hub
db_identity="$(PGSERVICE=virki-staging-worker psql --no-password -XAtqc \
  "select inet_server_addr()::text || '|' || inet_server_port()::text || '|' || current_database() || '|' || current_user || '|' || session_user || '|' || current_setting('server_version_num') || '|' || (select ssl::text from pg_stat_ssl where pid=pg_backend_pid())")"
IFS='|' read -r actual_db_addr actual_db_port actual_db_name actual_db_user actual_db_session_user actual_db_version actual_db_ssl <<<"$db_identity"
[[ "$actual_db_addr" == "$VIRKI_STAGING_APPROVED_DB_SERVER_ADDR" ]]
[[ "$actual_db_port" == "$VIRKI_STAGING_APPROVED_DB_PORT" ]]
[[ "$actual_db_name" == "$VIRKI_STAGING_APPROVED_DB_NAME" ]]
[[ "$actual_db_user" == "virki_email_worker" && "$actual_db_session_user" == "virki_email_worker" ]]
[[ "$actual_db_version" =~ ^[0-9]+$ ]]
[[ "$actual_db_ssl" == "true" ]]
printf 'STAGING_WORKER_DATABASE_TARGET=PASS\n'
hub_db_identity="$(PGSERVICE=virki-staging-hub psql --no-password -XAtqc \
  "select inet_server_addr()::text || '|' || inet_server_port()::text || '|' || current_database() || '|' || current_user || '|' || session_user || '|' || current_setting('server_version_num') || '|' || (select ssl::text from pg_stat_ssl where pid=pg_backend_pid())")"
IFS='|' read -r actual_hub_db_addr actual_hub_db_port actual_hub_db_name actual_hub_db_user actual_hub_db_session_user actual_hub_db_version actual_hub_db_ssl <<<"$hub_db_identity"
[[ "$actual_hub_db_addr" == "$VIRKI_STAGING_APPROVED_DB_SERVER_ADDR" ]]
[[ "$actual_hub_db_port" == "$VIRKI_STAGING_APPROVED_DB_PORT" ]]
[[ "$actual_hub_db_name" == "$VIRKI_STAGING_APPROVED_DB_NAME" ]]
[[ "$actual_hub_db_user" == "virki_runtime" && "$actual_hub_db_session_user" == "virki_runtime" ]]
[[ "$actual_hub_db_version" =~ ^[0-9]+$ ]]
[[ "$actual_hub_db_ssl" == "true" ]]
printf 'STAGING_HUB_DATABASE_TARGET=PASS\n'
queue_counts="$(PGSERVICE=virki-staging-worker psql --no-password -XAtqc \
  'select (select count(*) from public."EmailOutboxMessage")::text || chr(124) || (select count(*) from public."EmailDeliveryAttempt")::text')"
if [[ "$queue_counts" != "0|0" ]]; then
  printf 'BLOCK: staging outbox and delivery-attempt tables must both be virgin before Hub/worker activation\n' >&2
  exit 1
fi
printf 'STAGING_VIRGIN_QUEUE=PASS\n'
PGSERVICE=virki-staging-worker psql --no-password -XAtqc \
  'select kind,status,count(*) from public."EmailOutboxMessage" group by kind,status order by kind,status'
PGSERVICE=virki-staging-worker psql --no-password -XAtqc \
  'select status,count(*) from public."EmailDeliveryAttempt" group by status order by status'
```

The connection service must target the same host/port/database encoded in
`VIRKI_STAGING_EMAIL_WORKER_DATABASE_URL`; compare that URL's target without
printing its credentials. The query must match the independently signed
server address, port and database name, and both role fields must be
`virki_email_worker`. Before the first send, all outbox-state counts and
delivery-attempt counts must be zero. Independently verify the migrator,
runtime, Hub and worker roles are distinct and no production credential is
present. The worker's `VIRKI_EMAIL_WORKER_SCOPED_ROLE=required` gate checks
the database role/session identity and effective privilege matrix at startup
and before every outbox iteration; **it does not pin the database host or
database name**. The external endpoint comparison above is therefore
mandatory and does not eliminate a concurrent DBA grant race.

## 2.1 Start and verify the isolated Hub (worker remains stopped)

Start the separately approved Hub only after its exact Compose file, image,
project, external network and `virki_runtime` database target have passed the
checks above. This command starts **only** the Hub. Do not submit any recovery,
OTP or other email-producing action yet: the signed virgin-queue observation
must still show zero messages and zero delivery attempts immediately before
the worker window.

The Hub is deliberately set to `VIRKI_HUB_PERIMETER_MODE=native` for this
staging acceptance; that mode skips Cloudflare Access JWT validation inside
the Hub. Therefore it is **not** safe to expose the staging hostname publicly
without a separate edge boundary. Before this command, independently verify
and retain the owner-approved staging-only edge/firewall policy: default deny,
allow only the exact approved operator/test source IPs or private VPN, deny
unknown hosts, and do not create a broad Access bypass. No production DNS,
Access policy or hostname may be changed. If that edge policy is not live and
independently observed, do not start the Hub. Production remains on the
existing Cloudflare Access path; this staging flag is not production approval.

The current passkey implementation hardcodes USER RP ID `portal.biel.dev.br`
and ADMIN RP ID `hub.biel.dev.br`; its alternate `portal.localhost`/
`hub.localhost` RP IDs are restricted to non-production local testing. A
separate staging hostname therefore cannot currently exercise production-mode
WebAuthn without reusing production RP IDs or enabling the local-test bypass.
Both are prohibited. Keep both passkey flags explicitly `false` and do not set
`VIRKI_PASSKEYS_LOCAL_TESTING`; mark Portal/Hub RP separation **BLOCK**, not
PASS or SKIP, until dedicated staging RP IDs/origins are implemented and
independently reviewed. TOTP-based recovery coverage may proceed separately,
but it cannot satisfy the passkey release gate.

```sh
set -euo pipefail
hub_abort() {
  docker --context "$ctx" compose --project-name "$hub_project" -f "$hub_file" \
    stop --timeout 60 hub >/dev/null 2>&1 || true
  printf 'BLOCK: Hub runtime verification failed; independently confirm physical stop before continuing\n' >&2
  exit 1
}
existing_hub_containers="$(docker --context "$ctx" ps -aq \
  --filter "label=com.docker.compose.project=$hub_project")"
existing_hub_volumes="$(docker --context "$ctx" volume ls -q \
  --filter "label=com.docker.compose.project=$hub_project")"
existing_hub_networks="$(docker --context "$ctx" network ls -q \
  --filter "label=com.docker.compose.project=$hub_project")"
if [[ -n "$existing_hub_containers" || -n "$existing_hub_volumes" || -n "$existing_hub_networks" ]]; then
  printf 'BLOCK: Hub project already owns resources; do not adopt or reconcile them\n' >&2
  exit 1
fi
existing_hub_services="$(docker --context "$ctx" ps -aq \
  --filter "label=com.docker.compose.service=hub")"
if [[ -n "$existing_hub_services" ]]; then
  printf 'BLOCK: another Hub service container exists on the staging daemon\n' >&2
  exit 1
fi
if ! docker --context "$ctx" compose --project-name "$hub_project" -f "$hub_file" \
  up --no-deps --pull never --detach hub; then
  hub_abort
fi
if ! hub_id="$(docker --context "$ctx" compose --project-name "$hub_project" \
  -f "$hub_file" ps -q hub)" || [[ ! "$hub_id" =~ ^[a-f0-9]{64}$ ]]; then
  hub_abort
fi
if ! hub_project_containers="$(docker --context "$ctx" ps -aq \
  --filter "label=com.docker.compose.project=$hub_project")"; then
  hub_abort
fi
[[ "$hub_project_containers" == "$hub_id" ]] || hub_abort
hub_project_volumes="$(docker --context "$ctx" volume ls -q \
  --filter "label=com.docker.compose.project=$hub_project")"
hub_project_networks="$(docker --context "$ctx" network ls -q \
  --filter "label=com.docker.compose.project=$hub_project")"
[[ -z "$hub_project_volumes" && -z "$hub_project_networks" ]] || hub_abort
hub_service_containers="$(docker --context "$ctx" ps -aq \
  --filter "label=com.docker.compose.service=hub")"
[[ "$hub_service_containers" == "$hub_id" ]] || hub_abort
if ! docker --context "$ctx" inspect "$hub_id" | jq -e \
  --arg image "$hub_image" --arg image_id "$hub_image_id" \
  --arg network "$network" --arg network_id "$network_id" '
  .[0] as $c
  | $c.State.Status == "running"
    and $c.Config.Image == $image
    and $c.Image == $image_id
    and (($c.Config.Entrypoint // []) | length == 0)
    and $c.Config.Cmd == ["npm", "run", "start", "--workspace", "@virki/hub"]
    and ($c.NetworkSettings.Networks | keys == [$network])
    and $c.NetworkSettings.Networks[$network].NetworkID == $network_id
    and $c.HostConfig.NetworkMode == $network
    and $c.HostConfig.RestartPolicy.Name == "no"
    and $c.Config.User == "node:node"
    and $c.HostConfig.ReadonlyRootfs == true
    and $c.HostConfig.CapDrop == ["ALL"]
    and (($c.HostConfig.CapAdd // []) | length == 0)
    and $c.HostConfig.SecurityOpt == ["no-new-privileges:true"]
    and (($c.HostConfig.Binds // []) | length == 0)
    and (($c.HostConfig.Tmpfs // {}) | keys == ["/app/apps/hub/.next/cache", "/tmp"])
    and ((($c.HostConfig.Tmpfs["/tmp"] | split(",") | sort) == ["nodev","noexec","nosuid","rw","size=64m"])
      or (($c.HostConfig.Tmpfs["/tmp"] | split(",") | sort) == ["nodev","noexec","nosuid","rw","size=67108864"]))
    and ((($c.HostConfig.Tmpfs["/app/apps/hub/.next/cache"] | split(",") | sort) == ["nodev","noexec","nosuid","rw","size=128m"])
      or (($c.HostConfig.Tmpfs["/app/apps/hub/.next/cache"] | split(",") | sort) == ["nodev","noexec","nosuid","rw","size=134217728"]))
    and (($c.Mounts // []) | length == 2)
    and ([$c.Mounts[].Destination] | sort == ["/app/apps/hub/.next/cache", "/tmp"])
    and all($c.Mounts[]; .Type == "tmpfs")
    and (($c.HostConfig.Devices // []) | length == 0)
    and (($c.HostConfig.DeviceRequests // []) | length == 0)
    and (($c.HostConfig.DeviceCgroupRules // []) | length == 0)
    and (($c.HostConfig.Sysctls // {}) | length == 0)
    and (($c.HostConfig.VolumesFrom // []) | length == 0)
    and (($c.HostConfig.Links // []) | length == 0)
    and (($c.HostConfig.ExtraHosts // []) | length == 0)
    and (($c.HostConfig.GroupAdd // []) | length == 0)
    and (($c.HostConfig.Dns // []) | length == 0)
    and (($c.HostConfig.DnsSearch // []) | length == 0)
    and (($c.HostConfig.DnsOptions // []) | length == 0)
    and $c.HostConfig.Privileged == false
    and (($c.HostConfig.PortBindings // {}) | length == 0)
    and (($c.HostConfig.PidMode // "") == "" or $c.HostConfig.PidMode == "private")
    and (($c.HostConfig.IpcMode // "private") == "private")
    and (($c.HostConfig.UTSMode // "") == "" or $c.HostConfig.UTSMode == "private")
    and (($c.HostConfig.UsernsMode // "") == "" or $c.HostConfig.UsernsMode == "private")
    and (($c.HostConfig.CgroupnsMode // "private") == "private")
    and (($c.HostConfig.Runtime // "runc") == "runc")
    and (($c.HostConfig.PublishAllPorts // false) == false)
    and (($c.Config.Env // []) | index("DATABASE_URL=" + env.VIRKI_STAGING_HUB_DATABASE_URL) != null)
    and (($c.Config.Env // []) | index("VIRKI_EMAIL_OUTBOX_KEY=" + env.VIRKI_STAGING_EMAIL_OUTBOX_KEY) != null)
    and (($c.Config.Env // []) | index("NODE_ENV=production") != null)
    and (($c.Config.Env // []) | index("VIRKI_HUB_PERIMETER_MODE=native") != null)
    and (($c.Config.Env // []) | index("VIRKI_PASSKEYS_ENABLED=false") != null)
    and (($c.Config.Env // []) | index("VIRKI_ADMIN_PASSKEYS_ENABLED=false") != null)
    and ([$c.Config.Env[]? | split("=")[0] | select(. == "VIRKI_PASSKEYS_LOCAL_TESTING")] | length == 0)
    and (($c.Config.Env // []) | index("CLOUDFLARE_ACCESS_JWT_REQUIRED=false") != null)
    and ([$c.Config.Env[]? | split("=")[0] | select(. == "CLOUDFLARE_ACCESS_AUDIENCE" or . == "CLOUDFLARE_TEAM_DOMAIN" or . == "CLOUDFLARE_ACCESS_JWKS_URL")] | length == 0)
    and (($c.Config.Env // []) | index("VIRKI_EMAIL_TRANSPORT=smtp") != null)
    and ([$c.Config.Env[]? | split("=")[0] | select(startswith("VIRKI_EMAIL_SMTP_"))] | length == 0)
    and ([$c.Config.Env[]? | split("=")[0] | select(. == "VIRKI_EMAIL_WORKER_SCOPED_ROLE")] | length == 0)
' >/dev/null; then
  hub_abort
fi
if ! hub_health="$(docker --context "$ctx" inspect "$hub_id" \
  --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}NO_HEALTHCHECK{{end}}')"; then
  hub_abort
fi
[[ "$hub_health" == "healthy" ]] || hub_abort
printf 'STAGING_HUB_RUNTIME_ISOLATION=PASS\n'
```

Keep the Hub running for the approved browser window. The Hub runtime check
requires the exact immutable image, `restart=no`, `node:node`, read-only root,
all capabilities dropped, exact `no-new-privileges` security options, only the
two approved tmpfs mounts, no host/persistent mounts, devices, published ports,
privileged mode, added groups/capabilities, alternate runtime, or shared/host
network and process namespaces, and a healthy application check. It does not prove
ingress policy, user isolation or email delivery; those are separate
acceptance gates. Do not start the worker from the Hub project.

## 3. Explicit attended worker window

**Do not run this command until** Gate 0/1/2, independent owner/observer
signatures, provider-enforced allowlist and rejection of an unlisted
recipient, independently signed SMTP tenant/endpoint/account binding and
credential-authentication evidence, TLS/AUTH, rate cap, total-message cap,
empty queue, test inbox ownership and a fresh stopped-worker observation have
all passed. The
separate Hub must use the same staging outbox key and its own staging DB URL.
Immediately before activation, rerun the offline signed-declaration check
with a newly signed observation. Its four inputs must be absolute paths in a
private local directory; independently pin both public keys out of band.

```sh
set -euo pipefail
: "${VIRKI_STAGING_APPROVAL_JSON:?fresh owner-signed approval JSON path required}"
: "${VIRKI_STAGING_OBSERVATION_JSON:?fresh independent observation JSON path required}"
: "${VIRKI_STAGING_APPROVER_PUBLIC_KEY:?pinned owner public key path required}"
: "${VIRKI_STAGING_OBSERVER_PUBLIC_KEY:?pinned independent observer public key path required}"
: "${VIRKI_STAGING_APPROVED_SMTP_TENANT_ID:?signed staging SMTP tenant identity required}"
: "${VIRKI_STAGING_APPROVED_SMTP_ENDPOINT_ID:?signed staging SMTP endpoint identity required}"
: "${VIRKI_STAGING_APPROVED_SMTP_ACCOUNT_ID:?signed staging SMTP account identity required}"
smtp_username_sha256="$(printf '%s' "$VIRKI_STAGING_EMAIL_SMTP_USER" | sha256sum | cut -d' ' -f1)"
preflight_output="$(node scripts/staging-otp-preflight.mjs \
  --approval "$VIRKI_STAGING_APPROVAL_JSON" \
  --observation "$VIRKI_STAGING_OBSERVATION_JSON" \
  --approver-public-key "$VIRKI_STAGING_APPROVER_PUBLIC_KEY" \
  --observer-public-key "$VIRKI_STAGING_OBSERVER_PUBLIC_KEY" \
  --expected-source-sha "$VIRKI_STAGING_APPROVED_SOURCE_SHA" \
  --smtp-tenant-id "$VIRKI_STAGING_APPROVED_SMTP_TENANT_ID" \
  --smtp-endpoint-id "$VIRKI_STAGING_APPROVED_SMTP_ENDPOINT_ID" \
  --smtp-account-id "$VIRKI_STAGING_APPROVED_SMTP_ACCOUNT_ID" \
  --smtp-host "$VIRKI_STAGING_EMAIL_SMTP_HOST" \
  --smtp-port "$VIRKI_STAGING_EMAIL_SMTP_PORT" \
  --smtp-secure "$VIRKI_STAGING_EMAIL_SMTP_SECURE" \
  --smtp-username-sha256 "$smtp_username_sha256")"
unset smtp_username_sha256
expected_preflight_output=$'STAGING_OTP_PREFLIGHT=SIGNED_OFFLINE_DECLARATIONS_CONSISTENT\nLIVE_WORKER_STATE=NOT_OBSERVED_BY_THIS_TOOL\nSTAGING_AUTHORIZATION=NOT_GRANTED_BY_THIS_TOOL\nPRODUCTION_RELEASE=NO_GO'
[[ "$preflight_output" == "$expected_preflight_output" ]]
unset preflight_output expected_preflight_output

abort_worker() {
  docker --context "$ctx" compose --project-name "$project" \
    --profile "$profile" -f "$file" stop --timeout 60 email-worker >/dev/null 2>&1 || true
  docker --context "$ctx" compose --project-name "$hub_project" \
    -f "$hub_file" stop --timeout 60 hub >/dev/null 2>&1 || true
  printf 'BLOCK: worker runtime verification failed; physical stop of worker and Hub must be independently confirmed\n' >&2
  exit 1
}
queue_counts="$(PGSERVICE=virki-staging-worker psql --no-password -XAtqc \
  'select (select count(*) from public."EmailOutboxMessage")::text || chr(124) || (select count(*) from public."EmailDeliveryAttempt")::text')" || abort_worker
[[ "$queue_counts" == "0|0" ]] || abort_worker
if ! docker --context "$ctx" compose --project-name "$project" \
  --profile "$profile" -f "$file" \
  up --no-deps --pull never --detach email-worker; then
  abort_worker
fi

if ! worker_id="$(docker --context "$ctx" compose --project-name "$project" \
  --profile "$profile" -f "$file" ps -q email-worker)" || [[ ! "$worker_id" =~ ^[a-f0-9]{64}$ ]]; then
  abort_worker
fi
if ! worker_project_containers="$(docker --context "$ctx" ps -aq \
  --filter "label=com.docker.compose.project=$project")"; then
  abort_worker
fi
[[ "$worker_project_containers" == "$worker_id" ]] || abort_worker
worker_project_volumes="$(docker --context "$ctx" volume ls -q \
  --filter "label=com.docker.compose.project=$project")"
worker_project_networks="$(docker --context "$ctx" network ls -q \
  --filter "label=com.docker.compose.project=$project")"
[[ -z "$worker_project_volumes" && -z "$worker_project_networks" ]] || abort_worker
if ! worker_service_containers="$(docker --context "$ctx" ps -aq \
  --filter "label=com.docker.compose.service=email-worker")"; then
  abort_worker
fi
[[ "$worker_service_containers" == "$worker_id" ]] || abort_worker
if ! runtime_values="$(docker --context "$ctx" inspect "$worker_id" \
  --format '{{.State.Status}}|{{.State.ExitCode}}|{{.HostConfig.RestartPolicy.Name}}|{{.RestartCount}}|{{.Image}}')"; then
  abort_worker
fi
IFS='|' read -r actual_state actual_exit actual_restart actual_restarts actual_image <<<"$runtime_values"
if [[ "$actual_state" != "running" || "$actual_exit" != "0" || "$actual_restart" != "no" ||
      "$actual_restarts" != "0" || "$actual_image" != "$image_id" ]]; then
  abort_worker
fi
export VIRKI_STAGING_WORKER_INITIAL_RESTART_COUNT="$actual_restarts"
if ! health_state="$(docker --context "$ctx" inspect "$worker_id" \
  --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}NO_HEALTHCHECK{{end}}')"; then
  abort_worker
fi
if [[ "$health_state" != "NO_HEALTHCHECK" ]]; then
  abort_worker
fi
if ! resource_values="$(docker --context "$ctx" inspect "$worker_id" \
  --format '{{.HostConfig.Memory}}|{{.HostConfig.NanoCpus}}|{{.HostConfig.PidsLimit}}')"; then
  abort_worker
fi
IFS='|' read -r actual_memory actual_nano_cpus actual_pids <<<"$resource_values"
if [[ "$actual_memory" != "$memory_bytes" || "$actual_nano_cpus" != "$cpu_nanos" ||
      "$actual_pids" != "$VIRKI_STAGING_EMAIL_WORKER_PIDS_LIMIT" ]]; then
  abort_worker
fi
if ! docker --context "$ctx" inspect "$worker_id" | jq -e \
  --arg image "$image" --arg image_id "$image_id" \
  --arg network "$network" --arg network_id "$network_id" '
  .[0] as $c
  | $c.Config.Image == $image
    and $c.Image == $image_id
    and (($c.Config.Entrypoint // []) | length == 0)
    and $c.Config.Cmd == ["npm", "run", "email:worker", "--workspace", "@virki/auth"]
    and $c.Config.User == "node:node"
    and $c.HostConfig.ReadonlyRootfs == true
    and $c.HostConfig.CapDrop == ["ALL"]
    and (($c.HostConfig.SecurityOpt // []) | index("no-new-privileges:true") != null)
    and (($c.HostConfig.Tmpfs // {}) | keys == ["/tmp"])
    and ((($c.HostConfig.Tmpfs["/tmp"] | split(",") | sort) == ["nodev","noexec","nosuid","rw","size=64m"])
      or (($c.HostConfig.Tmpfs["/tmp"] | split(",") | sort) == ["nodev","noexec","nosuid","rw","size=67108864"]))
    and (($c.HostConfig.Binds // []) | length == 0)
    and (($c.Mounts // []) | length == 1)
    and $c.Mounts[0].Type == "tmpfs"
    and $c.Mounts[0].Destination == "/tmp"
    and (($c.HostConfig.Devices // []) | length == 0)
    and (($c.HostConfig.DeviceRequests // []) | length == 0)
    and (($c.HostConfig.CapAdd // []) | length == 0)
    and $c.HostConfig.Privileged == false
    and (($c.HostConfig.PortBindings // {}) | length == 0)
    and (($c.NetworkSettings.Networks // {}) | keys == [$network])
    and $c.NetworkSettings.Networks[$network].NetworkID == $network_id
    and $c.HostConfig.PidMode != "host"
    and $c.HostConfig.IpcMode != "host"
    and $c.HostConfig.UTSMode != "host"
    and $c.HostConfig.UsernsMode != "host"
    and $c.HostConfig.CgroupnsMode != "host"
    and (($c.Config.Env // []) | index("NODE_ENV=production") != null)
    and (($c.Config.Env // []) | index("DATABASE_URL=" + env.VIRKI_STAGING_EMAIL_WORKER_DATABASE_URL) != null)
    and (($c.Config.Env // []) | index("VIRKI_EMAIL_OUTBOX_KEY=" + env.VIRKI_STAGING_EMAIL_OUTBOX_KEY) != null)
    and (($c.Config.Env // []) | index("VIRKI_EMAIL_TRANSPORT=smtp") != null)
    and (($c.Config.Env // []) | index("VIRKI_EMAIL_WORKER_SCOPED_ROLE=required") != null)
    and (($c.Config.Env // []) | index("VIRKI_EMAIL_MIN_SEND_INTERVAL_MS=" + env.VIRKI_STAGING_EMAIL_MIN_SEND_INTERVAL_MS) != null)
    and (($c.Config.Env // []) | index("VIRKI_EMAIL_SMTP_HOST=" + env.VIRKI_STAGING_EMAIL_SMTP_HOST) != null)
    and (($c.Config.Env // []) | index("VIRKI_EMAIL_SMTP_PORT=" + env.VIRKI_STAGING_EMAIL_SMTP_PORT) != null)
    and (($c.Config.Env // []) | index("VIRKI_EMAIL_SMTP_SECURE=" + env.VIRKI_STAGING_EMAIL_SMTP_SECURE) != null)
    and (($c.Config.Env // []) | index("VIRKI_EMAIL_SMTP_USER=" + env.VIRKI_STAGING_EMAIL_SMTP_USER) != null)
    and (($c.Config.Env // []) | index("VIRKI_EMAIL_SMTP_PASSWORD=" + env.VIRKI_STAGING_EMAIL_SMTP_PASSWORD) != null)
    and (($c.Config.Env // []) | index("VIRKI_EMAIL_FROM=" + env.VIRKI_STAGING_EMAIL_FROM) != null)
    and (($c.Config.Env // []) | index("VIRKI_EMAIL_REPLY_TO=" + (env.VIRKI_STAGING_EMAIL_REPLY_TO // "")) != null)
' >/dev/null; then
  abort_worker
fi
if ! runtime_networks="$(docker --context "$ctx" inspect "$worker_id" \
  --format '{{range $name, $network := .NetworkSettings.Networks}}{{printf "%s|%s\n" $name $network.NetworkID}}{{end}}')"; then
  abort_worker
fi
[[ "$runtime_networks" == "$network|$network_id" ]] || abort_worker
printf 'STAGING_WORKER_RESOURCE_LIMITS=PASS\n'
```

### Real browser and OTP acceptance during the attended window

With the Hub already running and the worker's runtime image, environment,
network, filesystem and signed resource limits verified, execute the full
matrix in [`native-hub-staging-otp-acceptance-20261110.md`](native-hub-staging-otp-acceptance-20261110.md)
against the actual staging HTTPS origin. Use a fresh real browser profile with
no Cloudflare Access cookie/JWT and no synthetic Access/JWKS server. Exercise
USER and ADMIN authentication, USER/ADMIN recovery, each separate ADMIN
credential-recovery method, Portal/Hub passkey relying-party separation,
CSRF/Origin, session/elevation revocation, replay and concurrency cases. Do
not silently skip a case or substitute a local Playwright fixture.

Submit OTP-producing actions only during this one attended worker window and
only for the owner-approved test identities/inboxes. Correlate each Virki
outbox/attempt to the provider's distinct acceptance event and the authorized
recipient's actual inbox confirmation using a non-secret end-to-end trace
identifier. An SMTP `250`, `Message-ID`, database `SENT`, sender/subject/time
or missing error is not proof of receipt. If the trace is ambiguous, mark
`OTP_CORRELATION_UNPROVEN`, stop the worker and record NO-GO; never resend an
uncertain attempt or inspect a third-party inbox.

### Runtime observability during the attended window

Run these read-only observations while the worker is active. They emit
aggregate counts and process/resource metadata only; do not select recipient
addresses, message payloads, OTPs, recovery URLs, SMTP headers or raw attempt
rows.

```sh
set -euo pipefail
if ! docker --context "$ctx" stats --no-stream \
  --format '{{.Name}}|{{.CPUPerc}}|{{.MemUsage}}|{{.MemPerc}}' "$worker_id"; then
  abort_worker
fi
if ! docker --context "$ctx" top "$worker_id" -eo pid,comm; then
  abort_worker
fi
if ! PGSERVICE=virki-staging-worker psql --no-password -XAtqc \
  'select kind,status,count(*) from public."EmailOutboxMessage" group by kind,status order by kind,status'; then
  abort_worker
fi
if ! PGSERVICE=virki-staging-worker psql --no-password -XAtqc \
  'select status,count(*) from public."EmailDeliveryAttempt" group by status order by status'; then
  abort_worker
fi
```

Correlate only opaque outbox/attempt references, provider event IDs and
authorized test-inbox confirmations in the private evidence store. Stop the
worker on any unexpected recipient, new non-test queue item, repeated send
failure, resource-policy mismatch, restart, unknown/ambiguous SMTP result or
unbounded backlog. Because the worker has no Docker HEALTHCHECK, process
state, resource limits, database aggregates and provider/inbox evidence are
separate required signals; none alone proves delivery.

If any runtime assertion fails, immediately stop the worker and treat the
window as NO-GO; do not continue to send tests.

The only acceptable runtime policy is `restart=no`; verify it on the actual
container, not just YAML. The standalone worker has **no Docker HEALTHCHECK**.
Its memory, CPU and PID limits are mandatory signed inputs, rendered by
Compose and compared to the actual Docker `HostConfig` values above. If any
limit is absent, unbounded or does not match the signed resource policy, stop.
The owner-signed approval must carry `workerResourcePolicyId`,
`workerMemoryLimitBytes`, `workerCpuLimitNano` and `workerPidsLimit`;
the independent observation must repeat the same policy ID and three numeric
limits under `worker`, plus `resourcePolicyEvidenceRef`. The offline
preflight compares these exact values. Export the corresponding
`VIRKI_STAGING_APPROVED_WORKER_*` comparison variables from those verified
signed payloads. This runbook converts the Compose memory/CPU inputs and
requires exact equality with the signed byte/nanocore/PID values and the
signed policy/evidence references before rendering; do not estimate or
silently round them.
Do not call a running container healthy: observe process state, scoped DB
identity/privileges, bounded outbox/attempt transitions and sanitized worker
logs. The worker must remain on the approved network with no published ports,
bind mounts or persistent volume dependencies; its only mount is the declared
ephemeral `/tmp` tmpfs.
Record only opaque audit/provider receipt IDs and aggregate counts.

After the single approved OTP window, stop the worker:

```sh
set -euo pipefail
if ! docker --context "$ctx" compose --project-name "$project" \
  --profile "$profile" -f "$file" stop --timeout 60 email-worker; then
  abort_worker
fi
if ! worker_id="$(docker --context "$ctx" compose --project-name "$project" \
  --profile "$profile" -f "$file" ps -aq email-worker)" || [[ ! "$worker_id" =~ ^[a-f0-9]{64}$ ]]; then
  abort_worker
fi
if ! stop_values="$(docker --context "$ctx" inspect "$worker_id" \
  --format '{{.State.Status}}|{{.HostConfig.RestartPolicy.Name}}|{{.RestartCount}}')"; then
  abort_worker
fi
IFS='|' read -r stopped_state stopped_restart stopped_restarts <<<"$stop_values"
if [[ "$stopped_state" != "exited" || "$stopped_restart" != "no" ||
      "$stopped_restarts" != "${VIRKI_STAGING_WORKER_INITIAL_RESTART_COUNT:-0}" ]]; then
  abort_worker
fi
if ! running="$(docker --context "$ctx" compose --project-name "$project" \
  --profile "$profile" -f "$file" ps --status running -q email-worker)" || [[ -n "$running" ]]; then
  abort_worker
fi
if ! all_running_workers="$(docker --context "$ctx" ps -q \
  --filter "label=com.docker.compose.service=email-worker")" || [[ -n "$all_running_workers" ]]; then
  abort_worker
fi
if ! docker --context "$ctx" compose --project-name "$hub_project" \
  -f "$hub_file" stop --timeout 60 hub; then
  abort_worker
fi
if ! hub_stopped_state="$(docker --context "$ctx" inspect "$hub_id" --format '{{.State.Status}}')" ||
   [[ "$hub_stopped_state" != "exited" ]]; then
  abort_worker
fi
if ! hub_running="$(docker --context "$ctx" compose --project-name "$hub_project" \
  -f "$hub_file" ps --status running -q hub)" || [[ -n "$hub_running" ]]; then
  abort_worker
fi
if ! all_running_hubs="$(docker --context "$ctx" ps -q \
  --filter "label=com.docker.compose.service=hub")" || [[ -n "$all_running_hubs" ]]; then
  abort_worker
fi
printf 'STAGING_WORKER_STOPPED=PASS\n'
printf 'STAGING_HUB_STOPPED=PASS\n'
```

Require `exited|no|unchanged restart count`, zero running replicas and
independently observed autostart disabled. Reconcile every queued, processing, sent, retryable,
terminal and uncertain message/attempt. Never resend an ambiguous SMTP
attempt based only on a missing `250`, a reserved Message-ID or a stale lease.
The provider acceptance ID and authorized inbox confirmation must be joined
to the Virki-generated message independently; otherwise record
`OTP_CORRELATION_UNPROVEN` and stop.

## 4. Physical rollback — staging only

Run the database portion in a **separate protected shell on the actual
staging PostgreSQL host/namespace**, as the OS account mapped to
`POSTGRES_USER`, with the exact approved checkout and PostgreSQL client tools
available. `/var/run/postgresql` must be the local socket for the same staging
instance identified by the remote TLS services. Do not run this from the Hub,
worker or an unrelated Docker host. If PostgreSQL is containerized, use only a
controlled helper/exec environment that preserves the exact socket, peer UID,
read-only checkout and non-interactive client tools; if that cannot be
established, stop rather than substituting password authentication or a
different database host.

1. Stop the worker first and verify the actual container is `exited` with
   restart policy `no`. If it will not stop gracefully, do not delete it or
   force a restart while SMTP outcome is uncertain. Freeze staging Hub/API
   writes using the separately approved staging application Compose project.
   Stop and verify the Hub without deleting its container or database:

```sh
set -euo pipefail
if ! docker --context "$ctx" compose --project-name "$hub_project" \
  -f "$hub_file" stop --timeout 60 hub; then
  printf 'BLOCK: Hub stop failed; independently freeze staging ingress and verify the Hub is stopped\n' >&2
  exit 1
fi
if ! stopped_hub_id="$(docker --context "$ctx" compose --project-name "$hub_project" \
  -f "$hub_file" ps -aq hub)" || [[ "$stopped_hub_id" != "$hub_id" ]]; then
  printf 'BLOCK: Hub container identity changed during rollback\n' >&2
  exit 1
fi
hub_stopped_state="$(docker --context "$ctx" inspect "$hub_id" --format '{{.State.Status}}')"
hub_running="$(docker --context "$ctx" compose --project-name "$hub_project" \
  -f "$hub_file" ps --status running -q hub)"
all_running_hubs="$(docker --context "$ctx" ps -q \
  --filter "label=com.docker.compose.service=hub")"
[[ "$hub_stopped_state" == "exited" && -z "$hub_running" && -z "$all_running_hubs" ]]
printf 'STAGING_HUB_STOPPED=PASS\n'
```

2. Revoke/rotate the staging SMTP credential at the provider if there is any
   unexpected recipient, unbounded send, host mismatch or uncertain exposure.
   This is a provider-console action for the authorized operator.
3. Reconcile the complete outbox and delivery-attempt ledger, including leases
   and Message-IDs. Preserve uncertain items as quarantined evidence; do not
   retry them automatically.
4. Restore the approved baseline snapshot into a **new staging database**,
   never in-place and never into production. Use protected service/pass files:

```sh
set -euo pipefail
[[ -n "${BASH_VERSION:-}" && "${BASH_VERSINFO[0]}" -ge 4 ]]
umask 077
: "${PGSERVICEFILE:=/run/virki-staging/pg_service.conf}"
: "${PGPASSFILE:=/run/virki-staging/pgpass}"
export PGSERVICEFILE PGPASSFILE
service_file="$PGSERVICEFILE"
pass_file="$PGPASSFILE"
: "${VIRKI_STAGING_EVIDENCE_DIR:?private evidence directory required}"
: "${VIRKI_STAGING_RESTORE_DB:?fresh approved staging restore DB name required}"
: "${VIRKI_STAGING_BASELINE_DUMP:?owner-approved baseline dump path required}"
: "${VIRKI_STAGING_BASELINE_DUMP_SHA256:?signed baseline dump digest required}"
: "${VIRKI_STAGING_APPROVED_SOURCE_SHA:?owner-approved exact source SHA required}"
: "${VIRKI_STAGING_APPROVED_DB_SERVER_ADDR:?signed staging database server address required}"
: "${VIRKI_STAGING_APPROVED_DB_PORT:?signed staging database port required}"
: "${VIRKI_STAGING_APPROVED_DB_NAME:?signed staging database name required}"
: "${POSTGRES_USER:?staging bootstrap database role required}"
: "${POSTGRES_PASSWORD:?staging bootstrap password required}"
command -v realpath >/dev/null
command -v mktemp >/dev/null
command -v mv >/dev/null
command -v pg_dump >/dev/null
command -v pg_restore >/dev/null
command -v createdb >/dev/null
command -v psql >/dev/null
command -v grep >/dev/null
command -v awk >/dev/null
command -v stat >/dev/null
command -v id >/dev/null
command -v git >/dev/null
command -v mkdir >/dev/null
command -v chmod >/dev/null
command -v rm >/dev/null
command -v dirname >/dev/null
command -v sha256sum >/dev/null
command -v cut >/dev/null
service_dir="$(dirname "$PGSERVICEFILE")"
test ! -L "$service_dir"
test ! -L "$PGSERVICEFILE"
test ! -L "$PGPASSFILE"
[[ "$(realpath -e "$service_dir")" == "$service_dir" ]]
test "$(dirname "$PGPASSFILE")" = "$service_dir"
test "$(stat -c '%u:%a' "$service_dir")" = "$(id -u):700"
test "$(stat -c '%u:%a' "$PGSERVICEFILE")" = "$(id -u):600"
test "$(stat -c '%u:%a' "$PGPASSFILE")" = "$(id -u):600"
test -f "$PGSERVICEFILE" && test -f "$PGPASSFILE"
test ! -L "$PGSERVICEFILE" && test ! -L "$PGPASSFILE"
[[ "$(realpath -e "$PGSERVICEFILE")" == "$PGSERVICEFILE" ]]
[[ "$(realpath -e "$PGPASSFILE")" == "$PGPASSFILE" ]]
test "$(stat -c '%h' "$PGSERVICEFILE")" = "1"
test "$(stat -c '%h' "$PGPASSFILE")" = "1"
if grep -Eiq '^[[:space:]]*password[[:space:]]*=' "$PGSERVICEFILE" || grep -q '\*' "$PGPASSFILE"; then
  printf 'BLOCK: unsafe PostgreSQL service/pass file content\n' >&2
  exit 1
fi
require_service_tls() {
  local service="$1"
  awk -v section="[$service]" '
    $0 == section { if (found) bad=1; found=1; active=1; next }
    /^\[/ { if (active) active=0 }
    active && /^[[:space:]]*sslmode[[:space:]]*=/ {
      count++; value=$0; sub(/^[^=]*=/, "", value); gsub(/[[:space:]]/, "", value)
      if (value != "verify-full") bad=1
    }
    active && /^[[:space:]]*(password|passfile|hostaddr)[[:space:]]*=/ { bad=1 }
    END { exit !(found && count == 1 && !bad) }
  ' "$PGSERVICEFILE"
}
for service in virki-staging-migrator virki-staging-bootstrap virki-staging-worker; do
  require_service_tls "$service"
done
[[ "$VIRKI_STAGING_EVIDENCE_DIR" == /* ]]
evidence_parent="$(dirname "$VIRKI_STAGING_EVIDENCE_DIR")"
test -d "$evidence_parent"
test ! -L "$evidence_parent"
[[ "$(realpath -e "$evidence_parent")" == "$evidence_parent" ]]
test ! -e "$VIRKI_STAGING_EVIDENCE_DIR"
test ! -L "$VIRKI_STAGING_EVIDENCE_DIR"
mkdir -m 0700 -- "$VIRKI_STAGING_EVIDENCE_DIR"
test -d "$VIRKI_STAGING_EVIDENCE_DIR"
test ! -L "$VIRKI_STAGING_EVIDENCE_DIR"
test "$(stat -c '%u:%a' "$VIRKI_STAGING_EVIDENCE_DIR")" = "$(id -u):700"
[[ "$VIRKI_STAGING_RESTORE_DB" =~ ^virki_stage_restore_[a-f0-9]{8,16}$ ]]
[[ "$VIRKI_STAGING_BASELINE_DUMP_SHA256" =~ ^[a-f0-9]{64}$ ]]
[[ "$VIRKI_STAGING_BASELINE_DUMP" == /* ]]
test -f "$VIRKI_STAGING_BASELINE_DUMP"
test ! -L "$VIRKI_STAGING_BASELINE_DUMP"
[[ "$(realpath -e "$VIRKI_STAGING_BASELINE_DUMP")" == "$VIRKI_STAGING_BASELINE_DUMP" ]]
test "$(stat -c '%u:%a:%h' "$VIRKI_STAGING_BASELINE_DUMP")" = "$(id -u):600:1"
baseline_sha="$(sha256sum "$VIRKI_STAGING_BASELINE_DUMP" | cut -d' ' -f1)"
[[ "$baseline_sha" == "$VIRKI_STAGING_BASELINE_DUMP_SHA256" ]]
case "$POSTGRES_USER" in
  virki_runtime|virki_migrator|virki_audit_maintenance|virki_email_worker)
    printf 'BLOCK: restore requires a distinct staging-only bootstrap identity\n' >&2
    exit 1
    ;;
esac
[[ "$VIRKI_STAGING_APPROVED_DB_PORT" =~ ^[1-9][0-9]{0,4}$ ]]
(( 10#$VIRKI_STAGING_APPROVED_DB_PORT <= 65535 ))
[[ "$VIRKI_STAGING_APPROVED_DB_NAME" =~ ^[A-Za-z0-9_]+$ ]]
if ! migrator_identity="$(PGSERVICE=virki-staging-migrator psql --no-password -XAtqc \
  "select inet_server_addr()::text || '|' || inet_server_port() || '|' || current_database() || '|' || current_user || '|' || session_user || '|' || (select ssl::text from pg_stat_ssl where pid=pg_backend_pid()) || '|' || floor(extract(epoch from pg_postmaster_start_time()))::bigint::text")"; then
  printf 'BLOCK: pre-rollback migrator connection failed\n' >&2
  exit 1
fi
IFS='|' read -r migrator_addr migrator_port migrator_db migrator_user migrator_session_user migrator_ssl migrator_start <<<"$migrator_identity"
[[ "$migrator_addr" == "$VIRKI_STAGING_APPROVED_DB_SERVER_ADDR" ]]
[[ "$migrator_port" == "$VIRKI_STAGING_APPROVED_DB_PORT" ]]
[[ "$migrator_db" == "$VIRKI_STAGING_APPROVED_DB_NAME" ]]
[[ "$migrator_user" == "virki_migrator" && "$migrator_session_user" == "virki_migrator" ]]
[[ "$migrator_ssl" == "true" && -n "$migrator_start" ]]
if ! bootstrap_identity="$(PGSERVICE=virki-staging-bootstrap psql --no-password -XAtqc \
  "select inet_server_addr()::text || '|' || inet_server_port() || '|' || current_database() || '|' || current_user || '|' || session_user || '|' || (select ssl::text from pg_stat_ssl where pid=pg_backend_pid()) || '|' || floor(extract(epoch from pg_postmaster_start_time()))::bigint::text || '|' || (select rolsuper::text from pg_roles where rolname=current_user)")"; then
  printf 'BLOCK: staging bootstrap connection failed\n' >&2
  exit 1
fi
IFS='|' read -r bootstrap_addr bootstrap_port bootstrap_db bootstrap_user bootstrap_session_user bootstrap_ssl bootstrap_start bootstrap_superuser <<<"$bootstrap_identity"
[[ "$bootstrap_addr" == "$VIRKI_STAGING_APPROVED_DB_SERVER_ADDR" ]]
[[ "$bootstrap_port" == "$VIRKI_STAGING_APPROVED_DB_PORT" ]]
[[ "$bootstrap_db" == "postgres" ]]
[[ "$bootstrap_user" == "$POSTGRES_USER" && "$bootstrap_session_user" == "$POSTGRES_USER" ]]
[[ "$bootstrap_ssl" == "true" && "$bootstrap_start" == "$migrator_start" && "$bootstrap_superuser" == "true" ]]
[[ "$(git rev-parse HEAD)" == "$VIRKI_STAGING_APPROVED_SOURCE_SHA" ]]
[[ -z "$(git status --porcelain)" ]]
: "${VIRKI_RUNTIME_DB_PASSWORD:?staging runtime role password required}"
: "${VIRKI_MIGRATOR_DB_PASSWORD:?staging migrator role password required}"
: "${VIRKI_AUDIT_MAINTENANCE_DB_PASSWORD:?staging audit-maintenance password required}"
: "${VIRKI_EMAIL_WORKER_DB_PASSWORD:?staging email-worker password required}"
: "${VIRKI_EMAIL_WORKER_DB_SCRAM_VERIFIER:?staging email-worker SCRAM verifier required}"
[[ "$(id -un)" == "$POSTGRES_USER" ]]
verify_local_peer() {
  local database="$1"
  local identity
  local local_db local_user local_session_user local_port local_start local_superuser local_hba_rule_count local_auth_method local_hba_match local_hba_options local_hba_errors local_hba_file local_conf_load local_hba_files local_hba_mtime
  identity="$(
    unset PGHOSTADDR PGHOST PGPORT PGSERVICE PGSERVICEFILE PGOPTIONS PGUSER PGDATABASE
    unset PGSSLMODE PGSSLCERT PGSSLKEY PGSSLROOTCERT PGSSLCRL
    unset PGSSLMINPROTOCOLVERSION PGSSLMAXPROTOCOLVERSION PGCHANNELBINDING
    unset PGCONNECT_TIMEOUT PGTARGETSESSIONATTRS PGAPPNAME PGCLIENTENCODING
    unset PGSSLNEGOTIATION PGREQUIREPEER PGGSSENCMODE PGGSSDELEGATION PGKRBSRVNAME
    unset PGREQUIRESSL PGSSLCOMPRESSION PGLOADBALANCEHOSTS
    PGPASSWORD= PGPASSFILE=/dev/null psql --no-psqlrc --no-password \
      --host=/var/run/postgresql --port=5432 --username "$POSTGRES_USER" \
      --dbname "$database" -XAtqc \
      "select current_database() || '|' || current_user || '|' || session_user || '|' || current_setting('port') || '|' || floor(extract(epoch from pg_postmaster_start_time()))::bigint::text || '|' || (select rolsuper::text from pg_roles where rolname=current_user) || '|' || (select count(*)::text from pg_hba_file_rules where type='local') || '|' || coalesce((select auth_method from pg_hba_file_rules where type='local' order by line_number limit 1), 'none') || '|' || coalesce((select ((database @> ARRAY['all'] or database @> ARRAY[current_database()]) and (user_name @> ARRAY['all'] or user_name @> ARRAY[current_user]))::text from pg_hba_file_rules where type='local' order by line_number limit 1), 'false') || '|' || coalesce((select array_length(options, 1)::text from pg_hba_file_rules where type='local' order by line_number limit 1), '0') || '|' || (select count(*)::text from pg_hba_file_rules where error is not null) || '|' || current_setting('hba_file') || '|' || (pg_conf_load_time() >= (pg_stat_file(current_setting('hba_file'))).modification)::text || '|' || (select count(distinct file_name)::text from pg_hba_file_rules)"
  )"
  IFS='|' read -r local_db local_user local_session_user local_port local_start local_superuser local_hba_rule_count local_auth_method local_hba_match local_hba_options local_hba_errors local_hba_file local_conf_loaded local_hba_files <<<"$identity"
  [[ "$local_db" == "$database" ]]
  [[ "$local_user" == "$POSTGRES_USER" && "$local_session_user" == "$POSTGRES_USER" ]]
  [[ "$local_port" == "5432" && "$local_start" == "$bootstrap_start" ]]
  [[ "$local_superuser" == "true" && "$local_hba_rule_count" == "1" ]]
  [[ "$local_auth_method" == "peer" && "$local_hba_match" == "true" && "$local_hba_options" == "0" ]]
  [[ "$local_hba_errors" == "0" && "$local_conf_loaded" == "true" ]]
  [[ "$local_hba_files" == "1" && "$local_hba_file" == /* ]]
  [[ "$(realpath -e "$local_hba_file")" == "$local_hba_file" ]]
  local_hba_mtime="$(stat -c '%Y' "$local_hba_file")"
  [[ "$local_conf_load" =~ ^[0-9]+$ && "$local_hba_mtime" =~ ^[0-9]+$ ]]
  (( 10#$local_conf_load >= 10#$local_hba_mtime ))
}
verify_local_peer postgres
dump_tmp="$(mktemp "$VIRKI_STAGING_EVIDENCE_DIR/pre-rollback.XXXXXX")"
test -f "$dump_tmp"
test ! -L "$dump_tmp"
cleanup_dump() {
  if [[ -n "${dump_tmp:-}" && -e "$dump_tmp" && ! -L "$dump_tmp" ]]; then
    rm -f -- "$dump_tmp"
  fi
}
trap cleanup_dump EXIT
pg_dump --no-password --format=custom --no-owner --no-acl \
  --file="$dump_tmp" \
  --dbname='service=virki-staging-migrator'
test -s "$dump_tmp"
chmod 0600 "$dump_tmp"
test "$(stat -c '%u:%a:%h' "$dump_tmp")" = "$(id -u):600:1"
dump_final="$VIRKI_STAGING_EVIDENCE_DIR/pre-rollback.dump"
test ! -e "$dump_final"
test ! -L "$dump_final"
mv -nT -- "$dump_tmp" "$dump_final"
if [[ -e "$dump_tmp" || -L "$dump_tmp" ]]; then
  printf 'BLOCK: rollback evidence destination already exists or could not be committed\n' >&2
  exit 1
fi
test -f "$dump_final"
test ! -L "$dump_final"
test "$(stat -c '%u:%a:%h' "$dump_final")" = "$(id -u):600:1"
sha256sum "$dump_final"
dump_tmp=""

# RESTORE_DB must be a fresh, uniquely named staging DB approved by the owner.
# The staging bootstrap owns it during restore; script 10 provisions the
# migrator identity before ownership is transferred.
createdb --no-password --maintenance-db='service=virki-staging-bootstrap' \
  --owner="$POSTGRES_USER" "$VIRKI_STAGING_RESTORE_DB"
pg_restore --no-password --exit-on-error --single-transaction --no-owner --no-acl \
  --dbname="service=virki-staging-bootstrap dbname=$VIRKI_STAGING_RESTORE_DB" \
  "$VIRKI_STAGING_BASELINE_DUMP"
restored_identity="$(PGSERVICE=virki-staging-bootstrap psql \
  --dbname="service=virki-staging-bootstrap dbname=$VIRKI_STAGING_RESTORE_DB" -XAtqc \
  "select inet_server_addr()::text || '|' || inet_server_port() || '|' || current_database() || '|' || current_user || '|' || session_user || '|' || (select ssl::text from pg_stat_ssl where pid=pg_backend_pid()) || '|' || floor(extract(epoch from pg_postmaster_start_time()))::bigint::text")"
IFS='|' read -r restored_addr restored_port restored_db restored_user restored_session_user restored_ssl restored_start <<<"$restored_identity"
[[ "$restored_addr" == "$VIRKI_STAGING_APPROVED_DB_SERVER_ADDR" ]]
[[ "$restored_port" == "$VIRKI_STAGING_APPROVED_DB_PORT" ]]
[[ "$restored_db" == "$VIRKI_STAGING_RESTORE_DB" ]]
[[ "$restored_user" == "$POSTGRES_USER" && "$restored_session_user" == "$POSTGRES_USER" ]]
[[ "$restored_ssl" == "true" && "$restored_start" == "$bootstrap_start" ]]

# Run on the staging PostgreSQL host/instance using its local Unix socket.
# The staging-only bootstrap and role passwords/verifier below are injected
# by the approved secret manager; never paste them into this shell command.
export POSTGRES_DB="$VIRKI_STAGING_RESTORE_DB"
unset PGHOSTADDR PGHOST PGPORT PGSERVICE PGSERVICEFILE PGOPTIONS
unset PGPASSWORD PGPASSFILE PGSSLMODE PGUSER PGDATABASE
export PGHOST=/var/run/postgresql
export PGPORT=5432
verify_local_peer "$POSTGRES_DB"
export VIRKI_LOCAL_MIGRATOR_CREATEDB=false
sh infra/postgres-init/10-virki-database-roles.sh
psql --no-psqlrc --no-password --host=/var/run/postgresql --port=5432 \
  --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  --set ON_ERROR_STOP=1 \
  --set database_name="$VIRKI_STAGING_RESTORE_DB" \
  --command 'ALTER DATABASE :"database_name" OWNER TO virki_migrator'
restored_owner="$(psql --no-psqlrc --no-password --host=/var/run/postgresql \
  --port=5432 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" -XAtqc \
  "select pg_get_userbyid(datdba) from pg_database where datname=current_database()")"
[[ "$restored_owner" == "virki_migrator" ]]
unfinished_migrations="$(psql --no-psqlrc --no-password --host=/var/run/postgresql \
  --port=5432 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" -XAtqc \
  'select count(*) from public."_prisma_migrations" where finished_at is null and rolled_back_at is null')"
[[ "$unfinished_migrations" == "0" ]]
sh infra/postgres-init/11-virki-email-worker-role.sh
export PGSERVICEFILE="$service_file"
export PGPASSFILE="$pass_file"
worker_restore_identity="$(PGSERVICE=virki-staging-worker psql \
  --dbname="service=virki-staging-worker dbname=$VIRKI_STAGING_RESTORE_DB" -XAtqc \
  "select inet_server_addr()::text || '|' || inet_server_port() || '|' || current_database() || '|' || current_user || '|' || session_user || '|' || (select ssl::text from pg_stat_ssl where pid=pg_backend_pid()) || '|' || floor(extract(epoch from pg_postmaster_start_time()))::bigint::text || '|' || (select rolcanlogin::text || ',' || rolsuper::text || ',' || rolcreatedb::text || ',' || rolcreaterole::text || ',' || rolreplication::text || ',' || rolbypassrls::text || ',' || rolinherit::text from pg_roles where rolname=current_user) || '|' || has_table_privilege(current_user, 'public.\"EmailOutboxMessage\"', 'SELECT')::text || '|' || has_table_privilege(current_user, 'public.\"EmailDeliveryAttempt\"', 'SELECT')::text || '|' || has_table_privilege(current_user, 'public.\"EmailDeliveryAttempt\"', 'INSERT')::text || '|' || has_table_privilege(current_user, 'public.\"EmailOutboxMessage\"', 'INSERT')::text || '|' || has_table_privilege(current_user, 'public.\"EmailOutboxMessage\"', 'DELETE')::text || '|' || has_table_privilege(current_user, 'public.\"EmailDeliveryAttempt\"', 'UPDATE')::text || '|' || has_table_privilege(current_user, 'public.\"EmailDeliveryAttempt\"', 'DELETE')::text || '|' || has_column_privilege(current_user, 'public.\"EmailOutboxMessage\"', 'recipientEmail', 'UPDATE')::text || '|' || has_column_privilege(current_user, 'public.\"EmailOutboxMessage\"', 'payload', 'UPDATE')::text || '|' || has_table_privilege(current_user, 'public.\"User\"', 'SELECT')::text || '|' || has_table_privilege(current_user, 'public.\"Session\"', 'SELECT')::text || '|' || has_table_privilege(current_user, 'public.\"AuditLog\"', 'SELECT')::text || '|' || has_database_privilege(current_user, current_database(), 'CREATE')::text || '|' || has_database_privilege(current_user, current_database(), 'TEMPORARY')::text || '|' || has_schema_privilege(current_user, 'public', 'CREATE')::text")"
IFS='|' read -r worker_restore_addr worker_restore_port worker_restore_db worker_restore_user worker_restore_session worker_restore_ssl worker_restore_start worker_role_flags worker_outbox_select worker_attempt_select worker_attempt_insert worker_outbox_insert worker_outbox_delete worker_attempt_update worker_attempt_delete worker_recipient_update worker_payload_update worker_user_select worker_session_select worker_audit_select worker_db_create worker_db_temp worker_schema_create <<<"$worker_restore_identity"
[[ "$worker_restore_addr" == "$VIRKI_STAGING_APPROVED_DB_SERVER_ADDR" ]]
[[ "$worker_restore_port" == "$VIRKI_STAGING_APPROVED_DB_PORT" ]]
[[ "$worker_restore_db" == "$VIRKI_STAGING_RESTORE_DB" ]]
[[ "$worker_restore_user" == "virki_email_worker" && "$worker_restore_session" == "virki_email_worker" ]]
[[ "$worker_restore_ssl" == "true" && "$worker_restore_start" == "$bootstrap_start" ]]
[[ "$worker_role_flags" == "true,false,false,false,false,false,false" ]]
[[ "$worker_outbox_select" == "true" && "$worker_attempt_select" == "true" && "$worker_attempt_insert" == "true" ]]
[[ "$worker_outbox_insert" == "false" && "$worker_outbox_delete" == "false" ]]
[[ "$worker_attempt_update" == "false" && "$worker_attempt_delete" == "false" ]]
[[ "$worker_recipient_update" == "false" && "$worker_payload_update" == "false" ]]
[[ "$worker_user_select" == "false" && "$worker_session_select" == "false" && "$worker_audit_select" == "false" ]]
[[ "$worker_db_create" == "false" && "$worker_db_temp" == "false" && "$worker_schema_create" == "false" ]]
```

   The `virki-staging-bootstrap` service used by `createdb` and `pg_restore`
   must use the same separately authorized **staging-only PostgreSQL
   superuser** named by `POSTGRES_USER`, with `CREATEDB`, `CREATEROLE`,
   restore/extension, role-membership, object-ownership and ACL authority
   sufficient for both committed role scripts and transfer of database
   ownership to `virki_migrator`; never use the audit-maintenance,
   worker/runtime or a production identity. The runbook verifies
   `rolsuper=true` on the remote service and again on the local Unix socket.
   The role scripts clear `PGPASSWORD`/`PGPASSFILE` and therefore require an
   actual local `peer` HBA rule for the restore database and bootstrap role,
   with the invoking OS username exactly equal to `POSTGRES_USER`; the
   no-password local connection, sole local HBA rule, exact database/user
   match, absence of a `map=` option, parse-error count and loaded-file mtime
   are checked before either script runs. Do not fall back to `trust`, an
   interactive password prompt or an ambient pass file. `POSTGRES_PASSWORD`
   must be the same staging bootstrap credential used by the exact
   `virki-staging-bootstrap` PGPASSFILE entry; it is required by the scripts
   for credential-distinctness checks but is not the local-socket
   authentication mechanism. A custom `pg_dump` does not
   recreate cluster roles or per-database grants/default privileges. Therefore
   run the exact committed `infra/postgres-init/10-virki-database-roles.sh`
   against the restored DB to reapply runtime/migrator/audit-maintenance roles
   and grants, then run `infra/postgres-init/11-virki-email-worker-role.sh`
   locally after the restored mail tables exist; the latter pins the local
   Unix socket and provisions the isolated worker role. On a fresh empty
   database, run script 10 before migrations and script 11 only after the
   mail-table migrations. Verify the migration ledger, DB identity, worker
   privilege gate and redacted before/after counts before repointing any
   staging application. Keep the previous DB read-only until owner and
   independent reviewer accept the restore.
5. Keep the worker stopped throughout restore and application rollback.
   Verify the restored source/image/ingress policy, old sessions/recovery
   capabilities and replay denials, queue/attempt counts and audit integrity.
   Delete old staging resources only after a separate signed approval.

Never use `docker compose down -v`, `docker volume rm`, a production Compose
file, or a production/deManage DB URL as a rollback shortcut. The standalone
worker file declares no volumes; the staging DB's persistent volume belongs
to its separately approved base stack and is outside this worker-only file.

## 5. Evidence and stop conditions

Store evidence in an access-restricted repository outside Git. Capture exact
source SHA, OCI digest, Docker daemon ID, context/project, external network ID
and policy, PostgreSQL major/database/role identity, migration state,
worker container ID/state/restart policy, aggregate outbox/attempt counts,
sanitized audit references, provider event reference, recipient confirmation,
UTC timestamps, independent approvals and physical restore receipt.

Never capture raw `docker compose config`, environment, `docker inspect`
without a safe format, database URLs, SMTP AUTH data, OTPs, recovery links,
cookies, private keys, raw headers, mailbox addresses or unredacted logs.

Stop and record NO-GO on any target/project/network/image mismatch, unknown
network endpoint or egress policy, existing/running worker, unexpected
volume/port/mount, restart policy other than `no`, nonempty pre-drain queue,
nonzero historical attempts, widened DB grants, unlisted recipient accepted,
provider quota uncertainty, missing independent signature, uncertain send,
or failed physical restore. A local test, CI result, Compose render, SMTP
`250`, or signed declaration consistency is not external staging acceptance.
