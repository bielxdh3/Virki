# PR #118 — segregated staging operator runbook

> **PREPARED, NOT EXECUTED.** These commands are for a separately authorized
> staging operator after exact-SHA SOURCE GO and hosted checks. They do not
> provision a host, authorize SMTP, change Cloudflare, deploy, or approve
> production. Never point them at production or deManage.

## 1. Preconditions and secret handling

The earlier **runtime-code** baseline
`2cb74f576039cac8d83fd2d1cc52e47f36184ad1` preserves the original
`6feb2da5ab9bd25ce1cc2f53c6a7c4fc4807bd1c` as an ancestor, descending
from the previously CI-verified PR source
`678d81af31fb6aa5f1ab4effcdee823a030c38ce`. This hardening pass adds
operator-only PGPASS/Prisma migration-ledger verifiers and PostgreSQL
bootstrap protections **plus actual application runtime changes** to staging
WebAuthn RP-ID selection and recovery validation. The operator helpers are
not imported into Hub or worker; the passkey/recovery changes are. All of
these require exact-final-SHA review, independent acceptance and hosted
CI/CodeQL. Publishing a new source commit does not itself establish a
SOURCE GO. Any future staging image must use the final reviewed SHA and
immutable platform-specific digest; never use the older baseline SHA.

The originally requested SOURCE interval `678d81a..6feb2da` remains included.
The later local commits add the signed staging-preflight, standalone-worker
resource policy, relay tenant/endpoint/account binding and non-interactive
database-role provisioning. Reviewing only the original interval is no longer
sufficient: authenticated independent SOURCE review must cover the complete
application code diff `678d81a..2cb74f5`, including incremental
`6feb2da..2cb74f5`. Final independent SOURCE review must also cover the exact
final branch SHA and the operator-only verifier/test additions; reviewing only
the application interval or documentation changes is insufficient.

The operator must have an out-of-band approved staging context and Docker
daemon ID, project name, external network ID **and exact endpoint inventory**,
DB host/name/roles, immutable OCI digests with the exact source-revision/source
labels, relay tenant/endpoint/account, recipient policy, provider rate/message
caps, test inboxes, ingress/egress policy evidence, maintenance window and
named rollback owner. Compare these with the operator's production inventory;
a different string alone does not prove physical isolation. Any unexpected
network endpoint, image label or project resource is a hard stop. The network
policy evidence must explicitly deny container access to host-management
services, Docker Engine TCP API listeners (including 2375/2376 and any custom
port), SSH/RDP and unapproved host-gateway/private-network endpoints; the
worker may reach only its approved staging DB, SMTP relay and DNS resolution
path, while Hub egress is separately allowlisted to its approved DB,
identity/application endpoints and DNS resolution path.

All fenced `sh` blocks below are **Bash 4+** scripts for Linux with GNU
coreutils; do not execute them with `sh`, PowerShell or a Windows Docker
context. Keep the application/Docker operator shell separate from the
PostgreSQL-host rollback shell described in section 4. Each block first
disables inherited Bash xtrace/verbose mode before expanding any secret-bearing
environment variable; do not add `set -x` while running these procedures.

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

The operator must also supply `VIRKI_STAGING_APPROVED_NODE_BIN` (an absolute,
canonical, root-controlled executable path, not a PATH command or shim) and
`VIRKI_STAGING_APPROVED_NODE_SHA256` from the independently approved toolchain
inventory. The binary and its directory chain must be root-owned and not
group/world-writable; a symlinked or hardlinked binary is rejected. An
unapproved toolchain layout is BLOCK, never a reason to fall back to `node`
or `npm` found through `PATH`.

For database bootstrap and physical rollback, inject these additional
staging-only secrets from the approved secret manager (never from production):
`POSTGRES_USER`, `POSTGRES_PASSWORD`, `VIRKI_EMAIL_WORKER_DB_PASSWORD`,
`VIRKI_RUNTIME_DB_PASSWORD`, `VIRKI_MIGRATOR_DB_PASSWORD`,
`VIRKI_AUDIT_MAINTENANCE_DB_PASSWORD`, and
`VIRKI_EMAIL_WORKER_DB_SCRAM_VERIFIER`. The verifier must be the precomputed
SCRAM-SHA-256 verifier for the worker password; do not derive it in a logged
shell command or print it. The restore procedure exports the runtime and
migrator credentials before invoking the PGPASS binding helper, then requires
the audit-maintenance credential and worker verifier before local provisioning.

The operator must also provide the signed inventory's exact database server
hostname, resolved server address, port and database name as
`VIRKI_STAGING_APPROVED_DB_HOST`,
`VIRKI_STAGING_APPROVED_DB_SERVER_ADDR`,
`VIRKI_STAGING_APPROVED_DB_PORT` and
`VIRKI_STAGING_APPROVED_DB_NAME`. These are comparison values, not secrets.
The operator must separately pin `VIRKI_STAGING_APPROVED_DB_CA_FILE` and
`VIRKI_STAGING_APPROVED_DB_CA_SHA256` to the approved staging PostgreSQL CA
bundle. All four protected libpq service definitions must contain an explicit
`sslrootcert` entry exactly matching this canonical file, whose bytes, owner,
mode and link count are checked before any remote database probe. The SHA-256
must be taken from the signed/out-of-band approved CA inventory. `verify-full`
alone does not identify an approved root of trust.

The Hub and email-worker use the Prisma query engine, **not libpq**. Their
staging-only immutable OCI images must each include the **same approved CA
bytes** at the canonical in-container path `/app/ca/staging-db-root.pem`,
root-owned, non-symlink and read-only. Use the **separate**
`infra/Dockerfile.staging-db-trust` only after an independently approved
immutable `ghcr.io/bielxdh3/virki-runtime@sha256:...` base image is
available in the approved local image inventory. Its required build
arguments are `VIRKI_STAGING_APPROVED_BASE_IMAGE` (pinned base digest) and
`VIRKI_STAGING_APPROVED_DB_CA_SHA256` (independently approved CA digest),
and it requires a BuildKit secret `id=virki_staging_db_root_ca`. Do not
download a base image, use a mutable tag, reuse a cached CA layer without
checking its resulting bytes, or promote a label as CA proof. The normal
`infra/Dockerfile.prod` **must remain unchanged**. Never copy a CA into
the production image or replace a missing CA secret with a system root.
Each image's final flattened filesystem (not merely its Dockerfile or label)
must be independently inspected for exact CA bytes/hash, file type and
ownership and bound to an immutable OCI manifest digest/platform. Hub and
worker URLs must each include exactly the three Prisma 6 URL keys
`sslmode=require&sslaccept=strict&sslcert=%2Fapp%2Fca%2Fstaging-db-root.pem`
(decoded path `/app/ca/staging-db-root.pem`), with no duplicates or extras.
This is **not** libpq's `verify-full` syntax: Prisma 6 documentation
describes `sslcert` as the server CA and `sslaccept=strict` as certificate
verification. The installed Prisma 6.19.3 native query engine does not
establish that `sslrootcert` is a recognized argument, and its supported
`sslmode` list differs from libpq's. Do not substitute `sslrootcert`,
`sslaccept=accept_invalid_certs`, default `prefer`, or silent fallback.
Container CA and live TLS are **BLOCK** until actual image files are verified,
the approved Prisma 6.19.3 Linux engine's strict chain **and hostname**
verification are exercised, and positive/negative TLS CA/SAN tests are
independently witnessed. Source URL checks NEVER prove live TLS identity.
Provide separate independently verified non-secret egress-policy evidence:
`VIRKI_STAGING_EGRESS_POLICY_ID` and `VIRKI_STAGING_EGRESS_POLICY_RECEIPT`
for the worker's staging-DB/approved-SMTP-only egress, plus
`VIRKI_STAGING_HUB_EGRESS_POLICY_ID` and
`VIRKI_STAGING_HUB_EGRESS_POLICY_RECEIPT` for the Hub's approved DB and
identity/application endpoint allowlist. A policy ID or receipt string alone
is not proof that the host/firewall rule is active.

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
set +x +v
set -euo pipefail
[[ -n "${BASH_VERSION:-}" && "${BASH_VERSINFO[0]}" -ge 4 ]]
# The staging host and the starting Bash process must already be trusted.
# Remove dynamic-linker preloads before invoking any external verifier/tool.
unset LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT LD_DEBUG LD_ORIGIN_PATH LD_PROFILE LD_USE_LOAD_BIAS
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
# Both approval and independent observation must be pinned BEFORE any Hub
# activation, not only immediately before the later worker send window.
: "${VIRKI_STAGING_APPROVAL_JSON:?fresh owner-signed approval JSON path required}"
: "${VIRKI_STAGING_OBSERVATION_JSON:?fresh independent observation JSON path required}"
: "${VIRKI_STAGING_APPROVER_PUBLIC_KEY:?pinned owner public key path required}"
: "${VIRKI_STAGING_OBSERVER_PUBLIC_KEY:?pinned independent observer public key path required}"
: "${VIRKI_STAGING_APPROVED_SMTP_TENANT_ID:?signed staging SMTP tenant identity required}"
: "${VIRKI_STAGING_APPROVED_SMTP_ENDPOINT_ID:?signed staging SMTP endpoint identity required}"
: "${VIRKI_STAGING_APPROVED_SMTP_ACCOUNT_ID:?signed staging SMTP account identity required}"
command -v docker >/dev/null
test -x /usr/bin/git
command -v psql >/dev/null
command -v jq >/dev/null
command -v awk >/dev/null
command -v mktemp >/dev/null
command -v chmod >/dev/null
command -v rm >/dev/null
command -v realpath >/dev/null
command -v grep >/dev/null
command -v sha256sum >/dev/null
command -v cut >/dev/null
command -v stat >/dev/null
command -v timeout >/dev/null
command -v id >/dev/null
command -v od >/dev/null
command -v tr >/dev/null
command -v rmdir >/dev/null
: "${VIRKI_STAGING_APPROVED_SOURCE_SHA:?owner-signed SHA required}"
[[ "$VIRKI_STAGING_APPROVED_SOURCE_SHA" =~ ^[a-f0-9]{40}$ ]]
# git status --porcelain can hide assume-unchanged/skip-worktree files. Remove
# ambient Git redirections before validating the exact committed helper bytes.
for git_name in "${!GIT_@}"; do unset "$git_name"; done
[[ "$(GIT_NO_REPLACE_OBJECTS=1 /usr/bin/git rev-parse HEAD)" == "$VIRKI_STAGING_APPROVED_SOURCE_SHA" ]]
for source_file in \
  scripts/staging-toolchain-preflight.mjs \
  scripts/staging-otp-preflight.mjs \
  scripts/staging-pgpass-bootstrap-binding.mjs \
  scripts/staging-prisma-migration-ledger-binding.mjs \
  scripts/staging-remote-hba-active.sql \
  scripts/staging-remote-hba-rules.sql \
  scripts/staging-local-hba-peer.sql \
  infra/postgres-init/10-virki-database-roles.sh \
  infra/postgres-init/11-virki-email-worker-role.sh \
  infra/docker-compose.staging-email-worker-only.yml \
  infra/Dockerfile.staging-db-trust \
  scripts/staging-db-ca-image-contract.test.mjs \
  scripts/staging-prisma-ca-archive-proof.mjs \
  scripts/staging-prisma-ca-archive-proof.test.mjs \
  docs/security/pr118-staging-operator-runbook-20261114.md \
  package.json; do
  [[ -f "$source_file" && ! -L "$source_file" ]] || {
    printf 'BLOCK: approved checkout helper absent or linked: %s\n' "$source_file" >&2
    exit 1
  }
  committed_blob="$(GIT_NO_REPLACE_OBJECTS=1 /usr/bin/git rev-parse --verify "HEAD:$source_file")" || exit 1
  actual_blob="$(GIT_NO_REPLACE_OBJECTS=1 /usr/bin/git hash-object --no-filters -- "$source_file")" || exit 1
  [[ "$committed_blob" == "$actual_blob" ]] || {
    printf 'BLOCK: raw helper bytes differ from approved source: %s\n' "$source_file" >&2
    exit 1
  }
done
unset source_file committed_blob actual_blob git_name
: "${VIRKI_STAGING_APPROVED_NODE_BIN:?independently approved canonical Node executable required}"
: "${VIRKI_STAGING_APPROVED_NODE_SHA256:?independently approved Node binary digest required}"
node_bin="$VIRKI_STAGING_APPROVED_NODE_BIN"
[[ "$node_bin" == /* && "$node_bin" == "$(realpath -e -- "$node_bin")" &&
   -f "$node_bin" && -x "$node_bin" && ! -L "$node_bin" ]]
[[ "$VIRKI_STAGING_APPROVED_NODE_SHA256" =~ ^[a-f0-9]{64}$ ]]
[[ "$(stat -c '%u:%h' -- "$node_bin")" == "0:1" ]]
node_path_part="$node_bin"
while :; do
  node_path_part="$(dirname -- "$node_path_part")"
  [[ -d "$node_path_part" && ! -L "$node_path_part" ]]
  [[ "$(stat -c '%u' -- "$node_path_part")" == "0" ]]
  node_path_mode="$(stat -c '%a' -- "$node_path_part")"
  (( (8#$node_path_mode & 022) == 0 ))
  [[ "$node_path_part" == "/" ]] && break
done
node_file_mode="$(stat -c '%a' -- "$node_bin")"
(( (8#$node_file_mode & 022) == 0 ))
[[ "$(sha256sum -- "$node_bin" | cut -d' ' -f1)" == "$VIRKI_STAGING_APPROVED_NODE_SHA256" ]]
unset node_path_part node_path_mode node_file_mode
unset NODE_OPTIONS NODE_PATH
for name in "${!npm_config_@}" "${!NPM_CONFIG_@}"; do unset "$name"; done
"$node_bin" scripts/staging-toolchain-preflight.mjs

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
db_url_target="$("$node_bin" -e '
  const url = new URL(process.env.VIRKI_STAGING_EMAIL_WORKER_DATABASE_URL);
  if (!["postgres:", "postgresql:"].includes(url.protocol) ||
      !url.hostname || !url.username || !url.password || !url.pathname) process.exit(1);
  const queryKeys = [...url.searchParams.keys()];
  if (url.hash || queryKeys.length !== 3 || queryKeys[0] !== "sslmode" ||
      queryKeys[1] !== "sslaccept" || queryKeys[2] !== "sslcert" ||
      url.searchParams.get("sslmode") !== "require" ||
      url.searchParams.get("sslaccept") !== "strict" ||
      url.searchParams.get("sslcert") !== "/app/ca/staging-db-root.pem") process.exit(1);
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
actual_source_sha="$(/usr/bin/git rev-parse HEAD)"
[[ "$actual_source_sha" == "$VIRKI_STAGING_APPROVED_SOURCE_SHA" ]]
[[ -z "$(/usr/bin/git status --porcelain)" ]]

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

# Source-only definition: execute ONLY after independent source, OCI digest and
# CA approval. Docker CREATE and CP do not execute any image binary. Docker CP
# archives the final container filesystem; the host-pinned Node verifier parses
# the archive bytes, including its file type and ownership. No docker run/exec,
# network, image scripts, writable volume or credential-bearing command args.
# Both Docker calls have hard deadlines; bounded retries reconcile a late
# daemon-side create, but an inconclusive outcome always requires manual
# inspection and remains BLOCK (never a claim of completed cleanup).
# A signed image digest/daemon is still an external trust gate.
verify_staging_prisma_image_ca() (
  set -euo pipefail
  local inspected_image="$1" proof_container="" proof_name="" proof_nonce=""
  local proof_create_attempted=0 proof_create_completed=0 proof_ok=0
  local existing_proofs="" found_proofs="" owner_nonce="" cleanup_round=""
  [[ "$VIRKI_STAGING_APPROVED_DB_CA_SHA256" =~ ^[a-f0-9]{64}$ ]] || exit 1
  [[ "$(timeout --kill-after=5s 20s docker --context "$ctx" image inspect "$inspected_image" --format '{{json .Config.Volumes}}')" == "null" ]] || exit 1
  # Reserve a random name BEFORE create, so cleanup can find a daemon-created
  # container even if the client times out or loses create's stdout. Never
  # remove a pre-existing name or a container lacking our fresh nonce label.
  proof_nonce="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')" || exit 1
  [[ "$proof_nonce" =~ ^[a-f0-9]{32}$ ]] || exit 1
  proof_name="virki-staging-ca-proof-$proof_nonce"
  existing_proofs="$(timeout --kill-after=5s 20s docker --context "$ctx" ps -aq \
    --filter "name=^/$proof_name$")" || exit 1
  [[ -z "$existing_proofs" ]] || exit 1
  cleanup_ca_proof() {
    [[ "$proof_create_attempted" == "1" ]] || return 0
    # A timed-out client may have lost its reply while the daemon is *still*
    # creating the named resource. An immediate empty ps is NOT proof of
    # cleanup: observe several times and keep a manual reconciliation BLOCK
    # if the create outcome never becomes conclusive.
    for cleanup_round in 1 2 3 4 5; do
      found_proofs="$(timeout --kill-after=5s 20s docker --context "$ctx" ps -aq \
        --filter "name=^/$proof_name$")" || {
        printf 'BLOCK: inspection container inventory unavailable; independently inspect daemon\n' >&2
        return 1
      }
      if [[ -n "$found_proofs" ]]; then
        [[ "$found_proofs" =~ ^[a-f0-9]{12,64}$ ]] || return 1
        owner_nonce="$(timeout --kill-after=5s 20s docker --context "$ctx" container inspect \
          "$proof_name" --format '{{index .Config.Labels "org.virki.staging.ca-inspection-nonce"}}')" || return 1
        [[ "$owner_nonce" == "$proof_nonce" ]] || {
          printf 'BLOCK: inspection name does not belong to this attempt; no removal\n' >&2
          return 1
        }
        timeout --kill-after=5s 20s docker --context "$ctx" rm --force -- "$proof_name" >/dev/null || {
          printf 'BLOCK: could not remove OCI CA inspection container\n' >&2
          return 1
        }
        found_proofs="$(timeout --kill-after=5s 20s docker --context "$ctx" ps -aq \
          --filter "name=^/$proof_name$")" || return 1
        [[ -z "$found_proofs" ]] || return 1
        proof_create_attempted=0
        return 0
      fi
      [[ "$proof_create_completed" != "1" ]] || {
        printf 'BLOCK: created inspection container vanished without owned cleanup\n' >&2
        return 1
      }
      sleep 1
    done
    printf 'BLOCK: create outcome unknown; possible late OCI container. Manually reconcile the named inspection resource before any staging action\n' >&2
    return 1
  }
  trap 'cleanup_ca_proof || exit 1' EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM
  proof_create_attempted=1
  proof_container="$(timeout --kill-after=5s 20s docker --context "$ctx" create \
    --name "$proof_name" --pull=never --network=none --read-only --cap-drop=ALL \
    --security-opt=no-new-privileges --memory=64m --pids-limit=16 \
    --cpus=0.10 --user=65534:65534 --entrypoint=/bin/false \
    --label "org.virki.staging.ca-inspection-nonce=$proof_nonce" \
    "$inspected_image")" || exit 1
  proof_create_completed=1
  [[ "$proof_container" =~ ^[a-f0-9]{64}$ ]] || exit 1
  [[ "$(timeout --kill-after=5s 20s docker --context "$ctx" container inspect \
    "$proof_name" --format '{{.Id}}|{{index .Config.Labels "org.virki.staging.ca-inspection-nonce"}}')" == "$proof_container|$proof_nonce" ]] || exit 1
  if timeout --kill-after=5s 25s docker --context "$ctx" cp "$proof_container:/app/ca" - \
    | "$node_bin" scripts/staging-prisma-ca-archive-proof.mjs "$VIRKI_STAGING_APPROVED_DB_CA_SHA256" >/dev/null; then
    proof_ok=1
  fi
  cleanup_ca_proof || exit 1
  [[ "$proof_ok" == "1" ]]
)
if ! verify_staging_prisma_image_ca "$image"; then
  printf 'BLOCK: runtime worker OCI image CA is absent, altered or not independently approved\n' >&2
  exit 1
fi

network_id="$(docker --context "$ctx" network inspect "$network" --format '{{.Id}}')"
[[ "$network_id" == "$VIRKI_STAGING_APPROVED_NETWORK_ID" ]]
network_policy="$(docker --context "$ctx" network inspect "$network" --format '{{.Internal}}|{{.Driver}}|{{.Scope}}')"
printf 'STAGING_NETWORK_POLICY=%s\n' "$network_policy"
[[ "$network_policy" == "$VIRKI_STAGING_APPROVED_NETWORK_POLICY" ]]
: "${VIRKI_STAGING_EGRESS_POLICY_ID:?independent worker egress policy ID required}"
: "${VIRKI_STAGING_EGRESS_POLICY_RECEIPT:?independent worker egress policy evidence required}"
: "${VIRKI_STAGING_HUB_EGRESS_POLICY_ID:?independent Hub egress policy ID required}"
: "${VIRKI_STAGING_HUB_EGRESS_POLICY_RECEIPT:?independent Hub egress policy evidence required}"
[[ "$VIRKI_STAGING_EGRESS_POLICY_ID" != "$VIRKI_STAGING_HUB_EGRESS_POLICY_ID" ]]
[[ "$VIRKI_STAGING_EGRESS_POLICY_RECEIPT" != "$VIRKI_STAGING_HUB_EGRESS_POLICY_RECEIPT" ]]
# Distinct non-empty IDs/receipts are only references, not enforcement proof.
# Independently inspect the active host/firewall rules on the actual staging
# host and retain a separately authenticated observation for each policy.
docker --context "$ctx" network inspect "$network" \
  --format '{{range $id, $c := .Containers}}{{printf "%s\n" $c.Name}}{{end}}'
# Independently verify the two host/firewall egress policies regardless of the
# Docker Internal flag: the worker may reach only the staging DB, approved
# SMTP relay and DNS path; the Hub may reach only its signed DB/identity/
# application list and DNS path.
# In either case, deny all Docker Engine TCP API listeners (including 2375/2376
# and any custom port), SSH/RDP, host-gateway management services and all other
# unapproved destinations. Prefer an
# internal network with a separately controlled staging relay.

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
    and $w.security_opt == ["no-new-privileges:true"]
    and (($w.ports // []) | length == 0)
    and (($w.volumes // []) | length == 0)
    and (($w.depends_on // {}) | length == 0)
    and (($w.env_file // []) | length == 0)
    and (($w.build // null) == null)
    and (($w.privileged // false) == false)
    and (($w.devices // []) | length == 0)
    and (($w.device_cgroup_rules // []) | length == 0)
    and (($w.sysctls // {}) | length == 0)
    and (($w.group_add // []) | length == 0)
    and (($w.extra_hosts // []) | length == 0)
    and (($w.volumes_from // []) | length == 0)
    and (($w.secrets // []) | length == 0)
    and (($w.configs // []) | length == 0)
    and (($w.runtime // null) == null)
    and (($w.use_api_socket // false) == false)
    and (($w.dns // []) | length == 0)
    and (($w.dns_search // []) | length == 0)
    and (($w.dns_opt // []) | length == 0)
    and (($w.tmpfs // []) == ["/tmp:rw,noexec,nosuid,nodev,size=64m"])
    and (($w.network_mode // null) == null)
    and (($w.pid // null) == null)
    and (($w.ipc // null) == null)
    and (($w.uts // null) == null)
    and (($w.userns_mode // null) == null)
    and (($w.cgroup // null) == null)
    and (($w.container_name // null) == null)
    and (($w.healthcheck // null) == null)
    and (($w.deploy // {}) | length == 0)
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
    and $w.environment.DATABASE_URL == env.VIRKI_STAGING_EMAIL_WORKER_DATABASE_URL
    and $w.environment.VIRKI_EMAIL_OUTBOX_KEY == env.VIRKI_STAGING_EMAIL_OUTBOX_KEY
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
    and $w.environment.VIRKI_EMAIL_FROM == env.VIRKI_STAGING_EMAIL_FROM
    and $w.environment.VIRKI_EMAIL_REPLY_TO == (env.VIRKI_STAGING_EMAIL_REPLY_TO // "")
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
if ! verify_staging_prisma_image_ca "$hub_image"; then
  printf 'BLOCK: runtime Hub OCI image CA is absent, altered or not independently approved\n' >&2
  exit 1
fi

# OCI labels and a local image ID are consistency checks, not build provenance.
# Before any staging activation, the independent operator must verify and
# retain the exact-final-SHA hosted CI and CodeQL runs, GHCR provenance for the
# immutable manifest digest/platform, and the host's runtime image ID/config
# hash. A missing or mismatched provenance receipt is a hard stop.

hub_db_target="$("$node_bin" -e '
  const url = new URL(process.env.VIRKI_STAGING_HUB_DATABASE_URL);
  if (!["postgres:", "postgresql:"].includes(url.protocol) ||
      !url.hostname || !url.username || !url.password || !url.pathname) process.exit(1);
  const queryKeys = [...url.searchParams.keys()];
  if (url.hash || queryKeys.length !== 3 || queryKeys[0] !== "sslmode" ||
      queryKeys[1] !== "sslaccept" || queryKeys[2] !== "sslcert" ||
      url.searchParams.get("sslmode") !== "require" ||
      url.searchParams.get("sslaccept") !== "strict" ||
      url.searchParams.get("sslcert") !== "/app/ca/staging-db-root.pem") process.exit(1);
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
  | ["DATABASE_URL", "NODE_ENV", "VIRKI_HUB_URL", "VIRKI_PORTAL_URL",
     "VIRKI_HUB_HOSTNAME", "VIRKI_PORTAL_HOSTNAME", "VIRKI_OIDC_PROXY_URL",
     "VIRKI_PASSKEYS_ENABLED", "VIRKI_ADMIN_PASSKEYS_ENABLED",
     "VIRKI_HUB_PERIMETER_MODE", "VIRKI_RATE_LIMIT_HASH_SECRET",
     "VIRKI_AUDIT_HASH_SECRET", "VIRKI_CSRF_SIGNING_KEY",
     "VIRKI_CSRF_SIGNING_KEY_PREVIOUS", "VIRKI_TOTP_ENCRYPTION_KEY",
     "VIRKI_EMAIL_OUTBOX_KEY", "VIRKI_EMAIL_TRANSPORT",
     "CLOUDFLARE_ACCESS_JWT_REQUIRED"] as $hub_allowed_env_keys
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
    and (($h.dns // []) | length == 0)
    and (($h.dns_search // []) | length == 0)
    and (($h.dns_opt // []) | length == 0)
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
    and (($h.cgroup // null) == null)
    and (($h.container_name // null) == null)
    and (($h.healthcheck // null) != null)
    and (($h.deploy // {}) | length == 0)
    and (($h.build // null) == null)
    and (($h.env_file // []) | length == 0)
    and ($h.environment | type == "object")
    and all($h.environment | keys[]; . as $key | ($hub_allowed_env_keys | index($key)) != null)
    and (($h.environment | has("VIRKI_STAGING_PASSKEY_RP_ENABLED")) | not)
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
    and ([$h.environment | keys[] | select(test("(^|_)(SMTP|BREVO)(_|$)|(^|_)(MAIL|EMAIL)_(.*(PASSWORD|SECRET|TOKEN|API_KEY|USER))$"; "i"))] | length == 0)
    and (.services | keys == ["hub"])
    and (($h.networks // {}) | keys | length == 1)
    and (.networks | keys | length == 1)
    and ((.volumes // {}) | length == 0)
    and any($h.networks | keys[]; . as $key | $networks[$key].external == true and $networks[$key].name == $network)
' >/dev/null
# The signed file and in-memory Compose render contain credentials. Keep their
# exact bytes only in this protected shell; never pass them as CLI arguments or
# print them in an evidence log. The runtime check compares via stdin below.
# This function checks signed declarations against independently collected
# operator measurements. It does NOT itself attest that an edge or worker is
# live/stopped. Rerun with a NEW independent observation before worker start.
signed_staging_runtime_preflight() {
  local smtp_username_sha256 preflight_output expected_preflight_output
  : "${VIRKI_STAGING_APPROVAL_JSON:?signed approval required}" || return 1
  : "${VIRKI_STAGING_OBSERVATION_JSON:?signed observation required}" || return 1
  : "${VIRKI_STAGING_APPROVER_PUBLIC_KEY:?pinned owner key required}" || return 1
  : "${VIRKI_STAGING_OBSERVER_PUBLIC_KEY:?pinned observer key required}" || return 1
  smtp_username_sha256="$(printf '%s' "$VIRKI_STAGING_EMAIL_SMTP_USER" | sha256sum | cut -d' ' -f1)" || return 1
  [[ "$smtp_username_sha256" =~ ^[a-f0-9]{64}$ ]] || return 1
  preflight_output="$("$node_bin" scripts/staging-otp-preflight.mjs \
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
    --smtp-username-sha256 "$smtp_username_sha256" \
    --runtime-worker-oci-digest "${image##*@}" \
    --runtime-hub-oci-digest "${hub_image##*@}" \
    --runtime-worker-compose-project "$project" \
    --runtime-hub-compose-project "$hub_project" \
    --runtime-hub-compose-file-sha256 "$hub_file_sha" \
    --runtime-network-id "$network_id" \
    --runtime-db-name "$worker_db_name" \
    --runtime-resource-policy-id "$VIRKI_STAGING_RESOURCE_POLICY_ID" \
    --runtime-resource-policy-evidence-ref "$VIRKI_STAGING_RESOURCE_POLICY_RECEIPT" \
    --runtime-worker-memory-bytes "$memory_bytes" \
    --runtime-worker-cpu-nano "$cpu_nanos" \
    --runtime-worker-pids-limit "$VIRKI_STAGING_EMAIL_WORKER_PIDS_LIMIT" \
    --runtime-worker-interval-ms "$VIRKI_STAGING_EMAIL_MIN_SEND_INTERVAL_MS")" || return 1
  expected_preflight_output=$'STAGING_OTP_PREFLIGHT=SIGNED_OFFLINE_DECLARATIONS_CONSISTENT\nLIVE_WORKER_STATE=NOT_OBSERVED_BY_THIS_TOOL\nSTAGING_AUTHORIZATION=NOT_GRANTED_BY_THIS_TOOL\nPRODUCTION_RELEASE=NO_GO'
  [[ "$preflight_output" == "$expected_preflight_output" ]] || return 1
}
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
set +x +v
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
: "${VIRKI_STAGING_APPROVED_DB_CA_FILE:?approved staging DB CA path required}"
: "${VIRKI_STAGING_APPROVED_DB_CA_SHA256:?approved staging DB CA digest required}"
ca_file="$VIRKI_STAGING_APPROVED_DB_CA_FILE"
[[ "$ca_file" == /* && "$(dirname -- "$ca_file")" == "$service_dir" &&
   "$ca_file" == "$(realpath -e -- "$ca_file")" && -f "$ca_file" && ! -L "$ca_file" ]]
[[ "$VIRKI_STAGING_APPROVED_DB_CA_SHA256" =~ ^[a-f0-9]{64}$ ]]
[[ "$(stat -c '%u:%a:%h' -- "$ca_file")" == "$(id -u):600:1" ]]
[[ "$(sha256sum -- "$ca_file" | cut -d' ' -f1)" == "$VIRKI_STAGING_APPROVED_DB_CA_SHA256" ]]
if grep -Eiq '^[[:space:]]*password[[:space:]]*=' "$PGSERVICEFILE"; then
  printf 'BLOCK: password material must be in the protected pass file, not the service file\n' >&2
  exit 1
fi
# The operator-only PGPASSFILE verifier parses all five fields and rejects
# wildcard markers only in the four match fields; a literal '*' in a password
# field is valid and remains a credential byte.
require_service_tls() {
  local service="$1"
  awk -v section="[$service]" -v approved_ca="$ca_file" '
    { sub(/\r$/, "", $0) }
    $0 == section { if (found) bad=1; found=1; active=1; next }
    /^\[/ { if (active) active=0 }
    active && /^[[:space:]]*[A-Za-z][A-Za-z0-9_]*[[:space:]]*=/ {
      key=$0; sub(/^[[:space:]]*/, "", key); sub(/[[:space:]]*=.*/, "", key); key=tolower(key)
      if (seen[key]++) bad=1
      required[key]=1
    }
    active && /^[[:space:]]*sslmode[[:space:]]*=/ {
      count++; value=$0; sub(/^[^=]*=/, "", value); gsub(/[[:space:]]/, "", value)
      if (value != "verify-full") bad=1
    }
    active && /^[[:space:]]*sslrootcert[[:space:]]*=/ {
      ca_count++; value=$0; sub(/^[^=]*=/, "", value)
      sub(/^[[:space:]]*/, "", value); sub(/[[:space:]]*$/, "", value)
      if (value != approved_ca) bad=1
    }
    active && /^[[:space:]]*(password|passfile|hostaddr|sslcert|sslkey|sslpassword)[[:space:]]*=/ { bad=1 }
    END { exit !(found && count == 1 && ca_count == 1 && required["host"] && required["port"] && required["dbname"] && required["user"] && required["sslmode"] && required["sslrootcert"] && !bad) }
  ' "$PGSERVICEFILE"
}
require_service_tls virki-staging-worker
require_service_tls virki-staging-hub
require_service_tls virki-staging-migrator
require_service_tls virki-staging-bootstrap
: "${POSTGRES_USER:?staging-only bootstrap superuser name required}"
: "${POSTGRES_PASSWORD:?staging-only bootstrap superuser password required}"
: "${VIRKI_STAGING_RESTORE_DB:?owner-approved fresh restore database name required}"
: "${VIRKI_RUNTIME_DB_PASSWORD:?staging runtime database password required}"
: "${VIRKI_MIGRATOR_DB_PASSWORD:?staging migrator database password required}"
: "${VIRKI_EMAIL_WORKER_DB_PASSWORD:?staging email-worker database password required}"
[[ "$VIRKI_STAGING_RESTORE_DB" =~ ^virki_stage_restore_[a-f0-9]{8,16}$ ]]
export POSTGRES_USER POSTGRES_PASSWORD VIRKI_RUNTIME_DB_PASSWORD VIRKI_MIGRATOR_DB_PASSWORD
export VIRKI_EMAIL_WORKER_DB_PASSWORD VIRKI_STAGING_RESTORE_DB
export VIRKI_STAGING_APPROVED_DB_HOST VIRKI_STAGING_APPROVED_DB_PORT VIRKI_STAGING_APPROVED_DB_NAME
export VIRKI_STAGING_EMAIL_WORKER_DATABASE_URL VIRKI_STAGING_HUB_DATABASE_URL
"$node_bin" scripts/staging-pgpass-bootstrap-binding.mjs --require-runtime-urls
unset PGHOSTADDR PGHOST PGPORT PGSERVICE PGOPTIONS PGUSER PGDATABASE PGPASSWORD
unset PGSSLMODE PGSSLCERT PGSSLKEY PGSSLROOTCERT PGSSLCRL PGSSLKEYLOGFILE SSLKEYLOGFILE
unset PGSSLMINPROTOCOLVERSION PGSSLMAXPROTOCOLVERSION PGCHANNELBINDING
unset PGCONNECT_TIMEOUT PGTARGETSESSIONATTRS PGAPPNAME PGCLIENTENCODING
unset PGSSLNEGOTIATION PGREQUIREPEER PGGSSENCMODE PGGSSDELEGATION PGKRBSRVNAME
unset PGREQUIRESSL PGSSLCOMPRESSION PGLOADBALANCEHOSTS
unset PGREQUIREAUTH PGSSLCERTMODE PGSSLCRLDIR PGSSLSNI PGGSSLIB PGMINPROTOCOLVERSION PGMAXPROTOCOLVERSION PGSYSCONFDIR PGLOCALEDIR PGDATESTYLE PGTZ PGGEQO PGOAUTHDEBUG PGOAUTHCAFILE
same_ip_address() {
  # PostgreSQL inet output is canonical, but an owner-signed IPv6 literal may
  # be expanded. Compare IP values, not text or DNS names.
  "$node_bin" -e '
    const { isIP } = require("node:net");
    const [left, right] = process.argv.slice(1);
    const family = isIP(left);
    if (!family || family !== isIP(right)) process.exit(1);
    const canonical = (value) => family === 6
      ? new URL("http://[" + value + "]/").hostname
      : value;
    if (canonical(left) !== canonical(right)) process.exit(1);
  ' "$1" "$2"
}
remote_scram_probe() {
  local service="$1" database="$2" expected_user="$3" probe
  if ! probe="$(PGSERVICE="$service" psql --no-password \
    --dbname="service=$service dbname=$database hostaddr=$VIRKI_STAGING_APPROVED_DB_SERVER_ADDR" -XAtqc \
    "select coalesce(host(inet_server_addr()), '') || '|' || coalesce(inet_server_port()::text, '') || '|' || current_database() || '|' || current_user || '|' || session_user || '|' || (select ssl::text from pg_stat_ssl where pid=pg_backend_pid()) || '|' || coalesce(host(inet_client_addr()), '')")"; then
    return 1
  fi
  local probe_server_addr probe_server_port probe_database probe_user probe_session_user probe_ssl probe_client_addr
  IFS='|' read -r probe_server_addr probe_server_port probe_database probe_user probe_session_user probe_ssl probe_client_addr <<<"$probe"
  [[ "$probe_server_port" == "$VIRKI_STAGING_APPROVED_DB_PORT" && "$probe_database" == "$database" && "$probe_user" == "$expected_user" &&
     "$probe_session_user" == "$expected_user" && "$probe_ssl" == "true" &&
     -n "$probe_client_addr" ]] || return 1
  same_ip_address "$probe_server_addr" "$VIRKI_STAGING_APPROVED_DB_SERVER_ADDR" || return 1
  same_ip_address "$probe_client_addr" "$staging_db_client_addr" || return 1

  local negative_dir negative_pass_file
  negative_dir="$(mktemp -d "$service_dir/negative-passfile.XXXXXX")" || return 1
  negative_pass_file="$negative_dir/pgpass"
  (
    trap 'rm -f -- "$negative_pass_file"; rmdir -- "$negative_dir"' EXIT
    chmod 0700 -- "$negative_dir" || exit 1
    [[ "$(stat -c '%u:%a' "$negative_dir")" == "$(id -u):700" ]] || exit 1
    local wrong_password negative_output
    wrong_password="virki-invalid-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')" || exit 1
    [[ "$wrong_password" =~ ^virki-invalid-[a-f0-9]{32}$ ]] || exit 1
    local negative_host
    negative_host="${VIRKI_STAGING_APPROVED_DB_HOST//\\/\\\\}"
    negative_host="${negative_host//:/\\:}"
    printf '%s:%s:%s:%s:%s\n' "$negative_host" "$VIRKI_STAGING_APPROVED_DB_PORT" "$database" "$expected_user" "$wrong_password" > "$negative_pass_file" || exit 1
    chmod 0600 -- "$negative_pass_file" || exit 1
    [[ -f "$negative_pass_file" && ! -L "$negative_pass_file" ]] || exit 1
    [[ "$(stat -c '%u:%a:%h' "$negative_pass_file")" == "$(id -u):600:1" ]] || exit 1
    unset PGPASSWORD
    if negative_output="$(LC_ALL=C PGSERVICE="$service" PGPASSFILE="$negative_pass_file" psql --no-password \
      --dbname="service=$service dbname=$database hostaddr=$VIRKI_STAGING_APPROVED_DB_SERVER_ADDR" -XAtqc 'select 1' 2>&1)"; then
      exit 1
    fi
    [[ "$negative_output" == *"password authentication failed"* ]] || exit 1
  ) || return 1
}
verify_remote_hba_active() {
  local probe
  if ! probe="$(PGSERVICE=virki-staging-bootstrap psql --no-password \
    --dbname='service=virki-staging-bootstrap dbname=postgres' -XAtq --set=ON_ERROR_STOP=1 \
    --file=scripts/staging-remote-hba-active.sql)"; then
    return 1
  fi
  local hba_database hba_user hba_superuser hba_loaded hba_file_count hba_external_files hba_errors hba_includes hba_server_addr hba_server_port hba_client_addr
  IFS='|' read -r hba_database hba_user hba_superuser hba_loaded hba_file_count hba_external_files hba_errors hba_includes hba_server_addr hba_server_port hba_client_addr <<<"$probe"
  [[ "$hba_database" == "postgres" && "$hba_user" == "$POSTGRES_USER" &&
     "$hba_superuser" == "true" && "$hba_loaded" == "true" &&
     "$hba_file_count" == "1" && "$hba_external_files" == "0" && "$hba_errors" == "0" && "$hba_includes" == "0" && "$hba_server_port" == "$VIRKI_STAGING_APPROVED_DB_PORT" && -n "$hba_client_addr" ]] || return 1
  same_ip_address "$hba_server_addr" "$VIRKI_STAGING_APPROVED_DB_SERVER_ADDR" || return 1
  if [[ -n "${staging_db_client_addr:-}" ]]; then
    same_ip_address "$hba_client_addr" "$staging_db_client_addr" || return 1
  fi
  staging_db_client_addr="$hba_client_addr"
}
verify_remote_hba_active
verify_remote_hba_rules() {
  local result
  if ! result="$(PGSERVICE=virki-staging-bootstrap psql --no-password \
    --dbname='service=virki-staging-bootstrap dbname=postgres' \
    --set=approved_db="$VIRKI_STAGING_APPROVED_DB_NAME" \
    --set=restore_db="$VIRKI_STAGING_RESTORE_DB" \
    --set=bootstrap_user="$POSTGRES_USER" -XAtq --set=ON_ERROR_STOP=1 \
    --file=scripts/staging-remote-hba-rules.sql)"; then
    return 1
  fi
  [[ "$result" == "8|8|0|0|8|true" ]]
}
verify_remote_hba_rules
remote_scram_probe virki-staging-worker "$VIRKI_STAGING_APPROVED_DB_NAME" virki_email_worker
remote_scram_probe virki-staging-hub "$VIRKI_STAGING_APPROVED_DB_NAME" virki_runtime
remote_scram_probe virki-staging-migrator "$VIRKI_STAGING_APPROVED_DB_NAME" virki_migrator
remote_scram_probe virki-staging-bootstrap postgres "$POSTGRES_USER"
verify_remote_hba_rules
verify_remote_hba_active
db_identity="$(PGSERVICE=virki-staging-worker psql --no-password -XAtqc \
  "select host(inet_server_addr()) || '|' || inet_server_port()::text || '|' || current_database() || '|' || current_user || '|' || session_user || '|' || current_setting('server_version_num') || '|' || (select ssl::text from pg_stat_ssl where pid=pg_backend_pid())")"
IFS='|' read -r actual_db_addr actual_db_port actual_db_name actual_db_user actual_db_session_user actual_db_version actual_db_ssl <<<"$db_identity"
same_ip_address "$actual_db_addr" "$VIRKI_STAGING_APPROVED_DB_SERVER_ADDR"
[[ "$actual_db_port" == "$VIRKI_STAGING_APPROVED_DB_PORT" ]]
[[ "$actual_db_name" == "$VIRKI_STAGING_APPROVED_DB_NAME" ]]
[[ "$actual_db_user" == "virki_email_worker" && "$actual_db_session_user" == "virki_email_worker" ]]
[[ "$actual_db_version" =~ ^[0-9]+$ ]]
[[ "$actual_db_ssl" == "true" ]]
printf 'STAGING_WORKER_DATABASE_TARGET=PASS\n'
hub_db_identity="$(PGSERVICE=virki-staging-hub psql --no-password -XAtqc \
  "select host(inet_server_addr()) || '|' || inet_server_port()::text || '|' || current_database() || '|' || current_user || '|' || session_user || '|' || current_setting('server_version_num') || '|' || (select ssl::text from pg_stat_ssl where pid=pg_backend_pid())")"
IFS='|' read -r actual_hub_db_addr actual_hub_db_port actual_hub_db_name actual_hub_db_user actual_hub_db_session_user actual_hub_db_version actual_hub_db_ssl <<<"$hub_db_identity"
same_ip_address "$actual_hub_db_addr" "$VIRKI_STAGING_APPROVED_DB_SERVER_ADDR"
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
The Hub's egress policy is separate from this ingress rule: permit only the
signed staging DB, explicitly approved identity/application endpoints and the
approved DNS resolution path; do not provide SMTP credentials and deny
outbound SMTP connections, all Docker
Engine TCP API listeners (including 2375/2376 and any custom port), SSH/RDP,
host-gateway management services and every
unapproved destination. A shared
external network does not itself enforce these per-service egress boundaries.

Run the Hub and worker activation/stop blocks in the same protected interactive
shell and keep that shell open through the attended window. An EXIT/INT/TERM/HUP
cleanup trap remains armed while either service is active; closing the shell or
interrupting it stops the worker first and then the Hub. Do not run these blocks
as a short-lived `bash -c`/script process, which would immediately trigger the
cleanup trap after startup.

The source candidate adds a fail-closed staging RP-ID opt-in
(`VIRKI_STAGING_PASSKEY_RP_ENABLED=true`) that requires a production-mode
native Hub and distinct explicit canonical USER/ADMIN hostnames through
`VIRKI_PORTAL_HOSTNAME` and `VIRKI_HUB_HOSTNAME`; without the opt-in
the default production RPs stay `portal.biel.dev.br` and
`hub.biel.dev.br`. Both role-specific RP IDs are bound to their HTTPS
origins and recovery factors. **No owner-signed staging RP host pair, DNS,
TLS, actual browser ceremony or independently accepted final source SHA has
been observed.** Keep `VIRKI_STAGING_PASSKEY_RP_ENABLED` unset,
`VIRKI_PASSKEYS_ENABLED=false` and `VIRKI_ADMIN_PASSKEYS_ENABLED=false`
and never set `VIRKI_PASSKEYS_LOCAL_TESTING` for staging. Mark staging
Portal/Hub RP separation **BLOCK**, not PASS or SKIP, until a separately
approved staging inventory is exercised and independently reviewed.
TOTP-based recovery coverage cannot satisfy the passkey release gate.

```sh
set +x +v
set -euo pipefail
hub_cleanup_armed=0
worker_cleanup_armed=0
cleanup_staging_services() {
  local exit_status=$?
  trap - EXIT INT TERM HUP
  local cleanup_was_armed=0
  if [[ "${worker_cleanup_armed:-0}" == "1" || "${hub_cleanup_armed:-0}" == "1" ]]; then
    cleanup_was_armed=1
  fi
  if [[ "${worker_cleanup_armed:-0}" == "1" ]]; then
    docker --context "$ctx" compose --project-name "$project" \
      --profile "$profile" -f "$file" stop --timeout 60 email-worker >/dev/null 2>&1 || true
  fi
  if [[ "${hub_cleanup_armed:-0}" == "1" ]]; then
    docker --context "$ctx" compose --project-name "$hub_project" \
      -f "$hub_file" stop --timeout 60 hub >/dev/null 2>&1 || true
  fi
  if [[ "$cleanup_was_armed" == "1" ]]; then
    printf 'BLOCK: staging shell exited before explicit service stop; independently confirm worker and Hub are physically stopped\n' >&2
    # An unexpected exit is never a successful attended shutdown, even if the
    # command that closed the shell returned zero.
    if [[ "$exit_status" == "0" ]]; then exit_status=1; fi
  fi
  exit "$exit_status"
}
trap 'cleanup_staging_services' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
hub_abort() {
  printf 'BLOCK: Hub runtime verification failed; independently confirm physical stop before continuing\n' >&2
  exit 1
}
signed_staging_runtime_preflight || hub_abort
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
hub_cleanup_armed=1
if ! docker --context "$ctx" compose --project-name "$hub_project" -f "$hub_file" \
  up --no-deps --pull never --wait --wait-timeout 120 hub; then
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
if ! hub_project_volumes="$(docker --context "$ctx" volume ls -q \
  --filter "label=com.docker.compose.project=$hub_project")"; then hub_abort; fi
if ! hub_project_networks="$(docker --context "$ctx" network ls -q \
  --filter "label=com.docker.compose.project=$hub_project")"; then hub_abort; fi
[[ -z "$hub_project_volumes" && -z "$hub_project_networks" ]] || hub_abort
hub_service_containers="$(docker --context "$ctx" ps -aq \
  --filter "label=com.docker.compose.service=hub")"
[[ "$hub_service_containers" == "$hub_id" ]] || hub_abort
# Compare the signed image defaults, approved Compose render and actual
# container through stdin only; never expose resolved secrets in process argv.
if ! { printf '%s\n' "$hub_config"; \
       docker --context "$ctx" image inspect "$hub_image"; \
       docker --context "$ctx" inspect "$hub_id"; } | jq -s -e \
  --arg image "$hub_image" --arg image_id "$hub_image_id" \
  --arg network "$network" --arg network_id "$network_id" '
  length == 3
  and (.[0].services.hub.environment as $compose_env
  | .[1] as $images
  | .[2] as $containers
  | ($images[0].Config.Env // []) as $image_env
  | ($containers[0].Config.Env // []) as $runtime_env
  | ([$image_env[]? | split("=")[0]] | sort) as $image_env_keys
  | ([$runtime_env[]? | split("=")[0]] | sort) as $runtime_env_keys
  | (($image_env_keys + ($compose_env | keys)) | unique | sort) as $allowed_env_keys
  | $containers[0] as $c
  | ($images | length == 1)
    and ($containers | length == 1)
    and $images[0].Id == $image_id
    and ($compose_env | type == "object")
    and ($image_env | length == ($image_env_keys | unique | length))
    and ($runtime_env | length == ($runtime_env_keys | unique | length))
    and $runtime_env_keys == $allowed_env_keys
    and all($compose_env | to_entries[]; . as $entry
      | ($runtime_env | index($entry.key + "=" + ($entry.value | tostring))) != null)
    and all($image_env[]?; . as $entry | ($entry | split("=")[0]) as $key
      | ($compose_env | has($key)) or ($runtime_env | index($entry) != null))
    and ([$runtime_env_keys[] | select(. == "VIRKI_STAGING_PASSKEY_RP_ENABLED" or
        . == "VIRKI_PASSKEYS_LOCAL_TESTING" or . == "CLOUDFLARE_ACCESS_AUDIENCE" or
        . == "CLOUDFLARE_TEAM_DOMAIN" or . == "CLOUDFLARE_ACCESS_JWKS_URL")] | length == 0)
    and $c.State.Status == "running"
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
    and (($c.AppArmorProfile // "") != "unconfined")
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
    and ([$c.Config.Env[]? | split("=")[0] | select(test("(^|_)(SMTP|BREVO)(_|$)|(^|_)(MAIL|EMAIL)_(.*(PASSWORD|SECRET|TOKEN|API_KEY|USER))$"; "i"))] | length == 0)
    and ([$c.Config.Env[]? | split("=")[0] | select(. == "VIRKI_EMAIL_WORKER_SCOPED_ROLE")] | length == 0))
' >/dev/null; then
  hub_abort
fi
unset hub_config
if ! hub_health="$(docker --context "$ctx" inspect "$hub_id" \
  --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}NO_HEALTHCHECK{{end}}')"; then
  hub_abort
fi
[[ "$hub_health" == "healthy" ]] || hub_abort
if ! hub_initial_restarts="$(docker --context "$ctx" inspect "$hub_id" \
  --format '{{.RestartCount}}')" || [[ "$hub_initial_restarts" != "0" ]]; then
  hub_abort
fi
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
set +x +v
set -euo pipefail
[[ "${hub_cleanup_armed:-0}" == "1" && "${worker_cleanup_armed:-0}" == "0" &&
   "$(trap -p EXIT)" == *cleanup_staging_services* ]] || {
  printf 'BLOCK: worker requires the same protected Hub shell with an armed EXIT cleanup trap\n' >&2
  exit 1
}
signed_staging_runtime_preflight || {
  printf 'BLOCK: fresh signed worker preflight does not match witnessed staging identities\n' >&2
  exit 1
}

abort_worker() {
  printf 'BLOCK: worker runtime verification failed; protected EXIT cleanup will stop worker then Hub; independently confirm both physical stops\n' >&2
  exit 1
}
queue_counts="$(PGSERVICE=virki-staging-worker psql --no-password -XAtqc \
  'select (select count(*) from public."EmailOutboxMessage")::text || chr(124) || (select count(*) from public."EmailDeliveryAttempt")::text')" || abort_worker
[[ "$queue_counts" == "0|0" ]] || abort_worker
worker_cleanup_armed=1
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
if ! worker_project_volumes="$(docker --context "$ctx" volume ls -q \
  --filter "label=com.docker.compose.project=$project")"; then abort_worker; fi
if ! worker_project_networks="$(docker --context "$ctx" network ls -q \
  --filter "label=com.docker.compose.project=$project")"; then abort_worker; fi
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
if ! { docker --context "$ctx" image inspect "$image"; \
       docker --context "$ctx" inspect "$worker_id"; } | jq -s -e \
  --arg image "$image" --arg image_id "$image_id" \
  --arg network "$network" --arg network_id "$network_id" '
  length == 2
  and (.[0] | length == 1)
  and (.[1] | length == 1)
  and (.[0][0] as $img
  | .[1][0] as $c
  | ($img.Config.Env // []) as $image_env
  | ($c.Config.Env // []) as $runtime_env
  | ["DATABASE_URL","NODE_ENV","VIRKI_EMAIL_FROM","VIRKI_EMAIL_MIN_SEND_INTERVAL_MS",
     "VIRKI_EMAIL_OUTBOX_KEY","VIRKI_EMAIL_REPLY_TO","VIRKI_EMAIL_SMTP_HOST",
     "VIRKI_EMAIL_SMTP_PASSWORD","VIRKI_EMAIL_SMTP_PORT","VIRKI_EMAIL_SMTP_SECURE",
     "VIRKI_EMAIL_SMTP_USER","VIRKI_EMAIL_TRANSPORT","VIRKI_EMAIL_WORKER_SCOPED_ROLE"] as $worker_env_keys
  | ([$image_env[]? | split("=")[0]] | unique) as $image_env_keys
  | (($image_env_keys + $worker_env_keys) | unique | sort) as $allowed_env_keys
  | ([$runtime_env[]? | split("=")[0]] | sort) as $runtime_env_keys
  | $img.Id == $image_id
    and $c.Config.Image == $image
    and $c.Image == $image_id
    and (($c.Config.Entrypoint // []) | length == 0)
    and $c.Config.Cmd == ["npm", "run", "email:worker", "--workspace", "@virki/auth"]
    and $c.Config.User == "node:node"
    and $c.HostConfig.ReadonlyRootfs == true
    and $c.HostConfig.CapDrop == ["ALL"]
    and $c.HostConfig.SecurityOpt == ["no-new-privileges:true"]
    and (($c.HostConfig.Tmpfs // {}) | keys == ["/tmp"])
    and ((($c.HostConfig.Tmpfs["/tmp"] | split(",") | sort) == ["nodev","noexec","nosuid","rw","size=64m"])
      or (($c.HostConfig.Tmpfs["/tmp"] | split(",") | sort) == ["nodev","noexec","nosuid","rw","size=67108864"]))
    and (($c.HostConfig.Binds // []) | length == 0)
    and (($c.Mounts // []) | length == 1)
    and $c.Mounts[0].Type == "tmpfs"
    and $c.Mounts[0].Destination == "/tmp"
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
    and (($c.HostConfig.CapAdd // []) | length == 0)
    and $c.HostConfig.Privileged == false
    and (($c.HostConfig.PortBindings // {}) | length == 0)
    and (($c.HostConfig.PublishAllPorts // false) == false)
    and $c.HostConfig.NetworkMode == $network
    and (($c.NetworkSettings.Networks // {}) | keys == [$network])
    and $c.NetworkSettings.Networks[$network].NetworkID == $network_id
    and (($c.HostConfig.PidMode // "") == "" or $c.HostConfig.PidMode == "private")
    and (($c.HostConfig.IpcMode // "private") == "private")
    and (($c.HostConfig.UTSMode // "") == "" or $c.HostConfig.UTSMode == "private")
    and (($c.HostConfig.UsernsMode // "") == "" or $c.HostConfig.UsernsMode == "private")
    and (($c.HostConfig.CgroupnsMode // "private") == "private")
    and (($c.HostConfig.Runtime // "runc") == "runc")
    and (($c.AppArmorProfile // "") != "unconfined")
    and $runtime_env_keys == $allowed_env_keys
    and ([$runtime_env[]? | split("=")[0] as $key | select($key | test("(^|_)(SMTP|BREVO)(_|$)|(^|_)(MAIL|EMAIL)_(.*(PASSWORD|SECRET|TOKEN|API_KEY|USER))$"; "i")) | select(($worker_env_keys | index($key)) == null)] | length == 0)
    and all($worker_env_keys[]; . as $key | ($key == "NODE_ENV") or (($image_env_keys | index($key)) == null))
    and all($image_env[]?; . as $entry | ($entry | split("=")[0]) as $key
      | (($worker_env_keys | index($key)) != null) or ($runtime_env | index($entry) != null))
    and ($runtime_env | index("NODE_ENV=production") != null)
    and ($runtime_env | index("DATABASE_URL=" + env.VIRKI_STAGING_EMAIL_WORKER_DATABASE_URL) != null)
    and ($runtime_env | index("VIRKI_EMAIL_OUTBOX_KEY=" + env.VIRKI_STAGING_EMAIL_OUTBOX_KEY) != null)
    and ($runtime_env | index("VIRKI_EMAIL_TRANSPORT=smtp") != null)
    and ($runtime_env | index("VIRKI_EMAIL_WORKER_SCOPED_ROLE=required") != null)
    and ($runtime_env | index("VIRKI_EMAIL_MIN_SEND_INTERVAL_MS=" + env.VIRKI_STAGING_EMAIL_MIN_SEND_INTERVAL_MS) != null)
    and ($runtime_env | index("VIRKI_EMAIL_SMTP_HOST=" + env.VIRKI_STAGING_EMAIL_SMTP_HOST) != null)
    and ($runtime_env | index("VIRKI_EMAIL_SMTP_PORT=" + env.VIRKI_STAGING_EMAIL_SMTP_PORT) != null)
    and ($runtime_env | index("VIRKI_EMAIL_SMTP_SECURE=" + env.VIRKI_STAGING_EMAIL_SMTP_SECURE) != null)
    and ($runtime_env | index("VIRKI_EMAIL_SMTP_USER=" + env.VIRKI_STAGING_EMAIL_SMTP_USER) != null)
    and ($runtime_env | index("VIRKI_EMAIL_SMTP_PASSWORD=" + env.VIRKI_STAGING_EMAIL_SMTP_PASSWORD) != null)
    and ($runtime_env | index("VIRKI_EMAIL_FROM=" + env.VIRKI_STAGING_EMAIL_FROM) != null)
    and ($runtime_env | index("VIRKI_EMAIL_REPLY_TO=" + (env.VIRKI_STAGING_EMAIL_REPLY_TO // "")) != null))
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
set +x +v
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
set +x +v
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
worker_cleanup_armed=0
if ! docker --context "$ctx" compose --project-name "$hub_project" \
  -f "$hub_file" stop --timeout 60 hub; then
  abort_worker
fi
if ! stopped_hub_id="$(docker --context "$ctx" compose --project-name "$hub_project" \
  -f "$hub_file" ps -aq hub)" || [[ "$stopped_hub_id" != "$hub_id" ]]; then
  abort_worker
fi
if ! hub_stop_values="$(docker --context "$ctx" inspect "$hub_id" \
  --format '{{.State.Status}}|{{.HostConfig.RestartPolicy.Name}}|{{.RestartCount}}')"; then
  abort_worker
fi
IFS='|' read -r stopped_hub_state stopped_hub_restart stopped_hub_restarts <<<"$hub_stop_values"
if [[ "$stopped_hub_state" != "exited" || "$stopped_hub_restart" != "no" ||
      "$stopped_hub_restarts" != "$hub_initial_restarts" ]]; then
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
hub_cleanup_armed=0
trap - EXIT INT TERM HUP
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
set +x +v
set -euo pipefail
if [[ "${worker_cleanup_armed:-0}" == "1" ]]; then
  printf 'BLOCK: worker cleanup remains armed; complete the verified worker stop first\n' >&2
  exit 1
fi
if ! rollback_workers="$(docker --context "$ctx" ps -aq \
  --filter "label=com.docker.compose.service=email-worker")"; then
  printf 'BLOCK: cannot enumerate physical worker containers before rollback\n' >&2
  exit 1
fi
if [[ -n "$rollback_workers" ]]; then
  [[ "$rollback_workers" == "${worker_id:-}" && "$worker_id" =~ ^[a-f0-9]{64}$ ]] || {
    printf 'BLOCK: an unexpected worker container exists on the staging daemon\n' >&2
    exit 1
  }
  if ! rollback_worker_state="$(docker --context "$ctx" inspect "$worker_id" \
    --format '{{.State.Status}}|{{.HostConfig.RestartPolicy.Name}}|{{.RestartCount}}')"; then
    exit 1
  fi
  [[ "$rollback_worker_state" == "exited|no|${VIRKI_STAGING_WORKER_INITIAL_RESTART_COUNT:-0}" ]] || {
    printf 'BLOCK: worker is not physically stopped and unable to restart\n' >&2
    exit 1
  }
fi
if ! rollback_running_workers="$(docker --context "$ctx" ps -q \
  --filter "label=com.docker.compose.service=email-worker")" || [[ -n "$rollback_running_workers" ]]; then
  printf 'BLOCK: worker running during rollback\n' >&2
  exit 1
fi
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
set +x +v
set -euo pipefail
[[ -n "${BASH_VERSION:-}" && "${BASH_VERSINFO[0]}" -ge 4 ]]
unset LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT LD_DEBUG LD_ORIGIN_PATH LD_PROFILE LD_USE_LOAD_BIAS
umask 077
: "${PGSERVICEFILE:=/run/virki-staging/pg_service.conf}"
: "${PGPASSFILE:=/run/virki-staging/pgpass}"
export PGSERVICEFILE PGPASSFILE
service_file="$PGSERVICEFILE"
pass_file="$PGPASSFILE"
: "${VIRKI_STAGING_EVIDENCE_DIR:?private evidence directory required}"
: "${VIRKI_STAGING_RESTORE_DB:?fresh approved staging restore DB name required}"
[[ "$VIRKI_STAGING_RESTORE_DB" =~ ^virki_stage_restore_[a-f0-9]{8,16}$ ]]
: "${VIRKI_STAGING_BASELINE_DUMP:?owner-approved baseline dump path required}"
: "${VIRKI_STAGING_BASELINE_DUMP_SHA256:?signed baseline dump digest required}"
: "${VIRKI_STAGING_APPROVED_SOURCE_SHA:?owner-approved exact source SHA required}"
: "${VIRKI_STAGING_APPROVED_DB_HOST:?signed staging database hostname required}"
: "${VIRKI_STAGING_APPROVED_DB_SERVER_ADDR:?signed staging database server address required}"
: "${VIRKI_STAGING_APPROVED_DB_PORT:?signed staging database port required}"
: "${VIRKI_STAGING_APPROVED_DB_NAME:?signed staging database name required}"
: "${VIRKI_STAGING_EMAIL_WORKER_DATABASE_URL:?approved runtime worker DB URL required}"
: "${VIRKI_STAGING_HUB_DATABASE_URL:?approved runtime Hub DB URL required}"
: "${POSTGRES_USER:?staging bootstrap database role required}"
: "${POSTGRES_PASSWORD:?staging bootstrap password required}"
: "${VIRKI_EMAIL_WORKER_DB_PASSWORD:?staging email-worker password required}"
: "${VIRKI_RUNTIME_DB_PASSWORD:?staging runtime role password required}"
: "${VIRKI_MIGRATOR_DB_PASSWORD:?staging migrator role password required}"
: "${VIRKI_AUDIT_MAINTENANCE_DB_PASSWORD:?staging audit-maintenance password required}"
: "${VIRKI_EMAIL_WORKER_DB_SCRAM_VERIFIER:?staging email-worker SCRAM verifier required}"
export POSTGRES_USER POSTGRES_PASSWORD VIRKI_EMAIL_WORKER_DB_PASSWORD
export VIRKI_RUNTIME_DB_PASSWORD VIRKI_MIGRATOR_DB_PASSWORD VIRKI_AUDIT_MAINTENANCE_DB_PASSWORD
export VIRKI_EMAIL_WORKER_DB_SCRAM_VERIFIER
export VIRKI_STAGING_APPROVED_DB_HOST VIRKI_STAGING_APPROVED_DB_PORT VIRKI_STAGING_APPROVED_DB_NAME VIRKI_STAGING_RESTORE_DB
export VIRKI_STAGING_APPROVED_SOURCE_SHA
export VIRKI_STAGING_EMAIL_WORKER_DATABASE_URL VIRKI_STAGING_HUB_DATABASE_URL
command -v realpath >/dev/null
command -v mktemp >/dev/null
command -v mv >/dev/null
command -v pg_dump >/dev/null
command -v pg_restore >/dev/null
command -v createdb >/dev/null
command -v psql >/dev/null
test -x /usr/bin/git
command -v grep >/dev/null
command -v awk >/dev/null
command -v stat >/dev/null
command -v id >/dev/null
command -v mkdir >/dev/null
command -v chmod >/dev/null
command -v rm >/dev/null
command -v dirname >/dev/null
command -v sha256sum >/dev/null
command -v cut >/dev/null
for git_name in "${!GIT_@}"; do unset "$git_name"; done
[[ "$VIRKI_STAGING_APPROVED_SOURCE_SHA" =~ ^[a-f0-9]{40}$ ]]
[[ "$(GIT_NO_REPLACE_OBJECTS=1 /usr/bin/git rev-parse HEAD)" == "$VIRKI_STAGING_APPROVED_SOURCE_SHA" ]]
for source_file in \
  scripts/staging-toolchain-preflight.mjs \
  scripts/staging-otp-preflight.mjs \
  scripts/staging-pgpass-bootstrap-binding.mjs \
  scripts/staging-prisma-migration-ledger-binding.mjs \
  scripts/staging-remote-hba-active.sql \
  scripts/staging-remote-hba-rules.sql \
  scripts/staging-local-hba-peer.sql \
  infra/postgres-init/10-virki-database-roles.sh \
  infra/postgres-init/11-virki-email-worker-role.sh \
  infra/docker-compose.staging-email-worker-only.yml \
  infra/Dockerfile.staging-db-trust \
  scripts/staging-db-ca-image-contract.test.mjs \
  scripts/staging-prisma-ca-archive-proof.mjs \
  scripts/staging-prisma-ca-archive-proof.test.mjs \
  docs/security/pr118-staging-operator-runbook-20261114.md \
  package.json; do
  [[ -f "$source_file" && ! -L "$source_file" ]] || {
    printf 'BLOCK: approved rollback helper absent or linked: %s\n' "$source_file" >&2
    exit 1
  }
  committed_blob="$(GIT_NO_REPLACE_OBJECTS=1 /usr/bin/git rev-parse --verify "HEAD:$source_file")" || exit 1
  actual_blob="$(GIT_NO_REPLACE_OBJECTS=1 /usr/bin/git hash-object --no-filters -- "$source_file")" || exit 1
  [[ "$committed_blob" == "$actual_blob" ]] || {
    printf 'BLOCK: raw rollback helper bytes differ from approved source: %s\n' "$source_file" >&2
    exit 1
  }
done
unset source_file committed_blob actual_blob git_name
: "${VIRKI_STAGING_APPROVED_NODE_BIN:?independently approved canonical Node executable required}"
: "${VIRKI_STAGING_APPROVED_NODE_SHA256:?independently approved Node binary digest required}"
node_bin="$VIRKI_STAGING_APPROVED_NODE_BIN"
[[ "$node_bin" == /* && "$node_bin" == "$(realpath -e -- "$node_bin")" &&
   -f "$node_bin" && -x "$node_bin" && ! -L "$node_bin" ]]
[[ "$VIRKI_STAGING_APPROVED_NODE_SHA256" =~ ^[a-f0-9]{64}$ ]]
[[ "$(stat -c '%u:%h' -- "$node_bin")" == "0:1" ]]
node_path_part="$node_bin"
while :; do
  node_path_part="$(dirname -- "$node_path_part")"
  [[ -d "$node_path_part" && ! -L "$node_path_part" ]]
  [[ "$(stat -c '%u' -- "$node_path_part")" == "0" ]]
  node_path_mode="$(stat -c '%a' -- "$node_path_part")"
  (( (8#$node_path_mode & 022) == 0 ))
  [[ "$node_path_part" == "/" ]] && break
done
node_file_mode="$(stat -c '%a' -- "$node_bin")"
(( (8#$node_file_mode & 022) == 0 ))
[[ "$(sha256sum -- "$node_bin" | cut -d' ' -f1)" == "$VIRKI_STAGING_APPROVED_NODE_SHA256" ]]
unset node_path_part node_path_mode node_file_mode
unset NODE_OPTIONS NODE_PATH
for name in "${!npm_config_@}" "${!NPM_CONFIG_@}"; do unset "$name"; done
"$node_bin" scripts/staging-toolchain-preflight.mjs
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
if grep -Eiq '^[[:space:]]*password[[:space:]]*=' "$PGSERVICEFILE"; then
  printf 'BLOCK: unsafe PostgreSQL service file content\n' >&2
  exit 1
fi
: "${VIRKI_STAGING_APPROVED_DB_CA_FILE:?approved staging DB CA path required}"
: "${VIRKI_STAGING_APPROVED_DB_CA_SHA256:?approved staging DB CA digest required}"
ca_file="$VIRKI_STAGING_APPROVED_DB_CA_FILE"
[[ "$ca_file" == /* && "$(dirname -- "$ca_file")" == "$service_dir" &&
   "$ca_file" == "$(realpath -e -- "$ca_file")" && -f "$ca_file" && ! -L "$ca_file" ]]
[[ "$VIRKI_STAGING_APPROVED_DB_CA_SHA256" =~ ^[a-f0-9]{64}$ ]]
[[ "$(stat -c '%u:%a:%h' -- "$ca_file")" == "$(id -u):600:1" ]]
[[ "$(sha256sum -- "$ca_file" | cut -d' ' -f1)" == "$VIRKI_STAGING_APPROVED_DB_CA_SHA256" ]]
require_service_tls() {
  local service="$1"
  awk -v section="[$service]" -v approved_ca="$ca_file" '
    { sub(/\r$/, "", $0) }
    $0 == section { if (found) bad=1; found=1; active=1; next }
    /^\[/ { if (active) active=0 }
    active && /^[[:space:]]*[A-Za-z][A-Za-z0-9_]*[[:space:]]*=/ {
      key=$0; sub(/^[[:space:]]*/, "", key); sub(/[[:space:]]*=.*/, "", key); key=tolower(key)
      if (seen[key]++) bad=1
      required[key]=1
    }
    active && /^[[:space:]]*sslmode[[:space:]]*=/ {
      count++; value=$0; sub(/^[^=]*=/, "", value); gsub(/[[:space:]]/, "", value)
      if (value != "verify-full") bad=1
    }
    active && /^[[:space:]]*sslrootcert[[:space:]]*=/ {
      ca_count++; value=$0; sub(/^[^=]*=/, "", value)
      sub(/^[[:space:]]*/, "", value); sub(/[[:space:]]*$/, "", value)
      if (value != approved_ca) bad=1
    }
    active && /^[[:space:]]*(password|passfile|hostaddr|sslcert|sslkey|sslpassword)[[:space:]]*=/ { bad=1 }
    END { exit !(found && count == 1 && ca_count == 1 && required["host"] && required["port"] && required["dbname"] && required["user"] && required["sslmode"] && required["sslrootcert"] && !bad) }
  ' "$PGSERVICEFILE"
}
for service in virki-staging-migrator virki-staging-bootstrap virki-staging-worker virki-staging-hub; do
  require_service_tls "$service"
done
unset PGHOSTADDR PGHOST PGPORT PGSERVICE PGOPTIONS PGUSER PGDATABASE PGPASSWORD
unset PGSSLMODE PGSSLCERT PGSSLKEY PGSSLROOTCERT PGSSLCRL PGSSLKEYLOGFILE SSLKEYLOGFILE
unset PGSSLMINPROTOCOLVERSION PGSSLMAXPROTOCOLVERSION PGCHANNELBINDING
unset PGCONNECT_TIMEOUT PGTARGETSESSIONATTRS PGAPPNAME PGCLIENTENCODING
unset PGSSLNEGOTIATION PGREQUIREPEER PGGSSENCMODE PGGSSDELEGATION PGKRBSRVNAME
unset PGREQUIRESSL PGSSLCOMPRESSION PGLOADBALANCEHOSTS
unset PGREQUIREAUTH PGSSLCERTMODE PGSSLCRLDIR PGSSLSNI PGGSSLIB PGMINPROTOCOLVERSION PGMAXPROTOCOLVERSION PGSYSCONFDIR PGLOCALEDIR PGDATESTYLE PGTZ PGGEQO PGOAUTHDEBUG PGOAUTHCAFILE
[[ "$(/usr/bin/git rev-parse HEAD)" == "$VIRKI_STAGING_APPROVED_SOURCE_SHA" ]]
[[ -z "$(/usr/bin/git status --porcelain)" ]]
"$node_bin" scripts/staging-pgpass-bootstrap-binding.mjs --require-runtime-urls
same_ip_address() {
  "$node_bin" -e '
    const { isIP } = require("node:net");
    const [left, right] = process.argv.slice(1);
    const family = isIP(left);
    if (!family || family !== isIP(right)) process.exit(1);
    const canonical = (value) => family === 6
      ? new URL("http://[" + value + "]/").hostname
      : value;
    if (canonical(left) !== canonical(right)) process.exit(1);
  ' "$1" "$2"
}
verify_remote_hba_active() {
  local probe
  if ! probe="$(PGSERVICE=virki-staging-bootstrap psql --no-password \
    --dbname='service=virki-staging-bootstrap dbname=postgres' -XAtq --set=ON_ERROR_STOP=1 \
    --file=scripts/staging-remote-hba-active.sql)"; then
    return 1
  fi
  local hba_database hba_user hba_superuser hba_loaded hba_file_count hba_external_files hba_errors hba_includes hba_server_addr hba_server_port hba_client_addr
  IFS='|' read -r hba_database hba_user hba_superuser hba_loaded hba_file_count hba_external_files hba_errors hba_includes hba_server_addr hba_server_port hba_client_addr <<<"$probe"
  [[ "$hba_database" == "postgres" && "$hba_user" == "$POSTGRES_USER" &&
     "$hba_superuser" == "true" && "$hba_loaded" == "true" &&
     "$hba_file_count" == "1" && "$hba_external_files" == "0" && "$hba_errors" == "0" && "$hba_includes" == "0" && "$hba_server_port" == "$VIRKI_STAGING_APPROVED_DB_PORT" && -n "$hba_client_addr" ]] || return 1
  same_ip_address "$hba_server_addr" "$VIRKI_STAGING_APPROVED_DB_SERVER_ADDR" || return 1
  if [[ -n "${staging_db_client_addr:-}" ]]; then
    same_ip_address "$hba_client_addr" "$staging_db_client_addr" || return 1
  fi
  staging_db_client_addr="$hba_client_addr"
}
verify_remote_hba_active
verify_remote_hba_rules() {
  local result
  if ! result="$(PGSERVICE=virki-staging-bootstrap psql --no-password \
    --dbname='service=virki-staging-bootstrap dbname=postgres' \
    --set=approved_db="$VIRKI_STAGING_APPROVED_DB_NAME" \
    --set=restore_db="$VIRKI_STAGING_RESTORE_DB" \
    --set=bootstrap_user="$POSTGRES_USER" -XAtq --set=ON_ERROR_STOP=1 \
    --file=scripts/staging-remote-hba-rules.sql)"; then
    return 1
  fi
  [[ "$result" == "8|8|0|0|8|true" ]]
}
verify_remote_hba_rules
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
remote_scram_probe() {
  local service="$1" database="$2" expected_user="$3" probe
  if ! probe="$(PGSERVICE="$service" psql --no-password \
    --dbname="service=$service dbname=$database hostaddr=$VIRKI_STAGING_APPROVED_DB_SERVER_ADDR" -XAtqc \
    "select coalesce(host(inet_server_addr()), '') || '|' || coalesce(inet_server_port()::text, '') || '|' || current_database() || '|' || current_user || '|' || session_user || '|' || (select ssl::text from pg_stat_ssl where pid=pg_backend_pid()) || '|' || coalesce(host(inet_client_addr()), '')")"; then
    return 1
  fi
  local probe_server_addr probe_server_port probe_database probe_user probe_session_user probe_ssl probe_client_addr
  IFS='|' read -r probe_server_addr probe_server_port probe_database probe_user probe_session_user probe_ssl probe_client_addr <<<"$probe"
  [[ "$probe_server_port" == "$VIRKI_STAGING_APPROVED_DB_PORT" && "$probe_database" == "$database" && "$probe_user" == "$expected_user" &&
     "$probe_session_user" == "$expected_user" && "$probe_ssl" == "true" &&
     -n "$probe_client_addr" ]] || return 1
  same_ip_address "$probe_server_addr" "$VIRKI_STAGING_APPROVED_DB_SERVER_ADDR" || return 1
  same_ip_address "$probe_client_addr" "$staging_db_client_addr" || return 1

  local negative_dir negative_pass_file
  negative_dir="$(mktemp -d "$service_dir/negative-passfile.XXXXXX")" || return 1
  negative_pass_file="$negative_dir/pgpass"
  (
    trap 'rm -f -- "$negative_pass_file"; rmdir -- "$negative_dir"' EXIT
    chmod 0700 -- "$negative_dir" || exit 1
    [[ "$(stat -c '%u:%a' "$negative_dir")" == "$(id -u):700" ]] || exit 1
    local wrong_password negative_output
    wrong_password="virki-invalid-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')" || exit 1
    [[ "$wrong_password" =~ ^virki-invalid-[a-f0-9]{32}$ ]] || exit 1
    local negative_host
    negative_host="${VIRKI_STAGING_APPROVED_DB_HOST//\\/\\\\}"
    negative_host="${negative_host//:/\\:}"
    printf '%s:%s:%s:%s:%s\n' "$negative_host" "$VIRKI_STAGING_APPROVED_DB_PORT" "$database" "$expected_user" "$wrong_password" > "$negative_pass_file" || exit 1
    chmod 0600 -- "$negative_pass_file" || exit 1
    [[ -f "$negative_pass_file" && ! -L "$negative_pass_file" ]] || exit 1
    [[ "$(stat -c '%u:%a:%h' "$negative_pass_file")" == "$(id -u):600:1" ]] || exit 1
    unset PGPASSWORD
    if negative_output="$(LC_ALL=C PGSERVICE="$service" PGPASSFILE="$negative_pass_file" psql --no-password \
      --dbname="service=$service dbname=$database hostaddr=$VIRKI_STAGING_APPROVED_DB_SERVER_ADDR" -XAtqc 'select 1' 2>&1)"; then
      exit 1
    fi
    [[ "$negative_output" == *"password authentication failed"* ]] || exit 1
  ) || return 1
}
remote_scram_probe virki-staging-migrator "$VIRKI_STAGING_APPROVED_DB_NAME" virki_migrator
remote_scram_probe virki-staging-hub "$VIRKI_STAGING_APPROVED_DB_NAME" virki_runtime
remote_scram_probe virki-staging-worker "$VIRKI_STAGING_APPROVED_DB_NAME" virki_email_worker
if ! migrator_identity="$(PGSERVICE=virki-staging-migrator psql --no-password -XAtqc \
  "select host(inet_server_addr()) || '|' || inet_server_port() || '|' || current_database() || '|' || current_user || '|' || session_user || '|' || (select ssl::text from pg_stat_ssl where pid=pg_backend_pid()) || '|' || floor(extract(epoch from pg_postmaster_start_time()))::bigint::text")"; then
  printf 'BLOCK: pre-rollback migrator connection failed\n' >&2
  exit 1
fi
IFS='|' read -r migrator_addr migrator_port migrator_db migrator_user migrator_session_user migrator_ssl migrator_start <<<"$migrator_identity"
same_ip_address "$migrator_addr" "$VIRKI_STAGING_APPROVED_DB_SERVER_ADDR"
[[ "$migrator_port" == "$VIRKI_STAGING_APPROVED_DB_PORT" ]]
[[ "$migrator_db" == "$VIRKI_STAGING_APPROVED_DB_NAME" ]]
[[ "$migrator_user" == "virki_migrator" && "$migrator_session_user" == "virki_migrator" ]]
[[ "$migrator_ssl" == "true" && -n "$migrator_start" ]]
if ! bootstrap_identity="$(PGSERVICE=virki-staging-bootstrap psql --no-password -XAtqc \
  "select host(inet_server_addr()) || '|' || inet_server_port() || '|' || current_database() || '|' || current_user || '|' || session_user || '|' || (select ssl::text from pg_stat_ssl where pid=pg_backend_pid()) || '|' || floor(extract(epoch from pg_postmaster_start_time()))::bigint::text || '|' || (select rolsuper::text from pg_roles where rolname=current_user)")"; then
  printf 'BLOCK: staging bootstrap connection failed\n' >&2
  exit 1
fi
IFS='|' read -r bootstrap_addr bootstrap_port bootstrap_db bootstrap_user bootstrap_session_user bootstrap_ssl bootstrap_start bootstrap_superuser <<<"$bootstrap_identity"
same_ip_address "$bootstrap_addr" "$VIRKI_STAGING_APPROVED_DB_SERVER_ADDR"
[[ "$bootstrap_port" == "$VIRKI_STAGING_APPROVED_DB_PORT" ]]
[[ "$bootstrap_db" == "postgres" ]]
[[ "$bootstrap_user" == "$POSTGRES_USER" && "$bootstrap_session_user" == "$POSTGRES_USER" ]]
[[ "$bootstrap_ssl" == "true" && "$bootstrap_start" == "$migrator_start" && "$bootstrap_superuser" == "true" ]]
remote_scram_probe virki-staging-bootstrap postgres "$POSTGRES_USER"
verify_remote_hba_rules
verify_remote_hba_active
[[ "$(/usr/bin/git rev-parse HEAD)" == "$VIRKI_STAGING_APPROVED_SOURCE_SHA" ]]
[[ -z "$(/usr/bin/git status --porcelain)" ]]
: "${VIRKI_RUNTIME_DB_PASSWORD:?staging runtime role password required}"
: "${VIRKI_MIGRATOR_DB_PASSWORD:?staging migrator role password required}"
: "${VIRKI_AUDIT_MAINTENANCE_DB_PASSWORD:?staging audit-maintenance password required}"
: "${VIRKI_EMAIL_WORKER_DB_SCRAM_VERIFIER:?staging email-worker SCRAM verifier required}"
[[ "$(id -un)" == "$POSTGRES_USER" ]]
verify_local_peer() {
  local database="$1"
  local identity
  local local_db local_user local_session_user local_port local_start local_superuser local_hba_rule_count local_hba_postgres_rule_count local_hba_restore_rule_count local_hba_errors local_hba_includes local_hba_file local_conf_loaded local_hba_files local_hba_external_rules
  identity="$(
    unset PGHOSTADDR PGHOST PGPORT PGSERVICE PGSERVICEFILE PGOPTIONS PGUSER PGDATABASE
    unset PGSSLMODE PGSSLCERT PGSSLKEY PGSSLROOTCERT PGSSLCRL
    unset PGSSLMINPROTOCOLVERSION PGSSLMAXPROTOCOLVERSION PGCHANNELBINDING
    unset PGCONNECT_TIMEOUT PGTARGETSESSIONATTRS PGAPPNAME PGCLIENTENCODING
    unset PGSSLNEGOTIATION PGREQUIREPEER PGGSSENCMODE PGGSSDELEGATION PGKRBSRVNAME
    unset PGREQUIRESSL PGSSLCOMPRESSION PGLOADBALANCEHOSTS
    unset PGREQUIREAUTH PGSSLCERTMODE PGSSLCRLDIR PGSSLSNI PGGSSLIB PGMINPROTOCOLVERSION PGMAXPROTOCOLVERSION PGSYSCONFDIR PGLOCALEDIR PGDATESTYLE PGTZ PGGEQO PGOAUTHDEBUG PGOAUTHCAFILE
    PGPASSWORD= PGPASSFILE=/dev/null psql --no-psqlrc --no-password \
      --host=/var/run/postgresql --port=5432 --username "$POSTGRES_USER" \
      --dbname "$database" --set=restore_db="$VIRKI_STAGING_RESTORE_DB" \
      -XAtq --set=ON_ERROR_STOP=1 --file=scripts/staging-local-hba-peer.sql
  )"
  IFS='|' read -r local_db local_user local_session_user local_port local_start local_superuser local_hba_rule_count local_hba_postgres_rule_count local_hba_restore_rule_count local_hba_errors local_hba_includes local_hba_file local_conf_loaded local_hba_files local_hba_external_rules <<<"$identity"
  [[ "$local_db" == "$database" ]]
  [[ "$local_user" == "$POSTGRES_USER" && "$local_session_user" == "$POSTGRES_USER" ]]
  [[ "$local_port" == "5432" && "$local_start" == "$bootstrap_start" ]]
  [[ "$local_superuser" == "true" && "$local_hba_rule_count" == "2" ]]
  [[ "$local_hba_postgres_rule_count" == "1" && "$local_hba_restore_rule_count" == "1" ]]
  [[ "$local_hba_errors" == "0" && "$local_hba_includes" == "0" && "$local_conf_loaded" == "true" ]]
  [[ "$local_hba_files" == "1" && "$local_hba_external_rules" == "0" && "$local_hba_file" == /* ]]
  [[ "$(realpath -e "$local_hba_file")" == "$local_hba_file" ]]
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
remote_scram_probe virki-staging-bootstrap "$VIRKI_STAGING_RESTORE_DB" "$POSTGRES_USER"
pg_restore --no-password --exit-on-error --single-transaction --no-owner --no-acl \
  --dbname="service=virki-staging-bootstrap dbname=$VIRKI_STAGING_RESTORE_DB" \
  "$VIRKI_STAGING_BASELINE_DUMP"
restored_identity="$(PGSERVICE=virki-staging-bootstrap psql \
  --dbname="service=virki-staging-bootstrap dbname=$VIRKI_STAGING_RESTORE_DB" -XAtqc \
  "select host(inet_server_addr()) || '|' || inet_server_port() || '|' || current_database() || '|' || current_user || '|' || session_user || '|' || (select ssl::text from pg_stat_ssl where pid=pg_backend_pid()) || '|' || floor(extract(epoch from pg_postmaster_start_time()))::bigint::text")"
IFS='|' read -r restored_addr restored_port restored_db restored_user restored_session_user restored_ssl restored_start <<<"$restored_identity"
same_ip_address "$restored_addr" "$VIRKI_STAGING_APPROVED_DB_SERVER_ADDR"
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
export PGPASSFILE=/dev/null
unset PGREQUIREAUTH PGSSLCERTMODE PGSSLCRLDIR PGSSLSNI PGGSSLIB PGMINPROTOCOLVERSION PGMAXPROTOCOLVERSION PGSYSCONFDIR PGLOCALEDIR PGDATESTYLE PGTZ PGGEQO PGOAUTHDEBUG PGOAUTHCAFILE
export PGHOST=/var/run/postgresql
export PGPORT=5432
verify_local_peer "$POSTGRES_DB"
export VIRKI_LOCAL_MIGRATOR_CREATEDB=false
sh infra/postgres-init/10-virki-database-roles.sh
psql --no-psqlrc --no-password --host=/var/run/postgresql --port=5432 \
  --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  --set ON_ERROR_STOP=1 \
  --command "ALTER DATABASE \"$VIRKI_STAGING_RESTORE_DB\" OWNER TO virki_migrator"
# PostgreSQL -c sends SQL directly; it does NOT interpolate psql -v variables.
# VIRKI_STAGING_RESTORE_DB was strictly validated above before quoted expansion.
restored_owner="$(psql --no-psqlrc --no-password --host=/var/run/postgresql \
  --port=5432 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" -XAtqc \
  "select pg_get_userbyid(datdba) from pg_database where datname=current_database()")"
[[ "$restored_owner" == "virki_migrator" ]]
if ! psql --no-psqlrc --no-password --host=/var/run/postgresql --port=5432 \
  --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" -XAtq -v ON_ERROR_STOP=1 \
  --command "select encode(convert_to(migration_name, 'UTF8'), 'hex') || chr(9) || encode(convert_to(checksum, 'UTF8'), 'hex') || chr(9) || (finished_at is not null)::text || chr(9) || (rolled_back_at is not null)::text from public.\"_prisma_migrations\" order by migration_name collate \"C\"" \
  | "$node_bin" scripts/staging-prisma-migration-ledger-binding.mjs --hex-fields; then
  printf 'BLOCK: restored Prisma migration ledger does not exactly match the committed migration set and checksums\n' >&2
  exit 1
fi
verify_local_peer "$POSTGRES_DB"
sh infra/postgres-init/11-virki-email-worker-role.sh
unset PGHOSTADDR PGHOST PGPORT PGUSER PGDATABASE PGSERVICE PGOPTIONS PGSSLMODE
unset PGSSLCERT PGSSLKEY PGSSLROOTCERT PGSSLCRL
unset PGREQUIREAUTH PGSSLCERTMODE PGSSLCRLDIR PGSSLSNI PGGSSLIB PGMINPROTOCOLVERSION PGMAXPROTOCOLVERSION PGSYSCONFDIR PGLOCALEDIR PGDATESTYLE PGTZ PGGEQO PGOAUTHDEBUG PGOAUTHCAFILE
export PGSERVICEFILE="$service_file"
export PGPASSFILE="$pass_file"
remote_scram_probe virki-staging-migrator "$VIRKI_STAGING_APPROVED_DB_NAME" virki_migrator
remote_scram_probe virki-staging-hub "$VIRKI_STAGING_APPROVED_DB_NAME" virki_runtime
remote_scram_probe virki-staging-worker "$VIRKI_STAGING_APPROVED_DB_NAME" virki_email_worker
remote_scram_probe virki-staging-migrator "$VIRKI_STAGING_RESTORE_DB" virki_migrator
remote_scram_probe virki-staging-hub "$VIRKI_STAGING_RESTORE_DB" virki_runtime
remote_scram_probe virki-staging-worker "$VIRKI_STAGING_RESTORE_DB" virki_email_worker
verify_remote_hba_rules
verify_remote_hba_active
worker_restore_identity="$(PGSERVICE=virki-staging-worker psql \
  --dbname="service=virki-staging-worker dbname=$VIRKI_STAGING_RESTORE_DB" -XAtqc \
  "select host(inet_server_addr()) || '|' || inet_server_port() || '|' || current_database() || '|' || current_user || '|' || session_user || '|' || (select ssl::text from pg_stat_ssl where pid=pg_backend_pid()) || '|' || floor(extract(epoch from pg_postmaster_start_time()))::bigint::text || '|' || (select rolcanlogin::text || ',' || rolsuper::text || ',' || rolcreatedb::text || ',' || rolcreaterole::text || ',' || rolreplication::text || ',' || rolbypassrls::text || ',' || rolinherit::text from pg_roles where rolname=current_user) || '|' || has_table_privilege(current_user, 'public.\"EmailOutboxMessage\"', 'SELECT')::text || '|' || has_table_privilege(current_user, 'public.\"EmailDeliveryAttempt\"', 'SELECT')::text || '|' || has_table_privilege(current_user, 'public.\"EmailDeliveryAttempt\"', 'INSERT')::text || '|' || has_table_privilege(current_user, 'public.\"EmailOutboxMessage\"', 'INSERT')::text || '|' || has_table_privilege(current_user, 'public.\"EmailOutboxMessage\"', 'DELETE')::text || '|' || has_table_privilege(current_user, 'public.\"EmailDeliveryAttempt\"', 'UPDATE')::text || '|' || has_table_privilege(current_user, 'public.\"EmailDeliveryAttempt\"', 'DELETE')::text || '|' || has_column_privilege(current_user, 'public.\"EmailOutboxMessage\"', 'recipientEmail', 'UPDATE')::text || '|' || has_column_privilege(current_user, 'public.\"EmailOutboxMessage\"', 'payload', 'UPDATE')::text || '|' || has_table_privilege(current_user, 'public.\"User\"', 'SELECT')::text || '|' || has_table_privilege(current_user, 'public.\"Session\"', 'SELECT')::text || '|' || has_table_privilege(current_user, 'public.\"AuditLog\"', 'SELECT')::text || '|' || has_database_privilege(current_user, current_database(), 'CREATE')::text || '|' || has_database_privilege(current_user, current_database(), 'TEMPORARY')::text || '|' || has_schema_privilege(current_user, 'public', 'CREATE')::text")"
IFS='|' read -r worker_restore_addr worker_restore_port worker_restore_db worker_restore_user worker_restore_session worker_restore_ssl worker_restore_start worker_role_flags worker_outbox_select worker_attempt_select worker_attempt_insert worker_outbox_insert worker_outbox_delete worker_attempt_update worker_attempt_delete worker_recipient_update worker_payload_update worker_user_select worker_session_select worker_audit_select worker_db_create worker_db_temp worker_schema_create <<<"$worker_restore_identity"
same_ip_address "$worker_restore_addr" "$VIRKI_STAGING_APPROVED_DB_SERVER_ADDR"
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
   Before any remote identity is accepted, `remote_scram_probe` requires every
   potentially matching non-local network HBA rule for that database and role
   (including `host`, `hostssl`, `hostnossl`, `hostgssenc` and `hostnogssenc`)
   to be an exact database/user `hostssl` rule using `scram-sha-256` with no options;
   any non-local `replication` database rule is rejected because this staging
   workflow has no replication requirement. Exactly eight non-local rules
   must exist, and all eight must be the exact allowlisted SCRAM entries; this
   rejects unrelated-database/user rules as well as generic fallbacks. The HBA
   rules, replication-rule count and loaded-file mtime are checked in one
   materialized SQL statement; the same gate is repeated after connection
   probes to catch a changed file. Exactly one such rule must match the observed
   client address, and its source must be that exact IP (`/32` IPv4 or `/128` IPv6), never a broad
   CIDR or hostname. Generic
   `all`/group rules, `host` rules, `trust`, `cert`, MD5, map/client-certificate
   options and ambiguous source matches fail closed. Any `include`,
   `include_if_exists` or `include_dir` directive in the canonical HBA file is
   rejected, including an empty optional include. The probe covers the
   migrator, runtime, worker and bootstrap identities on their approved DB and
   the relevant restore DB, proving that successful remote connections really
   use the protected PGPASSFILE credential rather than merely having TLS.
   Scripts 10 and 11 explicitly set `PGPASSFILE=/dev/null` after clearing
   ambient libpq settings, preventing libpq from falling back to the operator's
   implicit `~/.pgpass`. The rollback clears `PGPASSWORD`/`PGPASSFILE` before
   script 10, and script 11 independently pins the same null passfile; both
   therefore require an actual local `peer`
   HBA rules for `postgres` and the restore database and bootstrap role,
   with the invoking OS username exactly equal to `POSTGRES_USER`; the
   no-password local connection, exactly two local HBA rules in the canonical
   main HBA file (included HBA files are rejected), one exact direct `peer`
   match for each database and the bootstrap role, and no rule options are
   checked before either script runs. The parse-error count and proof that the
   canonical HBA file was loaded after its modification time are also checked.
   Do not fall back to `trust`, an
   interactive password prompt or an ambient pass file. `POSTGRES_PASSWORD`
   must be the same staging bootstrap credential used by the exact
   `virki-staging-bootstrap` PGPASSFILE entries for both its default `postgres`
   database and the explicit fresh restore-database override. The same
   `staging-pgpass-bootstrap-binding.mjs` verifies the worker service target
   and exactly one matching PGPASSFILE entry for both its approved DB and the
   restore-database override against `VIRKI_EMAIL_WORKER_DB_PASSWORD`; it also
   verifies the Hub runtime and migrator service targets and their exact
   credentials for both databases. It rejects wildcard match fields but
   permits a literal `*` in a password field; no credential is printed. The bootstrap value is required
   by the scripts for credential-distinctness checks but is not the local-socket
   authentication mechanism. A custom `pg_dump` does not
   recreate cluster roles or per-database grants/default privileges. Therefore
   run the exact committed `infra/postgres-init/10-virki-database-roles.sh`
   against the restored DB to reapply runtime/migrator/audit-maintenance roles
   and grants, then run `infra/postgres-init/11-virki-email-worker-role.sh`
   locally after the restored mail tables exist; the latter pins the local
   Unix socket and provisions the isolated worker role. On a fresh empty
   database, run script 10 before migrations and script 11 only after the
   mail-table migrations. The operator-only migration-ledger helper compares
   every restored `_prisma_migrations` name and SHA-256 checksum against the
   exact approved Git tree (not the mutable filesystem directory), rejecting
   untracked/ignored migration entries and dirty migration SQL, and requiring each row finished,
   unrolled-back, unique and with no extra/missing migrations; a zero
   unfinished-row count alone is not acceptance. Verify the migration ledger,
   DB identity, worker
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
