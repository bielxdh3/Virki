# PR #118 — segregated staging operator runbook

> **PREPARED, NOT EXECUTED.** These commands are for a separately authorized
> staging operator after exact-SHA SOURCE GO and hosted checks. They do not
> provision a host, authorize SMTP, change Cloudflare, deploy, or approve
> production. Never point them at production or deManage.

## 1. Preconditions and secret handling

The seven-commit local **runtime-code** candidate is
`6feb2da5ab9bd25ce1cc2f53c6a7c4fc4807bd1c`, based on published
`678d81af31fb6aa5f1ab4effcdee823a030c38ce`. This runbook and the updated
execution ledger are documentation-only descendants; no runtime source
changed after that code candidate. The local branch is unpublished and has no
hosted checks. Any staging image must use the exact final branch SHA after
these documentation commits, not an earlier SHA. Do not build or attest a
release image until the independent SOURCE GO, publication authorization and
exact-SHA CI/CodeQL gates have completed.

The operator must have an out-of-band approved staging context and Docker
daemon ID, project name, external network ID, DB host/name/roles, immutable
OCI digest, relay tenant, recipient policy, provider rate/message caps, test
inboxes, maintenance window and named rollback owner. Compare these with the
operator's production inventory; a different string alone does not prove
physical isolation.

Inject the following required Compose variables from the approved staging
secret manager, never from the production `.env` or a committed file:

- `VIRKI_STAGING_COMPOSE_PROJECT`
- `VIRKI_STAGING_EMAIL_WORKER_NETWORK`
- `VIRKI_STAGING_EMAIL_WORKER_IMAGE` (exact repository plus
  `@sha256:<64 lowercase hex>`, already present on the host; no pull)
- `VIRKI_STAGING_EMAIL_WORKER_DATABASE_URL` (dedicated
  `virki_email_worker` login on the isolated staging database)
- `VIRKI_STAGING_EMAIL_OUTBOX_KEY` (the same staging-only key used by the
  staging Hub, distinct from production)
- `VIRKI_STAGING_EMAIL_SMTP_HOST`, `VIRKI_STAGING_EMAIL_SMTP_PORT`,
  `VIRKI_STAGING_EMAIL_SMTP_SECURE`, `VIRKI_STAGING_EMAIL_SMTP_USER`,
  `VIRKI_STAGING_EMAIL_SMTP_PASSWORD`
- `VIRKI_STAGING_EMAIL_FROM`,
  `VIRKI_STAGING_EMAIL_MIN_SEND_INTERVAL_MS`
- Optional `VIRKI_STAGING_EMAIL_REPLY_TO`.

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

```sh
set -euo pipefail
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
: "${VIRKI_STAGING_EMAIL_WORKER_IMAGE:?immutable staging image required}"
: "${VIRKI_STAGING_APPROVED_IMAGE:?owner-approved exact image ref required}"
command -v jq >/dev/null

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

[[ "$project" == "$VIRKI_STAGING_APPROVED_PROJECT" ]]
[[ "$project" != "virki-prod" && "$project" != demanage* ]]
[[ "$image" == "$VIRKI_STAGING_APPROVED_IMAGE" ]]
[[ "$image" =~ @sha256:[a-f0-9]{64}$ ]]

host_id="$(docker --context "$ctx" info --format '{{.ID}}|{{.OSType}}|{{.Architecture}}')"
[[ "$host_id" == "$VIRKI_STAGING_EXPECTED_DOCKER_ID|linux|amd64" ]]

image_id="$(docker --context "$ctx" image inspect "$image" --format '{{.Id}}')"
repo_digests="$(docker --context "$ctx" image inspect "$image" --format '{{join .RepoDigests "\n"}}')"
grep -Fqx "$image" <<<"$repo_digests"
[[ "$image_id" == sha256:* ]]

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
config="$(docker --context "$ctx" compose --project-name "$project" \
  --profile "$profile" -f "$file" config --format json)"
printf '%s' "$config" | jq -e --arg project "$project" --arg image "$image" --arg network "$network" '
  .services["email-worker"] as $w
  | .name == $project
    and (.services | keys == ["email-worker"])
    and $w.image == $image
    and $w.restart == "no"
    and $w.pull_policy == "never"
    and $w.profiles == ["staging-email-worker-manual"]
    and $w.user == "node:node"
    and $w.read_only == true
    and (($w.cap_drop // []) | index("ALL") != null)
    and (($w.security_opt // []) | index("no-new-privileges:true") != null)
    and (($w.ports // []) | length == 0)
    and (($w.volumes // []) | length == 0)
    and (($w.depends_on // {}) | length == 0)
    and (($w.env_file // []) | length == 0)
    and (($w.build // null) == null)
    and (($w.privileged // false) == false)
    and (($w.devices // []) | length == 0)
    and (($w.network_mode // null) == null)
    and (($w.pid // null) == null)
    and (($w.ipc // null) == null)
    and (($w.container_name // null) == null)
    and (($w.healthcheck // null) == null)
    and (($w.mem_limit // null) == null)
    and (($w.cpus // null) == null)
    and (($w.pids_limit // null) == null)
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
    and (["DATABASE_URL","VIRKI_EMAIL_OUTBOX_KEY","VIRKI_EMAIL_SMTP_HOST",
      "VIRKI_EMAIL_SMTP_PORT","VIRKI_EMAIL_SMTP_SECURE","VIRKI_EMAIL_SMTP_USER",
      "VIRKI_EMAIL_SMTP_PASSWORD","VIRKI_EMAIL_FROM","VIRKI_EMAIL_MIN_SEND_INTERVAL_MS"]
      | all(.[]; $w.environment[.] != null and $w.environment[.] != ""))
' >/dev/null
unset config

# First activation must not silently adopt/reconcile an existing worker.
existing="$(docker --context "$ctx" ps -aq \
  --filter "label=com.docker.compose.project=$project" \
  --filter "label=com.docker.compose.service=email-worker")"
[[ -z "$existing" ]]
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
export PGSERVICEFILE=/run/virki-staging/pg_service.conf
export PGPASSFILE=/run/virki-staging/pgpass
test "$(stat -c '%a' "$(dirname "$PGSERVICEFILE")")" = "700"
test "$(stat -c '%a' "$PGSERVICEFILE")" = "600"
test "$(stat -c '%a' "$PGPASSFILE")" = "600"
PGSERVICE=virki-staging-worker psql -XAtqc \
  "select current_database() || '|' || current_user || '|' || session_user"
PGSERVICE=virki-staging-worker psql -XAtqc \
  'select kind,status,count(*) from public."EmailOutboxMessage" group by kind,status order by kind,status'
PGSERVICE=virki-staging-worker psql -XAtqc \
  'select status,count(*) from public."EmailDeliveryAttempt" group by status order by status'
```

The first query must identify the approved staging DB and both user fields
must be `virki_email_worker`. Before the first send, all outbox-state counts
and delivery-attempt counts must be zero. Independently verify the migrator,
runtime, Hub and worker roles are distinct and no production credential is
present. The worker's `VIRKI_EMAIL_WORKER_SCOPED_ROLE=required` gate checks
the exact DB identity and privilege matrix at startup and before every
outbox iteration; it does not eliminate a concurrent DBA grant race.

## 3. Explicit attended worker window

**Do not run this command until** Gate 0/1/2, independent owner/observer
signatures, provider-enforced allowlist and rejection of an unlisted
recipient, TLS/AUTH, rate cap, total-message cap, empty queue, test inbox
ownership and a fresh stopped-worker observation have all passed. The
separate Hub must use the same staging outbox key and its own staging DB URL.

```sh
docker --context "$ctx" compose --project-name "$project" \
  --profile "$profile" -f "$file" \
  up --no-deps --pull never --detach email-worker

worker_id="$(docker --context "$ctx" compose --project-name "$project" \
  --profile "$profile" -f "$file" ps -q email-worker)"
test -n "$worker_id"
docker --context "$ctx" inspect "$worker_id" \
  --format '{{.State.Status}}|{{.State.ExitCode}}|{{.HostConfig.RestartPolicy.Name}}|{{.RestartCount}}|{{.Image}}|{{.HostConfig.Memory}}|{{.HostConfig.NanoCpus}}|{{.HostConfig.PidsLimit}}|{{.HostConfig.CgroupParent}}'
docker --context "$ctx" inspect "$worker_id" \
  --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}NO_HEALTHCHECK{{end}}'
```

The only acceptable runtime policy is `restart=no`; verify it on the actual
container, not just YAML. The standalone worker has **no Docker HEALTHCHECK**
and declares no Compose CPU, memory or PID limits. The signed resource policy
must prove effective Docker/cgroup limits on the actual container or host; the
fields above must match that policy. If the limits are unbounded or the policy
cannot be independently observed, stop. Do not call a running container
healthy: observe process state, scoped DB identity/privileges, bounded
outbox/attempt transitions and sanitized worker logs. The worker must remain
on the approved network with no published ports, mounts or volume dependencies.
Record only opaque audit/provider receipt IDs and aggregate counts.

After the single approved OTP window, stop the worker:

```sh
docker --context "$ctx" compose --project-name "$project" \
  --profile "$profile" -f "$file" stop --timeout 60 email-worker
worker_id="$(docker --context "$ctx" compose --project-name "$project" \
  --profile "$profile" -f "$file" ps -aq email-worker)"
test -n "$worker_id"
docker --context "$ctx" inspect "$worker_id" \
  --format '{{.State.Status}}|{{.HostConfig.RestartPolicy.Name}}|{{.RestartCount}}'
```

Require `exited|no|<unchanged restart count>`, zero running replicas and
autostart disabled. Reconcile every queued, processing, sent, retryable,
terminal and uncertain message/attempt. Never resend an ambiguous SMTP
attempt based only on a missing `250`, a reserved Message-ID or a stale lease.
The provider acceptance ID and authorized inbox confirmation must be joined
to the Virki-generated message independently; otherwise record
`OTP_CORRELATION_UNPROVEN` and stop.

## 4. Physical rollback — staging only

1. Stop the worker first and verify the actual container is `exited` with
   restart policy `no`. If it will not stop gracefully, do not delete it or
   force a restart while SMTP outcome is uncertain. Freeze staging Hub/API
   writes using the separately approved staging application Compose project.
2. Revoke/rotate the staging SMTP credential at the provider if there is any
   unexpected recipient, unbounded send, host mismatch or uncertain exposure.
   This is a provider-console action for the authorized operator.
3. Reconcile the complete outbox and delivery-attempt ledger, including leases
   and Message-IDs. Preserve uncertain items as quarantined evidence; do not
   retry them automatically.
4. Restore the approved baseline snapshot into a **new staging database**,
   never in-place and never into production. Use protected service/pass files:

```sh
umask 077
: "${VIRKI_STAGING_EVIDENCE_DIR:?private evidence directory required}"
: "${VIRKI_STAGING_RESTORE_DB:?fresh approved staging restore DB name required}"
: "${VIRKI_STAGING_BASELINE_DUMP:?owner-approved baseline dump path required}"
: "${VIRKI_STAGING_BASELINE_DUMP_SHA256:?signed baseline dump digest required}"
install -d -m 0700 "$VIRKI_STAGING_EVIDENCE_DIR"
chmod 0700 "$VIRKI_STAGING_EVIDENCE_DIR"
test -d "$VIRKI_STAGING_EVIDENCE_DIR"
test ! -L "$VIRKI_STAGING_EVIDENCE_DIR"
test "$(stat -c '%a' "$VIRKI_STAGING_EVIDENCE_DIR")" = "700"
[[ "$VIRKI_STAGING_RESTORE_DB" =~ ^virki_stage_restore_[a-f0-9]{8,16}$ ]]
test -f "$VIRKI_STAGING_BASELINE_DUMP"
test ! -L "$VIRKI_STAGING_BASELINE_DUMP"
baseline_sha="$(sha256sum "$VIRKI_STAGING_BASELINE_DUMP" | cut -d' ' -f1)"
[[ "$baseline_sha" == "$VIRKI_STAGING_BASELINE_DUMP_SHA256" ]]
test ! -e "$VIRKI_STAGING_EVIDENCE_DIR/pre-rollback.dump"
pg_dump --format=custom --no-owner --no-acl \
  --file="$VIRKI_STAGING_EVIDENCE_DIR/pre-rollback.dump" \
  --dbname='service=virki-staging-migrator'
sha256sum "$VIRKI_STAGING_EVIDENCE_DIR/pre-rollback.dump"

# RESTORE_DB must be a fresh, uniquely named staging DB approved by the owner.
createdb --maintenance-db='service=virki-staging-maintenance' \
  --owner=virki_migrator "$VIRKI_STAGING_RESTORE_DB"
pg_restore --exit-on-error --no-owner --no-acl \
  --dbname='service=virki-staging-restore' \
  "$VIRKI_STAGING_BASELINE_DUMP"
```

   The `virki-staging-restore` service entry must point to that new DB.
   It must authenticate as `virki_migrator`. The maintenance service must use
   a separately authorized **staging-only** DBA/bootstrap identity with
   `CREATEDB`, never the worker/runtime role or a production identity.
   Provision cluster roles with
   `10-virki-database-roles.sh` before migrations on a fresh provision, then
   apply `11-virki-email-worker-role.sh` locally on the staging DB host after
   migrations/restore (it pins a local Unix socket); a custom
   `pg_dump` does not recreate cluster roles. Verify the migration ledger,
   DB identity, worker privilege gate and redacted before/after counts before
   repointing any staging application. Keep the previous DB read-only until
   owner and independent reviewer accept the restore.
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
