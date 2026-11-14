import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { fileURLToPath } from "node:url";

const read = (relative) =>
  readFileSync(fileURLToPath(new URL("../" + relative, import.meta.url)), "utf8").replaceAll("\r\n", "\n");
const override = read("infra/docker-compose.staging-email-worker.yml");
const role = read("infra/postgres-init/11-virki-email-worker-role.sh");
const prod = read("infra/docker-compose.prod.yml");
const dev = read("infra/docker-compose.yml");
const stage = read("scripts/production-server.sh");
const proof = read("scripts/staging-email-worker-role.disposable.mjs");
const docs = read("docs/security/staging-email-worker-role-20261112.md");
const worker = read("packages/auth/src/email-worker.ts");
const guard = read("packages/auth/src/email-worker-role.ts");

test("staging override requires worker-only URL and never defaults to Hub runtime", () => {
  assert.match(override, /services:\n\x20{2}email-worker:\n(?:\x20{4}#.*\n)*\x20{4}profiles: \["staging-email-worker-manual"\]\n(?:\x20{4}#.*\n)*\x20{4}restart: "no"\n\x20{4}environment:\n/u,
    "manual staging worker must require an explicit profile and disable inherited production auto-restart");
  assert.ok(override.includes("DATABASE_URL: $" + "{VIRKI_STAGING_EMAIL_WORKER_DATABASE_URL:?"));
  assert.ok(override.includes("VIRKI_EMAIL_WORKER_SCOPED_ROLE: required"));
  assert.equal(override.split("\n      DATABASE_URL:").length - 1, 1);
  assert.equal(override.includes("$" + "{DATABASE_URL"), false);
  assert.equal(override.includes("VIRKI_RUNTIME_DB_PASSWORD"), false);
  assert.ok(prod.includes("email-worker:"));
  assert.match(prod, /\x20{2}email-worker:\n(?:\x20{4}[^\n]*\n)*\x20{4}restart: unless-stopped\n/u,
    "production worker intentionally has a restart policy; staging must override it");
  assert.ok(prod.includes("DATABASE_URL: $" + "{DATABASE_URL:?"));
  assert.equal((prod + dev + stage).includes("docker-compose.staging-email-worker.yml"), false,
    "normal production commands must not load an unapproved staging override");
  assert.ok(stage.includes("readonly staging_application_services=(public-site hub oidc-issuer session-cleanup)"));
});

test("postmigration SQL is atomic and limits worker to mail data instead of identity", () => {
  assert.ok(role.includes("requires the committed, migrated Virki schema"));
  assert.ok(role.includes("BEGIN;"));
  assert.ok(role.includes("COMMIT;"));
  assert.ok(role.includes("NOINHERIT PASSWORD :'worker_verifier'"));
  assert.equal(role.includes("PASSWORD :'worker_password'"), false,
    "raw password must not enter ALTER ROLE or server DDL logs");
  assert.ok(role.includes("VIRKI_EMAIL_WORKER_DB_SCRAM_VERIFIER"));
  assert.ok(guard.includes("has_column_privilege"));
  assert.ok(guard.includes("has_function_privilege"));
  assert.ok(worker.includes("if (checkScopedRole) await assertScopedEmailWorkerRole()"));
  assert.ok(worker.includes("processNext: async () =>"),
    "worker must verify effective grants repeatedly, not only on startup");
  assert.ok(role.includes("REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM virki_email_worker"));
  assert.ok(role.includes('GRANT SELECT ON TABLE public."EmailOutboxMessage" TO virki_email_worker'));
  assert.ok(role.includes('GRANT UPDATE ("status", "attemptCount", "availableAt"'));
  assert.ok(role.includes('GRANT SELECT ON TABLE public."EmailDeliveryAttempt" TO virki_email_worker'));
  assert.ok(role.includes('GRANT INSERT ("id", "messageId", "attempt", "status"'));
  assert.ok(role.includes("Staging database exposes excess worker privileges"));
  assert.ok(role.includes("psql --no-psqlrc --no-password --host=/var/run/postgresql --port=5432"),
    "privileged role provisioning must use the approved container's local Unix socket");
  assert.ok(role.includes("unset PGHOSTADDR PGHOST PGPORT PGSERVICE"));
  assert.ok(role.includes("inet_server_addr() IS NOT NULL"));
  assert.ok(role.includes("pg_attribute"),
    "role reconciliation must also examine column grants inherited from PUBLIC");
  assert.ok(role.includes("has_schema_privilege('virki_email_worker', namespace.oid, 'USAGE')"),
    "protected staging schemas must not be reachable by inherited PUBLIC USAGE");
  assert.ok(role.includes("has_function_privilege('virki_email_worker', routine.oid, 'EXECUTE')"),
    "PUBLIC must not grant worker an audit-deleting SECURITY DEFINER capability");
  assert.ok(role.includes("aclexplode(COALESCE(relation.relacl,"));
  assert.ok(role.includes("aclexplode(attribute.attacl)"));
  assert.ok(guard.includes("aclexplode(COALESCE(c.relacl,"));
  assert.ok(guard.includes("aclexplode(a.attacl)"));
  assert.ok(role.includes("has_table_privilege('virki_email_worker', relation.oid, 'MAINTAIN')"));
  assert.ok(guard.includes("has_table_privilege(current_user,c.oid,'MAINTAIN')"));
  assert.equal((prod + dev).includes("11-virki-email-worker-role.sh"), false,
    "the postmigration helper must never be mounted into Docker initdb");
});

test("disposable SQL proof is opt-in, network-none and cleans verified owned Docker identity", () => {
  assert.ok(proof.includes('VIRKI_STAGING_WORKER_ROLE_PROOF !== "local-disposable-only"'));
  assert.ok(proof.includes("dockerDesktopLinuxEngine"));
  assert.ok(proof.includes('"--network", "none"'));
  assert.ok(proof.includes("virki.worker-role-test.owner"));
  assert.ok(proof.includes("refuse to operate on any container whose ID, image, label or isolation differs"));
  assert.ok(proof.includes("LOCAL_DISPOSABLE_WORKER_ROLE_CLEANUP=PASS"));
  assert.ok(proof.includes('record("CREATE_PENDING")'),
    "record owner intent before an ambiguous Docker create");
  assert.ok(proof.includes("reconcileUnacknowledgedCreate"),
    "resolve only exact UUID-owned resources after ambiguous create");
  assert.ok(proof.includes("requireExactDockerAbsence"),
    "a nonzero inspect by itself must not prove Docker cleanup");
  assert.ok(proof.includes("simulate-post-remove-inspect-error"),
    "prove a daemon inspection error cannot report cleanup PASS");
  assert.equal(proof.includes("assert.notEqual(missing.status, 0"), false,
    "ambiguous Docker inspection failure must never be accepted as resource absence");
  assert.ok(docs.includes("STAGING DELIVERY NO-GO"));
  assert.ok(docs.includes("Brevo provider receipt"));
});
