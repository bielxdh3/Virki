// Explicit opt-in LOCAL role-grant proof. This NEVER reaches an external host,
// the Virki VM, production PostgreSQL, SMTP, SSH, or an integration env file.
// It uses one new, UUID-owned network:none PostgreSQL with tmpfs PGDATA.
import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";

if (process.env.VIRKI_STAGING_WORKER_ROLE_PROOF !== "local-disposable-only" ||
    process.platform !== "win32") {
  throw new Error("Worker role proof requires explicit local Windows disposable-only opt-in.");
}

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const setup = path.join(root, "infra", "postgres-init", "11-virki-email-worker-role.sh");
const setupInContainer = "/11-virki-email-worker-role.sh";
const docker = "C:\\Program Files\\Docker\\Docker\\resources\\bin\\docker.exe";
const engine = "npipe:////./pipe/dockerDesktopLinuxEngine";
const pgImage = "postgres:18.6-alpine3.24";
const expectedImageId = "sha256:57b23a0326ee442e83b3d3fa027c5a148be0a392d7c91d1ca4e1e70131ee859a";
const database = "virki_worker_role_test";
const owner = randomUUID().replaceAll("-", "");
const name = `virki-worker-role-local-${owner}`;
const secrets = {
  POSTGRES_PASSWORD: randomBytes(32).toString("hex"),
  VIRKI_RUNTIME_DB_PASSWORD: randomBytes(32).toString("hex"),
  VIRKI_MIGRATOR_DB_PASSWORD: randomBytes(32).toString("hex"),
  VIRKI_AUDIT_MAINTENANCE_DB_PASSWORD: randomBytes(32).toString("hex"),
  VIRKI_EMAIL_WORKER_DB_PASSWORD: randomBytes(32).toString("hex")
};
const processEnv = { ...process.env, ...secrets, DOCKER_HOST: engine };
let containerId = null;

if (!existsSync(docker) || !existsSync(setup)) throw new Error("Pinned Docker CLI or reviewed role source absent.");

function invoke(args, { allowFailure = false, input, env = processEnv, timeout = 20_000 } = {}) {
  const call = spawnSync(docker, ["--host", engine, ...args], {
    encoding: "utf8", windowsHide: true, timeout, input, env, maxBuffer: 2 * 1024 * 1024
  });
  const redact = (text) => Object.values(secrets).reduce(
    (out, secret) => out.replaceAll(secret, "[synthetic-redacted]"), String(text ?? "")
  ).slice(-1000);
  if (call.error) throw new Error(`Isolated Docker call failed: ${call.error.code ?? "unknown"}`);
  if (call.status !== 0 && !allowFailure) {
    throw new Error(`Isolated Docker ${args[0]} failed (exit ${call.status}): ${redact(call.stderr)}`);
  }
  return { status: call.status, stdout: redact(call.stdout).trim(), stderr: redact(call.stderr).trim() };
}

function inspectOwned() {
  assert.ok(containerId && /^([a-f0-9]{64})$/u.test(containerId), "exact owned container ID required");
  const actual = invoke(["inspect", containerId, "--format",
    '{{.Id}}|{{.Name}}|{{index .Config.Labels "virki.worker-role-test.owner"}}|{{.HostConfig.NetworkMode}}|{{.Image}}']).stdout;
  assert.equal(actual, `${containerId}|/${name}|${owner}|none|${expectedImageId}`,
    "refuse to operate on any container whose ID, image, label or isolation differs");
}

function psql(sql, options = {}) {
  inspectOwned();
  return invoke(["exec", "--interactive", containerId, "psql", "--no-psqlrc",
    "--username", "virki_bootstrap", "--dbname", database, "--set", "ON_ERROR_STOP=1",
    "--quiet", "--tuples-only", "--no-align"], { ...options, input: sql });
}

function assertDenied(statement, message) {
  const outcome = psql(`SET ROLE virki_email_worker; ${statement}\n`, { allowFailure: true });
  assert.notEqual(outcome.status, 0, message);
  assert.match(outcome.stderr, /permission denied|must be owner|insufficient privilege/iu, message);
}

const migrationFixture = `
CREATE ROLE virki_migrator LOGIN;
CREATE ROLE virki_runtime LOGIN;
CREATE ROLE virki_audit_maintenance LOGIN;
CREATE TYPE public."OutboxMessageStatus" AS ENUM ('QUEUED','PROCESSING','SENT','RETRYABLE_FAILURE','TERMINAL_FAILURE');
CREATE TYPE public."EmailMessageKind" AS ENUM ('EMAIL_TWO_FACTOR','ACCOUNT_RECOVERY');
CREATE TYPE public."DeliveryAttemptStatus" AS ENUM ('SENT','FAILED');
CREATE TABLE public."User" ("id" text PRIMARY KEY);
CREATE TABLE public."Session" ("id" text PRIMARY KEY, "userId" text REFERENCES public."User"("id"));
CREATE TABLE public."AuditLog" ("id" text PRIMARY KEY);
CREATE TABLE public."EmailOutboxMessage" (
  "id" text PRIMARY KEY, "idempotencyKey" text NOT NULL, "kind" public."EmailMessageKind" NOT NULL,
  "recipientEmail" text NOT NULL, "locale" text NOT NULL, "payload" jsonb NOT NULL,
  "status" public."OutboxMessageStatus" NOT NULL DEFAULT 'QUEUED',
  "attemptCount" integer NOT NULL DEFAULT 0, "availableAt" timestamp NOT NULL DEFAULT now(),
  "sentAt" timestamp, "terminalFailedAt" timestamp, "processingLeaseExpiresAt" timestamp,
  "pendingSmtpHeaderMessageId" varchar(255), "createdAt" timestamp NOT NULL DEFAULT now(),
  "updatedAt" timestamp NOT NULL DEFAULT now()
);
CREATE TABLE public."EmailDeliveryAttempt" (
  "id" text PRIMARY KEY, "messageId" text NOT NULL REFERENCES public."EmailOutboxMessage"("id"),
  "attempt" integer NOT NULL, "status" public."DeliveryAttemptStatus" NOT NULL,
  "errorCode" text, "smtpHeaderMessageId" varchar(255),
  "attemptedAt" timestamp NOT NULL DEFAULT now()
);
CREATE SCHEMA virki_security AUTHORIZATION virki_migrator;
CREATE FUNCTION virki_security.delete_expired_audit_logs() RETURNS integer
  LANGUAGE sql SECURITY DEFINER AS 'SELECT 0';
REVOKE EXECUTE ON FUNCTION virki_security.delete_expired_audit_logs() FROM PUBLIC;
INSERT INTO public."User" ("id") VALUES ('test-person');
INSERT INTO public."EmailOutboxMessage"
  ("id","idempotencyKey","kind","recipientEmail","locale","payload")
  VALUES ('mail-1','idempotent-1','EMAIL_TWO_FACTOR','owned@example.invalid','pt-BR','{}'::jsonb);
`;

try {
  const image = invoke(["image", "inspect", pgImage, "--format", "{{.Id}}"]).stdout;
  assert.equal(image, expectedImageId, "refuse registry pull or unpinned local database image");
  const version = invoke(["version", "--format", "{{.Server.Os}}|{{.Server.Arch}}"]).stdout;
  assert.equal(version, "linux|amd64", "requires pinned local Linux/amd64 Docker endpoint");
  const created = invoke(["create", "--name", name, "--network", "none",
    "--label", `virki.worker-role-test.owner=${owner}`,
    "--security-opt", "no-new-privileges:true",
    "--tmpfs", "/var/lib/postgresql/data:rw,nosuid,nodev,size=512m",
    "--tmpfs", "/var/run/postgresql:rw,nosuid,nodev,size=16m",
    "--tmpfs", "/tmp:rw,nosuid,nodev,size=32m",
    "--env", "PGDATA=/var/lib/postgresql/data/pgdata",
    "--env", `POSTGRES_DB=${database}`, "--env", "POSTGRES_USER=virki_bootstrap",
    ...Object.keys(secrets).flatMap((key) => ["--env", key]),
    pgImage]);
  containerId = created.stdout;
  inspectOwned();
  invoke(["start", containerId]);
  let ready = false;
  for (let attempt = 0; attempt < 60; attempt += 1) {
    inspectOwned();
    const status = invoke(["exec", containerId, "pg_isready", "--host", "/var/run/postgresql",
      "--username", "virki_bootstrap", "--dbname", database], { allowFailure: true });
    if (status.status === 0) { ready = true; break; }
    await delay(300);
  }
  if (!ready) {
    const diagnostic = invoke(["logs", "--tail", "20", containerId], { allowFailure: true });
    throw new Error(`isolated local database was not ready: ${diagnostic.stderr || diagnostic.stdout}`);
  }
  inspectOwned();
  // Docker cp into a tmpfs path may write to the underlying hidden overlay;
  // keep the test-only script on the owned container's ephemeral rootfs.
  invoke(["cp", setup, `${containerId}:${setupInContainer}`]);
  invoke(["exec", containerId, "test", "-f", setupInContainer]);

  const before = invoke(["exec", containerId, "sh", setupInContainer], { allowFailure: true });
  assert.notEqual(before.status, 0, "a missing migration must fail closed");
  assert.match(`${before.stderr} ${before.stdout}`, /requires the committed, migrated Virki schema/u,
    "the pre-migration refusal must be caused by the SQL schema gate, not by a missing script");
  assert.equal(psql("SELECT count(*)::integer FROM pg_roles WHERE rolname='virki_email_worker';").stdout, "0",
    "pre-migration refusal must leave no login role");

  psql(migrationFixture);
  const poisonedLibpq = {
    ...processEnv,
    PGHOSTADDR: "127.0.0.1",
    PGPORT: "1",
    PGSERVICE: "virki-nonexistent-postgres-service",
    PGOPTIONS: "-c statement_timeout=1",
    PGUSER: "wrong_user",
    PGDATABASE: "wrong_database"
  };
  const poisonedLibpqArgs = Object.keys(poisonedLibpq)
    .filter((key) => /^PG(?:HOSTADDR|PORT|SERVICE|OPTIONS|USER|DATABASE)$/u.test(key))
    .flatMap((key) => ["--env", key]);
  const redLibpq = invoke(["exec", ...poisonedLibpqArgs, containerId, "psql", "--no-psqlrc",
    "--no-password", "--host=/var/run/postgresql", "--username", "virki_bootstrap",
    "--dbname", database, "--command", "SELECT 1"], { env: poisonedLibpq, allowFailure: true });
  assert.notEqual(redLibpq.status, 0,
    "live libpq poison must genuinely redirect or break the unsanitized control invocation");
  const poisonedRole = invoke(["exec", ...poisonedLibpqArgs, containerId, "sh", setupInContainer],
    { env: poisonedLibpq, allowFailure: true });
  assert.notEqual(poisonedRole.status, 0, "unsafe PUBLIC baseline must still fail under poisoned libpq inputs");
  assert.match(poisonedRole.stderr, /excess worker privileges/u,
    "sanitized helper must reach its local database privilege gate, not the foreign port");
  const unsafePublicDefaults = invoke(["exec", containerId, "sh", setupInContainer], { allowFailure: true });
  assert.notEqual(unsafePublicDefaults.status, 0, "unsafe inherited PUBLIC TEMP privileges must fail closed");
  assert.match(unsafePublicDefaults.stderr, /excess worker privileges/u);
  assert.equal(psql("SELECT count(*)::integer FROM pg_roles WHERE rolname='virki_email_worker';").stdout, "0",
    "a failed SQL grant transaction must roll back creation of the worker role");
  psql(`REVOKE CONNECT, CREATE, TEMPORARY ON DATABASE ${database} FROM PUBLIC;`);
  inspectOwned();
  invoke(["exec", containerId, "sh", setupInContainer]);
  // Idempotence must not broaden permissions or break the required worker.
  invoke(["exec", containerId, "sh", setupInContainer]);
  psql('GRANT SELECT ON public."User" TO PUBLIC;');
  const publicDataLeak = invoke(["exec", containerId, "sh", setupInContainer], { allowFailure: true });
  assert.notEqual(publicDataLeak.status, 0, "unexpected PUBLIC identity-table grants must stop role reconciliation");
  assert.match(publicDataLeak.stderr, /excess worker privileges/u);
  psql('REVOKE SELECT ON public."User" FROM PUBLIC;');
  invoke(["exec", containerId, "sh", setupInContainer]);
  psql('GRANT USAGE ON SCHEMA virki_security TO PUBLIC; GRANT EXECUTE ON FUNCTION virki_security.delete_expired_audit_logs() TO PUBLIC;');
  assert.equal(psql(`SELECT has_schema_privilege('virki_email_worker','virki_security','USAGE')
    AND has_function_privilege('virki_email_worker','virki_security.delete_expired_audit_logs()','EXECUTE');`).stdout,
  "t", "protected audit deletion inherited-PUBLIC red oracle must be effective");
  const publicAuditCapability = invoke(["exec", containerId, "sh", setupInContainer], { allowFailure: true });
  assert.notEqual(publicAuditCapability.status, 0, "PUBLIC must not make SECURITY DEFINER audit deletion available to worker");
  assert.match(publicAuditCapability.stderr, /excess worker privileges/u);
  psql('REVOKE USAGE ON SCHEMA virki_security FROM PUBLIC; REVOKE EXECUTE ON FUNCTION virki_security.delete_expired_audit_logs() FROM PUBLIC;');
  invoke(["exec", containerId, "sh", setupInContainer]);
  psql('GRANT SELECT ("id") ON public."User" TO PUBLIC; GRANT INSERT ("id") ON public."EmailOutboxMessage" TO PUBLIC;');
  assert.equal(psql(`SELECT has_column_privilege('virki_email_worker','public."User"','id','SELECT')
    AND has_column_privilege('virki_email_worker','public."EmailOutboxMessage"','id','INSERT');`).stdout,
  "t", "PUBLIC column-grant red oracle must expose extra privileges before reconciliation");
  const publicColumnLeak = invoke(["exec", containerId, "sh", setupInContainer], { allowFailure: true });
  assert.notEqual(publicColumnLeak.status, 0, "PUBLIC column-only identity/outbox grants must not be ignored");
  assert.match(publicColumnLeak.stderr, /excess worker privileges/u);
  psql('REVOKE SELECT ("id") ON public."User" FROM PUBLIC; REVOKE INSERT ("id") ON public."EmailOutboxMessage" FROM PUBLIC;');
  invoke(["exec", containerId, "sh", setupInContainer]);
  psql('GRANT SELECT ("id") ON public."User" TO virki_email_worker; GRANT UPDATE ("recipientEmail") ON public."EmailOutboxMessage" TO virki_email_worker;');
  assert.equal(psql(`SELECT has_column_privilege('virki_email_worker','public."User"','id','SELECT')
    AND has_column_privilege('virki_email_worker','public."EmailOutboxMessage"','recipientEmail','UPDATE');`).stdout,
  "t", "stale direct-column grant red oracle must be effective before role reconciliation");
  invoke(["exec", containerId, "sh", setupInContainer]);
  assert.equal(psql(`SELECT NOT has_column_privilege('virki_email_worker','public."User"','id','SELECT')
    AND NOT has_column_privilege('virki_email_worker','public."EmailOutboxMessage"','recipientEmail','UPDATE');`).stdout,
  "t", "re-provisioning must revoke stale direct column grants on identity and recipient columns");
  psql('CREATE FUNCTION public.worker_public_definer_probe() RETURNS integer LANGUAGE sql SECURITY DEFINER AS \'SELECT 1\';');
  const publicDefiner = invoke(["exec", containerId, "sh", setupInContainer], { allowFailure: true });
  assert.notEqual(publicDefiner.status, 0, "unexpected PUBLIC SECURITY DEFINER routines must block role reconciliation");
  assert.match(publicDefiner.stderr, /excess worker privileges/u);
  psql('DROP FUNCTION public.worker_public_definer_probe();');
  invoke(["exec", containerId, "sh", setupInContainer]);
  const grants = psql(`SELECT
    (SELECT rolcanlogin AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolbypassrls AND NOT rolinherit
     FROM pg_roles WHERE rolname = 'virki_email_worker')
    AND NOT EXISTS (SELECT 1 FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.member
                    WHERE r.rolname='virki_email_worker')
    AND has_table_privilege('virki_email_worker','public."EmailOutboxMessage"','SELECT')
    AND NOT has_table_privilege('virki_email_worker','public."EmailOutboxMessage"','UPDATE')
    AND has_column_privilege('virki_email_worker','public."EmailOutboxMessage"','status','UPDATE')
    AND NOT has_column_privilege('virki_email_worker','public."EmailOutboxMessage"','recipientEmail','UPDATE')
    AND NOT has_column_privilege('virki_email_worker','public."EmailOutboxMessage"','payload','UPDATE')
    AND NOT has_table_privilege('virki_email_worker','public."EmailOutboxMessage"','INSERT')
    AND NOT has_table_privilege('virki_email_worker','public."EmailOutboxMessage"','DELETE')
    AND has_table_privilege('virki_email_worker','public."EmailDeliveryAttempt"','SELECT')
    AND has_column_privilege('virki_email_worker','public."EmailDeliveryAttempt"','messageId','INSERT')
    AND NOT has_table_privilege('virki_email_worker','public."EmailDeliveryAttempt"','UPDATE')
    AND NOT has_table_privilege('virki_email_worker','public."User"','SELECT')
    AND NOT has_table_privilege('virki_email_worker','public."Session"','SELECT')
    AND NOT has_table_privilege('virki_email_worker','public."AuditLog"','SELECT')
    AND NOT has_database_privilege('virki_email_worker',current_database(),'CREATE')
    AND NOT has_database_privilege('virki_email_worker',current_database(),'TEMPORARY')
    AND NOT has_schema_privilege('virki_email_worker','public','CREATE')
    AND NOT has_schema_privilege('virki_email_worker','virki_security','USAGE');`).stdout;
  if (grants !== "t") {
    const diagnostics = psql(`SELECT json_build_object(
      'roleSafe', (SELECT rolcanlogin AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolbypassrls AND NOT rolinherit FROM pg_roles WHERE rolname='virki_email_worker'),
      'membershipAbsent', NOT EXISTS(SELECT 1 FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.member WHERE r.rolname='virki_email_worker'),
      'outboxSelect',has_table_privilege('virki_email_worker','public."EmailOutboxMessage"','SELECT'),
      'outboxTableUpdate',has_table_privilege('virki_email_worker','public."EmailOutboxMessage"','UPDATE'),
      'outboxStatusUpdate',has_column_privilege('virki_email_worker','public."EmailOutboxMessage"','status','UPDATE'),
      'outboxRecipientUpdate',has_column_privilege('virki_email_worker','public."EmailOutboxMessage"','recipientEmail','UPDATE'),
      'outboxInsert',has_table_privilege('virki_email_worker','public."EmailOutboxMessage"','INSERT'),
      'deliverySelect',has_table_privilege('virki_email_worker','public."EmailDeliveryAttempt"','SELECT'),
      'deliveryColumnInsert',has_column_privilege('virki_email_worker','public."EmailDeliveryAttempt"','messageId','INSERT'),
      'deliveryTableUpdate',has_table_privilege('virki_email_worker','public."EmailDeliveryAttempt"','UPDATE'),
      'userSelect',has_table_privilege('virki_email_worker','public."User"','SELECT'),
      'sessionSelect',has_table_privilege('virki_email_worker','public."Session"','SELECT'),
      'auditSelect',has_table_privilege('virki_email_worker','public."AuditLog"','SELECT'),
      'databaseCreate',has_database_privilege('virki_email_worker',current_database(),'CREATE'),
      'databaseTemp',has_database_privilege('virki_email_worker',current_database(),'TEMPORARY'),
      'schemaCreate',has_schema_privilege('virki_email_worker','public','CREATE'),
      'securitySchemaUsage',has_schema_privilege('virki_email_worker','virki_security','USAGE'))::text;`).stdout;
    process.stderr.write(`WORKER_ROLE_ACL_DIAGNOSTIC=${diagnostics}\n`);
  }
  assert.equal(grants, "t", "actual PostgreSQL privilege matrix must match worker-only contract");

  const allowed = psql(`SET ROLE virki_email_worker;
    BEGIN;
    SELECT "payload" FROM public."EmailOutboxMessage" WHERE "id"='mail-1';
    UPDATE public."EmailOutboxMessage" SET "status"='PROCESSING', "attemptCount"=1,
      "processingLeaseExpiresAt"=now(), "updatedAt"=now() WHERE "id"='mail-1';
    INSERT INTO public."EmailDeliveryAttempt" ("id","messageId","attempt","status","attemptedAt")
      VALUES ('attempt-1','mail-1',1,'SENT',now());
    ROLLBACK;`).stdout;
  assert.ok(allowed.includes("{}"), "actual scoped ciphertext read should succeed");

  assertDenied('SELECT * FROM public."User";', "identity table SELECT must be denied");
  assertDenied('SELECT * FROM public."Session";', "session SELECT must be denied");
  assertDenied('SELECT * FROM public."AuditLog";', "audit SELECT must be denied");
  assertDenied('UPDATE public."EmailOutboxMessage" SET "recipientEmail"=\'attacker@example.invalid\';',
    "recipient alteration must be denied");
  assertDenied('UPDATE public."EmailOutboxMessage" SET "payload"=\'{}\'::jsonb;',
    "ciphertext alteration must be denied");
  assertDenied('DELETE FROM public."EmailOutboxMessage";', "outbox DELETE must be denied");
  assertDenied('INSERT INTO public."EmailOutboxMessage" ("id") VALUES (\'not-allowed\');',
    "worker cannot enqueue independent messages");
  assertDenied('UPDATE public."EmailDeliveryAttempt" SET "status"=\'FAILED\';',
    "worker cannot rewrite delivery receipts");
  assertDenied('CREATE TABLE public.worker_escalation("x" integer);', "worker cannot create schema objects");
  assertDenied('CREATE TEMP TABLE worker_temp_probe("x" integer);', "worker cannot create temporary objects");

  const invalid = invoke(["exec", "--env", "VIRKI_EMAIL_WORKER_DB_PASSWORD", containerId,
    "sh", setupInContainer], {
    env: { ...processEnv, VIRKI_EMAIL_WORKER_DB_PASSWORD: secrets.VIRKI_RUNTIME_DB_PASSWORD },
    allowFailure: true
  });
  assert.notEqual(invalid.status, 0, "the worker credential cannot reuse the runtime password");
  assert.equal(psql('SELECT has_table_privilege(\'virki_email_worker\',\'public."User"\',\'SELECT\');').stdout, "f",
    "rejected credential rotation cannot broaden grants");
  process.stdout.write("LOCAL_DISPOSABLE_WORKER_ROLE_PROOF=PASS (scoped grant, negative ACL, idempotence, no external network)\n");
} finally {
  if (containerId) {
    inspectOwned();
    const removed = invoke(["rm", "--force", containerId], { timeout: 30_000 });
    assert.equal(removed.stdout, containerId, "only the exact verified owned container may be removed");
    const missing = invoke(["inspect", containerId], { allowFailure: true });
    assert.notEqual(missing.status, 0, "disposable container must be absent after cleanup");
    process.stdout.write("LOCAL_DISPOSABLE_WORKER_ROLE_CLEANUP=PASS\n");
  }
}
