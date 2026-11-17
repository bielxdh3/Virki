import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  STAGING_PRISMA_CA_PATH,
  verifyDatabaseUrlBinding,
  verifyServicePgpassBinding
} from "./staging-pgpass-bootstrap-binding.mjs";

const standalone = fileURLToPath(new URL("../infra/docker-compose.staging-email-worker-only.yml", import.meta.url));
const source = () => readFileSync(standalone, "utf8").replaceAll("\r\n", "\n");
const runbookPath = fileURLToPath(new URL("../docs/security/pr118-staging-operator-runbook-20261114.md", import.meta.url));

const escapedPgpass = (value) => value.replaceAll("\\", "\\\\").replaceAll(":", "\\:");
// Construct synthetic test URLs from fields: there is no literal credentialed
// DSN to accidentally copy into operator instructions or release inventories.
const syntheticPgUrl = (user, password, host, database) => {
  const url = new URL(`postgresql://${user}@${host}:5432/${database}?sslmode=require&sslaccept=strict`);
  url.searchParams.set("sslcert", STAGING_PRISMA_CA_PATH);
  // URL.password does not escape a raw percent sign; encode before assigning
  // so the strict verifier can safely decode credentials containing '%'.
  url.password = encodeURIComponent(password);
  return url.toString();
};

test("staging PGPASSFILE accepts a literal backslash-star password and canonical IPv6 target", () => {
  const host = "2001:db8::1";
  const password = "literal\\*password:secure";
  const serviceFileText = `[virki-staging-worker]\nhost=${host}\nport=5432\ndbname=virki_stage\nuser=virki_email_worker\nsslmode=verify-full\n`;
  const passFileText = `${escapedPgpass(host)}:5432:virki_stage:virki_email_worker:${escapedPgpass(password)}\n`;
  const binding = {
    serviceFileText, passFileText, serviceName: "virki-staging-worker",
    expectedHost: "2001:0DB8:0:0:0:0:0:1", expectedPort: "5432",
    expectedDatabase: "virki_stage", expectedUser: "virki_email_worker",
    credential: password, failurePrefix: "WORKER"
  };
  assert.equal(verifyServicePgpassBinding(binding), true);
  assert.throws(() => verifyServicePgpassBinding({
    ...binding, passFileText: passFileText.replace(escapedPgpass(password), "literal\\*password:secure")
  }), { code: "INVALID_PGPASS_ESCAPE" }, "an ambiguous \\* sequence must not masquerade as a literal credential");
  assert.throws(() => verifyServicePgpassBinding({
    ...binding, passFileText: `${passFileText}\\*:5432:virki_stage:virki_email_worker:decoy\n`
  }), { code: "INVALID_PGPASS_ESCAPE" }, "escaped wildcard match fields must not bypass the strict inventory");
});

test("worker and Hub URLs bind percent-decoded passwords, IPv6, role, port, database and strict TLS", () => {
  const password = "percent%:@\\*secret";
  const workerUrl = syntheticPgUrl("virki_email_worker", password, "[2001:db8::1]", "virki_stage");
  const binding = {
    databaseUrl: workerUrl,
    expectedHost: "2001:0db8:0:0::1", expectedPort: "5432", expectedDatabase: "virki_stage",
    expectedUser: "virki_email_worker", credential: password, failurePrefix: "WORKER"
  };
  assert.equal(verifyDatabaseUrlBinding(binding), true);
  assert.throws(() => verifyDatabaseUrlBinding({ ...binding, credential: "incorrect" }), {
    code: "WORKER_DATABASE_URL_PASSWORD_MISMATCH"
  });
  for (const databaseUrl of [
    workerUrl.replace("?sslmode=require", "?sslmode=prefer"),
    workerUrl + "&sslmode=require",
    workerUrl + "#fragment",
    workerUrl.replace(/&sslcert=[^&]+/u, ""),
    workerUrl + "&sslcert=%2Fapp%2Fca%2Fstaging-db-root.pem",
    workerUrl.replace("staging-db-root.pem", "unapproved-root.pem"),
    workerUrl.replace("staging-db-root.pem", "..%2Fstaging-db-root.pem"),
    workerUrl.replace("staging-db-root.pem", "staging-db-root.pem%00"),
    workerUrl.replace("sslmode=require&sslaccept=strict&sslcert=", "sslcert="),
    workerUrl.replace("sslaccept=strict", "sslaccept=accept_invalid_certs"),
    workerUrl.replace("&sslaccept=strict", ""),
    workerUrl + "&sslrootcert=%2Fapp%2Fca%2Fstaging-db-root.pem",
    workerUrl.replace("virki_email_worker", "virki_runtime"),
    workerUrl.replace("virki_stage?", "production?")
  ]) {
    assert.throws(() => verifyDatabaseUrlBinding({ ...binding, databaseUrl }),
      { code: /WORKER_DATABASE_URL_(?:INVALID|TARGET_MISMATCH)/u });
  }
});

test("both worker and Hub pin the same Prisma-internal CA path without query downgrade", () => {
  const worker = syntheticPgUrl("virki_email_worker", "worker-test-password", "db.stage.invalid", "virki_stage");
  const hub = syntheticPgUrl("virki_runtime", "hub-test-password", "db.stage.invalid", "virki_stage");
  for (const [databaseUrl, expectedUser, credential] of [
    [worker, "virki_email_worker", "worker-test-password"],
    [hub, "virki_runtime", "hub-test-password"]
  ]) {
    const binding = { databaseUrl, expectedHost: "db.stage.invalid", expectedPort: "5432",
      expectedDatabase: "virki_stage", expectedUser, credential };
    assert.equal(verifyDatabaseUrlBinding(binding), true);
    for (const invalidUrl of [
      databaseUrl.replace(/&sslcert=[^&]+/u, ""),
      databaseUrl.replace("sslmode=require", "sslmode=disable"),
      databaseUrl.replace("sslaccept=strict", "sslaccept=accept_invalid_certs"),
      databaseUrl.replace("staging-db-root.pem", "other.pem"),
      databaseUrl + "&sslmode=require",
      databaseUrl + "&sslcert=%2Fapp%2Fca%2Fstaging-db-root.pem",
      databaseUrl + "&sslrootcert=%2Fapp%2Fca%2Fstaging-db-root.pem",
    ]) {
      assert.throws(() => verifyDatabaseUrlBinding({ ...binding, databaseUrl: invalidUrl }),
        { code: "DATABASE_DATABASE_URL_INVALID" });
    }
  }
});

test("the operator runbook enforces the same strict Prisma 6 CA URL for Hub and worker", () => {
  const runbook = readFileSync(runbookPath, "utf8");
  for (const requirement of [
    'queryKeys.length !== 3',
    'queryKeys[0] !== "sslmode"',
    'queryKeys[1] !== "sslaccept"',
    'queryKeys[2] !== "sslcert"',
    'url.searchParams.get("sslmode") !== "require"',
    'url.searchParams.get("sslaccept") !== "strict"',
    'url.searchParams.get("sslcert") !== "/app/ca/staging-db-root.pem"'
  ]) {
    assert.equal(runbook.split(requirement).length - 1, 2,
      `both independent runtime URL checks must require: ${requirement}`);
  }
  assert.doesNotMatch(runbook, /queryKeys\.length !== 1/u);
  assert.match(runbook, /Prisma 6\.19\.3 Linux engine/u,
    "source contract cannot silently promote local URL parsing to runtime TLS approval");
});

test("operator verifier requires both runtime URLs and prevents TLS key logging without echoing credentials", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "virki-staging-binding-"));
  const host = "staging-db.example.invalid";
  const restoreDatabase = "virki_stage_restore_abcdef12";
  const database = "virki_stage";
  const entries = [
    ["bootstrap", "postgres", "bootstrap_admin", "bootstrap-staging-secret"],
    ["worker", database, "virki_email_worker", "worker-staging-secret"],
    ["hub", database, "virki_runtime", "hub-staging-secret"],
    ["migrator", database, "virki_migrator", "migrator-staging-secret"]
  ];
  const serviceFileText = entries.map(([service, db, user]) =>
    `[virki-staging-${service}]\nhost=${host}\nport=5432\ndbname=${db}\nuser=${user}\nsslmode=verify-full\n`).join("\n");
  const passFileText = entries.flatMap(([, db, user, password]) => [db, restoreDatabase].map((targetDb) =>
    `${host}:5432:${targetDb}:${user}:${escapedPgpass(password)}`)).join("\n") + "\n";
  try {
    const servicePath = path.join(directory, "pg_service.conf");
    const passPath = path.join(directory, "pgpass");
    writeFileSync(servicePath, serviceFileText);
    writeFileSync(passPath, passFileText);
    const env = {
      ...process.env, PGSERVICEFILE: servicePath, PGPASSFILE: passPath,
      VIRKI_STAGING_APPROVED_DB_HOST: host, VIRKI_STAGING_APPROVED_DB_PORT: "5432",
      VIRKI_STAGING_APPROVED_DB_NAME: database, VIRKI_STAGING_RESTORE_DB: restoreDatabase,
      POSTGRES_USER: "bootstrap_admin", POSTGRES_PASSWORD: "bootstrap-staging-secret",
      VIRKI_EMAIL_WORKER_DB_PASSWORD: "worker-staging-secret",
      VIRKI_RUNTIME_DB_PASSWORD: "hub-staging-secret",
      VIRKI_MIGRATOR_DB_PASSWORD: "migrator-staging-secret",
      VIRKI_STAGING_EMAIL_WORKER_DATABASE_URL: syntheticPgUrl("virki_email_worker", "worker-staging-secret", host, database),
      VIRKI_STAGING_HUB_DATABASE_URL: syntheticPgUrl("virki_runtime", "hub-staging-secret", host, database)
    };
    delete env.PGSSLKEYLOGFILE;
    const run = (candidate) => spawnSync(process.execPath,
      [fileURLToPath(new URL("./staging-pgpass-bootstrap-binding.mjs", import.meta.url)), "--require-runtime-urls"],
      { env: candidate, encoding: "utf8", windowsHide: true, timeout: 10_000 });
    const accepted = run(env);
    assert.equal(accepted.status, 0, accepted.stderr);
    assert.ok(accepted.stdout.includes("STAGING_BOOTSTRAP_PASSFILE_BINDING=PASS"));
    for (const rejectedEnv of [
      { ...env, VIRKI_STAGING_EMAIL_WORKER_DATABASE_URL: undefined },
      { ...env, VIRKI_STAGING_HUB_DATABASE_URL: env.VIRKI_STAGING_HUB_DATABASE_URL.replace("hub-staging-secret", "wrong-secret") },
      { ...env, PGSSLKEYLOGFILE: path.join(directory, "keylog") },
      { ...env, SSLKEYLOGFILE: path.join(directory, "tls-keylog") }
    ]) {
      const rejected = run(rejectedEnv);
      assert.equal(rejected.status, 1);
      assert.equal(rejected.stdout, "");
      assert.equal(rejected.stderr, "BLOCK:STAGING_PGPASSFILE_BINDING\n");
      for (const [, , , secret] of entries) assert.ok(!rejected.stderr.includes(secret));
    }
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("worker runtime env gate preserves allowlisted SMTP keys and rejects unapproved sensitive keys", () => {
  const runbook = readFileSync(runbookPath, "utf8");
  const gate = runbook.split(/\r?\n/u).find((line) => line.includes("$worker_env_keys | index"));
  assert.ok(gate, "the runtime inspection must retain its sensitive-environment-key gate");
  assert.match(gate, /split\("="\)\[0\] as \$key/u,
    "the environment key must be bound before entering the allowlist array context");
  assert.match(gate, /index\(\$key\)/u,
    "the allowlist must compare the key string rather than the current jq array value");
  assert.doesNotMatch(gate, /index\(\.\)/u,
    "index(.) inside the array pipeline compares the wrong jq value");

  const allowedKeys = [
    "DATABASE_URL", "NODE_ENV", "VIRKI_EMAIL_FROM", "VIRKI_EMAIL_MIN_SEND_INTERVAL_MS",
    "VIRKI_EMAIL_OUTBOX_KEY", "VIRKI_EMAIL_REPLY_TO", "VIRKI_EMAIL_SMTP_HOST",
    "VIRKI_EMAIL_SMTP_PASSWORD", "VIRKI_EMAIL_SMTP_PORT", "VIRKI_EMAIL_SMTP_SECURE",
    "VIRKI_EMAIL_SMTP_USER", "VIRKI_EMAIL_TRANSPORT", "VIRKI_EMAIL_WORKER_SCOPED_ROLE",
    "VIRKI_STAGING_EMAIL_RECIPIENT_ALLOWLIST"
  ];
  const allowlistStart = runbook.indexOf('["DATABASE_URL"');
  const allowlistEnd = runbook.indexOf("as $worker_env_keys", allowlistStart);
  assert.ok(allowlistStart >= 0 && allowlistEnd > allowlistStart);
  const allowlistSource = runbook.slice(allowlistStart, allowlistEnd);
  for (const key of allowedKeys) assert.ok(allowlistSource.includes(`"${key}"`), `missing approved key ${key}`);

  const sensitive = /(^|_)(SMTP|BREVO)(_|$)|(^|_)(MAIL|EMAIL)_(.*(PASSWORD|SECRET|TOKEN|API_KEY|USER))$/iu;
  const isUnexpectedSensitiveKey = (key) => sensitive.test(key) && !allowedKeys.includes(key);
  assert.equal(isUnexpectedSensitiveKey("VIRKI_EMAIL_SMTP_HOST"), false);
  assert.equal(isUnexpectedSensitiveKey("VIRKI_EMAIL_SMTP_PASSWORD"), false);
  assert.equal(isUnexpectedSensitiveKey("VIRKI_EMAIL_FROM"), false);
  assert.equal(isUnexpectedSensitiveKey("VIRKI_EMAIL_SMTP_API_KEY"), true);
  assert.equal(isUnexpectedSensitiveKey("BREVO_SECRET"), true);
  assert.equal(isUnexpectedSensitiveKey("MAIL_PASSWORD"), true);
});

function composeCommand() {
  const attempt = (bin, args) => {
    const result = spawnSync(bin, args, { encoding: "utf8", timeout: 10_000, windowsHide: true });
    return result.status === 0 ? { bin, prefix: args.slice(0, -1) } : null;
  };
  return attempt("docker", ["compose", "version"]) ?? attempt("docker-compose", ["version"]);
}

test("isolated SMTP worker manifest has only a manual service, external staging network, no postgres or volumes", () => {
  const content = source();
  assert.match(content, /^name: \$\{VIRKI_STAGING_COMPOSE_PROJECT:\?/mu);
  assert.match(content, /^services:\n\x20{2}email-worker:/mu);
  const servicesOnly = content.split("\nnetworks:\n")[0];
  assert.equal((servicesOnly.match(/^\x20{2}[a-z][a-z-]*:/gmu) ?? []).length, 1,
    "no additional Compose services, especially postgres, may appear");
  assert.match(content, /^\x20{4}profiles: \["staging-email-worker-manual"\]/mu);
  assert.match(content, /^\x20{4}restart: "no"/mu);
  assert.match(content, /^\x20{4}mem_limit: \$\{VIRKI_STAGING_EMAIL_WORKER_MEMORY_LIMIT:\?/mu);
  assert.match(content, /^\x20{4}cpus: \$\{VIRKI_STAGING_EMAIL_WORKER_CPUS_LIMIT:\?/mu);
  assert.match(content, /^\x20{4}pids_limit: \$\{VIRKI_STAGING_EMAIL_WORKER_PIDS_LIMIT:\?/mu);
  assert.match(content, /^\x20{4}pull_policy: never/mu);
  assert.match(content, /^\x20{4}user: node:node$/mu);
  assert.match(content, /^\x20{4}command: npm run email:worker --workspace @virki\/auth$/mu);
  assert.match(content, /^\x20{6}VIRKI_STAGING_EMAIL_RECIPIENT_ALLOWLIST: \$\{VIRKI_STAGING_EMAIL_RECIPIENT_ALLOWLIST:\?/mu);
  assert.match(content, /^\x20{4}read_only: true/mu);
  assert.match(content, /^\x20{4}cap_drop: \[ALL\]/mu);
  assert.match(content, /^\x20{4}security_opt: \[no-new-privileges:true\]/mu);
  assert.match(content, /^\x20{4}tmpfs:\n\x20{6}- \/tmp:rw,noexec,nosuid,nodev,size=64m$/mu);
  assert.match(content, /^networks:\n\x20{2}staging-mail:\n\x20{4}external: true/mu);
  assert.match(content, /^\x20{4}name: \$\{VIRKI_STAGING_EMAIL_WORKER_NETWORK:\?/mu);
  for (const forbidden of [/^volumes:/mu, /^\x20{4}volumes:/mu, /^\x20{4}depends_on:/mu, /^\x20{4}ports:/mu, /^\x20{4}build:/mu, /virki_postgres_data/u]) {
    assert.doesNotMatch(content, forbidden, "worker-only manifest must never create a database/volume or expose ports");
  }
  for (const sourceName of [
    "VIRKI_STAGING_EMAIL_WORKER_IMAGE",
    "VIRKI_STAGING_EMAIL_WORKER_DATABASE_URL",
    "VIRKI_STAGING_EMAIL_WORKER_MEMORY_LIMIT",
    "VIRKI_STAGING_EMAIL_WORKER_CPUS_LIMIT",
    "VIRKI_STAGING_EMAIL_WORKER_PIDS_LIMIT",
    "VIRKI_STAGING_EMAIL_OUTBOX_KEY",
    "VIRKI_STAGING_EMAIL_SMTP_HOST",
    "VIRKI_STAGING_EMAIL_SMTP_PORT",
    "VIRKI_STAGING_EMAIL_SMTP_SECURE",
    "VIRKI_STAGING_EMAIL_SMTP_USER",
    "VIRKI_STAGING_EMAIL_SMTP_PASSWORD",
    "VIRKI_STAGING_EMAIL_RECIPIENT_ALLOWLIST",
    "VIRKI_STAGING_EMAIL_FROM",
    "VIRKI_STAGING_EMAIL_MIN_SEND_INTERVAL_MS"
  ]) {
    assert.ok(content.includes("${" + sourceName + ":?"), `missing mandatory staging source: ${sourceName}`);
  }
});

const availableCompose = composeCommand();
test("real Compose config selects only the external-network manual worker without database resources", () => {
  assert.ok(availableCompose, "Docker Compose CLI is mandatory for the standalone safety contract");
  // Only synthetic data are passed to Compose. No real env files, Docker
  // daemon, image fetch, container creation, or network is accessed.
  const sourceText = source();
  const required = [...new Set([...sourceText.matchAll(/\$\{([A-Z][A-Z0-9_]+):\?[^}]*\}/gu)]
    .map((match) => match[1]))];
  const env = {
    PATH: process.env.PATH,
    SystemRoot: process.env.SystemRoot,
    COMSPEC: process.env.COMSPEC,
    HOME: process.env.HOME,
    TMPDIR: process.env.TMPDIR,
    ProgramFiles: process.env.ProgramFiles,
    APPDATA: process.env.APPDATA,
    LOCALAPPDATA: process.env.LOCALAPPDATA,
    USERPROFILE: process.env.USERPROFILE,
    COMPOSE_DISABLE_ENV_FILE: "1"
  };
  for (const key of required) env[key] = "synthetic-only";
  Object.assign(env, {
    VIRKI_STAGING_COMPOSE_PROJECT: "virki-standalone-test",
    VIRKI_STAGING_EMAIL_WORKER_NETWORK: "approved-staging-test-network",
    VIRKI_STAGING_EMAIL_WORKER_IMAGE: "fixture.invalid/virki@sha256:" + "a".repeat(64),
    VIRKI_STAGING_EMAIL_WORKER_MEMORY_LIMIT: "512m",
    VIRKI_STAGING_EMAIL_WORKER_CPUS_LIMIT: "1.0",
    VIRKI_STAGING_EMAIL_WORKER_PIDS_LIMIT: "128",
    VIRKI_STAGING_EMAIL_SMTP_PORT: "587",
    VIRKI_STAGING_EMAIL_SMTP_SECURE: "false",
    VIRKI_STAGING_EMAIL_OUTBOX_KEY: "b".repeat(64),
    VIRKI_STAGING_EMAIL_MIN_SEND_INTERVAL_MS: "250"
  });
  const command = [...availableCompose.prefix, "--profile", "staging-email-worker-manual",
    "-f", standalone, "config", "--format", "json"];
  const run = (candidate) => spawnSync(availableCompose.bin, command, {
    env: candidate, encoding: "utf8", timeout: 15_000, windowsHide: true
  });
  const rendered = run(env);
  assert.equal(rendered.status, 0, `synthetic worker-only config must parse: ${rendered.stderr}`);
  const config = JSON.parse(rendered.stdout);
  assert.equal(config.name, "virki-standalone-test");
  assert.deepEqual(Object.keys(config.services), ["email-worker"]);
  assert.equal(config.services["email-worker"].restart, "no");
  assert.equal(config.services["email-worker"].mem_limit, "536870912");
  assert.equal(config.services["email-worker"].cpus, 1);
  assert.equal(config.services["email-worker"].pids_limit, 128);
  assert.equal(config.services["email-worker"].user, "node:node");
  assert.equal(Array.isArray(config.services["email-worker"].command)
    ? config.services["email-worker"].command.join(" ")
    : config.services["email-worker"].command,
  "npm run email:worker --workspace @virki/auth");
  assert.ok(config.services["email-worker"].entrypoint == null);
  assert.equal(config.services["email-worker"].read_only, true);
  assert.deepEqual(config.services["email-worker"].cap_drop, ["ALL"]);
  assert.deepEqual(config.services["email-worker"].cap_add ?? [], []);
  assert.deepEqual(config.services["email-worker"].security_opt, ["no-new-privileges:true"]);
  assert.deepEqual(config.services["email-worker"].tmpfs, ["/tmp:rw,noexec,nosuid,nodev,size=64m"]);
  assert.equal(config.services["email-worker"].depends_on, undefined);
  assert.equal(config.services["email-worker"].volumes, undefined);
  assert.equal(config.services["email-worker"].ports, undefined);
  assert.equal(config.services["email-worker"].healthcheck, undefined);
  assert.equal(config.services["email-worker"].env_file, undefined);
  assert.equal(config.services["email-worker"].build, undefined);
  assert.equal(config.services["email-worker"].privileged, undefined);
  assert.equal(config.services["email-worker"].devices, undefined);
  assert.deepEqual(config.services["email-worker"].device_cgroup_rules ?? [], []);
  assert.deepEqual(config.services["email-worker"].sysctls ?? {}, {});
  assert.deepEqual(config.services["email-worker"].group_add ?? [], []);
  assert.deepEqual(config.services["email-worker"].extra_hosts ?? [], []);
  assert.deepEqual(config.services["email-worker"].volumes_from ?? [], []);
  assert.deepEqual(config.services["email-worker"].secrets ?? [], []);
  assert.deepEqual(config.services["email-worker"].configs ?? [], []);
  assert.ok(config.services["email-worker"].runtime == null);
  assert.ok(config.services["email-worker"].use_api_socket == null || config.services["email-worker"].use_api_socket === false);
  assert.deepEqual(config.services["email-worker"].dns ?? [], []);
  assert.deepEqual(config.services["email-worker"].dns_search ?? [], []);
  assert.deepEqual(config.services["email-worker"].dns_opt ?? [], []);
  assert.equal(config.services["email-worker"].network_mode, undefined);
  assert.equal(config.services["email-worker"].pid, undefined);
  assert.equal(config.services["email-worker"].ipc, undefined);
  assert.equal(config.services["email-worker"].uts, undefined);
  assert.equal(config.services["email-worker"].userns_mode, undefined);
  assert.equal(config.services["email-worker"].cgroup, undefined);
  assert.equal(config.services["email-worker"].container_name, undefined);
  assert.deepEqual(Object.keys(config.services["email-worker"].environment).sort(), [
    "DATABASE_URL", "NODE_ENV", "VIRKI_EMAIL_FROM", "VIRKI_EMAIL_MIN_SEND_INTERVAL_MS",
    "VIRKI_EMAIL_OUTBOX_KEY", "VIRKI_EMAIL_REPLY_TO", "VIRKI_EMAIL_SMTP_HOST",
    "VIRKI_EMAIL_SMTP_PASSWORD", "VIRKI_EMAIL_SMTP_PORT", "VIRKI_EMAIL_SMTP_SECURE",
    "VIRKI_EMAIL_SMTP_USER", "VIRKI_EMAIL_TRANSPORT", "VIRKI_EMAIL_WORKER_SCOPED_ROLE",
    "VIRKI_STAGING_EMAIL_RECIPIENT_ALLOWLIST"
  ]);
  assert.ok(!config.volumes || Object.keys(config.volumes).length === 0);
  assert.deepEqual(Object.keys(config.networks), ["staging-mail"]);
  assert.equal(config.networks["staging-mail"].external, true);
  assert.equal(config.networks["staging-mail"].name, "approved-staging-test-network");
  for (const missing of [
    "VIRKI_STAGING_COMPOSE_PROJECT", "VIRKI_STAGING_EMAIL_WORKER_NETWORK",
    "VIRKI_STAGING_EMAIL_WORKER_IMAGE", "VIRKI_STAGING_EMAIL_SMTP_PASSWORD",
    "VIRKI_STAGING_EMAIL_WORKER_MEMORY_LIMIT", "VIRKI_STAGING_EMAIL_WORKER_CPUS_LIMIT",
    "VIRKI_STAGING_EMAIL_WORKER_PIDS_LIMIT",
    "VIRKI_STAGING_EMAIL_RECIPIENT_ALLOWLIST",
    "VIRKI_STAGING_EMAIL_OUTBOX_KEY", "VIRKI_STAGING_EMAIL_WORKER_DATABASE_URL"
  ]) {
    const candidate = { ...env };
    delete candidate[missing];
    const denied = run(candidate);
    assert.equal(denied.error, undefined, `Compose must actually execute while testing ${missing}`);
    assert.equal(denied.signal, null, `Compose must exit normally while testing ${missing}`);
    assert.ok(Number.isInteger(denied.status) && denied.status !== 0,
      `omitting ${missing} must produce a real Compose rejection`);
    assert.ok(denied.stderr.includes(missing),
      `Compose must identify the exact missing staging source ${missing}, not fail for another reason`);
  }
});
