import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

const standalone = fileURLToPath(new URL("../infra/docker-compose.staging-email-worker-only.yml", import.meta.url));
const source = () => readFileSync(standalone, "utf8").replaceAll("\r\n", "\n");

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
  assert.match(content, /^\x20{4}pull_policy: never/mu);
  assert.match(content, /^\x20{4}read_only: true/mu);
  assert.match(content, /^\x20{4}cap_drop: \[ALL\]/mu);
  assert.match(content, /^\x20{4}security_opt: \[no-new-privileges:true\]/mu);
  assert.match(content, /^networks:\n\x20{2}staging-mail:\n\x20{4}external: true/mu);
  assert.match(content, /^\x20{4}name: \$\{VIRKI_STAGING_EMAIL_WORKER_NETWORK:\?/mu);
  for (const forbidden of [/^volumes:/mu, /^\x20{4}volumes:/mu, /^\x20{4}depends_on:/mu, /^\x20{4}ports:/mu, /^\x20{4}build:/mu, /virki_postgres_data/u]) {
    assert.doesNotMatch(content, forbidden, "worker-only manifest must never create a database/volume or expose ports");
  }
  for (const sourceName of [
    "VIRKI_STAGING_EMAIL_WORKER_IMAGE",
    "VIRKI_STAGING_EMAIL_WORKER_DATABASE_URL",
    "VIRKI_STAGING_EMAIL_OUTBOX_KEY",
    "VIRKI_STAGING_EMAIL_SMTP_HOST",
    "VIRKI_STAGING_EMAIL_SMTP_PORT",
    "VIRKI_STAGING_EMAIL_SMTP_SECURE",
    "VIRKI_STAGING_EMAIL_SMTP_USER",
    "VIRKI_STAGING_EMAIL_SMTP_PASSWORD",
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
  assert.equal(rendered.status, 0, "synthetic worker-only config must parse");
  const config = JSON.parse(rendered.stdout);
  assert.equal(config.name, "virki-standalone-test");
  assert.deepEqual(Object.keys(config.services), ["email-worker"]);
  assert.equal(config.services["email-worker"].restart, "no");
  assert.equal(config.services["email-worker"].depends_on, undefined);
  assert.ok(!config.volumes || Object.keys(config.volumes).length === 0);
  assert.deepEqual(Object.keys(config.networks), ["staging-mail"]);
  assert.equal(config.networks["staging-mail"].external, true);
  assert.equal(config.networks["staging-mail"].name, "approved-staging-test-network");
  for (const missing of [
    "VIRKI_STAGING_COMPOSE_PROJECT", "VIRKI_STAGING_EMAIL_WORKER_NETWORK",
    "VIRKI_STAGING_EMAIL_WORKER_IMAGE", "VIRKI_STAGING_EMAIL_SMTP_PASSWORD",
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
