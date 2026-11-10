import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { RECOVERY_PG18_IMAGE, RECOVERY_PG18_IMAGE_DIGEST, RECOVERY_PG18_SUITES,
  privateRecoveryDockerAdmissionEnvironment, privateRecoveryTestEnvironment,
  requireExactRecoveryPg18Tap, requireRecoveryPg18ContainerImage, requireRecoveryPg18ImagePlatform,
  verifiedRecoveryPg18LocalImage } from "./recovery-pg18-contract.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "../..");
const verifiedImageId = `sha256:${"d".repeat(64)}`;

test("PG18 image is digest-pinned and each independent local/container identity must match", () => {
  assert.equal(RECOVERY_PG18_IMAGE, `postgres:18.6-alpine3.24@${RECOVERY_PG18_IMAGE_DIGEST}`);
  assert.equal(RECOVERY_PG18_IMAGE_DIGEST,
    "sha256:123b17998ccaf47e53b502e8c6a1e79afd8f579c6f3eec83c563da026f957395");
  assert.match(RECOVERY_PG18_IMAGE_DIGEST, /^sha256:[a-f0-9]{64}$/u);
  requireRecoveryPg18ImagePlatform("linux|amd64");
  for (const invalid of ["linux|arm64", "windows|amd64", "", "linux|amd64\nlinux|arm64"]) {
    assert.throws(() => requireRecoveryPg18ImagePlatform(invalid), /Private PG18/u);
  }
  const observed = `${verifiedImageId}|${JSON.stringify([`postgres@${RECOVERY_PG18_IMAGE_DIGEST}`])}`;
  assert.equal(verifiedRecoveryPg18LocalImage(observed), verifiedImageId);
  requireRecoveryPg18ContainerImage(`${verifiedImageId}|${RECOVERY_PG18_IMAGE}`, verifiedImageId);
  for (const forged of [
    observed.replace(RECOVERY_PG18_IMAGE_DIGEST, `sha256:${"f".repeat(64)}`),
    `${verifiedImageId}|[]`, `${verifiedImageId}|not-json`,
    `${verifiedImageId}|${JSON.stringify([`attacker/postgres@${RECOVERY_PG18_IMAGE_DIGEST}`])}`,
    `${"d".repeat(64)}|${JSON.stringify([`postgres@${RECOVERY_PG18_IMAGE_DIGEST}`])}`
  ]) assert.throws(() => verifiedRecoveryPg18LocalImage(forged), /Private PG18/u);
  for (const forged of [
    `sha256:${"f".repeat(64)}|${RECOVERY_PG18_IMAGE}`,
    `${verifiedImageId}|postgres:18.6-alpine3.24`,
    `${verifiedImageId}|postgres:latest`,
    `${verifiedImageId}|postgres:18.6-alpine3.24@sha256:${"f".repeat(64)}`
  ]) assert.throws(() => requireRecoveryPg18ContainerImage(forged, verifiedImageId), /Private PG18/u);
});

test("test children use strict host allowlist and independent disposable crypto, never ambient secrets or NODE_OPTIONS", () => {
  const ambient = {
    PATH: "/temporary/node/bin", HOME: "/fake/home", LANG: "C.UTF-8",
    NODE_OPTIONS: "--require=/fake/prod-preload.js", NODE_PATH: "/fake/prod-modules",
    DATABASE_URL: "postgresql://production.invalid/main", MIGRATION_DATABASE_URL: "postgresql://production.invalid/main",
    VIRKI_TOTP_ENCRYPTION_KEY: "a".repeat(64), VIRKI_EMAIL_OUTBOX_KEY: "b".repeat(64),
    VIRKI_OIDC_ADAPTER_KEY: "c".repeat(64), VIRKI_PRODUCTION_DB_PASSWORD: "prod-secret",
    VIRKI_EMAIL_TRANSPORT: "smtp", VIRKI_EMAIL_SMTP_PASSWORD: "smtp-secret",
    GITHUB_TOKEN: "gh-secret", ACTIONS_RUNTIME_TOKEN: "action-secret",
    DOCKER_HOST: "tcp://production.invalid:2376", DOCKER_CONTEXT: "production",
    GITHUB_ACTIONS: "true", CI: "true", RUNNER_OS: "Linux", RUNNER_ENVIRONMENT: "github-hosted",
    VIRKI_BUILD_REVISION: "e".repeat(40), VIRKI_BUILD_ARCH: "amd64", RUNNER_ARCH: "X64"
  };
  const admission = privateRecoveryDockerAdmissionEnvironment(ambient);
  assert.deepEqual(Object.keys(admission).sort(), ["PATH", "HOME", "LANG",
    "GITHUB_ACTIONS", "CI", "RUNNER_OS", "RUNNER_ENVIRONMENT",
    "VIRKI_BUILD_REVISION", "VIRKI_BUILD_ARCH", "RUNNER_ARCH"].sort());
  const a = privateRecoveryTestEnvironment({
    source: ambient, databaseUrl: "postgresql://virki_runtime_test@127.0.0.1:15432/virki_w11_admin_pairs_fake",
    migrationUrl: "postgresql://virki_migrator@127.0.0.1:15432/virki_w11_admin_pairs_fake",
    secret: () => randomSecretForContract()
  });
  const b = privateRecoveryTestEnvironment({
    source: ambient, databaseUrl: "postgresql://virki_runtime_test@127.0.0.1:15433/virki_w2_assisted_fake",
    migrationUrl: "postgresql://virki_migrator@127.0.0.1:15433/virki_w2_assisted_fake",
    secret: () => randomSecretForContract()
  });
  for (const env of [a, b]) {
    assert.deepEqual(Object.keys(env).sort(), ["PATH", "HOME", "LANG", "NODE_ENV", "CI",
      "VIRKI_INTEGRATION_ENABLED", "VIRKI_CORE_TEST_DATABASE_CONFIRM", "DATABASE_URL",
      "VIRKI_INTEGRATION_DATABASE_URL", "MIGRATION_DATABASE_URL", "VIRKI_PORTAL_URL",
      "VIRKI_HUB_URL", "VIRKI_OIDC_ADAPTER_KEY", "VIRKI_TOTP_ENCRYPTION_KEY", "VIRKI_EMAIL_OUTBOX_KEY"].sort());
    for (const key of ["VIRKI_TOTP_ENCRYPTION_KEY", "VIRKI_EMAIL_OUTBOX_KEY", "VIRKI_OIDC_ADAPTER_KEY"]) {
      assert.match(env[key], /^[a-f0-9]{64}$/u);
      assert.notEqual(env[key], ambient[key]);
    }
    assert.notEqual(env.VIRKI_OIDC_ADAPTER_KEY, env.VIRKI_TOTP_ENCRYPTION_KEY);
    assert.notEqual(env.VIRKI_TOTP_ENCRYPTION_KEY, env.VIRKI_EMAIL_OUTBOX_KEY);
    assert.equal(env.NODE_ENV, "test");
  }
  assert.notEqual(a.VIRKI_TOTP_ENCRYPTION_KEY, b.VIRKI_TOTP_ENCRYPTION_KEY);
  assert.notEqual(a.VIRKI_EMAIL_OUTBOX_KEY, b.VIRKI_EMAIL_OUTBOX_KEY);
});

let contractSecretCounter = 0;
function randomSecretForContract() {
  return (++contractSecretCounter).toString(16).padStart(64, "0");
}

function tap(suite) {
  return ["TAP version 13", ...suite.names.map((name, i) => `ok ${i + 1} - ${name}`),
    `1..${suite.names.length}`, `# tests ${suite.names.length}`, `# pass ${suite.names.length}`,
    "# fail 0", "# cancelled 0", "# skipped 0", "# todo 0", "# duration_ms 123.4", ""].join("\n");
}

test("all nine specific PG18 tests have a distinct physical TAP contract", () => {
  assert.deepEqual(RECOVERY_PG18_SUITES.map((suite) => suite.names.length), [5, 4]);
  assert.equal(new Set(RECOVERY_PG18_SUITES.flatMap((suite) => suite.names)).size, 9);
  for (const suite of RECOVERY_PG18_SUITES) {
    const file = readFileSync(path.join(root, suite.file), "utf8");
    assert.equal((file.match(/^test\("PG18 /gmu) ?? []).length, suite.names.length,
      "every source PG18 test must be represented in the physical evidence contract");
    for (const name of suite.names) assert.ok(file.includes(`test("${name}"`), name);
    assert.equal(requireExactRecoveryPg18Tap(tap(suite), suite), suite.names.length);
    for (const mutated of [
      tap(suite).replace(`# pass ${suite.names.length}`, "# pass 0"),
      tap(suite).replace("# skipped 0", "# skipped 1"),
      tap(suite).replace("# fail 0", "# fail 1"),
      tap(suite).replace("# todo 0", "# todo 1"),
      tap(suite).replace("# cancelled 0", "# cancelled 1"),
      tap(suite).replace("# tests", "# NOT_TESTS"),
      tap(suite).replace("# pass", "# NOT_PASS"),
      tap(suite).replace(`# pass ${suite.names.length}`, `# pass ${suite.names.length}\n# pass ${suite.names.length}`),
      tap(suite).replace(`ok 1 - ${suite.names[0]}`, `ok 1 - replaced unrelated case`),
      tap(suite).replace(`ok 1 - ${suite.names[0]}`, `ok 2 - ${suite.names[0]}`),
      tap(suite).replace(`ok 1 - ${suite.names[0]}`, `ok 1 - ${suite.names[0]} # SKIP`),
      tap(suite).replace(`ok 1 - ${suite.names[0]}`, `not ok 1 - ${suite.names[0]}`),
      tap(suite).replace("# pass", "# pass -1")
    ]) {
      assert.throws(() => requireExactRecoveryPg18Tap(mutated, suite), /PG18 recovery/u);
    }
    assert.throws(() => requireExactRecoveryPg18Tap(tap(suite) + "# pass 5\n", suite));
  }
});

test("required PG18 CI job does not substitute for or modify the existing PG17 gates", () => {
  const yaml = readFileSync(path.join(root, ".github/workflows/ci.yml"), "utf8").replace(/\r\n/gu, "\n");
  assert.match(yaml, /^ {2}recovery-pg18:\n {4}name: Mandatory independent ADMIN recovery PG18 proofs\n {4}runs-on: ubuntu-latest/mu);
  assert.match(yaml, /node --test scripts\/integration\/recovery-pg18-contract\.test\.mjs/u);
  assert.match(yaml, /run: node scripts\/integration\/recovery-pg18-disposable\.mjs/u);
  assert.match(yaml, /VIRKI_BUILD_REVISION: \$\{\{ github\.sha \}\}/u);
  assert.match(yaml, /RUNNER_ENVIRONMENT: \$\{\{ runner\.environment \}\}/u);
  assert.match(yaml, /VIRKI_BUILD_ARCH: amd64/u);
  assert.match(yaml, /run: bash scripts\/integration\/worker-hol-ci\.sh/u);
  assert.match(yaml, /postgres:17-alpine@sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24/u);
  assert.match(yaml, /VIRKI_INTEGRATION_DATABASE_URL="\$VIRKI_E2E_DATABASE_URL" npm run test:integration/u);
});

// Run a copy of the UNCHANGED production entrypoint with fake Docker/child
// boundaries. No daemon, network, migration or database is used by these tests.
function mockRun(scenario) {
  const fixture = mkdtempSync(path.join(os.tmpdir(), "virki-pg18-recovery-mock-"));
  const scripts = path.join(fixture, "scripts");
  const integration = path.join(scripts, "integration");
  const lib = path.join(scripts, "lib");
  const initRoles = path.join(fixture, "infra", "postgres-init", "10-virki-database-roles.sh");
  const initTestRole = path.join(scripts, "e2e", "20-virki-e2e-runtime-test-role.sh");
  mkdirSync(integration, { recursive: true });
  mkdirSync(lib, { recursive: true });
  mkdirSync(path.dirname(initRoles), { recursive: true });
  mkdirSync(path.dirname(initTestRole), { recursive: true });
  writeFileSync(initRoles, "# fake checked source; no PostgreSQL access\n");
  writeFileSync(initTestRole, "# fake checked source; no PostgreSQL access\n");
  writeFileSync(path.join(fixture, "package.json"), '{"type":"module"}\n');
  const runner = readFileSync(path.join(here, "recovery-pg18-disposable.mjs"), "utf8")
    .replace('from "node:child_process";', 'from "./fake-child.mjs";')
    .replace('from "node:fs";', 'from "./fake-fs.mjs";')
    .replace('from "../lib/disposable-docker-session.mjs";', 'from "../lib/fake-docker.mjs";')
    .replace('from "../lib/disposable-docker-receipt-security.mjs";', 'from "../lib/fake-security.mjs";');
  writeFileSync(path.join(integration, "recovery-pg18-disposable.mjs"), runner);
  writeFileSync(path.join(integration, "recovery-pg18-contract.mjs"),
    readFileSync(path.join(here, "recovery-pg18-contract.mjs"), "utf8"));
  writeFileSync(path.join(integration, "fake-fs.mjs"), `
    export { closeSync, fstatSync, fsyncSync, lstatSync, mkdirSync, openSync } from "node:fs";
    import { writeSync as actualWrite } from "node:fs";
    export function writeSync(fd, data, offset, length) {
      if (process.env.VIRKI_FAKE_CASE === "zero-write") return 0;
      return actualWrite(fd, data, offset, Math.min(3, length));
    }
  `);
  writeFileSync(path.join(lib, "fake-security.mjs"), `
    import { join } from "node:path";
    export function ownerEvidenceDirectory(root) { return join(root, ".virki-mission-tmp", "recovery-docker-recovery"); }
    export function ensurePrivateEvidenceDirectory() {}
    export function assertPrivateEvidenceFile() {}
  `);
  writeFileSync(path.join(integration, "fake-child.mjs"), `
    import { RECOVERY_PG18_SUITES } from "./recovery-pg18-contract.mjs";
    export function spawnSync(_exec, args, options) {
      const scenario = process.env.VIRKI_FAKE_CASE;
      const approved = ["PATH", "Path", "SystemRoot", "WINDIR", "HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA",
        "TEMP", "TMP", "TMPDIR", "LANG", "LC_ALL", "NODE_ENV", "CI", "VIRKI_INTEGRATION_ENABLED",
        "VIRKI_CORE_TEST_DATABASE_CONFIRM", "DATABASE_URL", "VIRKI_INTEGRATION_DATABASE_URL",
        "MIGRATION_DATABASE_URL", "VIRKI_PORTAL_URL", "VIRKI_HUB_URL", "VIRKI_OIDC_ADAPTER_KEY",
        "VIRKI_TOTP_ENCRYPTION_KEY", "VIRKI_EMAIL_OUTBOX_KEY"];
      if (Object.keys(options.env).some(key => !approved.includes(key))) throw Error("Ambient keys crossed child boundary");
      if (options.env.NODE_OPTIONS || options.env.NODE_PATH || options.env.GITHUB_TOKEN ||
          options.env.VIRKI_PRODUCTION_DB_PASSWORD || options.env.VIRKI_EMAIL_TRANSPORT ||
          options.env.VIRKI_EMAIL_SMTP_HOST || options.env.VIRKI_EMAIL_SMTP_PASSWORD ||
          !options.env.DATABASE_URL?.startsWith("postgresql://virki_runtime_test:") ||
          !options.env.MIGRATION_DATABASE_URL?.startsWith("postgresql://virki_migrator:") ||
          options.env.VIRKI_INTEGRATION_DATABASE_URL !== options.env.DATABASE_URL ||
          options.env.NODE_ENV !== "test") throw Error("DB/SMTP environment not segregated");
      for (const key of ["VIRKI_TOTP_ENCRYPTION_KEY", "VIRKI_EMAIL_OUTBOX_KEY", "VIRKI_OIDC_ADAPTER_KEY"]) {
        if (!/^[a-f0-9]{64}$/.test(options.env[key]) || options.env[key] === process.env[key]) {
          throw Error("Production crypto inherited by child");
        }
      }
      if (new Set([options.env.VIRKI_TOTP_ENCRYPTION_KEY, options.env.VIRKI_EMAIL_OUTBOX_KEY,
        options.env.VIRKI_OIDC_ADAPTER_KEY]).size !== 3) throw Error("Test crypto keys must be distinct");
      if (args[0].endsWith("prisma-migrate.mjs")) return { status: scenario === "migration-fail" ? 1 : 0, stdout: "", stderr: "" };
      if (!args[0].endsWith("integration/run.mjs") && !args[0].endsWith("integration\\\\run.mjs")) throw Error("Unexpected subprocess");
      const suite = RECOVERY_PG18_SUITES.find(s => s.file === args[1]);
      if (!suite) throw Error("Unrecognized suite");
      const variant = scenario === "second-skip" && suite.kind !== "assisted" ? "ok" : scenario;
      const names = suite.names.map((name, i) => "ok " + (i + 1) + " - " + name);
      if (variant === "wrong-name") names[0] = "ok 1 - unrelated test";
      if (variant === "skip" || variant === "second-skip") names[0] += " # SKIP";
      let lines = ["TAP version 13", ...names, "1.." + suite.names.length,
        "# tests " + suite.names.length, "# pass " + suite.names.length,
        "# fail 0", "# cancelled 0", "# skipped 0", "# todo 0"];
      if (["skip", "second-skip"].includes(variant)) lines = lines.map(x => x === "# skipped 0" ? "# skipped 1" : x);
      if (variant === "zero-tests") lines = ["TAP version 13", "1..0", "# tests 0", "# pass 0", "# fail 0", "# cancelled 0", "# skipped 0", "# todo 0"];
      if (variant === "missing-summary") lines = lines.filter(x => !x.startsWith("# pass"));
      if (variant === "test-fail") return { status: 1, stdout: lines.join("\\n"), stderr: "" };
      return { status: 0, stdout: lines.join("\\n") + "\\n", stderr: "" };
    }
  `);
  writeFileSync(path.join(lib, "fake-docker.mjs"), `
    import { appendFileSync } from "node:fs";
    import { RECOVERY_PG18_IMAGE, RECOVERY_PG18_IMAGE_DIGEST } from "../integration/recovery-pg18-contract.mjs";
    const containers = new Map();
    const imageId = "sha256:" + "d".repeat(64);
    const repoDigest = "postgres@" + RECOVERY_PG18_IMAGE_DIGEST;
    let count = 0;
    function log(data) { appendFileSync(process.env.VIRKI_FAKE_LOG, JSON.stringify(data) + "\\n"); }
    const ok = (stdout = "") => ({ status: 0, stdout, stderr: "" });
    const absent = target => ({ status: 1, stdout: "", stderr: "Error: No such object: " + target + "\\n" });
    export function createAdmittedOidcDockerClient(options) {
      if (Object.keys(options.env).some(key => ["NODE_OPTIONS", "NODE_PATH", "DATABASE_URL",
        "MIGRATION_DATABASE_URL", "VIRKI_TOTP_ENCRYPTION_KEY", "VIRKI_EMAIL_OUTBOX_KEY",
        "GITHUB_TOKEN", "DOCKER_HOST", "DOCKER_CONTEXT"].includes(key))) {
        throw Error("Docker admission inherited unsafe secret");
      }
      return { subprocessEnv: {
        VIRKI_EMAIL_TRANSPORT: "smtp",
        VIRKI_EMAIL_SMTP_HOST: "production.example.invalid",
        VIRKI_EMAIL_SMTP_PASSWORD: "untrusted-secret",
        NODE_OPTIONS: "--throw-deprecation",
        GITHUB_TOKEN: "untrusted-github-token",
        VIRKI_TOTP_ENCRYPTION_KEY: "a".repeat(64),
        VIRKI_EMAIL_OUTBOX_KEY: "b".repeat(64),
        DATABASE_URL: "postgresql://untrusted.example.invalid/other",
        MIGRATION_DATABASE_URL: "postgresql://untrusted.example.invalid/other"
      }, invoke(args) {
        const action = args[0], scenario = process.env.VIRKI_FAKE_CASE;
        if (action === "pull") {
          log({ action, image: args.at(-1) });
          return scenario === "pull-error" ? { status: 1, stderr: "pull rejected" } : ok("immutable digest pulled");
        }
        if (action === "image" && args[1] === "inspect") {
          log({ action: "image-inspect" });
          if (args.includes("{{.Os}}|{{.Architecture}}")) return ok(scenario === "bad-platform" ? "linux|arm64" : "linux|amd64");
          const id = scenario === "bad-image-id" ? "invalid-image-id" : imageId;
          const digest = scenario === "bad-image-digest" ? "postgres@sha256:" + "f".repeat(64) : repoDigest;
          return ok(id + "|" + JSON.stringify([digest]));
        }
        if (action === "run") {
          count++;
          const cid = (count === 1 ? "a" : "b").repeat(64);
          const name = args[args.indexOf("--name") + 1];
          const owner = args[args.indexOf("--label") + 1].split("=").at(-1);
          const dbArg = args.find(s => s.startsWith("POSTGRES_DB="));
          const record = { cid, name, owner, removed: false };
          containers.set(cid, record);
          containers.set(name, record);
          log({ action, cid, name, owner, db: dbArg?.slice(12),
            publish: args[args.indexOf("--publish") + 1],
            tmpfs: args[args.indexOf("--tmpfs") + 1],
            image: args.at(-1), mounts: args.filter(x => x.includes("/docker-entrypoint-initdb.d/")),
            usingMount: args.filter(x => x === "--mount").length,
            volume: args.some(x => x === "--volume") });
          return scenario === "lost-ack" ? { status: 1, stderr: "lost ACK" } :
            scenario === "bad-cid" ? ok("fake-cid") : ok(cid);
        }
        if (action === "inspect" && args.includes("{{.Image}}|{{.Config.Image}}")) {
          const id = scenario === "bad-container-image" ? "sha256:" + "f".repeat(64) : imageId;
          const ref = scenario === "bad-container-ref" ? "postgres:18.6-alpine3.24" : RECOVERY_PG18_IMAGE;
          return ok(id + "|" + ref);
        }
        if (action === "inspect" && args.includes("{{.State.Health.Status}}")) return ok(scenario === "unhealthy" ? "unhealthy" : "healthy");
        if (action === "inspect") {
          const target = args.at(-1), record = containers.get(target);
          if (!record || record.removed) return absent(target);
          const cid = scenario === "id-swap" ? "c".repeat(64) : record.cid;
          const owner = scenario === "foreign" ? "not-our-owner" : record.owner;
          const name = scenario === "name-swap" ? "/other-container" : "/" + record.name;
          return ok(cid + "|" + name + "|" + owner);
        }
        if (action === "port") return ok(scenario === "bad-port" ? "0.0.0.0:5432" : "127.0.0.1:5432");
        if (action === "exec") return ok(args.includes("SHOW server_version_num") ? (scenario === "bad-version" ? "170000" : "180006") : "");
        if (action === "rm") {
          const target = args.at(-1), record = containers.get(target);
          log({ action, target });
          if (scenario === "rm-fail") return { status: 1, stderr: "permission denied" };
          if (record && scenario !== "still-present") record.removed = true;
          return ok();
        }
        log({ action });
        return ok();
      } };
    }
  `);
  const log = path.join(fixture, "fake-commands.jsonl");
  const child = spawnSync(process.execPath,
    [path.join(integration, "recovery-pg18-disposable.mjs")],
    { cwd: fixture, encoding: "utf8", timeout: 25_000,
      env: { ...process.env, VIRKI_FAKE_CASE: scenario, VIRKI_FAKE_LOG: log,
        GITHUB_TOKEN: "untrusted-token", VIRKI_PRODUCTION_DB_PASSWORD: "untrusted-production-db",
        VIRKI_TOTP_ENCRYPTION_KEY: "a".repeat(64), VIRKI_EMAIL_OUTBOX_KEY: "b".repeat(64),
        NODE_OPTIONS: "--no-warnings", NODE_PATH: "/hostile/node-path",
        DOCKER_HOST: "tcp://foreign-prod:2376", DOCKER_CONTEXT: "production" } });
  const calls = existsSync(log) ? readFileSync(log, "utf8").trim().split(/\r?\n/u).map(JSON.parse) : [];
  rmSync(fixture, { recursive: true, force: true });
  return { child, calls };
}

test("mocked runner proves two separate owned containers, databases and exact 5+4 real names", () => {
  const { child, calls } = mockRun("ok");
  assert.equal(child.error, undefined);
  assert.equal(child.status, 0, child.stderr);
  assert.match(child.stdout, /9 real PASS, 0 FAIL, 0 SKIP/u);
  const started = calls.filter(x => x.action === "run");
  assert.equal(started.length, 2);
  assert.equal(new Set(started.map(x => x.owner)).size, 2);
  assert.equal(new Set(started.map(x => x.cid)).size, 2);
  assert.match(started[0].db, /^virki_w11_admin_pairs_[a-f0-9]{12}4[a-f0-9]{3}[89ab][a-f0-9]{15}$/u);
  assert.match(started[1].db, /^virki_w2_assisted_[a-f0-9]{12}4[a-f0-9]{3}[89ab][a-f0-9]{15}$/u);
  for (const item of started) {
    assert.equal(item.publish, "127.0.0.1::5432");
    assert.match(item.tmpfs, /^\/var\/lib\/postgresql:.*size=512m$/u);
    assert.equal(item.image, RECOVERY_PG18_IMAGE);
    assert.equal(item.mounts.length, 2);
    assert.equal(item.usingMount, 2);
    assert.equal(item.volume, false, "missing bind sources must fail instead of creating host directories");
    assert.ok(item.mounts.every(x => x.endsWith(",readonly")));
  }
  assert.deepEqual(calls.filter(x => x.action === "rm").map(x => x.target), started.map(x => x.cid));
  assert.deepEqual(calls.filter(x => x.action === "pull").map(x => x.image),
    [RECOVERY_PG18_IMAGE, RECOVERY_PG18_IMAGE]);
  assert.equal(calls.filter(x => x.action === "image-inspect").length, 4);
  assert.doesNotMatch(child.stdout + child.stderr, /password|postgresql:\/\//iu);
});

test("mocked runner rejects every missing/false-green summary and safely cleans owned containers", () => {
  for (const scenario of ["skip", "second-skip", "wrong-name", "zero-tests", "missing-summary", "test-fail",
    "migration-fail", "bad-port", "bad-version", "unhealthy",
    "pull-error", "bad-image-digest", "bad-image-id", "bad-platform", "bad-container-image", "bad-container-ref"]) {
    const { child, calls } = mockRun(scenario);
    assert.equal(child.error, undefined, scenario);
    assert.equal(child.status, 1, scenario);
    assert.doesNotMatch(child.stdout, /9 real PASS/u, scenario);
    assert.equal(calls.filter(x => x.action === "run").length,
      scenario === "second-skip" ? 2 : ["pull-error", "bad-image-digest", "bad-image-id", "bad-platform"].includes(scenario) ? 0 : 1, scenario);
    assert.equal(calls.filter(x => x.action === "rm").length,
      scenario === "second-skip" ? 2 : ["pull-error", "bad-image-digest", "bad-image-id", "bad-platform"].includes(scenario) ? 0 : 1, scenario);
  }
});

test("mocked runner rejects Docker identity spoofing, lost acknowledgments and cleanup uncertainty", () => {
  for (const [scenario, removed] of [
    ["foreign", 0], ["id-swap", 0], ["name-swap", 0],
    ["rm-fail", 1], ["still-present", 1], ["bad-cid", 1], ["lost-ack", 1], ["zero-write", 0]
  ]) {
    const { child, calls } = mockRun(scenario);
    assert.equal(child.error, undefined, scenario);
    assert.equal(child.status, 1, scenario);
    assert.equal(calls.filter(x => x.action === "rm").length, removed, scenario);
    assert.doesNotMatch(child.stdout, /9 real PASS/u, scenario);
    if (scenario === "zero-write") assert.equal(calls.filter(x => x.action === "run").length, 0);
  }
});
