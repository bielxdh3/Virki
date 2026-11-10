import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { RECOVERY_PG18_SUITES, requireExactRecoveryPg18Tap } from "./recovery-pg18-contract.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "../..");

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
      if (options.env.VIRKI_EMAIL_TRANSPORT || options.env.VIRKI_EMAIL_SMTP_HOST ||
          options.env.VIRKI_EMAIL_SMTP_PASSWORD || !options.env.DATABASE_URL?.startsWith("postgresql://virki_runtime_test:") ||
          !options.env.MIGRATION_DATABASE_URL?.startsWith("postgresql://virki_migrator:") ||
          options.env.VIRKI_INTEGRATION_DATABASE_URL !== options.env.DATABASE_URL ||
          options.env.NODE_ENV !== "test") throw Error("DB/SMTP environment not segregated");
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
    const containers = new Map();
    let count = 0;
    function log(data) { appendFileSync(process.env.VIRKI_FAKE_LOG, JSON.stringify(data) + "\\n"); }
    const ok = (stdout = "") => ({ status: 0, stdout, stderr: "" });
    const absent = target => ({ status: 1, stdout: "", stderr: "Error: No such object: " + target + "\\n" });
    export function createAdmittedOidcDockerClient() {
      return { subprocessEnv: {
        VIRKI_EMAIL_TRANSPORT: "smtp",
        VIRKI_EMAIL_SMTP_HOST: "production.example.invalid",
        VIRKI_EMAIL_SMTP_PASSWORD: "untrusted-secret",
        DATABASE_URL: "postgresql://untrusted.example.invalid/other",
        MIGRATION_DATABASE_URL: "postgresql://untrusted.example.invalid/other"
      }, invoke(args) {
        const action = args[0], scenario = process.env.VIRKI_FAKE_CASE;
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
    assert.equal(item.image, "postgres:18.6-alpine3.24");
    assert.equal(item.mounts.length, 2);
    assert.equal(item.usingMount, 2);
    assert.equal(item.volume, false, "missing bind sources must fail instead of creating host directories");
    assert.ok(item.mounts.every(x => x.endsWith(",readonly")));
  }
  assert.deepEqual(calls.filter(x => x.action === "rm").map(x => x.target), started.map(x => x.cid));
  assert.doesNotMatch(child.stdout + child.stderr, /password|postgresql:\/\//iu);
});

test("mocked runner rejects every missing/false-green summary and safely cleans owned containers", () => {
  for (const scenario of ["skip", "second-skip", "wrong-name", "zero-tests", "missing-summary", "test-fail",
    "migration-fail", "bad-port", "bad-version", "unhealthy"]) {
    const { child, calls } = mockRun(scenario);
    assert.equal(child.error, undefined, scenario);
    assert.equal(child.status, 1, scenario);
    assert.doesNotMatch(child.stdout, /9 real PASS/u, scenario);
    assert.equal(calls.filter(x => x.action === "run").length,
      scenario === "second-skip" ? 2 : 1, scenario);
    assert.equal(calls.filter(x => x.action === "rm").length,
      scenario === "second-skip" ? 2 : 1, scenario);
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
