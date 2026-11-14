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
import { PG18_WINDOWS_POWERSHELL, pg18WindowsAclProbeScript } from "./local-pg18-receipt.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "../..");
const verifiedImageId = `sha256:${"d".repeat(64)}`;

test("PG18 Windows receipt gate is scoped to a protected fixed PowerShell and never weakens shared ACL", () => {
  assert.equal(PG18_WINDOWS_POWERSHELL,
    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
  const parent = pg18WindowsAclProbeScript("C:\\Users\\private-owner", { parent: true });
  const child = pg18WindowsAclProbeScript("C:\\Users\\private-owner\\.virki-private-local-pg18");
  const leaf = pg18WindowsAclProbeScript("C:\\Users\\private-owner\\.virki-private-local-pg18\\receipt.jsonl", { file: true });
  for (const script of [parent, child, leaf]) {
    assert.match(script, /Get-Acl -LiteralPath \$p -ErrorAction Stop/u);
    assert.match(script, /Get-Item -LiteralPath \$p -Force -ErrorAction Stop/u);
    assert.match(script, /\$acl\.GetOwner\(\[System\.Security\.Principal\.SecurityIdentifier\]\)/u);
    assert.match(script, /\[System\.IO\.FileAttributes\]::ReparsePoint/u);
    assert.match(script, /FileSystemRights\]::DeleteSubdirectoriesAndFiles/u);
    assert.match(script, /FileSystemRights\]::ChangePermissions/u);
    assert.match(script, /FileSystemRights\]::TakeOwnership/u);
    assert.match(script, /PRIVATE_PG18_RECEIPT/u);
  }
  assert.match(parent, /foreign writer on parent/u);
  assert.doesNotMatch(parent, /private child or leaf permits foreign access/u);
  assert.match(child, /private child or leaf permits foreign access/u);
  assert.match(leaf, /\$entry\.PSIsContainer -ne \$false/u);
  assert.throws(() => pg18WindowsAclProbeScript("C:\\x\nspoof"), /Invalid PG18/u);
  const oldSecurity = readFileSync(path.join(root, "scripts/lib/disposable-docker-receipt-security.mjs"), "utf8");
  assert.match(oldSecurity, /Foreign access to private Docker receipt/u);
  const runner = readFileSync(path.join(here, "recovery-pg18-disposable.mjs"), "utf8");
  assert.match(runner, /pg18ReceiptDirectory\(root\)/u);
  assert.match(runner, /assertPrivatePg18ReceiptFile/u);
});

// These are synthetic PowerShell ACL objects, not actual ACL edits. Every case
// executes the same script as the real verifier, with mocked Get-Acl/Get-Item
// so the negative cases cannot modify user home permissions.
test("PG18 PowerShell allows inherited foreign read only on nonwritable parent", {
  skip: process.platform !== "win32"
}, () => {
  const evaluate = ({ rights = "ReadAndExecute", parent = true, owner = "self",
    foreign = true, reparse = false, file = false, itemFile = file }) => {
    const prefix = [
      "$ErrorActionPreference='Stop'",
      "$script:foreignSid=[System.Security.Principal.SecurityIdentifier]::new('S-1-1-0')",
      "$script:selfSid=[System.Security.Principal.WindowsIdentity]::GetCurrent().User",
      `$script:fixtureOwner = ${owner === "self" ? "$script:selfSid" : "$script:foreignSid"}`,
      `$script:fixtureAces = @(${foreign ? `[pscustomobject]@{ AccessControlType='Allow'; IdentityReference=$script:foreignSid; FileSystemRights=[System.Security.AccessControl.FileSystemRights]::${rights}; IsInherited=$true }` : ""})`,
      "$script:fixtureAcl=[pscustomobject]@{ Access=$script:fixtureAces }",
      "$script:fixtureAcl | Add-Member -MemberType ScriptMethod -Name GetOwner -Value { param($kind) return $script:fixtureOwner }",
      "function Get-Acl { param([string]$LiteralPath) return $script:fixtureAcl }",
      `$script:fixtureEntry=[pscustomobject]@{ Attributes=[System.IO.FileAttributes]::${reparse ? "ReparsePoint" : "Normal"}; PSIsContainer=${itemFile ? "$false" : "$true"} }`,
      "function Get-Item { param([string]$LiteralPath,[switch]$Force) return $script:fixtureEntry }"
    ].join("\n");
    return spawnSync(PG18_WINDOWS_POWERSHELL, [
      "-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
      prefix + "\n" + pg18WindowsAclProbeScript("C:\\synthetic\\pg18", { parent, file })
    ], { encoding: "utf8", windowsHide: true, timeout: 15_000 });
  };
  const allowedRead = evaluate({ rights: "ReadAndExecute" });
  assert.equal(allowedRead.status, 0, allowedRead.stderr);
  assert.equal(allowedRead.stdout.trim(), "PRIVATE_PG18_RECEIPT");
  const permittedPrivate = evaluate({ foreign: false, parent: false, file: true });
  assert.equal(permittedPrivate.status, 0, permittedPrivate.stderr);
  for (const [kind, options] of [
    ["foreign-write", { rights: "Write" }],
    ["foreign-delete", { rights: "Delete" }],
    ["foreign-permissions", { rights: "ChangePermissions" }],
    ["foreign-takeowner", { rights: "TakeOwnership" }],
    ["foreign-owner", { owner: "foreign", foreign: false }],
    ["private-read", { parent: false, rights: "Read" }],
    ["leaf-read", { parent: false, file: true, rights: "Read" }],
    ["reparse", { reparse: true, foreign: false }],
    ["type-mismatch", { itemFile: true, foreign: false }]
  ]) {
    const refused = evaluate(options);
    assert.notEqual(refused.status, 0, kind);
    assert.doesNotMatch(refused.stdout ?? "", /PRIVATE_PG18_RECEIPT/u, kind);
  }
});

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

test("private PG18 integration requires exact TAP rather than Node22's spec reporter", () => {
  const env = privateRecoveryTestEnvironment({
    source: {}, databaseUrl: "postgresql://virki_runtime_test@127.0.0.1:5432/virki_w11_admin_pairs_test",
    migrationUrl: "postgresql://virki_migrator@127.0.0.1:5432/virki_w11_admin_pairs_test",
    secret: () => "test-only-secret"
  });
  assert.equal(env.VIRKI_INTEGRATION_EXACT_TAP, "required");
  const runner = readFileSync(path.join(here, "run.mjs"), "utf8");
  assert.match(runner, /process\.env\.VIRKI_INTEGRATION_EXACT_TAP === "required" \? \["--test-reporter=tap"\] : \[\]/u);
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
      "VIRKI_INTEGRATION_ENABLED", "VIRKI_INTEGRATION_EXACT_TAP", "VIRKI_CORE_TEST_DATABASE_CONFIRM", "DATABASE_URL",
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
  const pg18Job = yaml.split("  recovery-pg18:\n")[1]?.split("\n  authenticated-e2e:\n")[0];
  assert.ok(pg18Job, "mandatory PG18 job must exist between the existing CI gates");
  const [jobHeader, steps] = pg18Job.split("\n    steps:\n");
  assert.ok(jobHeader && steps, "PG18 job must have executable steps");
  assert.equal(jobHeader.includes("runner.environment"), false,
    "runner context in jobs.<job_id>.env invalidates the entire GitHub Actions workflow before any job starts");
  assert.ok(steps.includes([
    "      - name: Physically prove 5 ADMIN pair and 4 assisted recovery tests on separate PG18 databases",
    "        # The runner context is available to step env, not jobs.<job_id>.env.",
    "        env:",
    "          RUNNER_ENVIRONMENT: ${{ runner.environment }}",
    "        run: node scripts/integration/recovery-pg18-disposable.mjs"
  ].join("\n")), "only the physical PG18 step receives GitHub's real runner environment");
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
    .replace('from "./local-pg18-receipt.mjs";', 'from "../lib/fake-security.mjs";');
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
    export function pg18ReceiptDirectory(root) { return join(root, ".virki-mission-tmp", "recovery-docker-recovery"); }
    export function ensurePrivatePg18ReceiptDirectory() {}
    export function assertPrivatePg18ReceiptFile() {}
  `);
  writeFileSync(path.join(integration, "fake-child.mjs"), `
    import { RECOVERY_PG18_SUITES } from "./recovery-pg18-contract.mjs";
    export function spawnSync(_exec, args, options) {
      const scenario = process.env.VIRKI_FAKE_CASE;
      const approved = ["PATH", "Path", "SystemRoot", "WINDIR", "HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA",
        "TEMP", "TMP", "TMPDIR", "LANG", "LC_ALL", "NODE_ENV", "CI", "VIRKI_INTEGRATION_ENABLED", "VIRKI_INTEGRATION_EXACT_TAP",
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
          options.env.NODE_ENV !== "test" || options.env.VIRKI_INTEGRATION_EXACT_TAP !== "required") throw Error("DB/SMTP environment not segregated");
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
    const absent = target => {
      const scenario = process.env.VIRKI_FAKE_CASE;
      const message = scenario === "docker29-lowercase" || scenario === "mixed-previous-diagnostic" ||
        scenario.startsWith("docker29-stdout-")
        ? "error: no such object: " + target + "\\n"
        : scenario === "legacy-container-absence"
          ? "Error response from daemon: No such container: " + target + "\\n"
          : scenario === "legacy-object-absence"
            ? "Error response from daemon: No such object: " + target + "\\n"
            : scenario === "unknown-absence"
              ? "permission denied\\n"
              : "Error: No such object: " + target + "\\n";
      if (scenario === "mixed-previous-diagnostic") {
        return { status: 1, stdout: "", stderr: "permission denied\\n" + message };
      }
      if (scenario === "absence-stdout") return { status: 1, stdout: "unexpected output", stderr: message };
      if (scenario === "absence-null-status") return { status: null, stdout: "", stderr: message };
      if (scenario === "absence-duplicate-lines") return { status: 1, stdout: "", stderr: message + message };
      if (scenario === "docker29-stdout-lf") return { status: 1, signal: null, stdout: "\\n", stderr: message };
      if (scenario === "docker29-stdout-crlf") return { status: 1, signal: null, stdout: "\\r\\n", stderr: message };
      if (scenario === "docker29-stdout-double-lf") return { status: 1, stdout: "\\n\\n", stderr: message };
      if (scenario === "docker29-stdout-mixed") return { status: 1, stdout: "\\npermission denied\\n", stderr: message };
      if (scenario === "docker29-stdout-space") return { status: 1, stdout: " \\n", stderr: message };
      return { status: 1, stdout: "", stderr: message };
    };
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

test("Docker 29 lowercase absent proof still requires immutable ID cleanup and rejects unknown inspect errors", () => {
  const lowercase = mockRun("docker29-lowercase");
  assert.equal(lowercase.child.status, 0, lowercase.child.stderr);
  assert.equal(lowercase.calls.filter((entry) => entry.action === "rm").length, 2);
  const unknown = mockRun("unknown-absence");
  assert.equal(unknown.child.status, 1, "permission denied is never confirmed removal");
  assert.doesNotMatch(unknown.child.stdout, /9 real PASS/u);
  assert.equal(unknown.calls.filter((entry) => entry.action === "rm").length, 1);
});

test("Docker cleanup requires one exact absence diagnostic without other output and a real nonzero exit", () => {
  for (const scenario of ["mixed-previous-diagnostic", "absence-stdout", "absence-null-status", "absence-duplicate-lines"]) {
    const { child, calls } = mockRun(scenario);
    assert.equal(child.error, undefined, scenario);
    assert.equal(child.status, 1, scenario);
    assert.doesNotMatch(child.stdout, /9 real PASS/u, scenario);
    assert.match(child.stderr, /Private PG18 cleanup uncertain \(removal-unconfirmed\)/u, scenario);
    assert.equal(calls.filter((entry) => entry.action === "rm").length, 1, scenario);
  }
  for (const scenario of ["legacy-container-absence", "legacy-object-absence"]) {
    const { child, calls } = mockRun(scenario);
    assert.equal(child.error, undefined, scenario);
    assert.equal(child.status, 0, `${scenario}: ${child.stderr}`);
    assert.equal(calls.filter((entry) => entry.action === "rm").length, 2, scenario);
  }
});

test("Docker 29 cleanup accepts only one empty stdout newline with canonical missing diagnostic", () => {
  for (const scenario of ["docker29-stdout-lf", "docker29-stdout-crlf"]) {
    const { child, calls } = mockRun(scenario);
    assert.equal(child.error, undefined, scenario);
    assert.equal(child.status, 0, scenario + ": " + child.stderr);
    assert.match(child.stdout, /9 real PASS, 0 FAIL, 0 SKIP/u, scenario);
    assert.equal(calls.filter((entry) => entry.action === "rm").length, 2, scenario);
  }
  for (const scenario of ["docker29-stdout-double-lf", "docker29-stdout-mixed", "docker29-stdout-space"]) {
    const { child, calls } = mockRun(scenario);
    assert.equal(child.error, undefined, scenario);
    assert.equal(child.status, 1, scenario + ": contradicted stdout must block cleanup");
    assert.match(child.stderr, /Private PG18 cleanup uncertain \(removal-unconfirmed\)/u, scenario);
    assert.doesNotMatch(child.stdout, /9 real PASS/u, scenario);
    assert.equal(calls.filter((entry) => entry.action === "rm").length, 1, scenario);
  }
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
