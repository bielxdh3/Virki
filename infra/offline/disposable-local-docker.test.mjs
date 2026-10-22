import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import test, { after } from "node:test";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  LOCAL_ENGINE, requireLocalFixtureEnvironment, runOwnedLocalLinuxFixture,
  runProtectedWindowsJournalOperation, verifyTrustedWindowsDockerCli,
} from "./disposable-local-docker.mjs";
import {
  HOSTED_DOCKER, HOSTED_ENGINE, requireHostedLinuxFixtureEnvironment,
  verifyTrustedHostedLinuxDockerCli,
} from "./disposable-hosted-linux-docker.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const cli = "C:\\Program Files\\Docker\\Docker\\resources\\bin\\docker.exe";
const image = "node:22.23.3-bookworm@sha256:0e5f906573693feaa1e21057ebdcfdb5bd5021f050b2dc7c9deceb629c7da2a8";
const evidenceDirectory = mkdtempSync(path.join(tmpdir(), "virki-owned-docker-test-"));
after(() => rmSync(evidenceDirectory, { recursive: true, force: true }));
const safeArgs = [
  "run", "--rm", "--pull=never", "--platform=linux/amd64",
  "--network=none", "--read-only", "--cap-drop=ALL",
  "--security-opt=no-new-privileges", "--user", "0:0",
  "--pids-limit=128", "--memory=512m",
  "--tmpfs", "/tmp:rw,exec,nosuid,nodev,size=64m,mode=1777",
  "--mount", `type=bind,src=${root},dst=/workspace,readonly`,
  "--workdir", "/workspace", "--env", "VIRKI_DISPOSABLE_PEER_PROBE=1",
  image, "node", "--test", "infra/offline/native-peer/native-peer-probe.test.mjs",
];
const coordinatorArgs = [
  "run", "--rm", "--pull=never", "--platform=linux/amd64",
  "--network=none", "--read-only", "--cap-drop=ALL",
  "--security-opt=no-new-privileges", "--pids-limit=128",
  "--tmpfs", "/etc:rw,nosuid,nodev,noexec,size=16m,mode=755",
  "--tmpfs", "/var/lib:rw,nosuid,nodev,noexec,size=256m,mode=755",
  "--tmpfs", "/usr/local/lib/virki:rw,nosuid,nodev,noexec,size=16m,mode=700",
  "--tmpfs", "/run:rw,exec,nosuid,nodev,size=32m,mode=755",
  "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=64m,mode=1777",
  "--mount", `type=bind,src=${root},dst=/workspace,readonly`,
  "--workdir", "/workspace", "--env", "VIRKI_COORDINATOR_DISPOSABLE_CONTAINER=1",
  "--env", "VIRKI_OWNER_INSTALL_DISPOSABLE_FIXTURE=1",
  image, "node", "--test", "infra/offline/trusted-release-coordinator.test.mjs",
  "infra/offline/trusted-owner-installation.test.mjs",
];
const base = {
  platform: "win32",
  env: { PATH: "C:\\evil-cli", SystemRoot: "C:\\bogus" },
  cwd: root,
  reconciliationDirectory: evidenceDirectory,
};

test("unsafe platform and Docker CLI overrides reject without contacting any daemon", () => {
  let touched = false;
  const invoke = () => { touched = true; throw Error("must not be called"); };
  for (const entry of [
    { platform: "linux" },
    { env: { DOCKER_CONTEXT: "remote" } },
    { env: { DOCKER_HOST: "tcp://remote.invalid:2375" } },
    { env: { DOCKER_CONFIG: "C:\\remote" } },
    { env: { DOCKER_TLS_VERIFY: "1" } },
  ]) {
    assert.throws(() => runOwnedLocalLinuxFixture(safeArgs,
      { ...base, ...entry, invoke }), /local Docker Desktop|GitHub-hosted Linux CI/u);
  }
  assert.equal(touched, false);
  assert.doesNotThrow(() => requireLocalFixtureEnvironment("win32", {}));
});

test("RED→GREEN: Ubuntu Validate coordinator routes to the Linux CI Docker guard", () => {
  const workflow = readFileSync(path.join(root, ".github", "workflows", "ci.yml"), "utf8");
  const coordinator = readFileSync(path.join(root, "infra", "offline", "run-trusted-release-coordinator-test.mjs"), "utf8");
  const implementation = readFileSync(path.join(root, "infra", "offline", "disposable-local-docker.mjs"), "utf8");
  assert.match(workflow, /validate:[\s\S]*?runs-on: ubuntu-latest[\s\S]*?run: npm run test:offline:coordinator:container/u);
  assert.doesNotMatch(workflow, /actions\/upload-artifact/u,
    "CI must never export raw Docker owner receipts as workflow artifacts");
  assert.match(coordinator, /runOwnedLocalLinuxFixture\(args, \{ cwd: sourceRoot, timeout: 60_000 \}\)/u);
  assert.match(implementation, /if \(platform === "linux"\)\s*\{\s*assertFixtureArguments\(args, cwd, timeout\);\s*return runOwnedHostedLinuxFixture/u);
});

test("RED→GREEN: Linux CI coordinator uses pinned Unix Docker and owned immutable-ID cleanup", {
  skip: process.platform !== "linux",
}, (t) => {
  const directory = mkdtempSync(path.join(tmpdir(), "virki-gh-ci-mock-"));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const env = { GITHUB_ACTIONS: "true", CI: "true", RUNNER_OS: "Linux",
    RUNNER_ENVIRONMENT: "github-hosted", GITHUB_WORKSPACE: root, RUNNER_TEMP: directory };
  const calls = [];
  const invoke = (exe, argv, options) => {
    assert.equal(exe, HOSTED_DOCKER);
    assert.deepEqual(argv.slice(0, 2), ["--host", HOSTED_ENGINE]);
    assert.equal(options.env.PATH, "/usr/bin:/bin");
    assert.equal(Object.hasOwn(options.env, "DOCKER_HOST"), false);
    calls.push(argv);
    if (argv[2] === "info") return { status: 0, stdout: "linux|/var/lib/docker\n" };
    if (argv[2] === "run") return { status: 0 };
    if (argv[2] === "inspect") {
      const run = calls.find((v) => v[2] === "run");
      const name = run[run.indexOf("--name") + 1];
      const owner = run[run.indexOf("--label") + 1].split("=")[1];
      return { status: 0, stdout: `${"a".repeat(64)}|/${name}|${owner}` };
    }
    if (argv[2] === "rm") return { status: 0 };
    throw Error("unreviewed Docker operation");
  };
  assert.doesNotThrow(() => runOwnedLocalLinuxFixture(safeArgs, {
    cwd: root, platform: "linux", env, invoke, reconciliationDirectory: directory,
  }));
  assert.deepEqual(calls.map((v) => v[2]), ["info", "run", "inspect", "rm"]);
  assert.deepEqual(calls[3].slice(3), ["--force", "--volumes", "a".repeat(64)]);
  assert.deepEqual(readdirSync(directory), []);
  // This is the exact profile called by the ubuntu-latest `validate` job;
  // accepting only a peer fixture would leave the original P1 unresolved.
  calls.length = 0;
  assert.doesNotThrow(() => runOwnedLocalLinuxFixture(coordinatorArgs, {
    cwd: root, platform: "linux", env, invoke, reconciliationDirectory: directory,
  }));
  assert.deepEqual(calls.map((v) => v[2]), ["info", "run", "inspect", "rm"]);
  assert.deepEqual(readdirSync(directory), []);
});

test("RED→GREEN: hosted Linux denies foreign runner, Docker overrides and unsafe CLI", {
  skip: process.platform !== "linux",
}, (t) => {
  const directory = mkdtempSync(path.join(tmpdir(), "virki-gh-ci-negative-"));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const env = { GITHUB_ACTIONS: "true", CI: "true", RUNNER_OS: "Linux",
    RUNNER_ENVIRONMENT: "github-hosted", GITHUB_WORKSPACE: root, RUNNER_TEMP: directory };
  assert.doesNotThrow(() => requireHostedLinuxFixtureEnvironment("linux", env, root));
  for (const override of [
    { GITHUB_ACTIONS: "false" }, { RUNNER_OS: "Windows" },
    { RUNNER_ENVIRONMENT: "self-hosted" }, { DOCKER_HOST: "tcp://foreign:2375" },
    { DOCKER_CONTEXT: "remote" }, { BUILDX_CONFIG: "/tmp/remote" },
    { GITHUB_WORKSPACE: directory },
  ]) {
    let contacted = false;
    assert.throws(() => runOwnedLocalLinuxFixture(safeArgs, {
      cwd: root, platform: "linux", env: { ...env, ...override },
      invoke: () => { contacted = true; throw Error("unexpected daemon contact"); },
    }), /GitHub-hosted Linux CI|runner paths/u);
    assert.equal(contacted, false);
  }
  const trusted = {
    stat: (p) => p === HOSTED_DOCKER
      ? { isFile: () => true, isSymbolicLink: () => false, uid: 0, mode: 0o100755 }
      : { isSocket: () => true, isSymbolicLink: () => false, uid: 0, mode: 0o140660 },
    canonical: (p) => p,
  };
  assert.equal(verifyTrustedHostedLinuxDockerCli(trusted), HOSTED_DOCKER);
  assert.throws(() => verifyTrustedHostedLinuxDockerCli({
    ...trusted, stat: (p) => p === HOSTED_DOCKER
      ? { isFile: () => true, isSymbolicLink: () => false, uid: 1000, mode: 0o100755 }
      : trusted.stat(p),
  }), /trusted root-owned local Docker/u);
});

test("RED→GREEN: hosted Linux retains journal and never removes a foreign or timed-out container", {
  skip: process.platform !== "linux",
}, (t) => {
  const directory = mkdtempSync(path.join(tmpdir(), "virki-gh-ci-failure-"));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const env = { GITHUB_ACTIONS: "true", CI: "true", RUNNER_OS: "Linux",
    RUNNER_ENVIRONMENT: "github-hosted", GITHUB_WORKSPACE: root, RUNNER_TEMP: directory };
  for (const scenario of ["foreign-label", "timeout-missing", "wrong-missing-name", "rm-failure"]) {
    const calls = [];
    const invoke = (_exe, argv) => {
      calls.push(argv);
      if (argv[2] === "info") return { status: 0, stdout: "linux|/var/lib/docker\n" };
      const run = calls.find((v) => v[2] === "run");
      const name = run?.[run.indexOf("--name") + 1];
      const owner = run?.[run.indexOf("--label") + 1].split("=")[1];
      if (argv[2] === "run") return scenario === "timeout-missing"
        ? { status: null, error: { code: "ETIMEDOUT" } } : { status: 0 };
      if (argv[2] === "inspect") {
        if (scenario === "timeout-missing") {
          return { status: 1, stderr: `Error: No such object: ${name}` };
        }
        if (scenario === "wrong-missing-name") {
          return { status: 1, stderr: "Error: No such object: foreign-container" };
        }
        return { status: 0, stdout: `${"c".repeat(64)}|/${name}|${scenario === "foreign-label" ? "foreign" : owner}` };
      }
      if (argv[2] === "rm") return { status: 1, stderr: "daemon unavailable" };
      throw Error("unreviewed Docker call");
    };
    assert.throws(() => runOwnedLocalLinuxFixture(coordinatorArgs, {
      cwd: root, platform: "linux", env, invoke, reconciliationDirectory: directory,
    }), /reconciliation required/iu);
    assert.equal(calls.filter((v) => v[2] === "rm").length,
      scenario === "rm-failure" ? 1 : 0);
  }
  assert.equal(readdirSync(directory).length, 4, "every uncertain attempt needs independent retained owner evidence");
});

function fakeEngine({
  runStatus = 0, inspectOwner = "correct", inspectExists = true,
  delayedInspection = false, inspectId = "e".repeat(64), info = "Docker Desktop|linux",
  runThrows = false, inspectThrows = false, rmThrows = false,
} = {}) {
  const calls = [];
  let inspections = 0;
  const invoke = (exe, argv, options) => {
    assert.equal(exe, cli);
    assert.deepEqual(argv.slice(0, 2), ["--host", LOCAL_ENGINE]);
    assert.equal(Object.hasOwn(options.env, "DOCKER_HOST"), false);
    assert.equal(options.env.PATH.includes("evil-cli"), false);
    assert.equal(options.env.SystemRoot, "C:\\Windows");
    const command = argv[2];
    calls.push({ command, args: argv.slice(3) });
    if (command === "info") return { status: 0, stdout: info };
    if (command === "run") {
      if (runThrows) throw Error("mock process transport failed");
      return { status: runStatus, error: runStatus ? { code: "ETIMEDOUT" } : undefined };
    }
    if (command === "inspect") {
      if (inspectThrows) throw Error("mock inspect transport failed");
      inspections += 1;
      if (!inspectExists || (delayedInspection && inspections === 1)) {
        return { status: 1, stderr: "Error: No such object" };
      }
      const run = calls.find((call) => call.command === "run").args;
      const name = run[run.indexOf("--name") + 1];
      const ownerLabel = run[run.indexOf("--label") + 1];
      const owner = ownerLabel.split("=")[1];
      return { status: 0, stdout: `${inspectId}|/${name}|${inspectOwner === "correct" ? owner : "forged"}` };
    }
    if (command === "rm") {
      if (rmThrows) throw Error("mock removal transport failed");
      return { status: 0, stdout: "removed" };
    }
    throw new Error("unexpected command");
  };
  return { calls, invoke };
}

test("success launches unique labeled fixture and only removes the verified immutable container ID", () => {
  const fake = fakeEngine();
  runOwnedLocalLinuxFixture(safeArgs,
    { ...base, invoke: fake.invoke });
  assert.deepEqual(fake.calls.map((call) => call.command), ["info", "run", "inspect", "rm"]);
  const run = fake.calls[1].args;
  assert.match(run[run.indexOf("--name") + 1], /^virki-offline-fixture-[a-f0-9]{32}$/u);
  assert.match(run[run.indexOf("--label") + 1], /^dev\.virki\.offline\.disposable-owner=[a-f0-9]{32}$/u);
  assert.deepEqual(fake.calls[3].args, ["--force", "--volumes", "e".repeat(64)]);
});

test("a completed --rm container requires no removal and cannot mutate unrelated resources", () => {
  const fake = fakeEngine({ inspectExists: false });
  runOwnedLocalLinuxFixture(safeArgs,
    { ...base, invoke: fake.invoke });
  assert.deepEqual(fake.calls.map((call) => call.command), ["info", "run", "inspect"]);
});

test("timeout attempts scoped cleanup, then reports failure without leaking executable output", () => {
  const fake = fakeEngine({ runStatus: 1 });
  assert.throws(() => runOwnedLocalLinuxFixture(safeArgs,
    { ...base, invoke: fake.invoke }), /failed or exceeded/u);
  assert.equal(fake.calls[3].command, "rm");
});

test("ownership mismatch refuses deletion and unexpected endpoint self-report blocks before Docker run", () => {
  const forged = fakeEngine({ inspectOwner: "forged" });
  assert.throws(() => runOwnedLocalLinuxFixture(safeArgs,
    { ...base, invoke: forged.invoke }), /ownership proof rejected/u);
  assert.equal(forged.calls.some((call) => call.command === "rm"), false);

  const foreign = fakeEngine({ info: "Linux|linux" });
  assert.throws(() => runOwnedLocalLinuxFixture(safeArgs,
    { ...base, invoke: foreign.invoke }), /unexpected Docker Desktop engine/u);
  assert.deepEqual(foreign.calls.map((call) => call.command), ["info"]);
});

test("rejects host escape flags, arbitrary mounts, devices, and execution profiles before invoking Docker", () => {
  const cases = [
    ["--privileged"], ["--network=host"], ["--pid=host"], ["--ipc=host"],
    ["--device=/dev/kvm"], ["--cap-add=SYS_ADMIN"], ["--security-opt=seccomp=unconfined"],
    ["-v", "/var/run/docker.sock:/var/run/docker.sock"],
    ["--mount", "type=bind,src=//./pipe/docker_engine,dst=/var/run/docker.sock"],
    ["--mount", "type=bind,src=C:\\Users,dst=/workspace,readonly"],
    ["--mount", `type=bind,src=${root},dst=/workspace`],
    ["--label", "dev.virki.offline.disposable-owner=forged"],
    ["--env", "DOCKER_HOST=tcp://foreign.invalid"],
    ["--tmpfs", "/workspace:rw,exec"],
  ];
  let calls = 0;
  for (const extra of cases) {
    const args = [...safeArgs.slice(0, -4), ...extra, ...safeArgs.slice(-4)];
    assert.throws(() => runOwnedLocalLinuxFixture(args, {
      ...base, invoke: () => { calls += 1; throw new Error("must not run"); },
    }), /Invalid bounded disposable Docker fixture command/u, JSON.stringify(extra));
  }
  for (const args of [
    [...safeArgs.slice(0, -1), "outside.test.mjs"],
    [...safeArgs.slice(0, -3), "alpine:latest", ...safeArgs.slice(-3)],
    [...safeArgs.slice(0, -1), "../trusted-owner-installation.test.mjs"],
  ]) {
    assert.throws(() => runOwnedLocalLinuxFixture(args, {
      ...base, invoke: () => { calls += 1; },
    }), /Invalid bounded disposable Docker fixture command/u);
  }
  assert.equal(calls, 0);
});

test("rejects missing, redirected, unsigned, and unexpected-publisher Docker CLIs", () => {
  const good = {
    stat: () => ({ isFile: () => true, isSymbolicLink: () => false }),
    canonicalize: () => cli,
    authenticate: (_exe, _args) => ({ status: 0, stdout: "DOCKER_SIGNED" }),
  };
  assert.equal(verifyTrustedWindowsDockerCli(good), cli);
  assert.throws(() => verifyTrustedWindowsDockerCli({
    ...good, stat: () => { throw new Error("ENOENT"); },
  }), /trusted Docker Desktop CLI/u);
  assert.throws(() => verifyTrustedWindowsDockerCli({
    ...good, canonicalize: () => "C:\\evil-cli\\docker.exe",
  }), /trusted Docker Desktop CLI/u);
  assert.throws(() => verifyTrustedWindowsDockerCli({
    ...good, stat: () => ({ isFile: () => true, isSymbolicLink: () => true }),
  }), /trusted Docker Desktop CLI/u);
  assert.throws(() => verifyTrustedWindowsDockerCli({
    ...good, authenticate: () => ({ status: 1, stdout: "" }),
  }), /trusted Docker Desktop CLI/u);
  assert.throws(() => verifyTrustedWindowsDockerCli({
    ...good, authenticate: () => ({ status: 0, stdout: "not Docker" }),
  }), /trusted Docker Desktop CLI/u);
});

function evidenceForRun(fake) {
  const run = fake.calls.find(({ command }) => command === "run").args;
  const name = run[run.indexOf("--name") + 1];
  const owner = run[run.indexOf("--label") + 1].split("=")[1];
  const file = path.join(evidenceDirectory, `${name}.jsonl`);
  return { name, owner, file };
}

function readEvidence(file) {
  return readFileSync(file, "utf8").trim().split("\n").map((entry) => JSON.parse(entry));
}

test("timeout plus immediate not-found inspect can hide a delayed orphan, retains owner evidence", () => {
  const fake = fakeEngine({ runStatus: 1, delayedInspection: true });
  let error;
  try {
    runOwnedLocalLinuxFixture(safeArgs, { ...base, invoke: fake.invoke });
  } catch (caught) {
    error = caught;
  }
  const evidence = evidenceForRun(fake);
  assert.match(error?.message ?? "", /reconciliation required/iu);
  assert.ok(error.message.includes(evidence.file));
  const [stored] = readEvidence(evidence.file);
  assert.equal(stored.name, evidence.name);
  assert.equal(stored.owner, evidence.owner);
  assert.equal(stored.engine, LOCAL_ENGINE);
  assert.equal(stored.image, image);
  assert.equal(fake.calls.filter(({ command }) => command === "rm").length, 0);
  // The daemon reveals the previously invisible container after the failed run.
  const appeared = fake.invoke(cli, ["--host", LOCAL_ENGINE, "inspect", "--format", "unused", evidence.name],
    { env: { PATH: "C:\\Windows", SystemRoot: "C:\\Windows" } });
  assert.equal(appeared.status, 0);
  assert.ok(appeared.stdout.includes(`/${evidence.name}|${evidence.owner}`));
  assert.equal(readdirSync(evidenceDirectory).includes(path.basename(evidence.file)), true);
});

test("malformed immutable CID cannot authorize cleanup and retains reconciliation evidence", () => {
  const fake = fakeEngine({ inspectId: "not-a-verified-cid" });
  let error;
  try {
    runOwnedLocalLinuxFixture(safeArgs, { ...base, invoke: fake.invoke });
  } catch (caught) {
    error = caught;
  }
  const evidence = evidenceForRun(fake);
  assert.match(error?.message ?? "", /ownership proof rejected/iu);
  assert.ok(error.message.includes(evidence.file));
  const [initial, observation] = readEvidence(evidence.file);
  assert.equal(initial.owner, evidence.owner);
  assert.equal(observation.observedId, "not-a-verified-cid");
  assert.equal(fake.calls.some(({ command }) => command === "rm"), false);
});

test("journal write failure denies launch without any docker run", () => {
  const invalidDirectory = path.join(evidenceDirectory, "not-a-directory");
  writeFileSync(invalidDirectory, "occupied");
  const fake = fakeEngine();
  assert.throws(() => runOwnedLocalLinuxFixture(safeArgs, {
    ...base, reconciliationDirectory: invalidDirectory, invoke: fake.invoke,
  }), /reconciliation evidence/iu);
  assert.deepEqual(fake.calls.map(({ command }) => command), ["info"]);
});

test("successful --rm and missing container clears its evidence only after a completed run", () => {
  const fake = fakeEngine({ inspectExists: false });
  runOwnedLocalLinuxFixture(safeArgs, { ...base, invoke: fake.invoke });
  const evidence = evidenceForRun(fake);
  assert.equal(existsSync(evidence.file), false);
  assert.equal(fake.calls.some(({ command }) => command === "rm"), false);
});

test("timed-out run retains evidence even after successful verified-ID removal", () => {
  const fake = fakeEngine({ runStatus: 1 });
  assert.throws(() => runOwnedLocalLinuxFixture(safeArgs, {
    ...base, invoke: fake.invoke,
  }), /reconciliation required/iu);
  const evidence = evidenceForRun(fake);
  assert.equal(existsSync(evidence.file), true);
  assert.deepEqual(fake.calls.map(({ command }) => command), ["info", "run", "inspect", "rm"]);
  assert.equal(readEvidence(evidence.file)[1].observedId, "e".repeat(64));
});

test("run exception and inspection transport failure both retain owner evidence", () => {
  for (const config of [{ runThrows: true, inspectExists: false }, { inspectThrows: true }]) {
    const fake = fakeEngine(config);
    assert.throws(() => runOwnedLocalLinuxFixture(safeArgs, {
      ...base, invoke: fake.invoke,
    }), /reconciliation required/iu);
    const evidence = evidenceForRun(fake);
    assert.equal(readEvidence(evidence.file)[0].owner, evidence.owner);
    assert.equal(fake.calls.some(({ command }) => command === "rm"), false);
  }
});

test("removal transport failure preserves inspected CID for manual reconciliation", () => {
  const fake = fakeEngine({ rmThrows: true });
  assert.throws(() => runOwnedLocalLinuxFixture(safeArgs, {
    ...base, invoke: fake.invoke,
  }), /reconciliation required/iu);
  const evidence = evidenceForRun(fake);
  assert.equal(readEvidence(evidence.file)[1].observedId, "e".repeat(64));
  assert.deepEqual(fake.calls.map(({ command }) => command), ["info", "run", "inspect", "rm"]);
});

test("Windows private journal binds creation, append, and removal to verified handles", {
  skip: process.platform !== "win32",
}, () => {
  const directory = mkdtempSync(path.join(homedir(), ".virki-journal-test-"));
  const owner = randomBytes(16).toString("hex");
  const name = `virki-offline-fixture-${owner}`;
  const file = path.join(directory, `${name}.jsonl`);
  const request = { directory, name, owner };
  try {
    assert.doesNotThrow(() => runProtectedWindowsJournalOperation("create",
      { ...request, line: JSON.stringify({ owner, name }) }));
    assert.equal(readFileSync(file, "utf8").trim(), JSON.stringify({ owner, name }));
    runProtectedWindowsJournalOperation("append", { ...request, line: '{"event":"inspect"}' });
    assert.equal(readFileSync(file, "utf8").trim().split("\n").length, 2);
    runProtectedWindowsJournalOperation("remove", request);
    assert.equal(existsSync(file), false);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("Windows journal rejects world-writable ACL and reparse ancestor before evidence creation", {
  skip: process.platform !== "win32",
}, () => {
  const directory = mkdtempSync(path.join(homedir(), ".virki-journal-test-"));
  const junction = path.join(directory, "redirect");
  const owner = randomBytes(16).toString("hex");
  const name = `virki-offline-fixture-${owner}`;
  const request = { name, owner, line: '{"version":1}' };
  try {
    // A new private leaf in a verified user profile may be created.
    runProtectedWindowsJournalOperation("create", { ...request, directory });
    const otherOwner = randomBytes(16).toString("hex");
    symlinkSync(directory, junction, "junction");
    assert.throws(() => runProtectedWindowsJournalOperation("create", {
      ...request, name: `virki-offline-fixture-${otherOwner}`,
      owner: otherOwner, directory: junction,
    }), /ACL binding unavailable/u);
    const granted = spawnSync("C:\\Windows\\System32\\icacls.exe",
      [directory, "/grant", "*S-1-1-0:(M)"], { encoding: "utf8", windowsHide: true });
    assert.equal(granted.status, 0);
    assert.throws(() => runProtectedWindowsJournalOperation("append",
      { ...request, directory, line: '{"event":"forged"}' }), /ACL binding unavailable/u);
    const before = readFileSync(path.join(directory, `${name}.jsonl`), "utf8");
    assert.equal(before.trim(), request.line);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("Windows journal checks opened file DACL before append and delete", {
  skip: process.platform !== "win32",
}, () => {
  const directory = mkdtempSync(path.join(homedir(), ".virki-journal-test-"));
  const owner = randomBytes(16).toString("hex");
  const name = `virki-offline-fixture-${owner}`;
  const file = path.join(directory, `${name}.jsonl`);
  const request = { directory, name, owner };
  try {
    runProtectedWindowsJournalOperation("create", { ...request, line: '{"version":1}' });
    const granted = spawnSync("C:\\Windows\\System32\\icacls.exe",
      [file, "/grant", "*S-1-1-0:(M)"], { encoding: "utf8", windowsHide: true });
    assert.equal(granted.status, 0);
    assert.throws(() => runProtectedWindowsJournalOperation("append",
      { ...request, line: '{"event":"unexpected"}' }), /ACL binding unavailable/u);
    assert.throws(() => runProtectedWindowsJournalOperation("remove", request),
      /ACL binding unavailable/u);
    assert.equal(readFileSync(file, "utf8").trim(), '{"version":1}');
    assert.equal(existsSync(file), true);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("Windows journal rejects read-only outsider access to its Docker owner token", {
  skip: process.platform !== "win32",
}, () => {
  for (const target of ["directory", "file"]) {
    const directory = mkdtempSync(path.join(homedir(), ".virki-journal-test-"));
    const owner = randomBytes(16).toString("hex");
    const name = `virki-offline-fixture-${owner}`;
    const file = path.join(directory, `${name}.jsonl`);
    const request = { directory, name, owner };
    try {
      runProtectedWindowsJournalOperation("create", { ...request, line: JSON.stringify({ owner, name }) });
      const granted = spawnSync("C:\\Windows\\System32\\icacls.exe",
        [target === "directory" ? directory : file, "/grant", "*S-1-1-0:(R)"],
        { encoding: "utf8", windowsHide: true });
      assert.equal(granted.status, 0);
      assert.throws(() => runProtectedWindowsJournalOperation("append",
        { ...request, line: '{"event":"forged"}' }), /ACL binding unavailable/u);
      assert.throws(() => runProtectedWindowsJournalOperation("remove", request),
        /ACL binding unavailable/u);
      assert.equal(readFileSync(file, "utf8").trim(), JSON.stringify({ owner, name }));
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  }
});
