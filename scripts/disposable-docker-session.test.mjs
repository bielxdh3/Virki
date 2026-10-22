import assert from "node:assert/strict";
import { fsyncSync, readFileSync, mkdtempSync, renameSync, rmSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { createDisposableDockerSession } from "./lib/disposable-docker-session.mjs";

const OWNER = "a".repeat(32);

function receipt(pathname) {
  return JSON.parse(readFileSync(pathname, "utf8").trim().split(/\r?\n/u).at(-1));
}

function fixture({ failCreate = false, failStart = false, missingAfterFailure = false, failCleanup = false,
  platform = "win32", nativeArch = "x64", serverArch = "amd64", envOverride = {} } = {}) {
  const root = mkdtempSync(path.join(os.tmpdir(), "virki-docker-session-test-"));
  const calls = [];
  let exists = false;
  const spawn = (cli, args, options) => {
    calls.push({ cli, args, env: options.env });
    const action = args.slice(2);
    if (action[0] === "version") return { status: 0, stdout: `linux|${serverArch}\n`, stderr: "" };
    if (action[0] === "network" && action[1] === "create") {
      exists = !missingAfterFailure;
      return { status: failCreate ? 1 : 0, stdout: "", stderr: failCreate ? "ambiguous Docker CLI timeout" : "" };
    }
    if (action[0] === "run" && failStart) {
      return { status: 1, stdout: "", stderr: "Docker CLI timed out before returning CID" };
    }
    if (action[0] === "network" && action[1] === "inspect") {
      if (exists && action[2] === "validation-network") {
        return { status: 0, stdout: JSON.stringify([{ Id: "b".repeat(64), Name: "validation-network", Labels: { "org.virki.validation": OWNER } }]), stderr: "" };
      }
      return { status: 1, stdout: "[]", stderr: `Error response from daemon: network ${action[2]} not found` };
    }
    if (action[0] === "container" && action[1] === "inspect") {
      return { status: 1, stdout: "[]", stderr: `Error response from daemon: No such container: ${action[2]}` };
    }
    if (action[0] === "network" && action[1] === "rm") {
      if (failCleanup) return { status: 1, stdout: "", stderr: "ambiguous removal" };
      exists = false;
      return { status: 0, stdout: "", stderr: "" };
    }
    throw Error(`Unexpected fake Docker action ${action.join(" ")}`);
  };
  const env = { ...process.env, DOCKER_HOST: "tcp://production.example.invalid:2376",
    DOCKER_CONTEXT: "production", DOCKER_TLS_VERIFY: "1",
    VIRKI_VALIDATION_EVIDENCE_DIR: path.join(root, "unused-user-environment-override"), ...envOverride };
  const session = createDisposableDockerSession({ kind: "runtime", owner: OWNER,
    containers: ["validation-container"], network: "validation-network", env,
    platform, nativeArch, receiptDirectory: root, spawn });
  return { root, calls, session, cleanup: () => rmSync(root, { recursive: true, force: true }) };
}

test("explicit Windows Docker Desktop Linux pipe is used, never ambient remote DOCKER_HOST", (t) => {
  const f = fixture(); t.after(f.cleanup);
  f.session.mutate("create-network", ["network", "create", "--label", `org.virki.validation=${OWNER}`, "validation-network"]);
  f.session.cleanup();
  f.session.finish(true);
  assert.ok(f.calls.every(({ cli, args, env }) =>
    cli === "C:\\Program Files\\Docker\\Docker\\resources\\bin\\docker.exe" &&
    args[0] === "--host" && args[1] === "npipe:////./pipe/dockerDesktopLinuxEngine" &&
    !Object.keys(env).some((key) => key.startsWith("DOCKER_"))));
});

test("lost Docker create ACK remains unresolved even if immediate inspection says absent", (t) => {
  const f = fixture({ failCreate: true, missingAfterFailure: true }); t.after(f.cleanup);
  assert.throws(() => f.session.mutate("create-network", ["network", "create", "--label", `org.virki.validation=${OWNER}`, "validation-network"]), /uncertain/u);
  f.session.cleanup();
  assert.throws(() => f.session.finish(false), /reconciliation/u);
  const record = receipt(f.session.receiptPath);
  assert.equal(record.status, "RECONCILIATION_REQUIRED");
  assert.equal(record.owner, OWNER);
  assert.deepEqual(record.resources, { containers: ["validation-container"], network: "validation-network" });
  assert.deepEqual(record.uncertainOperations, ["create-network"]);
});

test("ambiguous Docker rm keeps ownership receipt for manual reconciliation", (t) => {
  const f = fixture({ failCleanup: true }); t.after(f.cleanup);
  f.session.mutate("create-network", ["network", "create", "--label", `org.virki.validation=${OWNER}`, "validation-network"]);
  assert.throws(() => f.session.cleanup(), /uncertain/u);
  assert.throws(() => f.session.finish(true), /reconciliation/u);
  const record = receipt(f.session.receiptPath);
  assert.deepEqual(record.uncertainOperations, ["remove-network"]);
  assert.equal(record.status, "RECONCILIATION_REQUIRED");
});

test("lost container CID after Docker start cannot be cleared by an absent immediate inspect", (t) => {
  const f = fixture({ failStart: true, missingAfterFailure: true }); t.after(f.cleanup);
  assert.throws(() => f.session.mutate("create-container", ["run", "--detach", "--name", "validation-container",
    "--label", `org.virki.validation=${OWNER}`, "scratch-local-image"]), /uncertain/u);
  f.session.cleanup();
  assert.throws(() => f.session.finish(false), /reconciliation/u);
  const record = receipt(f.session.receiptPath);
  assert.deepEqual(record.uncertainOperations, ["create-container"]);
  assert.equal(record.resources.containers[0], "validation-container");
  assert.equal(f.calls.some((call) => call.args.includes("--force")), false);
});

test("Linux local/WSL refuses ambient Docker, only claimed trusted hosted CI is allowed", (t) => {
  assert.throws(() => createDisposableDockerSession({ kind: "runtime", owner: OWNER,
    network: "validation-network", containers: [], platform: "linux", env: {},
    spawn: () => { throw Error("Docker must not be contacted"); } }), /trusted runner/u);
  const f = fixture(); t.after(f.cleanup);
  assert.ok(f.session.receiptPath.startsWith(f.root));
  f.session.cleanup(); f.session.finish(true);
});

test("ARM64 hosted Linux matrix is accepted only with matching native process and engine arch", (t) => {
  const linuxEnv = { GITHUB_ACTIONS: "true", CI: "true", RUNNER_OS: "Linux",
    RUNNER_ENVIRONMENT: "github-hosted", RUNNER_ARCH: "ARM64", VIRKI_BUILD_ARCH: "arm64",
    VIRKI_BUILD_REVISION: "b".repeat(40) };
  const f = fixture({ platform: "linux", nativeArch: "arm64", serverArch: "arm64", envOverride: linuxEnv });
  t.after(f.cleanup);
  f.session.mutate("create-network", ["network", "create", "--label", `org.virki.validation=${OWNER}`, "validation-network"]);
  f.session.cleanup(); f.session.finish(true);
  assert.ok(f.calls.every(({ cli }) => cli === "/usr/bin/docker"));
  assert.equal(receipt(f.session.receiptPath).status, "PASS");
});

test("CI matrix architecture spoofing, wrong runner/native arch and Docker daemon mismatch reject", (t) => {
  const good = { GITHUB_ACTIONS: "true", CI: "true", RUNNER_OS: "Linux",
    RUNNER_ENVIRONMENT: "github-hosted", RUNNER_ARCH: "ARM64", VIRKI_BUILD_ARCH: "arm64",
    VIRKI_BUILD_REVISION: "c".repeat(40) };
  for (const variation of [
    { nativeArch: "x64", serverArch: "arm64" },
    { nativeArch: "arm64", serverArch: "amd64" },
    { nativeArch: "arm64", serverArch: "arm64", envOverride: { ...good, RUNNER_ARCH: "X64" } },
    { nativeArch: "arm64", serverArch: "arm64", envOverride: { ...good, VIRKI_BUILD_REVISION: "invalid" } },
  ]) {
    const root = mkdtempSync(path.join(os.tmpdir(), "virki-docker-bad-arch-"));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    assert.throws(() => createDisposableDockerSession({ kind: "runtime", owner: OWNER,
      network: "validation-network", containers: [], platform: "linux",
      nativeArch: variation.nativeArch, receiptDirectory: root,
      env: variation.envOverride ?? good,
      spawn: (_cli, _args) => ({ status: 0, stdout: `linux|${variation.serverArch}\n`, stderr: "" }),
    }), /refused/u);
  }
});

test("receipt root alias and preexisting receipt are rejected before any Docker mutation", (t) => {
  const root = mkdtempSync(path.join(os.tmpdir(), "virki-docker-root-"));
  const fake = mkdtempSync(path.join(os.tmpdir(), "virki-docker-alias-"));
  t.after(() => { rmSync(root, { recursive: true, force: true }); rmSync(fake, { recursive: true, force: true }); });
  const alias = path.join(root, "alias");
  try { symlinkSync(fake, alias, process.platform === "win32" ? "junction" : "dir"); }
  catch (error) {
    if (["EPERM", "EACCES"].includes(error.code)) { t.skip("symlink not permitted by this host"); return; }
    throw error;
  }
  const request = { kind: "runtime", owner: OWNER, network: "validation-network", containers: [],
    receiptDirectory: alias, platform: "win32", spawn: () => { throw Error("Docker may not be contacted"); } };
  assert.throws(() => createDisposableDockerSession(request), /unsafe path alias/u);
  writeFileSync(path.join(root, `runtime-${OWNER}.jsonl`), "preserve-original\n");
  assert.throws(() => createDisposableDockerSession({ ...request, receiptDirectory: root,
    spawn: (_cli, _args) => ({ status: 0, stdout: "linux|amd64\n", stderr: "" }) }), /EEXIST/u);
  assert.equal(readFileSync(path.join(root, `runtime-${OWNER}.jsonl`), "utf8"), "preserve-original\n");
});

test("live path swap after receipt open cannot redirect the pinned journal", (t) => {
  if (process.platform !== "linux") { t.skip("Linux inode swap fixture"); return; }
  const f = fixture();
  t.after(f.cleanup);
  const previous = `${f.session.receiptPath}.previous`;
  const unrelated = path.join(f.root, "unrelated.txt");
  writeFileSync(unrelated, "external-bytes\n");
  renameSync(f.session.receiptPath, previous);
  symlinkSync(unrelated, f.session.receiptPath);
  const previousCalls = f.calls.length;
  assert.throws(() => f.session.mutate("create-network", ["network", "create", "validation-network"]),
    /receipt directory or pinned file identity changed/u);
  assert.equal(f.calls.length, previousCalls);
  assert.equal(readFileSync(unrelated, "utf8"), "external-bytes\n");
  unlinkSync(f.session.receiptPath);
  renameSync(previous, f.session.receiptPath);
  f.session.cleanup();
  f.session.finish(false);
  assert.equal(receipt(f.session.receiptPath).status, "SMOKE_FAILED_CLEANED");
});

test("renamed and symlinked parent directory refuses mutation on the original receipt FD", (t) => {
  if (process.platform !== "linux") { t.skip("Linux directory rename fixture"); return; }
  const f = fixture();
  const original = `${f.root}.original`;
  const foreign = mkdtempSync(path.join(os.tmpdir(), "virki-foreign-root-"));
  t.after(() => { rmSync(f.root, { recursive: true, force: true }); rmSync(original, { recursive: true, force: true });
    rmSync(foreign, { recursive: true, force: true }); });
  renameSync(f.root, original);
  symlinkSync(foreign, f.root);
  assert.throws(() => f.session.mutate("create-network", ["network", "create", "validation-network"]),
    /unsafe path alias/u);
  unlinkSync(f.root);
  renameSync(original, f.root);
  f.session.cleanup(); f.session.finish(false);
  assert.equal(receipt(f.session.receiptPath).status, "SMOKE_FAILED_CLEANED");
});

test("POSIX fsync failure for receipt directory or parent blocks Docker before first contact", (t) => {
  if (process.platform !== "linux") { t.skip("Linux directory fsync test"); return; }
  const env = {
    GITHUB_ACTIONS: "true", CI: "true", RUNNER_OS: "Linux", RUNNER_ENVIRONMENT: "github-hosted",
    RUNNER_ARCH: "X64", VIRKI_BUILD_ARCH: "amd64", VIRKI_BUILD_REVISION: "a".repeat(40),
  };
  for (const failingDirectory of ["root", "parent"]) {
    const root = mkdtempSync(path.join(os.tmpdir(), "virki-powerloss-sync-"));
    t.after(() => rmSync(root, { force: true, recursive: true }));
    let dockerCalls = 0;
    const syncCalls = [];
    assert.throws(() => createDisposableDockerSession({
      kind: "runtime", owner: OWNER, containers: [], network: "validation-network",
      platform: "linux", nativeArch: "x64", env, receiptDirectory: root,
      spawn: () => { dockerCalls++; return { status: 0, stdout: "linux|amd64\n", stderr: "" }; },
      fsyncDirectory: (fd, label) => {
        syncCalls.push(label);
        if (label === failingDirectory) throw new Error(`injected ${label} fsync EIO`);
        fsyncSync(fd);
      },
    }), /injected (root|parent) fsync EIO/u);
    assert.equal(dockerCalls, 0, "neither preflight nor a Docker mutation should run without durable receipt namespace");
    assert.ok(syncCalls.includes(failingDirectory), `missing ${failingDirectory} fsync barrier`);
  }
});

test("POSIX persists receipt-root and mkdtemp-parent entries before the first Docker probe", (t) => {
  if (process.platform !== "linux") { t.skip("Linux fsync ordering test"); return; }
  const root = mkdtempSync(path.join(os.tmpdir(), "virki-powerloss-order-"));
  t.after(() => rmSync(root, { force: true, recursive: true }));
  const events = [];
  const session = createDisposableDockerSession({
    kind: "runtime", owner: OWNER, containers: [], network: "validation-network",
    platform: "linux", nativeArch: "x64", receiptDirectory: root,
    env: { GITHUB_ACTIONS: "true", CI: "true", RUNNER_OS: "Linux",
      RUNNER_ENVIRONMENT: "github-hosted", RUNNER_ARCH: "X64", VIRKI_BUILD_ARCH: "amd64",
      VIRKI_BUILD_REVISION: "b".repeat(40) },
    fsyncDirectory: (fd, label) => { fsyncSync(fd); events.push(`fsync:${label}`); },
    spawn: (_cli, args) => {
      if (args[2] === "version") {
        events.push("docker:probe");
        return { status: 0, stdout: "linux|amd64\n", stderr: "" };
      }
      return { status: 1, stdout: "", stderr: `Error response from daemon: network ${args[4]} not found` };
    },
  });
  assert.deepEqual(events, ["fsync:root", "fsync:parent", "docker:probe"]);
  session.cleanup(); session.finish(true);
  assert.equal(receipt(session.receiptPath).status, "PASS");
});
