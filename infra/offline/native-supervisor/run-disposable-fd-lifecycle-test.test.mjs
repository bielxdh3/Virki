import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  existsSync, mkdtempSync, rmSync, renameSync, mkdirSync, writeFileSync,
  readFileSync, linkSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  DISPOSABLE_IMAGE, LOCAL_DESKTOP_ENGINE, planDisposableFixture,
  validateCleanupIdentity, cleanupOwnedContainer, finalizeFixtureRecord,
  prepareOwnedFixtureDirectory, runnerFailureDiagnostic,
} from "./run-disposable-fd-lifecycle-test.mjs";

const runner = fileURLToPath(new URL("./run-disposable-fd-lifecycle-test.mjs", import.meta.url));
const token = "c".repeat(32);
const fullId = "a".repeat(64);
const planned = () => planDisposableFixture({
  ownerToken: token,
  cidfile: path.resolve("fixture-owned-container.id"),
});

test("fixed local Windows Docker Desktop Linux named pipe overrides ambient remote contexts", () => {
  const plan = planned();
  assert.deepEqual([...plan.dockerPrefix], ["--host", LOCAL_DESKTOP_ENGINE]);
  assert.equal(LOCAL_DESKTOP_ENGINE, "npipe:////./pipe/dockerDesktopLinuxEngine");
  assert.deepEqual(plan.args.slice(0, 3), ["--host", LOCAL_DESKTOP_ENGINE, "run"]);
  assert.ok(!plan.args.includes("--context"));
  assert.ok(!plan.args.includes("--privileged"));
  assert.ok(!plan.args.includes("/var/run/docker.sock"));
});
test("runner pins digest and refuses image pulls or Docker API endpoint substitution", () => {
  const args = planned().args;
  assert.match(DISPOSABLE_IMAGE, /@sha256:[0-9a-f]{64}$/u);
  assert.ok(args.includes("--pull=never"));
  assert.ok(args.includes(DISPOSABLE_IMAGE));
  assert.ok(!args.some((entry) => /ssh:\/\/|tcp:\/\/|unix:\/\//u.test(entry)));
});
test("runner requires labeled CID file and immutable 64-hex owner identity", () => {
  const args = planned().args;
  assert.ok(args.includes("--cidfile"));
  assert.ok(args.includes("--label"));
  assert.ok(args.includes("dev.virki.disposable-fd-lifecycle=" + token));
  assert.ok(validateCleanupIdentity(fullId, token, token));
  for (const [id, label, expected] of [
    ["containerName", token, token], [fullId.slice(0, 12), token, token],
    [fullId, "another-token", token], [fullId, token + "\n", token],
    [fullId + " --force", token, token], [fullId, token, "../other"],
  ]) assert.equal(validateCleanupIdentity(id, label, expected), false);
});
test("runner is read-only and cannot mount daemon sockets or join host network", () => {
  const args = planned().args;
  for (const required of [
    "--network=none", "--read-only", "--cap-drop=ALL",
    "--security-opt=no-new-privileges", "--pids-limit=128",
    "--memory=512m", "--rm",
  ]) assert.ok(args.includes(required), required);
  assert.ok(args.some((entry) => entry.endsWith(",dst=/workspace,readonly")));
});
test("runner prevents untrusted plan arguments from selecting image or arbitrary mounts", () => {
  assert.throws(() => planDisposableFixture({
    ownerToken: "not an owner token", cidfile: path.resolve("owned.cid"),
  }));
  assert.throws(() => planDisposableFixture({
    ownerToken: token, cidfile: "relative.cid",
  }));
  const plan = planDisposableFixture({ ownerToken: token,
    cidfile: path.resolve("owned.cid"), projectRoot: "/malicious" });
  assert.ok(!plan.args.some((value) => value.includes("/malicious")));
  assert.ok(Object.isFrozen(plan.args));
});
test("runner cannot automatically execute Docker on Windows or WSL", () => {
  const result = spawnSync(process.execPath, [runner], {
    timeout: 2000, encoding: "utf8",
    env: { ...process.env, VIRKI_DISPOSABLE_SUPERVISOR_RUN_DOCKER: "0",
      DOCKER_HOST: "tcp://203.0.113.99:2375", DOCKER_CONTEXT: "remote-prod" },
  });
  assert.equal(result.error, undefined);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Docker fixture blocked/u);
  assert.match(result.stderr, /before Docker CLI invocation/u);
  assert.doesNotMatch(result.stderr, /no daemon was contacted/u);
});

test("CLI-invoked error never falsely claims the daemon was not contacted", () => {
  const diagnostic = runnerFailureDiagnostic("cli-invoked");
  assert.match(diagnostic, /after Docker CLI invocation/u);
  assert.match(diagnostic, /contact cannot be ruled out/u);
  assert.doesNotMatch(diagnostic, /no daemon was contacted/u);
  const cleanup = runnerFailureDiagnostic("cleanup-attempted");
  assert.match(cleanup, /Docker CLI/u);
  assert.match(cleanup, /contact cannot be ruled out/u);
  assert.doesNotMatch(cleanup, /no daemon was contacted/u);
  assert.match(runnerFailureDiagnostic("unknown"), /contact cannot be ruled out/u);
  assert.match(runnerFailureDiagnostic("preflight"), /before Docker CLI invocation/u);
});

test("failed Docker spawn without CID cannot prove cleanup and must preserve its fixture path", (t) => {
  const { owned, cidfile } = prepareOwnedFixtureDirectory();
  t.after(() => rmSync(owned, { recursive: true, force: true }));
  const plan = planDisposableFixture({ ownerToken: token, cidfile });
  // Simulate a timed-out/errored docker run BEFORE cidfile creation.
  // This branch must never invoke docker inspect/rm or touch Docker itself.
  assert.equal(existsSync(cidfile), false);
  const cleanupConfirmed = cleanupOwnedContainer(cidfile, plan, {});
  assert.equal(cleanupConfirmed, false, "missing CID is not proof the child never spawned");
  assert.equal(finalizeFixtureRecord(owned, { completed: false, cleanupConfirmed }), false);
  assert.equal(existsSync(owned), true, "unresolved fixture data must be retained");
  // Successful --rm execution is a separate independently observed outcome.
  assert.equal(finalizeFixtureRecord(owned, { completed: true, cleanupConfirmed }), true);
  assert.equal(existsSync(owned), false);
});

test("a successful cleanup cannot recursively remove arbitrary caller-named directories", (t) => {
  const foreign = mkdtempSync(path.join(os.tmpdir(), "virki-foreign-owned-"));
  t.after(() => rmSync(foreign, { recursive: true, force: true }));
  const sentinel = path.join(foreign, "leave-me-untouched.txt");
  writeFileSync(sentinel, "foreign data");
  assert.equal(finalizeFixtureRecord(foreign, {
    completed: true, cleanupConfirmed: true,
  }), false);
  assert.equal(readFileSync(sentinel, "utf8"), "foreign data");
});

test("swapping owned fixture directory for another directory blocks cleanup", (t) => {
  const { owned, cidfile } = prepareOwnedFixtureDirectory();
  const backup = owned + "-before-swap";
  t.after(() => {
    rmSync(owned, { recursive: true, force: true });
    rmSync(backup, { recursive: true, force: true });
  });
  renameSync(owned, backup);
  mkdirSync(owned);
  const sentinel = path.join(owned, "foreign.txt");
  writeFileSync(sentinel, "do not delete");
  writeFileSync(cidfile, fullId + "\n");
  let cliCalls = 0;
  assert.equal(cleanupOwnedContainer(cidfile, planDisposableFixture({
    ownerToken: token, cidfile,
  }), {}, { run() { cliCalls++; throw new Error("Docker must not be invoked"); } }), false);
  assert.equal(cliCalls, 0, "swapped owner inode must be rejected before the CLI");
  assert.equal(finalizeFixtureRecord(owned, {
    completed: true, cleanupConfirmed: true,
  }), false);
  assert.equal(readFileSync(sentinel, "utf8"), "do not delete");
  assert.ok(existsSync(backup), "original owner fixture evidence is preserved");
});

test("hardlinked CID is not ownership evidence and never invokes Docker", (t) => {
  const { owned, cidfile } = prepareOwnedFixtureDirectory();
  const foreign = mkdtempSync(path.join(os.tmpdir(), "virki-linked-cid-"));
  t.after(() => {
    rmSync(owned, { recursive: true, force: true });
    rmSync(foreign, { recursive: true, force: true });
  });
  const external = path.join(foreign, "external-id");
  writeFileSync(external, fullId);
  linkSync(external, cidfile);
  let calls = 0;
  assert.equal(cleanupOwnedContainer(cidfile, planDisposableFixture({
    ownerToken: token, cidfile,
  }), {}, { run() { calls++; throw new Error("unexpected Docker invocation"); } }), false);
  assert.equal(calls, 0);
  assert.equal(readFileSync(external, "utf8"), fullId);
  assert.equal(finalizeFixtureRecord(owned, {
    completed: true, cleanupConfirmed: false,
  }), false, "hardlinked CID also blocks local recursive teardown");
});

test("simulated full-ID labeled inspection and cleanup uses no real Docker", (t) => {
  const { owned, cidfile } = prepareOwnedFixtureDirectory();
  t.after(() => rmSync(owned, { recursive: true, force: true }));
  writeFileSync(cidfile, fullId + "\n");
  const calls = [];
  const cleanupConfirmed = cleanupOwnedContainer(cidfile, planDisposableFixture({
    ownerToken: token, cidfile,
  }), {}, {
    run(args) {
      calls.push(args);
      return args.includes("inspect") ?
        { status: 0, stdout: fullId + " " + token + "\n" } :
        { status: 0, stdout: fullId + "\n" };
    },
  });
  assert.equal(cleanupConfirmed, true);
  assert.equal(calls.length, 2);
  assert.deepEqual(calls.map((args) => args.at(-1)), [fullId, fullId]);
  assert.ok(calls.every((args) => args[0] === "--host" &&
    args[1] === LOCAL_DESKTOP_ENGINE));
  assert.equal(finalizeFixtureRecord(owned, {
    completed: false, cleanupConfirmed,
  }), true);
  assert.equal(existsSync(owned), false);
});

test("unexpected contents in owner fixture are never recursively erased", (t) => {
  const { owned } = prepareOwnedFixtureDirectory();
  t.after(() => rmSync(owned, { recursive: true, force: true }));
  const unexpected = path.join(owned, "unexpected");
  mkdirSync(unexpected);
  const sentinel = path.join(unexpected, "sentinel");
  writeFileSync(sentinel, "preserve");
  assert.equal(finalizeFixtureRecord(owned, {
    completed: true, cleanupConfirmed: false,
  }), false);
  assert.equal(readFileSync(sentinel, "utf8"), "preserve");
});
