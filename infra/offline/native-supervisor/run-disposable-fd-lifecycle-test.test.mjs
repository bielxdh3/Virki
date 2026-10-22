import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  DISPOSABLE_IMAGE, LOCAL_DESKTOP_ENGINE, planDisposableFixture,
  validateCleanupIdentity,
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
});
