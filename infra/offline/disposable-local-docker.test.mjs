import assert from "node:assert/strict";
import test from "node:test";
import {
  LOCAL_ENGINE, requireLocalFixtureEnvironment, runOwnedLocalLinuxFixture,
} from "./disposable-local-docker.mjs";

const base = { platform: "win32", env: { PATH: "C:\\Windows", SystemRoot: "C:\\Windows" }, cwd: "C:\\Virki" };

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
    assert.throws(() => runOwnedLocalLinuxFixture(["run", "--rm"],
      { ...base, ...entry, invoke }), /local Docker Desktop/u);
  }
  assert.equal(touched, false);
  assert.doesNotThrow(() => requireLocalFixtureEnvironment("win32", {}));
});

function fakeEngine({ runStatus = 0, inspectOwner = "correct", inspectExists = true, info = "Docker Desktop|linux" } = {}) {
  const calls = [];
  const invoke = (exe, argv, options) => {
    assert.equal(exe, "docker");
    assert.deepEqual(argv.slice(0, 2), ["--host", LOCAL_ENGINE]);
    assert.equal(Object.hasOwn(options.env, "DOCKER_HOST"), false);
    const command = argv[2];
    calls.push({ command, args: argv.slice(3) });
    if (command === "info") return { status: 0, stdout: info };
    if (command === "run") return { status: runStatus, error: runStatus ? { code: "ETIMEDOUT" } : undefined };
    if (command === "inspect") {
      if (!inspectExists) return { status: 1, stderr: "Error: No such object" };
      const run = calls.find((call) => call.command === "run").args;
      const name = run[run.indexOf("--name") + 1];
      const ownerLabel = run[run.indexOf("--label") + 1];
      const owner = ownerLabel.split("=")[1];
      return { status: 0, stdout: `${"e".repeat(64)}|/${name}|${inspectOwner === "correct" ? owner : "forged"}` };
    }
    if (command === "rm") return { status: 0, stdout: "removed" };
    throw new Error("unexpected command");
  };
  return { calls, invoke };
}

test("success launches unique labeled fixture and only removes the verified immutable container ID", () => {
  const fake = fakeEngine();
  runOwnedLocalLinuxFixture(["run", "--rm", "--network=none", "--read-only", "fixture:fixed"],
    { ...base, invoke: fake.invoke });
  assert.deepEqual(fake.calls.map((call) => call.command), ["info", "run", "inspect", "rm"]);
  const run = fake.calls[1].args;
  assert.match(run[run.indexOf("--name") + 1], /^virki-offline-fixture-[a-f0-9]{32}$/u);
  assert.match(run[run.indexOf("--label") + 1], /^dev\.virki\.offline\.disposable-owner=[a-f0-9]{32}$/u);
  assert.deepEqual(fake.calls[3].args, ["--force", "--volumes", "e".repeat(64)]);
});

test("a completed --rm container requires no removal and cannot mutate unrelated resources", () => {
  const fake = fakeEngine({ inspectExists: false });
  runOwnedLocalLinuxFixture(["run", "--rm", "fixture:fixed"],
    { ...base, invoke: fake.invoke });
  assert.deepEqual(fake.calls.map((call) => call.command), ["info", "run", "inspect"]);
});

test("timeout attempts scoped cleanup, then reports failure without leaking executable output", () => {
  const fake = fakeEngine({ runStatus: 1 });
  assert.throws(() => runOwnedLocalLinuxFixture(["run", "--rm", "fixture:fixed"],
    { ...base, invoke: fake.invoke }), /failed or exceeded/u);
  assert.equal(fake.calls[3].command, "rm");
});

test("ownership mismatch refuses deletion and unexpected endpoint self-report blocks before Docker run", () => {
  const forged = fakeEngine({ inspectOwner: "forged" });
  assert.throws(() => runOwnedLocalLinuxFixture(["run", "--rm", "fixture:fixed"],
    { ...base, invoke: forged.invoke }), /ownership proof rejected/u);
  assert.equal(forged.calls.some((call) => call.command === "rm"), false);

  const foreign = fakeEngine({ info: "Linux|linux" });
  assert.throws(() => runOwnedLocalLinuxFixture(["run", "--rm", "fixture:fixed"],
    { ...base, invoke: foreign.invoke }), /unexpected Docker Desktop engine/u);
  assert.deepEqual(foreign.calls.map((call) => call.command), ["info"]);
});
