import assert from "node:assert/strict";
import test from "node:test";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  LOCAL_ENGINE, requireLocalFixtureEnvironment, runOwnedLocalLinuxFixture,
  verifyTrustedWindowsDockerCli,
} from "./disposable-local-docker.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const cli = "C:\\Program Files\\Docker\\Docker\\resources\\bin\\docker.exe";
const image = "node:22.23.3-bookworm@sha256:0e5f906573693feaa1e21057ebdcfdb5bd5021f050b2dc7c9deceb629c7da2a8";
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
const base = {
  platform: "win32",
  env: { PATH: "C:\\evil-cli", SystemRoot: "C:\\bogus" },
  cwd: root,
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
      { ...base, ...entry, invoke }), /local Docker Desktop/u);
  }
  assert.equal(touched, false);
  assert.doesNotThrow(() => requireLocalFixtureEnvironment("win32", {}));
});

function fakeEngine({ runStatus = 0, inspectOwner = "correct", inspectExists = true, info = "Docker Desktop|linux" } = {}) {
  const calls = [];
  const invoke = (exe, argv, options) => {
    assert.equal(exe, cli);
    assert.deepEqual(argv.slice(0, 2), ["--host", LOCAL_ENGINE]);
    assert.equal(Object.hasOwn(options.env, "DOCKER_HOST"), false);
    assert.equal(options.env.PATH.includes("evil-cli"), false);
    assert.equal(options.env.SystemRoot, "C:\\Windows");
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
