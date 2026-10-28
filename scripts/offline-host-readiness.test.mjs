import assert from "node:assert/strict";
import test from "node:test";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, symlinkSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  OFFLINE_COMPONENTS, inspectOfflineHostReadiness,
} from "./offline-host-readiness.mjs";

const config = Object.freeze({
  sshAlias: "virki-prod", host: "production.example.invalid",
  port: "2222", root: "/srv/virki", sshUser: "deploy",
});

function harness({ host = config.host, port = config.port, proxyCommand = "none", sshConfig, lines, fail = false } = {}) {
  const calls = [];
  return {
    calls,
    execute(command, args, options = {}) {
      calls.push({ command, args, options });
      assert.equal(command, "ssh");
      if (args.includes("-G")) {
        return { status: 0, stdout: sshConfig ?? `hostname ${host}\nport ${port}\nuser deploy\nstricthostkeychecking yes\nproxycommand ${proxyCommand}\nproxyjump none\npermitlocalcommand no\nclearallforwardings yes\n` };
      }
      if (fail) return { status: 255, stdout: "", stderr: "sensitive host data" };
      return { status: 0, stdout: (lines ?? OFFLINE_COMPONENTS.map((key) =>
        `VIRKI_OFFLINE_COMPONENT_${key}=UNVERIFIED`)).join("\n") + "\n" };
    },
  };
}

test("rejects wrong host/port and missing config before running remote script", async () => {
  const wrong = harness({ host: "other.example.invalid" });
  const denied = await inspectOfflineHostReadiness({ config, execute: wrong.execute });
  assert.equal(denied.status, "HOST_READINESS_UNVERIFIED");
  assert.equal(denied.deployAuthorized, false);
  assert.equal(wrong.calls.length, 1);

  const proxy = harness({ proxyCommand: "/bin/false" });
  assert.equal((await inspectOfflineHostReadiness({ config, execute: proxy.execute })).status,
    "HOST_READINESS_UNVERIFIED");
  assert.equal(proxy.calls.length, 1);

  const invalid = harness();
  const refused = await inspectOfflineHostReadiness({
    config: { ...config, sshAlias: "-oProxyCommand=evil" }, execute: invalid.execute,
  });
  assert.equal(refused.status, "HOST_READINESS_UNVERIFIED");
  assert.deepEqual(invalid.calls, []);
});

test("accepts OpenSSH canonical 'true' and omitted disabled proxies only with pinned safe args", async () => {
  const env = harness({ sshConfig: `hostname ${config.host}\nport ${config.port}\nuser deploy\nstricthostkeychecking true\npermitlocalcommand false\nclearallforwardings true\n` });
  const result = await inspectOfflineHostReadiness({ config, execute: env.execute });
  assert.equal(result.status, "HOST_COMPONENTS_INSPECTED_ONLY");
  assert.equal(result.deployAuthorized, false);
  for (const args of env.calls.map((call) => call.args)) {
    assert.equal(args[args.indexOf("-F") + 1], "none", "never parse local ssh_config Match exec");
    for (const required of ["StrictHostKeyChecking=yes", "ProxyCommand=none", "ProxyJump=none", "ControlMaster=no", "ControlPath=none", "PermitLocalCommand=no", "ClearAllForwardings=yes"]) {
      assert.ok(args.includes(required), `missing pinned SSH option ${required}`);
    }
    for (const required of [`HostName=${config.host}`, `Port=${config.port}`, `User=${config.sshUser}`]) {
      assert.ok(args.includes(required), `missing explicit SSH peer identity ${required}`);
    }
  }
});

test("missing or invalid explicitly pinned SSH user refuses before reading arbitrary ssh_config", async () => {
  for (const sshUser of [undefined, "", "-oProxyCommand=evil", "u@host", "user name"]) {
    const env = harness();
    const result = await inspectOfflineHostReadiness({
      config: { ...config, sshUser }, sshUser: sshUser ?? "", execute: env.execute,
    });
    assert.equal(result.status, "HOST_READINESS_UNVERIFIED");
    assert.equal(env.calls.length, 0);
  }
});

test("refuses unsafe OpenSSH overrides, duplicates, omitted strict checking and wrong identity", async () => {
  const base = `hostname ${config.host}\nport ${config.port}\nuser deploy\nstricthostkeychecking true\npermitlocalcommand no\nclearallforwardings yes\n`;
  const candidates = [
    base.replace(" true", " accept-new"),
    base.replace("stricthostkeychecking true\n", ""),
    base + "proxycommand /bin/evil\n",
    base + "proxyjump intermediate\n",
    base + "stricthostkeychecking no\n",
    base.replace("permitlocalcommand no", "permitlocalcommand yes"),
    base.replace("clearallforwardings yes", "clearallforwardings no"),
    base + "localcommand echo DEV_ONLY\n",
    base + "localforward [127.0.0.1]:15193 127.0.0.1:22\n",
    base + "remoteforward 127.0.0.1:15193 127.0.0.1:22\n",
    base + "dynamicforward 127.0.0.1:15193\n",
    base + `hostname ${config.host}\n`,
    base.replace("user deploy", "user -unsafe"),
    base.replace("user deploy", "user another-user"),
    base.replace("port 2222", "port 22"),
  ];
  for (const sshConfig of candidates) {
    const env = harness({ sshConfig });
    const result = await inspectOfflineHostReadiness({ config, execute: env.execute });
    assert.equal(result.status, "HOST_READINESS_UNVERIFIED");
    assert.equal(env.calls.length, 1, "no remote command after invalid ssh -G");
  }
});

test("read-only readiness emits categories, never authority or sensitive SSH output", async () => {
  const env = harness({ lines: OFFLINE_COMPONENTS.map((key, i) =>
    `VIRKI_OFFLINE_COMPONENT_${key}=${i === 0 ? "METADATA_OBSERVED" : "UNVERIFIED"}`) });
  const result = await inspectOfflineHostReadiness({ config, execute: env.execute });
  assert.deepEqual(result, {
    status: "HOST_COMPONENTS_INSPECTED_ONLY",
    metadataObserved: [OFFLINE_COMPONENTS[0]],
    unverified: OFFLINE_COMPONENTS.slice(1),
    transferAuthorized: false, deployAuthorized: false,
  });
  assert.equal(env.calls.length, 2);
  const second = env.calls[1];
  assert.ok(second.args.includes("StrictHostKeyChecking=yes"));
  assert.ok(second.args.includes("ProxyCommand=none"));
  assert.ok(second.args.includes("ProxyJump=none"));
  assert.equal(second.args.at(-1), "bash -s --");
  assert.doesNotMatch(second.options.input, /docker\s+(?:load|run|rm|pull)|pg_dump|psql|rm\s+-|sudo|curl|wget/u);
  assert.match(second.options.input, /stat -c/u);
});

test("malformed, duplicate, swapped or extra remote output fails closed", async () => {
  const valid = OFFLINE_COMPONENTS.map((key) => `VIRKI_OFFLINE_COMPONENT_${key}=UNVERIFIED`);
  const cases = [
    valid.slice(0, -1), [valid[0], valid[0], ...valid.slice(2)],
    [...valid, "password=redacted"], valid.map((line, i) => i === 0 ? line.replace("UNVERIFIED", "READY") : line),
    [...valid].reverse(),
  ];
  for (const lines of cases) {
    const env = harness({ lines });
    const result = await inspectOfflineHostReadiness({ config, execute: env.execute });
    assert.deepEqual(result, {
      status: "HOST_READINESS_UNVERIFIED",
      transferAuthorized: false, deployAuthorized: false,
    });
  }
  const down = harness({ fail: true });
  assert.equal((await inspectOfflineHostReadiness({ config, execute: down.execute })).status,
    "HOST_READINESS_UNVERIFIED");
});

test("CLI with no private config never claims success", () => {
  const child = spawnSync(process.execPath, ["scripts/offline-host-readiness.mjs"], {
    env: { PATH: process.env.PATH ?? "" }, encoding: "utf8",
  });
  assert.equal(child.status, 1);
  assert.match(child.stdout, /HOST_READINESS_UNVERIFIED/u);
  assert.doesNotMatch(child.stdout, /example.invalid|password|private key/iu);
});

test("aliased CLI entrypoints must not silently exit successfully", {
  skip: process.platform !== "linux",
}, () => {
  const temp = mkdtempSync(path.join(os.tmpdir(), "virki-host-inspection-"));
  try {
    const entry = fileURLToPath(new URL("./offline-host-readiness.mjs", import.meta.url));
    const aliasDirectory = path.join(temp, "scripts");
    symlinkSync(path.dirname(entry), aliasDirectory, "dir");
    const alias = path.join(aliasDirectory, "offline-host-readiness.mjs");
    for (const args of [[alias], ["--preserve-symlinks-main", alias]]) {
      const result = spawnSync(process.execPath, args, {
        env: { PATH: process.env.PATH ?? "" }, encoding: "utf8",
      });
      assert.equal(result.status, 1);
      assert.match(result.stdout, /HOST_READINESS_UNVERIFIED/u);
    }
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
});
