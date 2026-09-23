import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  buildSshArgs,
  parseSshConfig,
  runProductionPreflight,
} from "./production-preflight.mjs";
import {
  parseRemoteProductionCommand,
  runRemoteProductionCommand,
} from "./production-remote.mjs";
import { ProductionRevisionError } from "./lib/production-revision.mjs";
import { isValidProductionConfig } from "./lib/production-config.mjs";

const operatorConfig = {
  sshAlias: "test-production",
  host: "production.example.invalid",
  port: "2222",
  root: "C:\\BielOS",
};
const productionServerScript = readFileSync(new URL("./production-server.ps1", import.meta.url), "utf8");

test("production server checks private configuration and markers at the root once", () => {
  assert.match(
    productionServerScript,
    /foreach \(\$requiredFile in @\('\.env', '\.env\.oidc', '\.bielos-deploy-revision', '\.bielos-source-state'\)\)/u,
  );
  assert.match(
    productionServerScript,
    /Test-Path -LiteralPath \(Join-Path \$Root \$requiredFile\) -PathType Leaf/u,
  );
});

test("SSH preflight resolves only the canonical server target", () => {
  assert.deepEqual(
    parseSshConfig(`user deploy\nhostname ${operatorConfig.host}\nport ${operatorConfig.port}\n`),
    { user: "deploy", hostname: operatorConfig.host, port: operatorConfig.port },
  );
  assert.deepEqual(buildSshArgs(["powershell.exe"], operatorConfig).slice(-2), [operatorConfig.sshAlias, "powershell.exe"]);
  assert.equal(isValidProductionConfig({ ...operatorConfig, root: "C:\\..\\unsafe" }), false);
  assert.equal(isValidProductionConfig({ ...operatorConfig, root: "C:\\BielOS; Write-Output bad" }), false);
});

test("remote production actions use a fixed allowlist", () => {
  for (const action of ["start", "stop", "status", "ports", "revision", "health", "logs", "backup-verify", "migrate", "migration-status", "baseline", "config"]) {
    assert.equal(parseRemoteProductionCommand([action]), action);
  }
  assert.throws(
    () => parseRemoteProductionCommand(["powershell", "-Command", "whoami"]),
    (error) => error instanceof ProductionRevisionError && error.code === "ARGUMENT_INVALID",
  );
});

test("remote status routing performs preflight before SSH action", async () => {
  const calls = [];
  const result = await runRemoteProductionCommand(["status"], {
    preflight: async () => ({ status: 0, lines: ["preflight ok"] }),
    execute: (command, args) => {
      calls.push({ command, args });
      return { status: 0, stdout: "remote status\n" };
    },
    config: operatorConfig,
  });

  assert.equal(result.status, 0);
  assert.deepEqual(result.lines, ["preflight ok", "remote status"]);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].command, "ssh");
  assert.ok(calls[0].args.includes("-Action"));
  assert.ok(calls[0].args.includes("status"));
});

test("SSH preflight requires eight stable probes and Docker", async () => {
  let probes = 0;
  const result = await runProductionPreflight({
    config: operatorConfig,
    sleep: async () => {},
    execute: (command, args) => {
      if (command !== "ssh") return { status: 1, stdout: "" };
      if (args[0] === "-G") {
        return { status: 0, stdout: `user deploy\nhostname ${operatorConfig.host}\nport ${operatorConfig.port}\n` };
      }
      probes += 1;
      if (probes <= 8) {
        return {
          status: 0,
          stdout: "BIELOS_PROBE_ID=server\nBIELOS_PROBE_WD=C:\\Users\\Biel\nBIELOS_PROBE_POWERSHELL=powershell.exe\nBIELOS_PROBE_DOCKER=docker.exe\n",
        };
      }
      return {
        status: 0,
        stdout: "BIELOS_DOCKER_VERSION=29\nBIELOS_DOCKER_INFO=29\nBIELOS_COMPOSE_VERSION=5\nBIELOS_DISK_FREE_GB=100\nBIELOS_DEMANAGE_COUNT=3\n",
      };
    },
  });

  assert.equal(result.status, 0);
  assert.equal(probes, 9);
  assert.ok(result.lines.some((line) => line.includes("8/8")));
  assert.ok(result.lines.every((line) => !line.includes(operatorConfig.host)));
});
