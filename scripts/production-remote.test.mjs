import assert from "node:assert/strict";
import test from "node:test";
import {
  buildSshArgs,
  parseSshConfig,
  PRODUCTION_HOST,
  PRODUCTION_PORT,
  PRODUCTION_SSH_ALIAS,
  runProductionPreflight,
} from "./production-preflight.mjs";
import {
  parseRemoteProductionCommand,
  runRemoteProductionCommand,
} from "./production-remote.mjs";
import { ProductionRevisionError } from "./lib/production-revision.mjs";

test("SSH preflight resolves only the canonical server target", () => {
  assert.deepEqual(
    parseSshConfig(`user biel\nhostname ${PRODUCTION_HOST}\nport ${PRODUCTION_PORT}\n`),
    { user: "biel", hostname: PRODUCTION_HOST, port: PRODUCTION_PORT },
  );
  assert.deepEqual(buildSshArgs(["powershell.exe"]).slice(-2), [PRODUCTION_SSH_ALIAS, "powershell.exe"]);
});

test("remote production actions use a fixed allowlist", () => {
  for (const action of ["start", "stop", "status", "ports", "revision", "health", "logs", "backup", "config"]) {
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
    sleep: async () => {},
    execute: (command, args) => {
      if (command !== "ssh") return { status: 1, stdout: "" };
      if (args[0] === "-G") {
        return { status: 0, stdout: "user biel\nhostname 192.168.2.67\nport 22\n" };
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
});
