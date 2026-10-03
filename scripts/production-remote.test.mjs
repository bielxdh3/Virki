import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  buildRemoteSshArgs,
  parseRemoteProductionCommand,
  runRemoteProductionCommand,
} from "./production-remote.mjs";
import { ProductionRevisionError } from "./lib/production-revision.mjs";
import { isValidProductionConfig } from "./lib/production-config.mjs";

const revision = "0123456789abcdef0123456789abcdef01234567";
const operatorConfig = {
  sshAlias: "test-production",
  host: "production.example.invalid",
  port: "2222",
  root: "/srv/bielos",
};

test("remote Linux Bash script uses LF line endings", () => {
  const script = readFileSync(new URL("./production-server.sh", import.meta.url), "utf8");
  assert.equal(script.includes("\r"), false);
});

test("production configuration accepts only safe absolute Linux roots", () => {
  assert.equal(isValidProductionConfig(operatorConfig), true);
  assert.equal(isValidProductionConfig({ ...operatorConfig, root: "C:\\BielOS" }), false);
  assert.equal(isValidProductionConfig({ ...operatorConfig, root: "/srv/../unsafe" }), false);
  assert.equal(isValidProductionConfig({ ...operatorConfig, root: "/srv/bielos;touch" }), false);
  assert.equal(isValidProductionConfig({ ...operatorConfig, root: "/" }), false);
});

test("remote actions use a fixed list and a non-interactive Linux Bash runner", () => {
  for (const action of ["start", "stop", "status", "ports", "revision", "health", "logs", "backup-verify", "maintenance-on", "maintenance-off", "config"]) {
    assert.equal(parseRemoteProductionCommand([action]), action);
  }
  assert.throws(
    () => parseRemoteProductionCommand(["bash", "-c", "whoami"]),
    (error) => error instanceof ProductionRevisionError && error.code === "ARGUMENT_INVALID",
  );

  const args = buildRemoteSshArgs("status", revision, operatorConfig);
  assert.equal(args.at(-1), `bash -s -- status ${operatorConfig.root} ${revision}`);
  assert.ok(args.includes("StrictHostKeyChecking=yes"));
  assert.equal(args.join(" ").includes("powershell"), false);
  assert.throws(() => buildRemoteSshArgs("status", "bad", operatorConfig), /Revision is invalid/u);
});

test("remote actions require exact main-source and CI gates before preflight and SSH", async () => {
  const calls = [];
  const result = await runRemoteProductionCommand(["status"], {
    config: operatorConfig,
    inspectSource: () => {
      calls.push("source");
      return { branch: "main", revision };
    },
    verifyCi: ({ revision: observed }) => {
      calls.push(`ci:${observed}`);
      return { ok: true, lines: ["exact SHA green"] };
    },
    preflight: async () => {
      calls.push("preflight");
      return { status: 0, lines: ["native Linux preflight ok"] };
    },
    execute: (command, args, options) => {
      calls.push("ssh");
      assert.equal(command, "ssh");
      assert.ok(args.at(-1).includes(`bash -s -- status ${operatorConfig.root} ${revision}`));
      assert.ok(options.input.includes("verify_host"));
      return { status: 0, stdout: "status ok\n" };
    },
  });

  assert.deepEqual(calls, ["source", `ci:${revision}`, "preflight", "ssh"]);
  assert.equal(result.status, 0);
  assert.deepEqual(result.lines, ["native Linux preflight ok", "status ok"]);
});

test("an unverified CI result fails before contacting the production host", async () => {
  let preflightCalls = 0;
  const result = await runRemoteProductionCommand(["restart"], {
    config: operatorConfig,
    inspectSource: () => ({ branch: "main", revision }),
    verifyCi: () => ({ ok: false, lines: ["CI not green"] }),
    preflight: async () => {
      preflightCalls += 1;
      return { status: 0, lines: [] };
    },
    execute: () => assert.fail("Production SSH must not run when CI is not green."),
  });
  assert.equal(preflightCalls, 0);
  assert.deepEqual(result, { status: 1, lines: ["CI not green"] });
});
