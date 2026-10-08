import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  buildInteractiveRemoteSshArgs,
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
  root: "/srv/virki",
};

test("remote Linux Bash script uses LF line endings", () => {
  const script = readFileSync(new URL("./production-server.sh", import.meta.url), "utf8");
  assert.equal(script.includes("\r"), false);
});

test("production configuration accepts only safe absolute Linux roots", () => {
  assert.equal(isValidProductionConfig(operatorConfig), true);
  assert.equal(isValidProductionConfig({ ...operatorConfig, sshAlias: "-oProxyCommand=touch /tmp/pwned" }), false);
  assert.equal(isValidProductionConfig({ ...operatorConfig, sshAlias: "--help" }), false);
  assert.equal(isValidProductionConfig({ ...operatorConfig, sshAlias: "safe-production" }), true);
  assert.equal(isValidProductionConfig({ ...operatorConfig, root: "C:\\Virki" }), false);
  assert.equal(isValidProductionConfig({ ...operatorConfig, root: "/srv/../unsafe" }), false);
  assert.equal(isValidProductionConfig({ ...operatorConfig, root: "/srv/virki;touch" }), false);
  assert.equal(isValidProductionConfig({ ...operatorConfig, root: "/" }), false);
});

test("remote actions use a fixed list and a non-interactive Linux Bash runner", () => {
  for (const action of ["stage", "start", "stop", "status", "ports", "revision", "health", "logs", "backup-verify", "maintenance-on", "maintenance-off", "config"]) {
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

test("first ADMIN bootstrap uses a protected SSH TTY and carries no credential as an argument", () => {
  assert.equal(parseRemoteProductionCommand(["first-admin-bootstrap"]), "first-admin-bootstrap");
  const args = buildInteractiveRemoteSshArgs("first-admin-bootstrap", revision, operatorConfig);
  assert.ok(args.includes("-tt"));
  assert.equal(args.at(-1), `bash ${operatorConfig.root}/current/scripts/production-server.sh first-admin-bootstrap ${operatorConfig.root} ${revision}`);
  assert.equal(args.join(" ").includes("password"), false);
  assert.equal(args.some((value) => value.includes("@")), false);
  assert.throws(() => buildInteractiveRemoteSshArgs("stage", revision, operatorConfig), (error) => error.code === "ARGUMENT_INVALID");
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

test("interactive first ADMIN bootstrap passes through the terminal without a script pipe", async () => {
  const calls = [];
  const result = await runRemoteProductionCommand(["first-admin-bootstrap"], {
    config: operatorConfig,
    inspectSource: () => ({ branch: "main", revision }),
    verifyCi: () => ({ ok: true, lines: ["exact SHA green"] }),
    preflight: async () => ({ status: 0, lines: ["preflight passed"] }),
    execute: (command, args, options) => {
      calls.push({ command, args, options });
      return { status: 0, stdout: "" };
    },
  });

  assert.equal(result.status, 0);
  assert.deepEqual(result.lines, ["preflight passed"]);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].command, "ssh");
  assert.equal(calls[0].options.interactive, true);
  assert.equal(Object.hasOwn(calls[0].options, "input"), false);
  assert.ok(calls[0].args.includes("-tt"));
});
