import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  inspectProductionSource,
  ProductionRevisionError,
  runCommand,
} from "./lib/production-revision.mjs";
import { verifyExactShaCi } from "./lib/production-ci.mjs";
import { SSH_OPTIONS, runProductionPreflight } from "./production-preflight.mjs";
import { readProductionConfig, isValidProductionConfig } from "./lib/production-config.mjs";

const repositoryRoot = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const serverScript = readFileSync(new URL("./production-server.sh", import.meta.url), "utf8");
const allowedCommands = new Set([
  "start",
  "stage",
  "first-admin-bootstrap",
  "restart",
  "start-tunnel",
  "stop",
  "maintenance-on",
  "maintenance-off",
  "status",
  "ports",
  "revision",
  "health",
  "logs",
  "backup-verify",
  "migration-status",
  "audit-recent",
  "audit-cleanup",
  "sessions-cleanup",
  "config",
]);

export function parseRemoteProductionCommand(args) {
  if (args.length !== 1 || !allowedCommands.has(args[0])) {
    throw new ProductionRevisionError("ARGUMENT_INVALID");
  }
  return args[0];
}

export function buildRemoteSshArgs(action, revision, config = readProductionConfig()) {
  if (!isValidProductionConfig(config)) throw new ProductionRevisionError("OPERATOR_CONFIG_INVALID");
  if (!/^[a-z-]+$/u.test(action)) throw new ProductionRevisionError("ARGUMENT_INVALID");
  if (!/^[0-9a-f]{40}$/u.test(revision)) throw new ProductionRevisionError("REVISION_INVALID");
  const remoteCommand = `bash -s -- ${action} ${config.root} ${revision}`;
  return [...SSH_OPTIONS, config.sshAlias, remoteCommand];
}

export function buildInteractiveRemoteSshArgs(action, revision, config = readProductionConfig()) {
  if (!isValidProductionConfig(config)) throw new ProductionRevisionError("OPERATOR_CONFIG_INVALID");
  if (action !== "first-admin-bootstrap") throw new ProductionRevisionError("ARGUMENT_INVALID");
  if (!/^[0-9a-f]{40}$/u.test(revision)) throw new ProductionRevisionError("REVISION_INVALID");
  const remoteCommand = `bash ${config.root}/current/scripts/production-server.sh ${action} ${config.root} ${revision}`;
  return [...SSH_OPTIONS, "-tt", config.sshAlias, remoteCommand];
}

function runRemoteAction(action, revision, execute, config) {
  const interactive = action === "first-admin-bootstrap";
  const result = interactive
    ? execute("ssh", buildInteractiveRemoteSshArgs(action, revision, config), { interactive: true })
    : execute("ssh", buildRemoteSshArgs(action, revision, config), { input: serverScript });
  return {
    status: result.status,
    lines:
      result.status === 0 && !interactive
        ? result.stdout.trim().split(/\r?\n/u).filter(Boolean)
        : result.status === 0 ? [] : ["Remote production command failed."],
  };
}

export function runRemoteProductionCommand(
  args,
  {
    execute = runCommand,
    preflight = runProductionPreflight,
    inspectSource = inspectProductionSource,
    verifyCi = verifyExactShaCi,
    config = readProductionConfig(),
  } = {},
) {
  const command = parseRemoteProductionCommand(args);
  if (!isValidProductionConfig(config)) {
    return { status: 1, lines: ["Private production operator configuration is missing or invalid."] };
  }

  let source;
  try {
    source = inspectSource({ repositoryRoot, execute });
  } catch (error) {
    return { status: 1, lines: [error instanceof ProductionRevisionError ? error.message : "Production source state could not be verified."] };
  }
  const ci = verifyCi({ revision: source.revision, execute, repositoryRoot });
  if (!ci.ok) return { status: 1, lines: ci.lines };

  const preflightResult = preflight({ execute, config });
  if (preflightResult instanceof Promise) {
    return preflightResult.then((result) => finishRemoteCommand(command, source.revision, result, execute, config));
  }
  return finishRemoteCommand(command, source.revision, preflightResult, execute, config);
}

function finishRemoteCommand(command, revision, preflightResult, execute, config) {
  if (preflightResult.status !== 0) return preflightResult;
  const result = runRemoteAction(command, revision, execute, config);
  return {
    status: result.status,
    lines: [...preflightResult.lines, ...result.lines],
  };
}

function isMainModule() {
  if (!process.argv[1]) return false;
  return path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
}

if (isMainModule()) {
  Promise.resolve(runRemoteProductionCommand(process.argv.slice(2)))
    .then((result) => {
      for (const line of result.lines) {
        if (result.status === 0) console.log(line);
        else console.error(line);
      }
      process.exitCode = result.status;
    })
    .catch((error) => {
      const message =
        error instanceof ProductionRevisionError
          ? error.message
          : "Remote production command failed.";
      console.error(message);
      process.exitCode = 1;
    });
}
