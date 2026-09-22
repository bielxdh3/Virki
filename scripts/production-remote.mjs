import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  inspectProductionSource,
  ProductionRevisionError,
  runCommand,
} from "./lib/production-revision.mjs";
import {
  SSH_OPTIONS,
  runProductionPreflight,
} from "./production-preflight.mjs";
import { PRODUCTION_CONFIG, isValidProductionConfig } from "./lib/production-config.mjs";

const repositoryRoot = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const allowedCommands = new Set([
  "start",
  "restart",
  "prepare",
  "start-tunnel",
  "stop",
  "status",
  "ports",
  "revision",
  "health",
  "logs",
  "backup-verify",
  "migrate",
  "migration-status",
  "baseline",
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

function sshRunnerArgs(action, expectedRevision, config = PRODUCTION_CONFIG) {
  if (!isValidProductionConfig(config)) throw new ProductionRevisionError("OPERATOR_CONFIG_INVALID");
  const remoteRunner = `${config.root.replaceAll("\\", "/")}/scripts/production-server.ps1`;
  const args = [
    ...SSH_OPTIONS,
    config.sshAlias,
    "powershell.exe",
    "-NoLogo",
    "-NoProfile",
    "-NonInteractive",
    "-ExecutionPolicy",
    "Bypass",
    "-File",
    remoteRunner,
    "-Root",
    config.root,
    "-Action",
    action,
  ];
  if (expectedRevision) args.push("-ExpectedRevision", expectedRevision);
  return args;
}

function runRemoteAction(action, expectedRevision, execute = runCommand, config = PRODUCTION_CONFIG) {
  const result = execute("ssh", sshRunnerArgs(action, expectedRevision, config));
  return {
    status: result.status,
    lines:
      result.status === 0
        ? result.stdout.trim().split(/\r?\n/u).filter(Boolean)
        : ["Remote production command failed."],
  };
}

export function runRemoteProductionCommand(
  args,
  { execute = runCommand, preflight = runProductionPreflight, config = PRODUCTION_CONFIG } = {},
) {
  const command = parseRemoteProductionCommand(args);
  const preflightResult = preflight({ execute, config });
  if (preflightResult instanceof Promise) {
    return preflightResult.then((result) => finishRemoteCommand(command, result, execute, config));
  }
  return finishRemoteCommand(command, preflightResult, execute, config);
}

function finishRemoteCommand(command, preflightResult, execute, config) {
  if (preflightResult.status !== 0) return preflightResult;

  let expectedRevision;
  if (["start", "restart", "prepare", "backup-verify", "migrate", "migration-status", "baseline"].includes(command)) {
    expectedRevision = inspectProductionSource({ repositoryRoot, execute }).revision;
  }

  const result = runRemoteAction(command, expectedRevision, execute, config);
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
  runRemoteProductionCommand(process.argv.slice(2))
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
