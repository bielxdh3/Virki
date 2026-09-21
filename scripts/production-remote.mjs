import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  inspectProductionSource,
  ProductionRevisionError,
  runCommand,
} from "./lib/production-revision.mjs";
import {
  PRODUCTION_ROOT,
  PRODUCTION_SSH_ALIAS,
  SSH_OPTIONS,
  runProductionPreflight,
} from "./production-preflight.mjs";

const repositoryRoot = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const remoteRunner = `${PRODUCTION_ROOT.replaceAll("\\", "/")}/scripts/production-server.ps1`;
const allowedCommands = new Set([
  "start",
  "core-up",
  "restart",
  "start-tunnel",
  "stop",
  "status",
  "ports",
  "revision",
  "health",
  "logs",
  "backup",
  "audit-recent",
  "audit-cleanup",
  "seed-owner",
  "sessions-cleanup",
  "config",
]);

export function parseRemoteProductionCommand(args) {
  if (args.length !== 1 || !allowedCommands.has(args[0])) {
    throw new ProductionRevisionError("ARGUMENT_INVALID");
  }
  return args[0];
}

function sshRunnerArgs(action, expectedRevision) {
  const args = [
    ...SSH_OPTIONS,
    PRODUCTION_SSH_ALIAS,
    "powershell.exe",
    "-NoLogo",
    "-NoProfile",
    "-NonInteractive",
    "-File",
    remoteRunner,
    "-Action",
    action,
  ];
  if (expectedRevision) args.push("-ExpectedRevision", expectedRevision);
  return args;
}

function runRemoteAction(action, expectedRevision, execute = runCommand) {
  const result = execute("ssh", sshRunnerArgs(action, expectedRevision));
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
  { execute = runCommand, preflight = runProductionPreflight } = {},
) {
  const command = parseRemoteProductionCommand(args);
  const preflightResult = preflight({ execute });
  if (preflightResult instanceof Promise) {
    return preflightResult.then((result) => finishRemoteCommand(command, result, execute));
  }
  return finishRemoteCommand(command, preflightResult, execute);
}

function finishRemoteCommand(command, preflightResult, execute) {
  if (preflightResult.status !== 0) return preflightResult;

  let expectedRevision;
  if (["start", "core-up", "restart"].includes(command)) {
    expectedRevision = inspectProductionSource({ repositoryRoot, execute }).revision;
  }

  const result = runRemoteAction(command, expectedRevision, execute);
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
