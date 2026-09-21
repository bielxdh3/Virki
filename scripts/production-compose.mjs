import path from "node:path";
import { fileURLToPath } from "node:url";
import { ProductionRevisionError } from "./lib/production-revision.mjs";

const allowedCommands = new Set(["up", "restart", "verify", "config"]);

export function parseProductionCommand(args) {
  if (args.length !== 1 || !allowedCommands.has(args[0])) {
    throw new ProductionRevisionError("ARGUMENT_INVALID");
  }

  return args[0];
}

export function runProductionCommand(args) {
  parseProductionCommand(args);
  throw new ProductionRevisionError("REMOTE_REQUIRED");
}

function isMainModule() {
  if (!process.argv[1]) return false;
  return path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
}

if (isMainModule()) {
  try {
    const result = runProductionCommand(process.argv.slice(2));
    for (const line of result.lines) {
      if (result.status === 0) console.log(line);
      else console.error(line);
    }
    process.exitCode = result.status;
  } catch (error) {
    const message =
      error instanceof ProductionRevisionError
        ? error.message
        : "Production command failed.";
    console.error(message);
    process.exitCode = 1;
  }
}
