import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  inspectProductionSource,
  ProductionRevisionError,
  runCommand,
} from "./lib/production-revision.mjs";
import { verifyServiceRevisions } from "./verify-production-revision.mjs";

const repositoryRoot = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const allowedCommands = new Set(["up", "restart", "verify", "config"]);
const composeArguments = [
  "compose",
  "--env-file",
  ".env",
  "-f",
  "infra/docker-compose.prod.yml",
  "-f",
  "infra/docker-compose.cloudflare.yml",
];

export function parseProductionCommand(args) {
  if (args.length !== 1 || !allowedCommands.has(args[0])) {
    throw new ProductionRevisionError("ARGUMENT_INVALID");
  }

  return args[0];
}

function dockerArgumentsFor(command) {
  if (command === "up") return [...composeArguments, "up", "--build", "-d"];
  if (command === "restart") {
    return [...composeArguments, "up", "--build", "-d", "--force-recreate"];
  }
  if (command === "config") {
    return [...composeArguments, "config", "--no-env-resolution", "--quiet"];
  }
  throw new ProductionRevisionError("ARGUMENT_INVALID");
}

export function runProductionCommand(args, execute = runCommand) {
  const command = parseProductionCommand(args);
  const source = inspectProductionSource({ repositoryRoot, execute });

  if (command === "verify") {
    const result = verifyServiceRevisions({
      expectedRevision: source.revision,
      execute,
    });
    return { status: result.ok ? 0 : 1, lines: result.lines };
  }

  const result = execute("docker", dockerArgumentsFor(command), {
    cwd: repositoryRoot,
    env: {
      ...process.env,
      BIELOS_BUILD_REVISION: source.revision,
    },
  });

  return {
    status: result.status,
    lines:
      result.status === 0
        ? [`production ${command} complete`, `revision ${source.revision}`]
        : ["Docker command failed."],
  };
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
