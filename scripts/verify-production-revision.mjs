import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  normalizeRevision,
  ProductionRevisionError,
  PRODUCTION_SERVICES,
  REVISION_LABEL,
  runCommand,
} from "./lib/production-revision.mjs";

const repositoryRoot = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const composeArguments = [
  "compose",
  "--env-file",
  ".env",
  "-f",
  "infra/docker-compose.prod.yml",
  "-f",
  "infra/docker-compose.cloudflare.yml",
];

export function parseVerifierArguments(args) {
  if (args.length === 0) {
    return { expectedRevision: null };
  }

  if (args.length === 1 && args[0].startsWith("--expected=")) {
    return { expectedRevision: normalizeRevision(args[0].slice(11)) };
  }

  if (args.length === 2 && args[0] === "--expected") {
    return { expectedRevision: normalizeRevision(args[1]) };
  }

  throw new ProductionRevisionError("ARGUMENT_INVALID");
}

function commandSucceeded(result) {
  return result && result.status === 0;
}

export function verifyServiceRevisions({
  expectedRevision,
  execute = runCommand,
}) {
  const expected = normalizeRevision(expectedRevision);
  const lines = [`expected ${expected}`];
  let valid = true;

  for (const service of PRODUCTION_SERVICES) {
    const containerResult = execute(
      "docker",
      [...composeArguments, "ps", "-q", service],
      { cwd: repositoryRoot },
    );

    if (!commandSucceeded(containerResult)) {
      lines.push(`${service}: unavailable`);
      valid = false;
      continue;
    }

    const containers = containerResult.stdout
      .split(/\r?\n/u)
      .map((value) => value.trim())
      .filter(Boolean);

    if (containers.length !== 1) {
      lines.push(`${service}: missing`);
      valid = false;
      continue;
    }

    const labelResult = execute(
      "docker",
      [
        "inspect",
        "--format",
        `{{index .Config.Labels "${REVISION_LABEL}"}}`,
        containers[0],
      ],
      { cwd: repositoryRoot },
    );

    if (!commandSucceeded(labelResult)) {
      lines.push(`${service}: unavailable`);
      valid = false;
      continue;
    }

    const observed = labelResult.stdout.trim();
    if (observed.length === 0 || observed === "<no value>") {
      lines.push(`${service}: label missing`);
      valid = false;
      continue;
    }

    let normalizedObserved;
    try {
      normalizedObserved = normalizeRevision(observed);
    } catch {
      lines.push(`${service}: label malformed`);
      valid = false;
      continue;
    }

    if (normalizedObserved !== expected) {
      lines.push(`${service}: mismatch`);
      valid = false;
      continue;
    }

    lines.push(`${service}: match`);
  }

  lines.push(valid ? "production revision verified" : "revision verification failed");
  return { ok: valid, lines };
}

function resolveExpectedRevision(parsed, execute) {
  if (parsed.expectedRevision) {
    return parsed.expectedRevision;
  }

  const result = execute("git", ["rev-parse", "--verify", "HEAD"], {
    cwd: repositoryRoot,
  });
  if (!commandSucceeded(result)) {
    throw new ProductionRevisionError("COMMAND_FAILED");
  }

  return normalizeRevision(result.stdout.trim());
}

export function runRevisionVerification(args, execute = runCommand) {
  const parsed = parseVerifierArguments(args);
  const expectedRevision = resolveExpectedRevision(parsed, execute);
  return verifyServiceRevisions({ expectedRevision, execute });
}

function isMainModule() {
  if (!process.argv[1]) return false;
  return path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
}

if (isMainModule()) {
  try {
    const result = runRevisionVerification(process.argv.slice(2));
    for (const line of result.lines) console.log(line);
    if (!result.ok) process.exitCode = 1;
  } catch (error) {
    const message =
      error instanceof ProductionRevisionError
        ? error.message
        : "Revision verification failed.";
    console.error(message);
    process.exitCode = 1;
  }
}
