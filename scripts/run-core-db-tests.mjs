import { spawnSync } from "node:child_process";
import { createServer } from "node:net";
import { readdirSync } from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

import {
  assertDisposableCoreTestDatabase,
  CORE_TEST_DATABASE_CONFIRMATION,
  sanitizeCoreTestOutput
} from "./core-test-database-safety.mjs";

const rootDirectory = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const integrationDirectory = path.join(
  rootDirectory,
  "apps",
  "hub",
  "src",
  "app",
  "core",
  "integration"
);
const suite = readSuite(process.argv.slice(2));
const externalDatabaseUrl = process.env.CORE_TEST_DATABASE_URL?.trim();
const composeFile = path.join(rootDirectory, "infra", "docker-compose.core-test.yml");
const require = createRequire(import.meta.url);
const tsxCli = require.resolve("tsx/cli");
const npmCli = process.env.npm_execpath;

if (!npmCli) {
  throw new Error("Core database tests must be launched through an npm script.");
}

let composeProject;
let databaseUrl = externalDatabaseUrl;
let testPort;

try {
  if (!databaseUrl) {
    testPort = await findAvailablePort();
    composeProject = `bielos-core-test-${process.pid}-${Date.now()}`;
    databaseUrl = buildLocalDatabaseUrl(testPort);
    const composeEnvironment = {
      ...process.env,
      CORE_TEST_DB_PORT: String(testPort)
    };

    runCommand(
      "docker",
      [
        "compose",
        "-p",
        composeProject,
        "-f",
        composeFile,
        "up",
        "-d",
        "--wait",
        "--wait-timeout",
        "60"
      ],
      { environment: composeEnvironment, quiet: true, timeoutMs: 90_000 }
    );
  }

  const testEnvironment = {
    ...process.env,
    NODE_ENV: "test",
    DATABASE_URL: databaseUrl,
    BIELOS_CORE_TEST_DATABASE_CONFIRM: CORE_TEST_DATABASE_CONFIRMATION
  };

  assertDisposableCoreTestDatabase(databaseUrl, testEnvironment);

  runCommand(process.execPath, [npmCli, "run", "prisma:migrate:deploy"], {
    environment: testEnvironment,
    quiet: true,
    timeoutMs: 120_000,
    databaseUrl
  });

  const testFiles = getTestFiles(suite);

  if (testFiles.length === 0) {
    throw new Error(`No Core database tests were found for suite ${suite}.`);
  }

  runCommand(
    process.execPath,
    [tsxCli, "--test", "--test-concurrency=1", ...testFiles],
    {
      environment: testEnvironment,
      quiet: false,
      timeoutMs: 240_000,
      databaseUrl
    }
  );
} finally {
  if (composeProject) {
    runCommand(
      "docker",
      [
        "compose",
        "-p",
        composeProject,
        "-f",
        composeFile,
        "down",
        "--volumes",
        "--remove-orphans",
        "--timeout",
        "10"
      ],
      {
        environment: { ...process.env, CORE_TEST_DB_PORT: String(testPort) },
        quiet: true,
        timeoutMs: 60_000
      }
    );
  }
}

function readSuite(argumentsList) {
  const suiteIndex = argumentsList.indexOf("--suite");
  const value = suiteIndex >= 0 ? argumentsList[suiteIndex + 1] : "all";

  if (
    value !== "all" &&
    value !== "smoke" &&
    value !== "integration" &&
    value !== "concurrency"
  ) {
    throw new Error(
      "Core database test suite must be all, smoke, integration, or concurrency."
    );
  }

  return value;
}

function getTestFiles(selectedSuite) {
  const files = readdirSync(integrationDirectory, { withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name.endsWith(".db.test.ts"))
    .map((entry) => path.join(integrationDirectory, entry.name))
    .sort();

  if (selectedSuite === "smoke") {
    return files.filter((filePath) => filePath.endsWith(".smoke.db.test.ts"));
  }

  if (selectedSuite === "concurrency") {
    return files.filter((filePath) => filePath.endsWith(".concurrency.db.test.ts"));
  }

  if (selectedSuite === "integration") {
    return files.filter((filePath) => !filePath.endsWith(".concurrency.db.test.ts"));
  }

  return files;
}

function runCommand(command, argumentsList, options) {
  const result = spawnSync(command, argumentsList, {
    cwd: rootDirectory,
    env: options.environment,
    encoding: "utf8",
    timeout: options.timeoutMs,
    maxBuffer: 10 * 1024 * 1024,
    windowsHide: true
  });
  const combinedOutput = `${result.stdout ?? ""}${result.stderr ?? ""}`;
  const sanitizedOutput = options.databaseUrl
    ? sanitizeCoreTestOutput(combinedOutput, options.databaseUrl)
    : combinedOutput;

  if (!options.quiet && sanitizedOutput && !result.error && result.status === 0) {
    process.stdout.write(sanitizedOutput);
  }

  if (result.error || result.status !== 0) {
    if (sanitizedOutput) {
      process.stderr.write(sanitizedOutput);
    }

    if (!options.ignoreFailure) {
      const failureCode = result.error?.code ?? result.status ?? "unknown";
      throw new Error(
        `Core database test command failed: ${path.basename(command)} (${failureCode}).`
      );
    }
  }
}

function findAvailablePort() {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.unref();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();

      if (!address || typeof address === "string") {
        server.close(() => reject(new Error("Unable to allocate a local test port.")));
        return;
      }

      const port = address.port;
      server.close((error) => (error ? reject(error) : resolve(port)));
    });
  });
}

function buildLocalDatabaseUrl(port) {
  const target = new URL("postgresql://127.0.0.1/bielos_core_test");
  target.username = "bielos_test";
  target.password = "local-validation-only";
  target.port = String(port);
  return target.toString();
}
