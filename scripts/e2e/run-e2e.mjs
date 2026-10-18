import { spawnSync } from "node:child_process";
import { dirname, posix, resolve, win32 } from "node:path";
import { fileURLToPath } from "node:url";

const modulePath = fileURLToPath(import.meta.url);
const repositoryRoot = resolve(dirname(modulePath), "../..");

export function buildE2ECommand(platform, playwrightArguments = [], repoRoot = repositoryRoot) {
  if (!Array.isArray(playwrightArguments) || playwrightArguments.some((argument) => typeof argument !== "string")) {
    throw new TypeError("Playwright arguments must be an array of strings.");
  }

  const joinPath = platform === "win32" ? win32.join : posix.join;
  if (platform === "win32") {
    return {
      executable: "powershell.exe",
      args: [
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-File",
        win32.join(repoRoot, "scripts", "e2e", "run-isolated-linux-docker.ps1"),
        "-E2EOnly"
      ],
      environment: { VIRKI_E2E_PLAYWRIGHT_ARGUMENTS_JSON: JSON.stringify(playwrightArguments) }
    };
  }

  return {
    executable: process.execPath,
    args: [
      joinPath(repoRoot, "node_modules", "playwright", "cli.js"),
      "test",
      "--config=playwright.config.mts",
      ...playwrightArguments
    ],
    environment: {}
  };
}

function runE2E() {
  const command = buildE2ECommand(process.platform, process.argv.slice(2));
  const result = spawnSync(command.executable, command.args, {
    cwd: repositoryRoot,
    env: { ...process.env, ...command.environment },
    stdio: "inherit",
    windowsHide: true
  });

  if (result.error) {
    process.stderr.write(`Could not start the E2E runner (${result.error.code ?? "unknown error"}).\n`);
    process.exitCode = 1;
    return;
  }
  if (result.signal) {
    process.stderr.write(`The E2E runner stopped with signal ${result.signal}.\n`);
    process.exitCode = 1;
    return;
  }
  process.exitCode = result.status ?? 1;
}

if (process.argv[1] && resolve(process.argv[1]) === modulePath) runE2E();
