import { spawnSync } from "node:child_process";
import { dirname, posix, resolve, win32 } from "node:path";
import { fileURLToPath } from "node:url";

const modulePath = fileURLToPath(import.meta.url);
const repositoryRoot = resolve(dirname(modulePath), "../..");

export function assertDirectPlaywrightPlatform(platform, discoveryOnly = false) {
  if (platform === "win32" && !discoveryOnly) {
    throw new Error("Direct Playwright execution on Windows can install a test CA in CurrentUser\\Root. Use npm run test:e2e to run in isolated Linux Docker.");
  }
}

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

export function shouldBuildProductionHub(environment = process.env) {
  return environment.VIRKI_E2E_HUB_MODE === "production" && environment.VIRKI_E2E_HUB_BUILD_READY !== "true";
}

function runE2E() {
  const command = buildE2ECommand(process.platform, process.argv.slice(2));
  if (process.platform !== "win32" && shouldBuildProductionHub()) {
    const build = spawnSync("npm", ["run", "build", "--workspace", "@virki/hub"], {
      cwd: repositoryRoot,
      env: process.env,
      stdio: "inherit",
      windowsHide: true
    });
    if (build.error) {
      process.stderr.write(`Could not start the production Hub build (${build.error.code ?? "unknown error"}).\n`);
      process.exitCode = 1;
      return;
    }
    if (build.signal || build.status !== 0) {
      process.exitCode = build.status ?? 1;
      return;
    }
  }
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
