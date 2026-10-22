import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";

// Development-only guard. The Windows named pipe is an OS-local endpoint,
// NOT an independent cryptographic proof of a production Docker daemon.
export const LOCAL_ENGINE = "npipe:////./pipe/dockerDesktopLinuxEngine";
const OWNER_LABEL = "dev.virki.offline.disposable-owner";

export function requireLocalFixtureEnvironment(platform = process.platform, env = process.env) {
  if (platform !== "win32" || Object.keys(env).some((key) => /^DOCKER_/iu.test(key))) {
    throw new Error("Disposable offline tests require Windows local Docker Desktop without Docker environment overrides.");
  }
}

function syntheticEnvironment(env) {
  return {
    PATH: env.PATH ?? env.Path ?? "",
    SystemRoot: env.SystemRoot ?? "",
  };
}

function assertExit(result, message) {
  if (result.error || result.status !== 0) throw new Error(message);
}

/**
 * Run an owned ephemeral Linux fixture only through the local Docker Desktop
 * named pipe. A cancelled docker CLI does not imply the container has exited,
 * so cleanup is by immutable ID after independent name+label inspection.
 */
export function runOwnedLocalLinuxFixture(args, {
  cwd, timeout = 90_000, stdio = "inherit",
  platform = process.platform, env = process.env, invoke = spawnSync,
} = {}) {
  requireLocalFixtureEnvironment(platform, env);
  if (!Array.isArray(args) || args[0] !== "run" || args[1] !== "--rm" ||
      args.some((arg) => typeof arg !== "string" || arg.includes("\u0000")) ||
      !Number.isSafeInteger(timeout) || timeout < 1000 || timeout > 180_000) {
    throw new Error("Invalid bounded disposable Docker fixture command.");
  }
  const options = {
    cwd, shell: false, windowsHide: true,
    env: syntheticEnvironment(env),
  };
  const docker = (argv, extra = {}) => invoke("docker", ["--host", LOCAL_ENGINE, ...argv],
    { ...options, ...extra });
  const info = docker(["info", "--format", "{{.OperatingSystem}}|{{.OSType}}"],
    { encoding: "utf8", timeout: 10000, maxBuffer: 4096 });
  assertExit(info, "Pinned local Docker Desktop Linux engine could not be verified.");
  if (info.stdout.trim() !== "Docker Desktop|linux") {
    throw new Error("Disposable fixture refused unexpected Docker Desktop engine identity.");
  }

  const owner = randomBytes(16).toString("hex");
  const name = `virki-offline-fixture-${owner}`;
  const runArgs = ["run", "--rm", "--name", name,
    "--label", `${OWNER_LABEL}=${owner}`, ...args.slice(2)];
  let result;
  let cleanupFailure;
  try {
    result = docker(runArgs, { stdio, timeout });
  } finally {
    // Do not use 'docker rm' by mutable name: inspection and removal may race.
    // A foreign container with the same name cannot pass the owner label proof.
    const inspect = docker(["inspect", "--format",
      `{{.Id}}|{{.Name}}|{{index .Config.Labels "${OWNER_LABEL}"}}`, name],
    { encoding: "utf8", timeout: 10000, maxBuffer: 4096 });
    if (inspect.error) {
      cleanupFailure = "Disposable Docker engine unavailable during ownership check.";
    } else if (inspect.status === 0) {
      const [id, actualName, actualOwner] = inspect.stdout.trim().split("|");
      if (!/^[a-f0-9]{64}$/u.test(id) || actualName !== `/${name}` || actualOwner !== owner) {
        cleanupFailure = "Disposable Docker ownership proof rejected; no cleanup attempted.";
      } else {
        const removed = docker(["rm", "--force", "--volumes", id],
          { encoding: "utf8", timeout: 10000, maxBuffer: 4096 });
        if (removed.error || removed.status !== 0) {
          cleanupFailure = "Disposable Docker cleanup by verified ID failed.";
        }
      }
    } else if (!/no such object|no such container/iu.test(inspect.stderr ?? "")) {
      cleanupFailure = "Disposable Docker cleanup state could not be verified.";
    }
  }
  if (cleanupFailure) throw new Error(cleanupFailure);
  assertExit(result, "Disposable Linux fixture failed or exceeded bounded runtime.");
}
