import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { lstatSync, realpathSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

// Development-only guard. The Windows named pipe is an OS-local endpoint,
// NOT an independent cryptographic proof of a production Docker daemon.
export const LOCAL_ENGINE = "npipe:////./pipe/dockerDesktopLinuxEngine";
const OWNER_LABEL = "dev.virki.offline.disposable-owner";
const DOCKER_CLI = "C:\\Program Files\\Docker\\Docker\\resources\\bin\\docker.exe";
const POWERSHELL = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
const FIXTURE_IMAGE = "node:22.23.3-bookworm@sha256:0e5f906573693feaa1e21057ebdcfdb5bd5021f050b2dc7c9deceb629c7da2a8";
const SOURCE_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

// This runner is intentionally limited to the three checked-in, read-only
// test profiles. Docker run exposes dozens of host escape surfaces; accepting
// a subset of CLI options with a blacklist would silently reopen them.
function fixtureProfiles(root) {
  const common = [
    "run", "--rm", "--pull=never", "--platform=linux/amd64",
    "--network=none", "--read-only", "--cap-drop=ALL",
    "--security-opt=no-new-privileges",
  ];
  const source = ["--mount", `type=bind,src=${root},dst=/workspace,readonly`, "--workdir", "/workspace"];
  const execute = (tests) => [FIXTURE_IMAGE, "node", "--test", ...tests];
  return [
    [
      ...common, "--user", "0:0", "--pids-limit=128", "--memory=512m",
      "--tmpfs", "/tmp:rw,exec,nosuid,nodev,size=64m,mode=1777",
      ...source, "--env", "VIRKI_DISPOSABLE_PEER_PROBE=1",
      ...execute(["infra/offline/native-peer/native-peer-probe.test.mjs"]),
    ],
    [
      ...common, "--pids-limit=128",
      "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=128m,mode=1777",
      ...source, "--env", "VIRKI_NATIVE_RECOVERY_DISPOSABLE_TEST=1",
      ...execute(["infra/offline/trusted-native-recovery-fixture.test.mjs"]),
    ],
    [
      ...common, "--pids-limit=128",
      "--tmpfs", "/etc:rw,nosuid,nodev,noexec,size=16m,mode=755",
      "--tmpfs", "/var/lib:rw,nosuid,nodev,noexec,size=256m,mode=755",
      "--tmpfs", "/usr/local/lib/virki:rw,nosuid,nodev,noexec,size=16m,mode=700",
      "--tmpfs", "/run:rw,exec,nosuid,nodev,size=32m,mode=755",
      "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=64m,mode=1777",
      ...source, "--env", "VIRKI_COORDINATOR_DISPOSABLE_CONTAINER=1",
      "--env", "VIRKI_OWNER_INSTALL_DISPOSABLE_FIXTURE=1",
      ...execute([
        "infra/offline/trusted-release-coordinator.test.mjs",
        "infra/offline/trusted-owner-installation.test.mjs",
      ]),
    ],
  ];
}

function assertFixtureArguments(args, cwd, timeout) {
  if (!Array.isArray(args) || !Number.isSafeInteger(timeout) ||
      timeout < 1000 || timeout > 180_000 || typeof cwd !== "string") {
    throw new Error("Invalid bounded disposable Docker fixture command.");
  }
  let root;
  try {
    root = realpathSync.native(SOURCE_ROOT);
    if (realpathSync.native(cwd).toLowerCase() !== root.toLowerCase() ||
        /[,\r\n]/u.test(root)) {
      throw new Error("untrusted root");
    }
  } catch {
    throw new Error("Invalid bounded disposable Docker fixture command.");
  }
  if (!fixtureProfiles(root).some((expected) =>
    expected.length === args.length && expected.every((value, i) => value === args[i]))) {
    throw new Error("Invalid bounded disposable Docker fixture command.");
  }
}

/**
 * Use only Docker Inc's Authenticode-signed executable in the protected,
 * standard Windows Docker Desktop installation directory. Never search PATH.
 * Alternate installations fail closed until explicitly reviewed.
 */
export function verifyTrustedWindowsDockerCli({
  stat = lstatSync,
  canonicalize = realpathSync.native,
  authenticate = spawnSync,
} = {}) {
  try {
    const entry = stat(DOCKER_CLI);
    if (!entry.isFile() || entry.isSymbolicLink() ||
        canonicalize(DOCKER_CLI).toLowerCase() !== DOCKER_CLI.toLowerCase()) {
      throw new Error("unexpected Docker CLI file");
    }
    const script = `$ErrorActionPreference = 'Stop'; $sig = Get-AuthenticodeSignature -LiteralPath '${DOCKER_CLI}'; if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch '(^|, )O=Docker Inc(,|$)') { exit 1 }; [Console]::Out.Write('DOCKER_SIGNED')`;
    const result = authenticate(POWERSHELL,
      ["-NoProfile", "-NonInteractive", "-Command", script],
      {
        shell: false, windowsHide: true, timeout: 10_000,
        encoding: "utf8", maxBuffer: 1024,
        env: syntheticEnvironment(),
      });
    if (result.error || result.status !== 0 || result.stdout !== "DOCKER_SIGNED") {
      throw new Error("untrusted Docker CLI signature");
    }
    return DOCKER_CLI;
  } catch {
    throw new Error("Disposable offline tests require a trusted Docker Desktop CLI installation.");
  }
}

export function requireLocalFixtureEnvironment(platform = process.platform, env = process.env) {
  if (platform !== "win32" || Object.keys(env).some((key) => /^DOCKER_/iu.test(key))) {
    throw new Error("Disposable offline tests require Windows local Docker Desktop without Docker environment overrides.");
  }
}

function syntheticEnvironment() {
  return {
    PATH: "C:\\Windows\\System32;C:\\Windows",
    SystemRoot: "C:\\Windows",
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
  assertFixtureArguments(args, cwd, timeout);
  // Only a mocked process runner may skip the real on-disk signature check.
  // The executable passed to either runner is always the fixed absolute path.
  const executable = invoke === spawnSync ? verifyTrustedWindowsDockerCli() : DOCKER_CLI;
  const options = {
    cwd, shell: false, windowsHide: true,
    env: syntheticEnvironment(),
  };
  const docker = (argv, extra = {}) => invoke(executable, ["--host", LOCAL_ENGINE, ...argv],
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
