import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { readProductionConfig, isValidProductionConfig } from "./lib/production-config.mjs";
import { inspectProductionSource, ProductionRevisionError, runCommand } from "./lib/production-revision.mjs";
import { verifyExactShaCi } from "./lib/production-ci.mjs";

const repositoryRoot = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
export const SSH_OPTIONS = [
  "-o", "BatchMode=yes",
  "-o", "StrictHostKeyChecking=yes",
  "-o", "ConnectTimeout=10",
  "-o", "ConnectionAttempts=1",
  "-o", "ServerAliveInterval=5",
  "-o", "ServerAliveCountMax=2",
];

const PROBE_COUNT = 8;
const PROBE_SCRIPT = `
set -eu
root=$2
fail() { printf 'VIRKI_PROBE_FAILURE=%s\\n' "$1"; exit 1; }
[[ "$(uname -s)" == Linux ]] || fail NOT_LINUX
kernel=$(tr '[:upper:]' '[:lower:]' < /proc/sys/kernel/osrelease)
[[ "$kernel" != *microsoft* && "$kernel" != *wsl* ]] || fail WSL
[[ -d "$root" && ! -L "$root" && "$(stat -c '%a' -- "$root")" == 700 && "$(stat -c '%u' -- "$root")" == "$(id -u)" ]] || fail ROOT_METADATA_INVALID
[[ "$(readlink -f -- "$root")" == "$root" ]] || fail ROOT_NOT_CANONICAL
for name in .deploy-tmp releases backups; do
  directory="$root/$name"
  [[ -d "$directory" && ! -L "$directory" && "$(stat -c '%a' -- "$directory")" == 700 && "$(stat -c '%u' -- "$directory")" == "$(id -u)" ]] || fail DIRECTORY_METADATA_INVALID
done
marker="$root/.virki-production-host"
[[ -f "$marker" && ! -L "$marker" && "$(stat -c '%a' -- "$marker")" == 600 && "$(stat -c '%u' -- "$marker")" == "$(id -u)" && "$(wc -l < "$marker")" -eq 4 ]] || fail MARKER_METADATA_INVALID
host=$(hostname -s)
grep -Fxq 'role=production' "$marker" || fail MARKER_CONTENT_INVALID
grep -Fxq 'protocol=2' "$marker" || fail MARKER_CONTENT_INVALID
grep -Fxq "hostname=$host" "$marker" || fail MARKER_CONTENT_INVALID
grep -Fxq "path=$root" "$marker" || fail MARKER_CONTENT_INVALID
for name in .env .env.oidc .env.oidc-data .ghcr-read-token; do
  file="$root/$name"
  [[ -f "$file" && ! -L "$file" ]] || fail "PROTECTED_ENV_FILE_MISSING_OR_UNSAFE:$name"
  [[ "$(stat -c '%a' -- "$file")" == 600 && "$(stat -c '%u' -- "$file")" == "$(id -u)" ]] || fail "PROTECTED_ENV_METADATA_INVALID:$name"
done
printf 'VIRKI_PROBE_ID=%s\\n' "$host"
printf 'VIRKI_PROBE_WD=%s\\n' "$root"
printf 'VIRKI_PROBE_PLATFORM=linux-native\\n'
printf 'VIRKI_PROBE_MARKER=valid\\n'
`;

// Explicitly opted-in offline validation must not depend on a GHCR credential.
// Keep the hosted probe unchanged: it still requires its dedicated read token.
const OFFLINE_PROBE_SCRIPT = PROBE_SCRIPT.replace(
  "for name in .env .env.oidc .env.oidc-data .ghcr-read-token; do",
  "for name in .env .env.oidc .env.oidc-data; do",
);

export const DOCKER_SCRIPT = `
set -eu
root=$2
version=$(docker version --format '{{.Server.Version}}')
info=$(docker info --format '{{.ServerVersion}}')
compose=$(docker compose version --short)
docker_os=$(docker info --format '{{.OSType}}')
docker_arch=$(docker info --format '{{.Architecture}}')
command -v flock >/dev/null 2>&1
free=$(df -Pk -- "$root" | awk 'NR == 2 { printf "%.1f", $4 / 1024 / 1024 }')
container_names=$(docker ps --format '{{.Names}}')
demanage=$(printf '%s\n' "$container_names" | awk 'tolower($0) ~ /demanage/ { count++ } END { print count + 0 }')
case "$docker_arch" in
  x86_64|amd64) docker_arch=amd64 ;;
  aarch64|arm64) docker_arch=arm64 ;;
  *) exit 1 ;;
esac
[[ "$docker_os" == linux && -n "$version" && -n "$info" && -n "$compose" && "$free" =~ ^[0-9]+([.][0-9]+)?$ && "$demanage" =~ ^[0-9]+$ ]]
printf 'VIRKI_DOCKER_VERSION=%s\\n' "$version"
printf 'VIRKI_DOCKER_INFO=%s\\n' "$info"
printf 'VIRKI_COMPOSE_VERSION=%s\\n' "$compose"
printf 'VIRKI_PLATFORM=linux/%s\\n' "$docker_arch"
printf 'VIRKI_FLOCK=available\\n'
printf 'VIRKI_DISK_FREE_GB=%s\\n' "$free"
printf 'VIRKI_DEMANAGE_COUNT=%s\\n' "$demanage"
`;

export class ProductionPreflightError extends Error {
  constructor(code, message = code) {
    super(message);
    this.name = "ProductionPreflightError";
    this.code = code;
  }
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    encoding: "utf8",
    input: options.input,
    shell: false,
    windowsHide: true,
    maxBuffer: 8 * 1024 * 1024,
    stdio: options.input === undefined ? ["ignore", "pipe", "pipe"] : ["pipe", "pipe", "pipe"],
  });

  if (result.error) return { status: 1, stdout: "", stderr: "" };
  return {
    status: Number.isInteger(result.status) ? result.status : 1,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
  };
}

export function parseSshConfig(output) {
  const values = new Map();
  for (const line of output.split(/\r?\n/u)) {
    const match = line.trim().match(/^(hostname|port|user)\s+(.+)$/iu);
    if (match) values.set(match[1].toLowerCase(), match[2].trim());
  }
  return {
    hostname: values.get("hostname") ?? "",
    port: values.get("port") ?? "",
    user: values.get("user") ?? "",
  };
}

export function buildSshArgs(remoteCommand, config = readProductionConfig(), input = "") {
  if (!isValidProductionConfig(config)) throw new ProductionPreflightError("OPERATOR_CONFIG_INVALID");
  return {
    args: [...SSH_OPTIONS, config.sshAlias, remoteCommand],
    input,
  };
}

function sshRemoteCommand(scriptName, root) {
  return `bash -s -- ${scriptName} ${root}`;
}

function runRemoteScript(script, scriptName, execute, config) {
  const { args, input } = buildSshArgs(sshRemoteCommand(scriptName, config.root), config, script);
  return execute("ssh", args, { input });
}

function lineValue(output, prefix) {
  const line = output.split(/\r?\n/u).find((value) => value.startsWith(prefix));
  return line ? line.slice(prefix.length).trim() : "";
}

function probeIsValid(result) {
  return result.status === 0 &&
    lineValue(result.stdout, "VIRKI_PROBE_ID=").length > 0 &&
    lineValue(result.stdout, "VIRKI_PROBE_WD=").length > 0 &&
    lineValue(result.stdout, "VIRKI_PROBE_PLATFORM=") === "linux-native" &&
    lineValue(result.stdout, "VIRKI_PROBE_MARKER=") === "valid";
}

function describeProbeFailure(result) {
  const hostCheck = lineValue(result.stdout, "VIRKI_PROBE_FAILURE=");
  const hostCheckMessages = {
    NOT_LINUX: "target is not native Linux.",
    WSL: "target is running under WSL.",
    ROOT_METADATA_INVALID: "production root metadata is invalid.",
    ROOT_NOT_CANONICAL: "production root is not canonical.",
    DIRECTORY_METADATA_INVALID: "required production directory metadata is invalid.",
    MARKER_METADATA_INVALID: "production host marker is missing or has unsafe metadata.",
    MARKER_CONTENT_INVALID: "production host marker does not match the host and root.",
  };
  if (Object.hasOwn(hostCheckMessages, hostCheck)) return hostCheckMessages[hostCheck];
  for (const name of [".env", ".env.oidc", ".env.oidc-data", ".ghcr-read-token"]) {
    if (hostCheck === `PROTECTED_ENV_FILE_MISSING_OR_UNSAFE:${name}`) {
      return `protected production environment file ${name} is missing or is not a regular file.`;
    }
    if (hostCheck === `PROTECTED_ENV_METADATA_INVALID:${name}`) {
      return `protected production environment file ${name} has unsafe ownership or permissions.`;
    }
  }

  const sshError = String(result.stderr ?? "").toLowerCase();
  if (/host key verification failed|remote host identification has changed|no .* host key is known/u.test(sshError)) {
    return "strict host-key verification rejected the SSH target.";
  }
  if (/permission denied/u.test(sshError)) return "SSH authentication failed for the configured alias.";
  if (/connection timed out|connection refused|no route to host|could not resolve hostname|connection reset/u.test(sshError)) {
    return "SSH could not reach the configured host.";
  }
  return "SSH transport or remote probe did not return a verifiable result.";
}

export async function runProductionPreflight({
  execute = run,
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  config: operatorConfig = readProductionConfig(),
  mode = "hosted",
} = {}) {
  if (mode !== "hosted" && mode !== "offline") {
    return { status: 1, lines: ["Unknown production preflight release mode."] };
  }
  if (!isValidProductionConfig(operatorConfig)) {
    return { status: 1, lines: ["Private production operator configuration is missing or invalid."] };
  }
  const resolvedConfig = execute("ssh", ["-G", operatorConfig.sshAlias]);
  if (resolvedConfig.status !== 0) {
    return { status: 1, lines: ["SSH configuration could not be resolved."] };
  }

  const resolved = parseSshConfig(resolvedConfig.stdout);
  if (
    resolved.hostname.toLowerCase() !== operatorConfig.host.toLowerCase() ||
    resolved.port !== String(operatorConfig.port) ||
    !resolved.user
  ) {
    return { status: 1, lines: ["SSH target does not match the canonical Virki production server."] };
  }

  let identity = "";
  const lines = [];
  for (let attempt = 1; attempt <= PROBE_COUNT; attempt += 1) {
    const result = runRemoteScript(mode === "offline" ? OFFLINE_PROBE_SCRIPT : PROBE_SCRIPT,
      "probe", execute, operatorConfig);
    if (!probeIsValid(result)) {
      return { status: 1, lines: [`SSH preflight failed on probe ${attempt}; ${describeProbeFailure(result)}`] };
    }

    const observed = `${lineValue(result.stdout, "VIRKI_PROBE_ID=")}\n${lineValue(result.stdout, "VIRKI_PROBE_WD=")}`;
    if (identity && identity !== observed) {
      return { status: 1, lines: ["SSH preflight observed inconsistent native Linux server identity."] };
    }
    identity = observed;
    lines.push(`SSH probe ${attempt}/${PROBE_COUNT}: native Linux identity and pre-provisioned marker verified`);
    if (attempt < PROBE_COUNT) await sleep(1000);
  }

  const docker = runRemoteScript(DOCKER_SCRIPT, "docker", execute, operatorConfig);
  if (
    docker.status !== 0 ||
    !lineValue(docker.stdout, "VIRKI_DOCKER_VERSION=") ||
    !lineValue(docker.stdout, "VIRKI_DOCKER_INFO=") ||
    !lineValue(docker.stdout, "VIRKI_COMPOSE_VERSION=") ||
    !/^linux\/(?:amd64|arm64)$/u.test(lineValue(docker.stdout, "VIRKI_PLATFORM=")) ||
    lineValue(docker.stdout, "VIRKI_FLOCK=") !== "available" ||
    !/^\d+(?:\.\d+)?$/u.test(lineValue(docker.stdout, "VIRKI_DISK_FREE_GB=")) ||
    !/^\d+$/u.test(lineValue(docker.stdout, "VIRKI_DEMANAGE_COUNT="))
  ) {
    return { status: 1, lines: [...lines, "Remote Docker, Compose, locking, or disk preflight failed."] };
  }

  lines.push("SSH preflight passed with a stable native Linux identity.");
  lines.push(`Remote Docker ${lineValue(docker.stdout, "VIRKI_DOCKER_VERSION=")} / Compose ${lineValue(docker.stdout, "VIRKI_COMPOSE_VERSION=")}.`);
  lines.push(`Remote Docker platform ${lineValue(docker.stdout, "VIRKI_PLATFORM=")}.`);
  lines.push(`Remote free disk ${lineValue(docker.stdout, "VIRKI_DISK_FREE_GB=")} GB; deManage container names observed ${lineValue(docker.stdout, "VIRKI_DEMANAGE_COUNT=")}.`);
  return { status: 0, lines, platform: lineValue(docker.stdout, "VIRKI_PLATFORM=") };
}

export async function runAcceptedProductionPreflight({
  sourceExecute = runCommand,
  execute = run,
  inspectSource = inspectProductionSource,
  verifyCi = verifyExactShaCi,
  preflight = runProductionPreflight,
  config = readProductionConfig(),
} = {}) {
  if (!isValidProductionConfig(config)) {
    return { status: 1, lines: ["Private production operator configuration is missing or invalid."] };
  }

  let source;
  try {
    source = inspectSource({ repositoryRoot, execute: sourceExecute });
  } catch (error) {
    return {
      status: 1,
      lines: [error instanceof ProductionRevisionError
        ? error.message
        : "Production source state could not be verified."]
    };
  }

  let gate;
  try {
    gate = verifyCi({ revision: source.revision, execute: sourceExecute, repositoryRoot });
  } catch {
    return { status: 1, lines: ["Exact-SHA release evidence could not be verified."] };
  }
  if (!gate?.ok) {
    return {
      status: 1,
      lines: Array.isArray(gate?.lines) && gate.lines.length > 0
        ? gate.lines
        : ["Exact-SHA release evidence could not be verified."]
    };
  }

  const result = await preflight({ execute, config });
  return { ...result, lines: [...(gate.lines ?? []), ...(result.lines ?? [])] };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  runAcceptedProductionPreflight().then((result) => {
    for (const line of result.lines) console.log(line);
    process.exitCode = result.status;
  });
}
