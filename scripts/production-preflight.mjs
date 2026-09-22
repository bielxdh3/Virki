import { spawnSync } from "node:child_process";
import { PRODUCTION_CONFIG, isValidProductionConfig } from "./lib/production-config.mjs";

export const SSH_OPTIONS = [
  "-o",
  "BatchMode=yes",
  "-o",
  "StrictHostKeyChecking=yes",
  "-o",
  "ConnectTimeout=10",
  "-o",
  "ConnectionAttempts=1",
  "-o",
  "ServerAliveInterval=5",
  "-o",
  "ServerAliveCountMax=2",
];

const PROBE_COUNT = 8;

export class ProductionPreflightError extends Error {
  constructor(code, message = code) {
    super(message);
    this.name = "ProductionPreflightError";
    this.code = code;
  }
}

function run(command, args) {
  const result = spawnSync(command, args, {
    encoding: "utf8",
    shell: false,
    windowsHide: true,
    maxBuffer: 8 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
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

export function buildSshArgs(remoteArguments, config = PRODUCTION_CONFIG) {
  if (!isValidProductionConfig(config)) throw new ProductionPreflightError("OPERATOR_CONFIG_INVALID");
  return [...SSH_OPTIONS, config.sshAlias, ...remoteArguments];
}

function encodePowerShell(script) {
  return Buffer.from(script, "utf16le").toString("base64");
}

function probeScript() {
  return [
    "$ErrorActionPreference='Stop'",
    "$id=[Environment]::MachineName",
    "$wd=(Get-Location).Path",
    "$pw=(Get-Command powershell.exe -ErrorAction Stop).Source",
    "$dk=(Get-Command docker.exe -ErrorAction Stop).Source",
    "if(-not (Test-Path -LiteralPath 'C:\\')){throw 'filesystem unavailable'}",
    "Write-Output ('BIELOS_PROBE_ID=' + $id)",
    "Write-Output ('BIELOS_PROBE_WD=' + $wd)",
    "Write-Output ('BIELOS_PROBE_POWERSHELL=' + $pw)",
    "Write-Output ('BIELOS_PROBE_DOCKER=' + $dk)",
  ].join(";");
}

function dockerScript() {
  return [
    "$ErrorActionPreference='Stop'",
    "$version=(docker version --format '{{.Server.Version}}').Trim()",
    "$info=(docker info --format '{{.ServerVersion}}').Trim()",
    "$compose=(docker compose version --short).Trim()",
    "$free=[math]::Round((Get-PSDrive -Name C).Free/1GB,1)",
    "$names=@(docker ps --format '{{.Names}}')",
    "$dem=@($names | Where-Object {$_ -match 'demanage'})",
    "Write-Output ('BIELOS_DOCKER_VERSION=' + $version)",
    "Write-Output ('BIELOS_DOCKER_INFO=' + $info)",
    "Write-Output ('BIELOS_COMPOSE_VERSION=' + $compose)",
    "Write-Output ('BIELOS_DISK_FREE_GB=' + $free)",
    "Write-Output ('BIELOS_DEMANAGE_COUNT=' + $dem.Count)",
  ].join(";");
}

function runPowerShell(script, execute = run, config = PRODUCTION_CONFIG) {
  return execute(
    "ssh",
    buildSshArgs([
      "powershell.exe",
      "-NoLogo",
      "-NoProfile",
      "-NonInteractive",
      "-EncodedCommand",
      encodePowerShell(script),
    ], config),
  );
}

function lineValue(output, prefix) {
  const line = output.split(/\r?\n/u).find((value) => value.startsWith(prefix));
  return line ? line.slice(prefix.length).trim() : "";
}

function probeIsValid(result) {
  return (
    result.status === 0 &&
    lineValue(result.stdout, "BIELOS_PROBE_ID=").length > 0 &&
    lineValue(result.stdout, "BIELOS_PROBE_WD=").length > 0 &&
    lineValue(result.stdout, "BIELOS_PROBE_POWERSHELL=").length > 0 &&
    lineValue(result.stdout, "BIELOS_PROBE_DOCKER=").length > 0
  );
}

export async function runProductionPreflight({ execute = run, sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)), config: operatorConfig = PRODUCTION_CONFIG } = {}) {
  if (!isValidProductionConfig(operatorConfig)) {
    return { status: 1, lines: ["Private production operator configuration is missing or invalid."] };
  }
  const config = execute("ssh", ["-G", operatorConfig.sshAlias]);
  if (config.status !== 0) {
    return { status: 1, lines: ["SSH configuration could not be resolved."] };
  }

  const resolved = parseSshConfig(config.stdout);
  if (resolved.hostname.toLowerCase() !== operatorConfig.host.toLowerCase() || resolved.port !== String(operatorConfig.port) || !resolved.user) {
    return { status: 1, lines: ["SSH target does not match the canonical BielOS production server."] };
  }

  let identity = "";
  const lines = [];
  for (let attempt = 1; attempt <= PROBE_COUNT; attempt += 1) {
    const result = execute(
      "ssh",
      buildSshArgs([
        "powershell.exe",
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-EncodedCommand",
        encodePowerShell(probeScript()),
      ], operatorConfig),
    );
    if (!probeIsValid(result)) {
      return { status: 1, lines: [`SSH preflight failed on probe ${attempt}.`] };
    }

    const observed = lineValue(result.stdout, "BIELOS_PROBE_ID=");
    if (identity && identity !== observed) {
      return { status: 1, lines: ["SSH preflight observed inconsistent server identity."] };
    }
    identity = observed;
    lines.push(`SSH probe ${attempt}/${PROBE_COUNT}: ok`);
    if (attempt < PROBE_COUNT) await sleep(1000);
  }

  const docker = runPowerShell(dockerScript(), execute, operatorConfig);
  if (
    docker.status !== 0 ||
    !lineValue(docker.stdout, "BIELOS_DOCKER_VERSION=") ||
    !lineValue(docker.stdout, "BIELOS_DOCKER_INFO=") ||
    !lineValue(docker.stdout, "BIELOS_COMPOSE_VERSION=")
  ) {
    return { status: 1, lines: [...lines, "Remote Docker preflight failed."] };
  }

  lines.push("SSH preflight passed with a stable server identity.");
  lines.push(`Remote Docker ${lineValue(docker.stdout, "BIELOS_DOCKER_VERSION=")} / Compose ${lineValue(docker.stdout, "BIELOS_COMPOSE_VERSION=")}.`);
  lines.push(`Remote free disk ${lineValue(docker.stdout, "BIELOS_DISK_FREE_GB=")} GB; deManage containers ${lineValue(docker.stdout, "BIELOS_DEMANAGE_COUNT=")}.`);
  return { status: 0, lines };
}

if (process.argv[1] && process.argv[1].endsWith("production-preflight.mjs")) {
  runProductionPreflight().then((result) => {
    for (const line of result.lines) console.log(line);
    process.exitCode = result.status;
  });
}
