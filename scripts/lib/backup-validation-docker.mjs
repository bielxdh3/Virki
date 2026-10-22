import { randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import { realpathSync, statSync } from "node:fs";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

// Only the explicit local Windows fixture or a GitHub-hosted disposable Linux CI runner.
export const DOCKER_BINARY = "C:\\Program Files\\Docker\\Docker\\resources\\bin\\docker.exe";
export const DOCKER_HOST = "npipe:////./pipe/dockerDesktopLinuxEngine";
export const LINUX_CI_DOCKER_BINARY = "/usr/bin/docker";
export const LINUX_CI_DOCKER_HOST = "unix:///var/run/docker.sock";
export const POSTGRES_IMAGE = "postgres:17-alpine@sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24";
const OWNER_LABEL = "virki.backup-validation.owner";
const FIXTURE_LABEL = "virki.backup-validation.fixture";
const ID_PATTERN = /^[a-f0-9]{64}$/u;

// Written BEFORE `docker run`, so a failed CLI or delayed container creation
// cannot destroy the only independently useful name/owner lookup information.
export async function createBackupOwnerEvidence(docker, parent = os.tmpdir()) {
  const directory = await mkdtemp(path.join(parent, "virki-backup-owner-"));
  const manifest = {
    version: 1,
    fixture: "prisma-backup-restore",
    name: docker.name,
    ownerLabel: `${OWNER_LABEL}=${docker.nonce}`,
    image: POSTGRES_IMAGE,
    daemonId: docker.daemonId,
    endpoint: docker.host,
  };
  try {
    await writeFile(path.join(directory, "owner.json"), `${JSON.stringify(manifest)}\n`, { flag: "wx", mode: 0o600 });
    return directory;
  } catch (error) {
    await rm(directory, { recursive: true, force: true });
    throw error;
  }
}

export async function finalizeBackupOwnerEvidence(docker, directory) {
  if (!directory) return { retained: false };
  if (docker?.runAttempted && !docker.cleaned) return { retained: true, directory };
  await rm(directory, { recursive: true, force: true });
  return { retained: false };
}

export async function readBackupOwnerEvidence(directory) {
  // Read-only manual reconciliation aid; this never authorizes container removal.
  return JSON.parse(await readFile(path.join(directory, "owner.json"), "utf8"));
}

export function assertLocalBackupEnvironment(env = process.env, platform = process.platform) {
  const windows = platform === "win32" && env.VIRKI_BACKUP_VALIDATION_LOCAL_DOCKER === "1" && !env.VIRKI_BACKUP_VALIDATION_LINUX_CI;
  const linuxCI = platform === "linux" && env.VIRKI_BACKUP_VALIDATION_LINUX_CI === "1" && !env.VIRKI_BACKUP_VALIDATION_LOCAL_DOCKER &&
    env.GITHUB_ACTIONS === "true" && env.CI === "true" && env.RUNNER_OS === "Linux" &&
    env.RUNNER_ENVIRONMENT === "github-hosted" && env.GITHUB_REPOSITORY === "bielxdh3/Virki" &&
    /^[1-9][0-9]{0,19}$/u.test(env.GITHUB_RUN_ID ?? "") && /^[1-9][0-9]*$/u.test(env.GITHUB_RUN_ATTEMPT ?? "");
  if (!windows && !linuxCI) {
    throw new Error("Backup validation requires explicit Windows Docker Desktop or verified GitHub-hosted Linux CI opt-in.");
  }
  const forbidden = Object.keys(env).filter((key) =>
    /^(?:DOCKER_|COMPOSE_|PG(?:HOST|PORT|SERVICE|SERVICEFILE|PASSFILE|PASSWORD|OPTIONS|USER|DATABASE)$|DATABASE_URL$|MIGRATION_DATABASE_URL$|NODE_OPTIONS$|NODE_EXTRA_CA_CERTS$)/iu.test(key));
  if (forbidden.length) {
    throw new Error("Backup validation refuses ambient Docker, database and Node overrides; unset them before local testing.");
  }
  return linuxCI ? "linux-ci" : "windows-local";
}

export function inspectLinuxRunnerSocket({
  stat = statSync, realpath = realpathSync, hostname = os.hostname,
} = {}) {
  let socket, binary, resolvedSocket, resolvedBinary;
  try {
    socket = stat("/var/run/docker.sock");
    binary = stat(LINUX_CI_DOCKER_BINARY);
    resolvedSocket = realpath("/var/run/docker.sock");
    resolvedBinary = realpath(LINUX_CI_DOCKER_BINARY);
  } catch {
    throw new Error("GitHub-hosted Linux Docker socket or CLI could not be verified.");
  }
  if (resolvedSocket !== "/run/docker.sock" || resolvedBinary !== LINUX_CI_DOCKER_BINARY ||
    !socket.isSocket() || socket.uid !== 0 || (socket.mode & 0o002) !== 0 ||
    !binary.isFile() || binary.uid !== 0 || (binary.mode & 0o002) !== 0 ||
    !Number.isSafeInteger(socket.dev) || !Number.isSafeInteger(socket.ino) ||
    !/^[A-Za-z0-9][A-Za-z0-9.-]{0,253}$/u.test(hostname())) {
    throw new Error("GitHub-hosted Linux Docker socket, CLI or hostname is not trustworthy.");
  }
  return { socketDevice: socket.dev, socketInode: socket.ino, hostname: hostname() };
}

function assertDockerSuccess(result, operation) {
  if (result.error || result.status !== 0 || typeof result.stdout !== "string") {
    throw new Error(`Local backup Docker ${operation} failed (details redacted).`);
  }
  return result.stdout.trim();
}

export class LocalBackupDocker {
  constructor({ configDirectory, env = process.env, platform = process.platform, spawn = spawnSync,
    linuxProbe = inspectLinuxRunnerSocket, nonce = randomBytes(24).toString("hex") }) {
    this.mode = assertLocalBackupEnvironment(env, platform);
    if (!configDirectory || !/^[a-f0-9]{48}$/u.test(nonce)) throw new Error("Invalid backup validation isolation configuration.");
    this.spawn = spawn;
    this.linuxProbe = linuxProbe;
    this.linuxIdentity = this.mode === "linux-ci" ? this.linuxProbe() : null;
    this.binary = this.mode === "linux-ci" ? LINUX_CI_DOCKER_BINARY : DOCKER_BINARY;
    this.host = this.mode === "linux-ci" ? LINUX_CI_DOCKER_HOST : DOCKER_HOST;
    this.configDirectory = configDirectory;
    this.nonce = nonce;
    this.name = `virki-backup-validation-${nonce}`;
    this.id = null;
    this.runAttempted = false;
    this.cleaned = false;
    this.daemonId = null;
    this.expectedImageId = null;
    this.dockerEnvironment = this.mode === "linux-ci"
      ? { HOME: configDirectory, LANG: "C", DOCKER_CONFIG: configDirectory }
      : { SystemRoot: env.SystemRoot ?? "C:\\Windows", WINDIR: env.WINDIR ?? "C:\\Windows",
          TEMP: env.TEMP ?? "C:\\Windows\\Temp", TMP: env.TMP ?? "C:\\Windows\\Temp", DOCKER_CONFIG: configDirectory };
  }

  assertEndpoint() {
    if (this.linuxIdentity) {
      const current = this.linuxProbe();
      if (current.socketDevice !== this.linuxIdentity.socketDevice || current.socketInode !== this.linuxIdentity.socketInode ||
          current.hostname !== this.linuxIdentity.hostname) {
        throw new Error("Linux CI Docker socket or runner identity changed; manual reconciliation required.");
      }
    }
  }

  call(args, { input, binary = false, timeout = 120_000, maxBuffer = 10 * 1024 * 1024 } = {}) {
    this.assertEndpoint();
    return this.spawn(this.binary, ["--host", this.host, "--config", this.configDirectory, ...args], {
      input, encoding: binary ? null : "utf8", windowsHide: true, timeout, maxBuffer,
      env: this.dockerEnvironment,
    });
  }

  command(args, options) {
    return assertDockerSuccess(this.call(args, options), args[0]);
  }

  engine() {
    let info;
    this.assertEndpoint();
    try { info = JSON.parse(this.command(["info", "--format", "{{json .}}"])); }
    catch { throw new Error("Local Docker Desktop Linux engine identity cannot be verified."); }
    const trustedOS = this.mode === "linux-ci" ? info?.Name === this.linuxIdentity.hostname && !info?.OperatingSystem?.includes("Docker Desktop")
      : /^Docker Desktop(?:\b|$)/u.test(info?.OperatingSystem ?? "");
    if (info?.OSType !== "linux" || !trustedOS ||
        typeof info.ID !== "string" || info.ID.length < 8) {
      throw new Error("Backup validation requires the local Docker Desktop Linux engine.");
    }
    if (this.daemonId !== null && info.ID !== this.daemonId) {
      throw new Error("Docker engine changed during backup validation; owned cleanup requires manual inspection.");
    }
    this.daemonId = info.ID;
  }

  inspect(target = this.id) {
    if (target === null || (target !== this.name && !ID_PATTERN.test(target))) {
      throw new Error("Invalid backup validation container identity.");
    }
    let container;
    try { container = JSON.parse(this.command(["inspect", "--type", "container", "--format", "{{json .}}", target])); }
    catch { throw new Error("Owned backup validation container could not be inspected."); }
    if (!ID_PATTERN.test(container?.Id ?? "") || container?.Name !== `/${this.name}` ||
        container?.Config?.Labels?.[OWNER_LABEL] !== this.nonce ||
        container?.Config?.Labels?.[FIXTURE_LABEL] !== "prisma-backup-restore" ||
        container?.Config?.Image !== POSTGRES_IMAGE ||
        container?.Image !== this.expectedImageId ||
        container?.HostConfig?.Privileged !== false ||
        (container?.HostConfig?.Binds?.length ?? 0) !== 0 ||
        !Array.isArray(container?.Mounts) ||
        container.Mounts.some((mount) => mount.Type === "bind" || mount.Type === "volume") ||
        !container?.HostConfig?.Tmpfs?.["/var/lib/postgresql/data"] ||
        !Array.isArray(container?.HostConfig?.PortBindings?.["5432/tcp"]) ||
        container.HostConfig.PortBindings["5432/tcp"].length !== 1 ||
        container.HostConfig.PortBindings["5432/tcp"][0].HostIp !== "127.0.0.1" ||
        (container?.State?.Running !== false && (
          !Array.isArray(container?.NetworkSettings?.Ports?.["5432/tcp"]) ||
          container.NetworkSettings.Ports["5432/tcp"].length !== 1 ||
          container.NetworkSettings.Ports["5432/tcp"][0].HostIp !== "127.0.0.1"
        ))) {
      throw new Error("Backup validation container failed independent ownership/isolation inspection.");
    }
    if (this.id !== null && container.Id !== this.id) {
      throw new Error("Backup validation container immutable ID changed.");
    }
    return container;
  }

  start({ database, user, password }) {
    this.engine();
    if (this.mode === "linux-ci") {
      // The ephemeral hosted CI job may start with an empty image cache. The
      // sole allowed network fetch is this exact immutable PostgreSQL digest.
      this.command(["pull", POSTGRES_IMAGE], { timeout: 180_000 });
      this.engine();
    }
    // Never trigger a registry fetch or silently substitute a locally tagged image.
    const imageId = this.command(["image", "inspect", POSTGRES_IMAGE, "--format", "{{.Id}}"]).trim();
    if (!/^sha256:[a-f0-9]{64}$/u.test(imageId)) throw new Error("Cached PostgreSQL image identity is invalid.");
    this.expectedImageId = imageId;
    this.runAttempted = true;
    const result = this.call([
      "run", "--detach", "--pull=never", "--name", this.name,
      "--label", `${OWNER_LABEL}=${this.nonce}`, "--label", `${FIXTURE_LABEL}=prisma-backup-restore`,
      "--publish", "127.0.0.1::5432", "--tmpfs", "/var/lib/postgresql/data:rw,noexec,nosuid,nodev,size=512m",
      "--env", `POSTGRES_DB=${database}`, "--env", `POSTGRES_USER=${user}`,
      "--env", `POSTGRES_PASSWORD=${password}`,
      "--health-cmd", `pg_isready -h 127.0.0.1 -U ${user} -d ${database}`,
      "--health-interval", "1s", "--health-timeout", "3s", "--health-retries", "60",
      POSTGRES_IMAGE,
    ]);
    const returnedId = result.status === 0 && !result.error && typeof result.stdout === "string" ? result.stdout.trim() : "";
    if (ID_PATTERN.test(returnedId)) this.id = returnedId;
    else {
      // A Docker CLI can fail after creating a container. Adopt only our independently
      // verified, unpredictable name+owner label; cleanup remains ID-scoped.
      try { this.engine(); this.id = this.inspect(this.name).Id; } catch { /* no verified ownership */ }
      throw new Error("Local backup Docker run failed or returned an invalid container ID (details redacted).");
    }
    this.engine();
    this.inspect();
  }

  state() {
    this.engine();
    return this.inspect().State?.Health?.Status;
  }

  port() {
    this.engine();
    const inspected = this.inspect();
    const mapping = inspected.State?.Running ? inspected.NetworkSettings?.Ports?.["5432/tcp"]?.[0] : null;
    if (!/^[1-9][0-9]{0,4}$/u.test(mapping?.HostPort ?? "") || Number(mapping?.HostPort) > 65535) {
      throw new Error("Backup validation published port is invalid.");
    }
    return mapping.HostPort;
  }

  exec(command, { environment = {}, input, binary = false, timeout = 120_000, maxBuffer } = {}) {
    this.engine();
    this.inspect();
    const envArgs = Object.entries(environment).flatMap(([key, value]) => ["--env", `${key}=${value}`]);
    const args = ["exec", "--interactive", ...envArgs, this.id, ...command];
    const result = this.call(args, { input, binary, timeout, maxBuffer: maxBuffer ?? (binary ? 100 * 1024 * 1024 : 10 * 1024 * 1024) });
    if (result.error || result.status !== 0) throw new Error("Local backup Docker exec failed (details redacted).");
    return result.stdout;
  }

  cleanup() {
    if (!this.id) return;
    this.engine();
    this.inspect();
    const ownedId = this.id;
    this.command(["rm", "--force", "--volumes", ownedId], { timeout: 60_000 });
    this.engine();
    if (this.command(["ps", "--all", "--no-trunc", "--filter", `id=${ownedId}`, "--format", "{{.ID}}"] ) !== "") {
      throw new Error("Backup validation container removal was not independently confirmed; owner evidence must be preserved.");
    }
    this.id = null;
    this.cleaned = true;
  }
}
