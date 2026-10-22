import { randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";

// This is an explicitly local Windows development fixture, never a generic Docker launcher.
export const DOCKER_BINARY = "C:\\Program Files\\Docker\\Docker\\resources\\bin\\docker.exe";
export const DOCKER_HOST = "npipe:////./pipe/dockerDesktopLinuxEngine";
export const POSTGRES_IMAGE = "postgres:17-alpine@sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24";
const OWNER_LABEL = "virki.backup-validation.owner";
const FIXTURE_LABEL = "virki.backup-validation.fixture";
const ID_PATTERN = /^[a-f0-9]{64}$/u;

export function assertLocalBackupEnvironment(env = process.env, platform = process.platform) {
  if (env.VIRKI_BACKUP_VALIDATION_LOCAL_DOCKER !== "1" || platform !== "win32") {
    throw new Error("Backup validation requires explicit Windows local Docker Desktop opt-in (VIRKI_BACKUP_VALIDATION_LOCAL_DOCKER=1).");
  }
  const forbidden = Object.keys(env).filter((key) =>
    /^(?:DOCKER_|COMPOSE_|PG(?:HOST|PORT|SERVICE|SERVICEFILE|PASSFILE|PASSWORD|OPTIONS|USER|DATABASE)$|DATABASE_URL$|MIGRATION_DATABASE_URL$|NODE_OPTIONS$|NODE_EXTRA_CA_CERTS$)/iu.test(key));
  if (forbidden.length) {
    throw new Error("Backup validation refuses ambient Docker, database and Node overrides; unset them before local testing.");
  }
}

function assertDockerSuccess(result, operation) {
  if (result.error || result.status !== 0 || typeof result.stdout !== "string") {
    throw new Error(`Local backup Docker ${operation} failed (details redacted).`);
  }
  return result.stdout.trim();
}

export class LocalBackupDocker {
  constructor({ configDirectory, env = process.env, platform = process.platform, spawn = spawnSync, nonce = randomBytes(24).toString("hex") }) {
    assertLocalBackupEnvironment(env, platform);
    if (!configDirectory || !/^[a-f0-9]{48}$/u.test(nonce)) throw new Error("Invalid backup validation isolation configuration.");
    this.spawn = spawn;
    this.configDirectory = configDirectory;
    this.nonce = nonce;
    this.name = `virki-backup-validation-${nonce}`;
    this.id = null;
    this.daemonId = null;
    this.expectedImageId = null;
    this.dockerEnvironment = {
      SystemRoot: env.SystemRoot ?? "C:\\Windows",
      WINDIR: env.WINDIR ?? "C:\\Windows",
      TEMP: env.TEMP ?? "C:\\Windows\\Temp",
      TMP: env.TMP ?? "C:\\Windows\\Temp",
      DOCKER_CONFIG: configDirectory,
    };
  }

  call(args, { input, binary = false, timeout = 120_000, maxBuffer = 10 * 1024 * 1024 } = {}) {
    return this.spawn(DOCKER_BINARY, ["--host", DOCKER_HOST, "--config", this.configDirectory, ...args], {
      input, encoding: binary ? null : "utf8", windowsHide: true, timeout, maxBuffer,
      env: this.dockerEnvironment,
    });
  }

  command(args, options) {
    return assertDockerSuccess(this.call(args, options), args[0]);
  }

  engine() {
    let info;
    try { info = JSON.parse(this.command(["info", "--format", "{{json .}}"])); }
    catch { throw new Error("Local Docker Desktop Linux engine identity cannot be verified."); }
    if (info?.OSType !== "linux" || !/^Docker Desktop(?:\b|$)/u.test(info.OperatingSystem ?? "") ||
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
    // Never trigger a registry fetch or silently substitute a locally tagged image.
    const imageId = this.command(["image", "inspect", POSTGRES_IMAGE, "--format", "{{.Id}}"]).trim();
    if (!/^sha256:[a-f0-9]{64}$/u.test(imageId)) throw new Error("Cached PostgreSQL image identity is invalid.");
    this.expectedImageId = imageId;
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
    this.command(["rm", "--force", "--volumes", this.id], { timeout: 60_000 });
    this.id = null;
  }
}
