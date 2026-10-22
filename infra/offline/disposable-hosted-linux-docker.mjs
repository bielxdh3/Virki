import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import {
  closeSync, constants, fsyncSync, lstatSync, mkdtempSync,
  openSync, realpathSync, rmdirSync, unlinkSync, writeFileSync,
} from "node:fs";
import path from "node:path";

// GitHub-hosted Linux has a local Unix Docker socket, not the Windows Desktop
// named pipe. Never accept a Docker context, PATH-resolved CLI, or remote host.
export const HOSTED_DOCKER = "/usr/bin/docker";
export const HOSTED_ENGINE = "unix:///var/run/docker.sock";
const SOCKET = "/var/run/docker.sock";
const OWNER_LABEL = "dev.virki.offline.disposable-owner";
const DENIED_OVERRIDE = /^(?:DOCKER_|BUILDX_|CONTAINER_HOST$)/iu;
const quote = (value) => value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");

export function requireHostedLinuxFixtureEnvironment(platform, env, sourceRoot) {
  if (platform !== "linux" || env.GITHUB_ACTIONS !== "true" ||
      env.CI !== "true" || env.RUNNER_OS !== "Linux" ||
      env.RUNNER_ENVIRONMENT !== "github-hosted" ||
      typeof env.GITHUB_WORKSPACE !== "string" ||
      typeof env.RUNNER_TEMP !== "string" ||
      Object.keys(env).some((key) => DENIED_OVERRIDE.test(key))) {
    throw Error("Disposable Linux fixture requires a pinned GitHub-hosted Linux CI environment.");
  }
  try {
    if (realpathSync.native(env.GITHUB_WORKSPACE) !== realpathSync.native(sourceRoot) ||
        !path.isAbsolute(env.RUNNER_TEMP) ||
        realpathSync.native(env.RUNNER_TEMP) !== path.resolve(env.RUNNER_TEMP)) {
      throw Error("untrusted GitHub runner paths");
    }
    const parent = lstatSync(env.RUNNER_TEMP);
    if (!parent.isDirectory() || parent.isSymbolicLink() ||
        parent.uid !== (process.getuid?.() ?? parent.uid) || (parent.mode & 0o022) !== 0) {
      throw Error("untrusted GitHub runner temporary directory");
    }
  } catch {
    throw Error("Disposable Linux fixture rejected untrusted GitHub runner paths.");
  }
}

export function verifyTrustedHostedLinuxDockerCli({ stat = lstatSync, canonical = realpathSync.native } = {}) {
  try {
    const executable = stat(HOSTED_DOCKER);
    const socket = stat(SOCKET);
    if (!executable.isFile() || executable.isSymbolicLink() || executable.uid !== 0 ||
        (executable.mode & 0o022) !== 0 || canonical(HOSTED_DOCKER) !== HOSTED_DOCKER ||
        !socket.isSocket() || socket.isSymbolicLink() || socket.uid !== 0 ||
        (socket.mode & 0o002) !== 0) {
      throw Error("invalid executable or socket");
    }
    return HOSTED_DOCKER;
  } catch {
    throw Error("Disposable Linux fixture requires a trusted root-owned local Docker CLI/socket.");
  }
}

function durableAppend(file, data) {
  const fd = openSync(file, constants.O_WRONLY | constants.O_APPEND | constants.O_NOFOLLOW);
  try { writeFileSync(fd, JSON.stringify(data) + "\n"); fsyncSync(fd); }
  finally { closeSync(fd); }
}

function directorySync(directory) {
  const fd = openSync(directory, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try { fsyncSync(fd); } finally { closeSync(fd); }
}

function privateJournal(base, owner) {
  const directory = mkdtempSync(path.join(base, "virki-offline-ci-"), { mode: 0o700 });
  const entry = lstatSync(directory);
  if (!entry.isDirectory() || entry.isSymbolicLink() ||
      entry.uid !== process.getuid() || (entry.mode & 0o077) !== 0 ||
      realpathSync.native(directory) !== directory) {
    throw Error("Disposable Linux journal private directory identity invalid.");
  }
  const file = path.join(directory, "reconciliation.jsonl");
  const fd = openSync(file, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try {
    writeFileSync(fd, JSON.stringify({ owner, state: "run_may_still_start",
      engine: HOSTED_ENGINE, createdAt: new Date().toISOString() }) + "\n");
    fsyncSync(fd);
  } finally { closeSync(fd); }
  directorySync(directory);
  directorySync(base);
  return { file, directory, entry };
}

function validateJournal(journal) {
  const entry = lstatSync(journal.directory);
  if (entry.dev !== journal.entry.dev || entry.ino !== journal.entry.ino ||
      !entry.isDirectory() || entry.isSymbolicLink() ||
      entry.uid !== process.getuid() || (entry.mode & 0o077) !== 0) {
    throw Error("Disposable Linux journal identity changed.");
  }
  const file = lstatSync(journal.file);
  if (!file.isFile() || file.isSymbolicLink() || file.uid !== process.getuid() ||
      (file.mode & 0o077) !== 0 || file.nlink !== 1) {
    throw Error("Disposable Linux journal content ownership changed.");
  }
}

export function runOwnedHostedLinuxFixture(args, {
  cwd, timeout = 90_000, stdio = "inherit", platform = process.platform,
  env = process.env, invoke = spawnSync, reconciliationDirectory,
} = {}) {
  requireHostedLinuxFixtureEnvironment(platform, env, cwd);
  if (reconciliationDirectory !== undefined && invoke === spawnSync) {
    throw Error("Real hosted Linux fixture cannot redirect reconciliation storage.");
  }
  const executable = invoke === spawnSync ? verifyTrustedHostedLinuxDockerCli() : HOSTED_DOCKER;
  const executionEnv = { PATH: "/usr/bin:/bin", HOME: "/nonexistent", LANG: "C", CI: "true" };
  const docker = (argv, extra = {}) => invoke(executable, ["--host", HOSTED_ENGINE, ...argv], {
    cwd, shell: false, env: executionEnv, ...extra,
  });
  const info = docker(["info", "--format", "{{.OSType}}|{{.DockerRootDir}}"], {
    encoding: "utf8", timeout: 10_000, maxBuffer: 4096,
  });
  if (info.error || info.status !== 0 ||
      !/^linux\|\/[A-Za-z0-9/._-]+\s*$/u.test(info.stdout ?? "")) {
    throw Error("Pinned hosted Linux Docker Engine identity unavailable.");
  }
  const owner = randomBytes(16).toString("hex");
  const name = `virki-offline-fixture-${owner}`;
  const journal = privateJournal(reconciliationDirectory ?? env.RUNNER_TEMP, owner);
  const evidence = journal.file;
  const runArgs = ["run", "--rm", "--name", name,
    "--label", `${OWNER_LABEL}=${owner}`, ...args.slice(2)];
  let result;
  let cleanupFailure;
  let observedId = null;
  try {
    try { result = docker(runArgs, { stdio, timeout }); }
    catch { result = { error: true, status: null }; }
  } finally {
    let inspect;
    try {
      inspect = docker(["inspect", "--format",
        `{{.Id}}|{{.Name}}|{{index .Config.Labels "${OWNER_LABEL}"}}`, name],
      { encoding: "utf8", timeout: 10_000, maxBuffer: 4096 });
    } catch { inspect = { error: true }; }
    if (inspect.error) {
      cleanupFailure = "Hosted Linux Docker ownership inspection transport failed.";
    } else if (inspect.status === 0) {
      const [id, actualName, actualOwner] = (inspect.stdout ?? "").trim().split("|");
      observedId = /^[a-f0-9]{64}$/u.test(id ?? "") ? id : null;
      try { validateJournal(journal); durableAppend(evidence, { event: "inspection", id, actualName, actualOwner }); }
      catch { cleanupFailure = "Hosted Linux Docker ownership evidence could not be persisted."; }
      if (!cleanupFailure && (!/^[a-f0-9]{64}$/u.test(id) ||
          actualName !== `/${name}` || actualOwner !== owner)) {
        cleanupFailure = "Hosted Linux Docker container ownership mismatch.";
      } else if (!cleanupFailure) {
        let removed;
        try {
          removed = docker(["rm", "--force", "--volumes", id],
            { encoding: "utf8", timeout: 10_000, maxBuffer: 4096 });
        } catch { removed = { error: true }; }
        if (removed.error || removed.status !== 0) {
          cleanupFailure = "Hosted Linux Docker verified container ID removal failed.";
        }
      }
    } else if (!new RegExp(`^(?:Error: |Error response from daemon: )No such (?:object|container): ${quote(name)}$`, "iu")
      .test((inspect.stderr ?? "").trim())) {
      cleanupFailure = "Hosted Linux Docker container absence could not be established.";
    }
  }
  if (result?.error || result?.status !== 0) {
    cleanupFailure ??= "Hosted Linux fixture failed or timed out; late creation requires reconciliation.";
  }
  if (cleanupFailure) {
    // GitHub destroys RUNNER_TEMP after the job. Preserve the minimal
    // non-secret reconciliation tuple in its retained job logs instead of
    // uploading raw owner journals as artifacts (disallowed by CI policy).
    // The hostname/socket is local to this disposable hosted runner.
    if (invoke === spawnSync) process.stderr.write(
      `OFFLINE_FIXTURE_RECONCILIATION_REQUIRED owner=${owner} name=${name} cid=${observedId ?? "unknown"} engine=${HOSTED_ENGINE}\n`,
    );
    throw Error(`${cleanupFailure} Operator reconciliation required: ${evidence}`);
  }
  try {
    validateJournal(journal);
    unlinkSync(evidence);
    directorySync(journal.directory);
    rmdirSync(journal.directory);
    directorySync(reconciliationDirectory ?? env.RUNNER_TEMP);
  } catch {
    throw Error(`Hosted Linux Docker reconciliation evidence cleanup uncertain: ${evidence}`);
  }
}
