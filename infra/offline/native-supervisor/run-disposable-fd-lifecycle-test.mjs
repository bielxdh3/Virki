import { randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  closeSync, constants, existsSync, fstatSync, lstatSync,
  mkdirSync, mkdtempSync, openSync, readSync,
  readdirSync, rmdirSync, unlinkSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

// TEST ONLY. A host Docker client is not inherently a local Docker Desktop
// client: default contexts and DOCKER_HOST may silently target remote daemons.
// This runner is opt-in, Windows-only and pins the fixed Desktop Linux npipe.
// No real dockerd is inside the disposable container and no host socket mounts.
const DOCKER_BINARY = "C:\\Program Files\\Docker\\Docker\\resources\\bin\\docker.exe";
export const LOCAL_DESKTOP_ENGINE = "npipe:////./pipe/dockerDesktopLinuxEngine";
export const DISPOSABLE_IMAGE =
  "node:22.23.3-bookworm@sha256:0e5f906573693feaa1e21057ebdcfdb5bd5021f050b2dc7c9deceb629c7da2a8";
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const CONTAINER_LABEL = "dev.virki.disposable-fd-lifecycle";
// This state deliberately changes BEFORE a CLI attempt, not on success:
// timeout or spawn failure may still mean that Docker was contacted.
let runnerStage = "preflight";
export function runnerFailureDiagnostic(stage) {
  if (stage === "preflight")
    return "Docker fixture blocked before Docker CLI invocation.";
  if (stage === "cli-invoked")
    return "Docker fixture failed after Docker CLI invocation; daemon contact cannot be ruled out.";
  if (stage === "cleanup-attempted")
    return "Docker fixture failed during cleanup after Docker CLI invocation; daemon contact cannot be ruled out.";
  return "Docker fixture failed at unknown stage; Docker CLI/daemon contact cannot be ruled out.";
}
// Resource ownership is established only by mkdtemp within this process.
// A caller must not be able to use the exported test helper to delete a
// different filesystem tree by supplying its path.
const ownedFixtureDirectories = new Map();

export function planDisposableFixture({ ownerToken, cidfile } = {}) {
  if (!/^[a-f0-9]{32}$/u.test(ownerToken ?? "") ||
      typeof cidfile !== "string" || !path.isAbsolute(cidfile))
    throw new Error("Disposable fixture requires an owner token and absolute cidfile");
  const dockerPrefix = ["--host", LOCAL_DESKTOP_ENGINE];
  const label = CONTAINER_LABEL + "=" + ownerToken;
  const args = [
    ...dockerPrefix, "run", "--rm", "--cidfile", cidfile,
    "--label", label,
    "--pull=never", "--platform=linux/amd64",
    "--network=none", "--read-only", "--cap-drop=ALL",
    "--security-opt=no-new-privileges", "--user", "0:0",
    "--pids-limit=128", "--memory=512m",
    "--tmpfs", "/tmp:rw,exec,nosuid,nodev,size=64m,mode=1777",
    "--mount", "type=bind,src=" + root + ",dst=/workspace,readonly",
    "--workdir", "/workspace",
    "--env", "VIRKI_DISPOSABLE_SUPERVISOR_TEST=1",
    DISPOSABLE_IMAGE,
    "node", "--test", "infra/offline/native-supervisor/fd-lifecycle-fixture.test.mjs",
  ];
  return Object.freeze({ label, args: Object.freeze(args),
    dockerPrefix: Object.freeze(dockerPrefix) });
}

export function validateCleanupIdentity(id, labelText, expectedToken) {
  return typeof id === "string" && /^[a-f0-9]{64}$/u.test(id) &&
    typeof labelText === "string" && labelText === expectedToken &&
    /^[a-f0-9]{32}$/u.test(expectedToken);
}

function sanitizedCliEnvironment(dockerConfigDir) {
  return {
    SystemRoot: process.env.SystemRoot ?? "C:\\Windows",
    WINDIR: process.env.WINDIR ?? "C:\\Windows",
    PATH: "C:\\Windows\\System32",
    TEMP: os.tmpdir(),
    TMP: os.tmpdir(),
    DOCKER_CONFIG: dockerConfigDir,
  };
}

function runCli(args, env, timeout = 45000, stdio = "pipe") {
  return spawnSync(DOCKER_BINARY, args, {
    cwd: root, env, stdio, shell: false, timeout, windowsHide: true,
    encoding: "utf8", maxBuffer: 4096,
  });
}

function sameCidIdentity(before, after) {
  return ["dev", "ino", "mode", "nlink", "size", "mtimeNs", "ctimeNs"]
    .every((field) => before[field] === after[field]);
}

export function cleanupOwnedContainer(cidfile, plan, env, {
  run = runCli, beforeCidOpen,
} = {}) {
  // A failed or timed-out `docker run` may start its container before Docker
  // can atomically write --cidfile. Missing evidence is NOT a cleanup proof.
  if (!existsSync(cidfile)) return false;
  // A CID pathname is not evidence if its parent was swapped or it points to
  // an unrelated hardlinked/reparse file. Refuse BEFORE any Docker CLI call.
  const ownerRoot = path.dirname(cidfile);
  const original = ownedFixtureDirectories.get(ownerRoot);
  if (!original) return false;
  let id;
  try {
    const owner = lstatSync(ownerRoot, { bigint: true });
    const cid = lstatSync(cidfile, { bigint: true });
    if (!owner.isDirectory() || owner.isSymbolicLink() ||
        owner.dev !== original.dev || owner.ino !== original.ino ||
        !cid.isFile() || cid.isSymbolicLink() || cid.nlink !== 1n ||
        cid.size < 64n || cid.size > 66n)
      return false;
    // Deterministic test-only boundary injection. The actual runner cannot
    // supply a hook, and no hook is allowed with the real Docker CLI.
    if (beforeCidOpen !== undefined) {
      if (run === runCli || typeof beforeCidOpen !== "function") return false;
      beforeCidOpen();
    }
    // O_NOFOLLOW is available on native Linux but not Node Windows. The
    // opened handle's device/inode identity is mandatory on BOTH platforms:
    // never trust a pathname reopened after the original lstat.
    const fd = openSync(cidfile, constants.O_RDONLY |
      (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0));
    try {
      const opened = fstatSync(fd, { bigint: true });
      if (!opened.isFile() || opened.nlink !== 1n ||
          !sameCidIdentity(cid, opened)) return false;
      // Do not use readFileSync(fd): an in-place append after preflight could
      // otherwise cause an unbounded allocation. Read at most 67 bytes.
      const bounded = Buffer.alloc(67);
      const count = readSync(fd, bounded, 0, bounded.length, 0);
      if (count !== Number(opened.size) || count > 66) return false;
      if (!sameCidIdentity(opened, fstatSync(fd, { bigint: true })) ||
          !sameCidIdentity(opened, lstatSync(cidfile, { bigint: true })))
        return false;
      const ownerNow = lstatSync(ownerRoot, { bigint: true });
      if (!ownerNow.isDirectory() || ownerNow.isSymbolicLink() ||
          ownerNow.dev !== original.dev || ownerNow.ino !== original.ino)
        return false;
      id = bounded.toString("utf8", 0, count).trim();
    } finally {
      closeSync(fd);
    }
  } catch { return false; }
  if (!/^[a-f0-9]{64}$/u.test(id)) return false;
  // NEVER remove by mutable name, wildcard, label selection or ambient context.
  // The inspect must prove the exact owned label on the immutable full ID.
  const metadata = run([...plan.dockerPrefix, "inspect",
    "--format", "{{.Id}} {{index .Config.Labels \"dev.virki.disposable-fd-lifecycle\"}}",
    id], env, 4000);
  if (metadata.error || metadata.status !== 0) return false;
  const [inspectedId, labelToken, ...extra] = metadata.stdout.trim().split(" ");
  const ownerToken = plan.label.split("=")[1];
  if (extra.length || inspectedId !== id ||
    !validateCleanupIdentity(id, labelToken, ownerToken))
    return false;
  const killed = run([...plan.dockerPrefix, "container", "rm", "--force", id],
    env, 4000);
  return !killed.error && killed.status === 0;
}

export function prepareOwnedFixtureDirectory() {
  const owned = mkdtempSync(path.join(os.tmpdir(), "virki-owned-fd-lifecycle-"));
  const state = lstatSync(owned, { bigint: true });
  if (!state.isDirectory() || state.isSymbolicLink()) {
    throw new Error("Disposable owner directory is not an actual directory");
  }
  const configDir = path.join(owned, "empty-docker-config");
  mkdirSync(configDir);
  ownedFixtureDirectories.set(owned, Object.freeze({
    dev: state.dev, ino: state.ino,
  }));
  return Object.freeze({ owned, cidfile: path.join(owned, "container.id"),
    configDir });
}

export function finalizeFixtureRecord(owned, { completed, cleanupConfirmed }) {
  if (!completed && !cleanupConfirmed) return false;
  const original = ownedFixtureDirectories.get(owned);
  if (!original) return false;
  try {
    // No arbitrary recursive deletion: verify our original private root,
    // require an exact two-entry allowlist, and delete only known leaf files.
    const state = lstatSync(owned, { bigint: true });
    if (!state.isDirectory() || state.isSymbolicLink() ||
        state.dev !== original.dev || state.ino !== original.ino) return false;
    const entries = readdirSync(owned);
    if (entries.length < 1 || entries.length > 2 ||
        entries.some((name) => name !== "empty-docker-config" &&
          name !== "container.id") ||
        !entries.includes("empty-docker-config")) return false;
    const configDir = path.join(owned, "empty-docker-config");
    const config = lstatSync(configDir);
    if (!config.isDirectory() || config.isSymbolicLink() ||
        readdirSync(configDir).length !== 0) return false;
    if (entries.includes("container.id")) {
      const cidfile = path.join(owned, "container.id");
      const cid = lstatSync(cidfile);
      if (!cid.isFile() || cid.isSymbolicLink() || cid.nlink !== 1) return false;
      unlinkSync(cidfile);
    }
    rmdirSync(configDir);
    rmdirSync(owned);
    ownedFixtureDirectories.delete(owned);
    return true;
  } catch {
    return false;
  }
}

export function runDisposableFdLifecycleFixture() {
  runnerStage = "preflight";
  if (process.platform !== "win32" ||
    process.env.VIRKI_DISPOSABLE_SUPERVISOR_RUN_DOCKER !== "1" ||
    !existsSync(DOCKER_BINARY) || process.argv.length !== 2) {
    throw new Error("Docker fixture refused: explicit Windows Desktop Linux npipe opt-in required");
  }
  const { owned, cidfile, configDir } = prepareOwnedFixtureDirectory();
  const plan = planDisposableFixture({
    ownerToken: randomBytes(16).toString("hex"), cidfile,
  });
  const env = sanitizedCliEnvironment(configDir);
  let completed = false;
  try {
    runnerStage = "cli-invoked";
    const result = runCli(plan.args, env, 45000, "inherit");
    completed = !result.error && result.status === 0;
    if (result.error || result.status !== 0) {
      process.stderr.write("Disposable native supervisor fixture refused or failed.\n");
      process.exitCode = 1;
    }
  } finally {
    runnerStage = "cleanup-attempted";
    const cleanupConfirmed = cleanupOwnedContainer(cidfile, plan, env);
    // A successful `docker run --rm` is allowed to have removed its own
    // container before the final inspect. Any incomplete or failed run must
    // preserve its CID record for explicitly reviewed manual reconciliation.
    if (!finalizeFixtureRecord(owned, { completed, cleanupConfirmed })) {
      process.stderr.write("Disposable cleanup unconfirmed; fixture directory preserved at " +
        owned + " (CID may be absent). No arbitrary container deletion attempted.\n");
      process.exitCode = 1;
    }
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { runDisposableFdLifecycleFixture(); }
  catch { process.stderr.write(runnerFailureDiagnostic(runnerStage) + "\n");
    process.exitCode = 1; }
}
