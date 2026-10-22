import { randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync,
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

function cleanupOwnedContainer(cidfile, plan, env) {
  if (!existsSync(cidfile)) return true;
  let id;
  try { id = readFileSync(cidfile, "utf8").trim(); }
  catch { return false; }
  if (!/^[a-f0-9]{64}$/u.test(id)) return false;
  // NEVER remove by mutable name, wildcard, label selection or ambient context.
  // The inspect must prove the exact owned label on the immutable full ID.
  const metadata = runCli([...plan.dockerPrefix, "inspect",
    "--format", "{{.Id}} {{index .Config.Labels \"dev.virki.disposable-fd-lifecycle\"}}",
    id], env, 4000);
  if (metadata.error || metadata.status !== 0) return false;
  const [inspectedId, labelToken, ...extra] = metadata.stdout.trim().split(" ");
  const ownerToken = plan.label.split("=")[1];
  if (extra.length || inspectedId !== id ||
    !validateCleanupIdentity(id, labelToken, ownerToken))
    return false;
  const killed = runCli([...plan.dockerPrefix, "container", "rm", "--force", id],
    env, 4000);
  return !killed.error && killed.status === 0;
}

export function runDisposableFdLifecycleFixture() {
  if (process.platform !== "win32" ||
    process.env.VIRKI_DISPOSABLE_SUPERVISOR_RUN_DOCKER !== "1" ||
    !existsSync(DOCKER_BINARY) || process.argv.length !== 2) {
    throw new Error("Docker fixture refused: explicit Windows Desktop Linux npipe opt-in required");
  }
  const owned = mkdtempSync(path.join(os.tmpdir(), "virki-owned-fd-lifecycle-"));
  const cidfile = path.join(owned, "container.id");
  const configDir = path.join(owned, "empty-docker-config");
  mkdirSync(configDir);
  const plan = planDisposableFixture({
    ownerToken: randomBytes(16).toString("hex"), cidfile,
  });
  const env = sanitizedCliEnvironment(configDir);
  let completed = false;
  try {
    const result = runCli(plan.args, env, 45000, "inherit");
    completed = !result.error && result.status === 0;
    if (result.error || result.status !== 0) {
      process.stderr.write("Disposable native supervisor fixture refused or failed.\n");
      process.exitCode = 1;
    }
  } finally {
    const cleanupConfirmed = cleanupOwnedContainer(cidfile, plan, env);
    // A successful `docker run --rm` is allowed to have removed its own
    // container before the final inspect. Any incomplete or failed run must
    // preserve its CID record for explicitly reviewed manual reconciliation.
    if (cleanupConfirmed || completed) {
      rmSync(owned, { recursive: true, force: true });
    } else {
      process.stderr.write("Disposable cleanup unconfirmed; ownership CID preserved at " +
        cidfile + ". No arbitrary container deletion attempted.\n");
      process.exitCode = 1;
    }
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { runDisposableFdLifecycleFixture(); }
  catch { process.stderr.write("Docker fixture blocked; no daemon was contacted.\n");
    process.exitCode = 1; }
}
