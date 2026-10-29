import path from "node:path";
import { fileURLToPath } from "node:url";
import { verifyTrustedWindowsDockerCli } from "../../infra/offline/disposable-local-docker.mjs";

// This is a fixed DEV-ONLY transport recipe, never a generic Docker runner.
// The executing caller MUST verify the Authenticode publisher immediately
// before every spawn and use an empty, newly created private --config folder.
const CLI = "C:\\Program Files\\Docker\\Docker\\resources\\bin\\docker.exe";
const ENDPOINT = "npipe:////./pipe/dockerDesktopLinuxEngine";
const IMAGE = "postgres:17-alpine@sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24";
const LABEL = "dev.virki.disposable.pg-owner";
const SOURCE = path.resolve(fileURLToPath(new URL("../..", import.meta.url)));
const CASES = new Set([
  "happy", "tamper", "incompatible", "fail_live", "corrupt_backup", "crash_live", "race",
  "crash_admit", "crash_rollback_clone", "crash_rollback_proven", "crash_rollback_dropped",
  "crash_rollback_created", "crash_rollback_loaded", "crash_rollback_restored",
  "rollback_precheckpoint_error",
  "canary_unhealthy", "crash_canary", "precanary_unhealthy", "postcanary_unhealthy",
  "manual_fenced_rollback", "manual_fence_sigkill",
]);
function refuse() { throw new Error("Disposable PostgreSQL Docker transport refused."); }
const same = (a, b) => a.length === b.length && a.every((item, i) => item === b[i]);

export function assertDisposablePgDockerEnvironment(env = process.env, platform = process.platform) {
  if (platform !== "win32" || Object.keys(env).some((key) =>
    /^(?:DOCKER_|COMPOSE_|PG(?:HOST|HOSTADDR|PORT|SERVICE|SERVICEFILE|PASSFILE|PASSWORD|OPTIONS|USER|DATABASE)$|DATABASE_URL$|MIGRATION_DATABASE_URL$|NODE_OPTIONS$|NODE_EXTRA_CA_CERTS$)/iu.test(key))) refuse();
}

function approvedArgs(args, ownership) {
  if (!Array.isArray(args) || args.some((part) => typeof part !== "string" || part.length > 4096)) refuse();
  const owned = (id) => ownership && typeof ownership === "object" &&
    Object.keys(ownership).length === 3 &&
    ["id", "name", "owner"].every((key) => Object.hasOwn(ownership, key)) &&
    ownership.id === id && /^[a-f0-9]{64}$/u.test(id) &&
    ownership.name === `virki-disposable-pg-${ownership.owner}` &&
    /^[a-f0-9]{32}$/u.test(ownership.owner);
  if (same(args, ["info", "--format", "{{.OperatingSystem}}|{{.OSType}}"])) return;
  if (same(args, ["image", "inspect", IMAGE, "--format", "{{.Id}}"])) return;

  const name = args[5];
  const match = /^virki-disposable-pg-([a-f0-9]{32})$/u.exec(name ?? "");
  if (args[0] === "run" && match) {
    for (const testCase of CASES) {
      const common = [
        "run", "--rm", "--pull=never", "--platform=linux/amd64",
        "--name", name, "--label", `${LABEL}=${match[1]}`,
        "--network=none", "--read-only", "--user=postgres",
        "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=128",
        "--tmpfs", "/tmp:rw,nosuid,nodev,size=128m,uid=70,gid=70,mode=700",
        "--tmpfs", "/var/lib/postgresql/data:rw,nosuid,nodev,size=512m,uid=70,gid=70,mode=700",
        "--mount", `type=bind,src=${SOURCE},dst=/workspace,readonly`,
        "--workdir", "/workspace", "--env", "VIRKI_OFFLINE_PG_DISPOSABLE=1",
      ];
      const command = [IMAGE, "sh", "/workspace/scripts/fixtures/offline-pg-recovery/run.sh", testCase];
      if (same(args, [...common, ...command]) ||
          (testCase === "happy" && same(args, [...common,
            "--env", "DATABASE_URL=postgresql://reject.invalid/invalid", ...command]))) return;
    }
  }
  if (args[0] === "inspect" && args.length === 4 && args[1] === "--format" &&
      args[2] === `{{.Id}}|{{.Name}}|{{index .Config.Labels "${LABEL}"}}` &&
      (/^virki-disposable-pg-[a-f0-9]{32}$/u.test(args[3] ?? "") ||
        owned(args[3]))) return;
  if (args[0] === "rm" && same(args.slice(0, 3), ["rm", "--force", "--volumes"]) &&
      args.length === 4 && owned(args[3])) return;
  refuse();
}

/** Pure, inspectable argv. The real caller may not override binary or host. */
export function buildDisposablePgDockerInvocation(args, configDirectory, ownership) {
  if (typeof configDirectory !== "string" || configDirectory.length > 4096 ||
      /^(?:\\\\|\/\/)/u.test(configDirectory) || !path.win32.isAbsolute(configDirectory) ||
      path.win32.normalize(configDirectory) !== configDirectory ||
      /[\r\n\0]/u.test(configDirectory)) refuse();
  approvedArgs(args, ownership);
  return Object.freeze({
    binary: CLI,
    args: ["--host", ENDPOINT, "--config", configDirectory, ...args],
    options: {
      cwd: SOURCE, shell: false, windowsHide: true, timeout: 120_000,
      encoding: "utf8", maxBuffer: 65536,
      env: {
        SystemRoot: "C:\\Windows", WINDIR: "C:\\Windows",
        PATH: "C:\\Windows\\System32;C:\\Windows",
      },
    },
  });
}

/** Verifies the real signed CLI, separately from the mockable pure argv. */
export function requireSignedPgDockerCli() {
  assertDisposablePgDockerEnvironment();
  if (verifyTrustedWindowsDockerCli() !== CLI) refuse();
  return CLI;
}
