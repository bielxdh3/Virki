import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(scriptDirectory, "..", "..");
const testRequire = createRequire(join(repositoryRoot, "package.json"));

const platformEnvironment = {
  posix: ["PATH", "HOME", "TMPDIR", "TMP", "TEMP", "LANG", "LC_ALL"],
  windows: [
    "PATH", "PATHEXT", "SystemRoot", "WINDIR", "ComSpec", "TEMP", "TMP",
    "USERPROFILE", "HOMEDRIVE", "HOMEPATH", "APPDATA", "LOCALAPPDATA",
    "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "SYSTEMDRIVE",
    "LOGONSERVER", "USERDOMAIN", "USERNAME"
  ]
};

const serviceEnvironment = {
  jwks: ["BIELOS_E2E_JWKS_REGISTRATION_TOKEN"],
  "public-site": ["NODE_ENV", "NEXT_TELEMETRY_DISABLED", "BIELOS_PORTAL_URL"],
  hub: [
    "NODE_ENV", "NEXT_TELEMETRY_DISABLED", "BIELOS_HUB_HOSTNAME", "BIELOS_PORTAL_HOSTNAME",
    "BIELOS_HUB_URL", "BIELOS_PORTAL_URL", "DATABASE_URL", "CLOUDFLARE_ACCESS_JWT_REQUIRED",
    "CLOUDFLARE_ACCESS_AUDIENCE", "CLOUDFLARE_TEAM_DOMAIN", "BIELOS_E2E_TLS_KEY_PATH",
    "BIELOS_E2E_TLS_CERTIFICATE_PATH"
  ]
};

export function buildServiceEnvironment(service, source = process.env, platform = process.platform) {
  const serviceKeys = serviceEnvironment[service];
  if (!serviceKeys) throw new Error("Unknown E2E service.");

  const result = {};
  const platformKeys = platform === "win32" ? platformEnvironment.windows : platformEnvironment.posix;
  for (const key of [...platformKeys, ...serviceKeys]) {
    const value = source[key];
    if (typeof value === "string") result[key] = value;
  }

  if (service !== "jwks") {
    result.NODE_ENV = "development";
    result.NEXT_TELEMETRY_DISABLED = "1";
  }
  if (service === "hub" && (!result.DATABASE_URL || !result.BIELOS_E2E_TLS_KEY_PATH || !result.BIELOS_E2E_TLS_CERTIFICATE_PATH)) {
    throw new Error("Hub E2E configuration is incomplete.");
  }
  if (service === "jwks" && !result.BIELOS_E2E_JWKS_REGISTRATION_TOKEN) {
    throw new Error("JWKS E2E registration configuration is incomplete.");
  }

  return result;
}

export function startIsolatedService(service, source = process.env) {
  const env = buildServiceEnvironment(service, source);
  const { cwd, args } = getServiceCommand(service, source);
  const child = spawn(process.execPath, args, {
    cwd,
    env,
    stdio: "inherit",
    windowsHide: true
  });

  let stopping = false;
  const forwardSignal = (signal) => {
    stopping = true;
    child.kill(signal);
  };
  process.once("SIGINT", forwardSignal);
  process.once("SIGTERM", forwardSignal);
  child.once("error", () => {
    process.stderr.write("E2E service could not start.\n");
    process.exitCode = 1;
  });
  child.once("exit", (code) => {
    process.off("SIGINT", forwardSignal);
    process.off("SIGTERM", forwardSignal);
    process.exitCode = code ?? (stopping ? 0 : 1);
  });
  return child;
}

function getServiceCommand(service, source) {
  if (service === "jwks") {
    return { cwd: repositoryRoot, args: [join(scriptDirectory, "jwks-server.mjs")] };
  }

  const workspace = service === "hub" ? "hub" : service === "public-site" ? "public-site" : undefined;
  if (!workspace) throw new Error("Unknown E2E service.");
  const workspaceDirectory = join(repositoryRoot, "apps", workspace);
  const nextCli = testRequire.resolve("next/dist/bin/next", { paths: [workspaceDirectory] });
  const args = [nextCli, "dev", "--webpack", "-p", service === "hub" ? "3001" : "3000", "--hostname", "127.0.0.1"];

  if (service === "hub") {
    const keyPath = source.BIELOS_E2E_TLS_KEY_PATH;
    const certificatePath = source.BIELOS_E2E_TLS_CERTIFICATE_PATH;
    if (!keyPath || !certificatePath || !isAbsolute(keyPath) || !isAbsolute(certificatePath) || !existsSync(keyPath) || !existsSync(certificatePath)) {
      throw new Error("Hub E2E TLS files are unavailable.");
    }
    args.push("--experimental-https", "--experimental-https-key", keyPath, "--experimental-https-cert", certificatePath);
  }

  return { cwd: workspaceDirectory, args };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    startIsolatedService(process.argv[2]);
  } catch {
    process.stderr.write("E2E service configuration is invalid.\n");
    process.exitCode = 1;
  }
}

export const platformEnvironmentVariableNames = Object.freeze({
  posix: Object.freeze([...platformEnvironment.posix]),
  windows: Object.freeze([...platformEnvironment.windows])
});
