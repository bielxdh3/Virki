import { spawn } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { assertDisposableCoreTestDatabase } from "../core-test-database-safety.mjs";

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
    "CLOUDFLARE_ACCESS_AUDIENCE", "CLOUDFLARE_TEAM_DOMAIN", "BIELOS_E2E_ACCESS_DIAGNOSTICS", "BIELOS_TOTP_ENCRYPTION_KEY", "BIELOS_OIDC_PROXY_URL", "BIELOS_E2E_TLS_KEY_PATH",
    "BIELOS_E2E_TLS_CERTIFICATE_PATH", "BIELOS_EMAIL_OUTBOX_KEY"
  ],
  issuer: ["DATABASE_URL", "BIELOS_E2E_OIDC_PRIVATE_CONFIG_FILE", "BIELOS_OIDC_ISSUER", "BIELOS_OIDC_BIND_ADDRESS", "OIDC_ISSUER_PORT"]
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
  if (service === "hub" && (!result.DATABASE_URL || !result.BIELOS_OIDC_PROXY_URL || !result.BIELOS_E2E_TLS_KEY_PATH || !result.BIELOS_E2E_TLS_CERTIFICATE_PATH)) {
    throw new Error("Hub E2E configuration is incomplete.");
  }
  if (service === "issuer" && (!result.DATABASE_URL || !result.BIELOS_E2E_OIDC_PRIVATE_CONFIG_FILE || !result.BIELOS_OIDC_ISSUER || result.BIELOS_OIDC_BIND_ADDRESS !== "127.0.0.1" || !result.OIDC_ISSUER_PORT)) {
    throw new Error("OIDC issuer E2E configuration is incomplete.");
  }
  if (service === "hub" || service === "issuer") {
    const databaseUrl = result.DATABASE_URL?.trim();
    if (!databaseUrl) throw new Error("E2E database configuration is incomplete.");
    assertDisposableCoreTestDatabase(databaseUrl, source);
    result.DATABASE_URL = databaseUrl;
  }
  if (service === "jwks" && !result.BIELOS_E2E_JWKS_REGISTRATION_TOKEN) {
    throw new Error("JWKS E2E registration configuration is incomplete.");
  }

  return result;
}

export function startIsolatedService(service, source = process.env, { manageProcessLifecycle = true } = {}) {
  const env = buildServiceEnvironment(service, source);
  if (service === "issuer") loadIssuerPrivateConfiguration(env);
  const { cwd, args } = getServiceCommand(service, source);
  const child = spawn(process.execPath, args, {
    cwd,
    env,
    stdio: "inherit",
    windowsHide: true
  });

  if (!manageProcessLifecycle) return child;

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

  if (service === "issuer") {
    const workspaceDirectory = join(repositoryRoot, "apps", "issuer");
    const tsxCli = testRequire.resolve("tsx/cli", { paths: [workspaceDirectory] });
    return { cwd: workspaceDirectory, args: [tsxCli, "src/server.ts"] };
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

function loadIssuerPrivateConfiguration(environment) {
  const file = environment.BIELOS_E2E_OIDC_PRIVATE_CONFIG_FILE;
  if (!file || !isAbsolute(file) || !existsSync(file)) throw new Error("OIDC issuer private E2E configuration is unavailable.");
  const config = JSON.parse(readFileSync(file, "utf8"));
  if (!config || typeof config !== "object" || Array.isArray(config) ||
    typeof config.adapterKey !== "string" || !/^[a-f0-9]{64}$/iu.test(config.adapterKey) ||
    typeof config.cookieKey !== "string" || !/^[A-Za-z0-9_-]{43}$/u.test(config.cookieKey) ||
    !config.signingJwks || !Array.isArray(config.signingJwks.keys) || !config.signingJwks.keys.length) {
    throw new Error("OIDC issuer private E2E configuration is invalid.");
  }
  environment.BIELOS_OIDC_ADAPTER_KEY = config.adapterKey;
  environment.BIELOS_OIDC_COOKIE_KEY = config.cookieKey;
  environment.BIELOS_OIDC_SIGNING_JWKS = JSON.stringify(config.signingJwks);
  delete environment.BIELOS_E2E_OIDC_PRIVATE_CONFIG_FILE;
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
