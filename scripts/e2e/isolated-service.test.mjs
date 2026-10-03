import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { buildServiceEnvironment, platformEnvironmentVariableNames } from "./isolated-service.mjs";

test("service children receive only their E2E allowlist and required OS paths", () => {
  const source = {
    PATH: process.env.PATH ?? process.env.Path ?? "",
    HOME: "e2e-home-sentinel",
    TMPDIR: "e2e-tmpdir-sentinel",
    TMP: "e2e-tmp-sentinel",
    TEMP: "e2e-temp-sentinel",
    LANG: "C.UTF-8",
    LC_ALL: "C.UTF-8",
    PATHEXT: process.env.PATHEXT ?? ".EXE;.CMD;.BAT",
    SystemRoot: process.env.SystemRoot ?? process.env.SYSTEMROOT ?? "C:\\Windows",
    WINDIR: process.env.WINDIR ?? "C:\\Windows",
    ComSpec: process.env.ComSpec ?? process.env.COMSPEC ?? "C:\\Windows\\System32\\cmd.exe",
    USERPROFILE: process.env.USERPROFILE ?? "C:\\Users\\e2e",
    HOMEDRIVE: process.env.HOMEDRIVE ?? "C:",
    HOMEPATH: process.env.HOMEPATH ?? "\\Users\\e2e",
    APPDATA: process.env.APPDATA ?? "C:\\Users\\e2e\\AppData\\Roaming",
    LOCALAPPDATA: process.env.LOCALAPPDATA ?? "C:\\Users\\e2e\\AppData\\Local",
    ProgramFiles: process.env.ProgramFiles ?? "C:\\Program Files",
    "ProgramFiles(x86)": process.env["ProgramFiles(x86)"] ?? "C:\\Program Files (x86)",
    ProgramW6432: process.env.ProgramW6432 ?? "C:\\Program Files",
    SYSTEMDRIVE: process.env.SYSTEMDRIVE ?? "C:",
    LOGONSERVER: process.env.LOGONSERVER ?? "\\E2E",
    USERDOMAIN: process.env.USERDOMAIN ?? "E2E",
    USERNAME: process.env.USERNAME ?? "e2e",
    NODE_OPTIONS: "--require caller-controlled-preload.cjs",
    NODE_PATH: "caller-controlled-module-path",
    CALLER_SECRET_SENTINEL: "must-not-reach-service",
    BIELOS_E2E_DATABASE_URL: "must-stay-in-the-runner",
    BIELOS_E2E_JWKS_REGISTRATION_TOKEN: "fixture-registration-token",
    BIELOS_PORTAL_URL: "https://portal.localhost:3001",
    BIELOS_HUB_HOSTNAME: "hub.localhost",
    BIELOS_PORTAL_HOSTNAME: "portal.localhost",
    BIELOS_HUB_URL: "https://hub.localhost:3001",
    DATABASE_URL: "fixture-database-url",
    CLOUDFLARE_ACCESS_JWT_REQUIRED: "true",
    CLOUDFLARE_ACCESS_AUDIENCE: "fixture-audience",
    CLOUDFLARE_TEAM_DOMAIN: "http://127.0.0.1:3010",
    BIELOS_E2E_TLS_KEY_PATH: "C:\\Temp\\fixture-key.pem",
    BIELOS_E2E_TLS_CERTIFICATE_PATH: "C:\\Temp\\fixture-cert.pem"
  };

  const services = [
    { name: "jwks", allowed: ["BIELOS_E2E_JWKS_REGISTRATION_TOKEN"] },
    { name: "public-site", allowed: ["NODE_ENV", "NEXT_TELEMETRY_DISABLED", "BIELOS_PORTAL_URL"] },
    {
      name: "hub",
      allowed: [
        "NODE_ENV", "NEXT_TELEMETRY_DISABLED", "BIELOS_HUB_HOSTNAME", "BIELOS_PORTAL_HOSTNAME",
        "BIELOS_HUB_URL", "BIELOS_PORTAL_URL", "DATABASE_URL", "CLOUDFLARE_ACCESS_JWT_REQUIRED",
        "CLOUDFLARE_ACCESS_AUDIENCE", "CLOUDFLARE_TEAM_DOMAIN", "BIELOS_E2E_TLS_KEY_PATH",
        "BIELOS_E2E_TLS_CERTIFICATE_PATH"
      ]
    }
  ];

  for (const service of services) {
    const environment = buildServiceEnvironment(service.name, source, process.platform);
    const probe = `process.stdout.write(JSON.stringify({
      keys: Object.keys(process.env).sort(),
      path: process.env.PATH === ${JSON.stringify(source.PATH)},
      home: process.env.HOME === "e2e-home-sentinel",
      tmpdir: process.env.TMPDIR === "e2e-tmpdir-sentinel",
      temp: process.env.TEMP === "e2e-temp-sentinel",
      tmp: process.env.TMP === "e2e-tmp-sentinel",
      systemRoot: process.env.SystemRoot === ${JSON.stringify(source.SystemRoot)},
      pathext: process.env.PATHEXT === ${JSON.stringify(source.PATHEXT)}
    }));`;
    const child = spawnSync(process.execPath, ["-e", probe], { env: environment, encoding: "utf8", windowsHide: true });

    assert.equal(child.status, 0, `${service.name} sentinel child exits successfully`);
    const result = JSON.parse(child.stdout);
    const allowedKeys = new Set([
      ...(process.platform === "win32" ? platformEnvironmentVariableNames.windows : platformEnvironmentVariableNames.posix),
      ...service.allowed
    ]);
    if (service.name !== "jwks") {
      allowedKeys.add("NODE_ENV");
      allowedKeys.add("NEXT_TELEMETRY_DISABLED");
    }
    assert.deepEqual(result.keys, [...allowedKeys].sort(), `${service.name} receives no unlisted caller variables`);
    assert.equal(result.keys.includes("NODE_OPTIONS"), false);
    assert.equal(result.keys.includes("NODE_PATH"), false);
    assert.equal(result.path, true);
    assert.equal(result.temp, true);
    assert.equal(result.tmp, true);
    if (process.platform === "win32") {
      assert.equal(result.systemRoot, true);
      assert.equal(result.pathext, true);
    } else {
      assert.equal(result.home, true);
      assert.equal(result.tmpdir, true);
    }
  }

  const windowsEnvironment = buildServiceEnvironment("public-site", source, "win32");
  for (const key of platformEnvironmentVariableNames.windows) {
    if (source[key] !== undefined) assert.equal(windowsEnvironment[key], source[key], `${key} is preserved on Windows`);
  }
  const posixEnvironment = buildServiceEnvironment("public-site", source, "linux");
  for (const key of platformEnvironmentVariableNames.posix) {
    if (source[key] !== undefined) assert.equal(posixEnvironment[key], source[key], `${key} is preserved on POSIX`);
  }
});
