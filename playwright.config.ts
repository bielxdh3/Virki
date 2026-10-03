import { defineConfig } from "@playwright/test";
import { randomBytes } from "node:crypto";
import { execFileSync } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, rmSync } from "node:fs";
import { delimiter, join } from "node:path";
import { tmpdir } from "node:os";

// @ts-expect-error This JavaScript safety helper has no declaration file.
import { CORE_TEST_DATABASE_CONFIRMATION } from "./scripts/core-test-database-safety.mjs";

const portalUrl = "https://portal.localhost:3001";
const accessTeamDomain = "http://127.0.0.1:3010";
const accessAudience = "bielos-e2e-access-audience";
const registrationTokenEnv = "BIELOS_E2E_JWKS_REGISTRATION_TOKEN";
const registrationTokenInitializedEnv = "BIELOS_E2E_JWKS_REGISTRATION_TOKEN_INITIALIZED";
const initializedRegistrationToken = process.env[registrationTokenInitializedEnv] === "true"
  ? process.env[registrationTokenEnv]
  : undefined;
if (process.env[registrationTokenInitializedEnv] === "true" && !initializedRegistrationToken) {
  throw new Error("E2E JWKS registration token initialization is incomplete.");
}
const jwksRegistrationToken = initializedRegistrationToken ?? randomBytes(32).toString("base64url");
const e2eDatabaseUrl = process.env.BIELOS_E2E_DATABASE_URL;
const tlsDirectory = mkdtempSync(join(tmpdir(), "bielos-e2e-tls-"));
const tlsKeyPath = join(tlsDirectory, "server-key.pem");
const tlsCertificatePath = join(tlsDirectory, "server-cert.pem");
const oidcPrivateConfigPath = join(tlsDirectory, "issuer-config.json");

try {
  restrictTemporaryDirectory(tlsDirectory);
  generateLocalTlsPair(tlsKeyPath, tlsCertificatePath);
} catch {
  rmSync(tlsDirectory, { recursive: true, force: true });
  throw new Error("E2E requires an already-installed OpenSSL or PowerShell certificate API.");
}

process.once("exit", () => rmSync(tlsDirectory, { recursive: true, force: true }));

const localOnlyEnv = {
  NODE_OPTIONS: "",
  NODE_PATH: "",
  NODE_ENV: "development",
  NEXT_TELEMETRY_DISABLED: "1",
  BIELOS_HUB_HOSTNAME: "hub.localhost",
  BIELOS_PORTAL_HOSTNAME: "portal.localhost",
  BIELOS_HUB_URL: "https://hub.localhost:3001",
  BIELOS_PORTAL_URL: portalUrl,
  BIELOS_OIDC_PROXY_URL: "http://127.0.0.1:3003",
  CLOUDFLARE_ACCESS_JWT_REQUIRED: "true",
  CLOUDFLARE_ACCESS_AUDIENCE: accessAudience,
  CLOUDFLARE_TEAM_DOMAIN: accessTeamDomain,
  BIELOS_E2E_JWKS_REGISTRATION_TOKEN: "",
  BIELOS_E2E_JWKS_REGISTRATION_TOKEN_INITIALIZED: "",
  BIELOS_CORE_TEST_DATABASE_CONFIRM: CORE_TEST_DATABASE_CONFIRMATION,
  DATABASE_URL: e2eDatabaseUrl ?? "postgresql://127.0.0.1:1/bielos_e2e_test?connect_timeout=1"
};
const publicSiteEnv = {
  NODE_OPTIONS: "",
  NODE_PATH: "",
  NODE_ENV: "development",
  NEXT_TELEMETRY_DISABLED: "1",
  BIELOS_PORTAL_URL: portalUrl
};
const hubEnv = {
  ...localOnlyEnv,
  BIELOS_E2E_TLS_KEY_PATH: tlsKeyPath,
  BIELOS_E2E_TLS_CERTIFICATE_PATH: tlsCertificatePath
};
process.env.BIELOS_E2E_ACCESS_AUDIENCE = accessAudience;
process.env.BIELOS_E2E_ACCESS_ISSUER = accessTeamDomain;
process.env.BIELOS_E2E_TLS_KEY_PATH = tlsKeyPath;
process.env.BIELOS_E2E_TLS_CERTIFICATE_PATH = tlsCertificatePath;
process.env.BIELOS_E2E_OIDC_PRIVATE_CONFIG_FILE = oidcPrivateConfigPath;
process.env[registrationTokenEnv] = jwksRegistrationToken;
process.env[registrationTokenInitializedEnv] = "true";

export default defineConfig({
  testDir: "./e2e",
  globalSetup: e2eDatabaseUrl ? "./scripts/e2e/global-setup.ts" : undefined,
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: "list",
  use: {
    browserName: "chromium",
    ignoreHTTPSErrors: true,
    launchOptions: {
      args: [
        "--disable-background-networking",
        "--disable-component-update",
        "--disable-sync",
        "--no-default-browser-check",
        "--disable-extensions",
        "--host-resolver-rules=MAP portal.localhost 127.0.0.1,MAP hub.localhost 127.0.0.1"
      ]
    }
  },
  webServer: [
    {
      command: "node scripts/e2e/isolated-service.mjs jwks",
      url: `${accessTeamDomain}/cdn-cgi/access/certs`,
      reuseExistingServer: false,
      timeout: 30_000,
      env: {
        NODE_OPTIONS: "",
        NODE_PATH: "",
        BIELOS_E2E_JWKS_REGISTRATION_TOKEN: jwksRegistrationToken
      }
    },
    {
      command: "node scripts/e2e/isolated-service.mjs public-site",
      url: "http://127.0.0.1:3000",
      reuseExistingServer: false,
      timeout: 120_000,
      env: publicSiteEnv
    },
    {
      command: "node scripts/e2e/isolated-service.mjs hub",
      url: "https://127.0.0.1:3001/login",
      ignoreHTTPSErrors: true,
      reuseExistingServer: false,
      timeout: 120_000,
      env: hubEnv
    }
  ]
});

function restrictTemporaryDirectory(directory: string): void {
  if (process.platform === "win32") {
    const identity = execFileSync("whoami", [], { encoding: "utf8" }).trim();
    if (!identity || /[\r\n]/u.test(identity)) throw new Error("Could not resolve the current Windows identity.");
    execFileSync("icacls", [directory, "/inheritance:r", "/grant:r", `${identity}:(OI)(CI)F`], { stdio: "ignore" });
    return;
  }
  chmodSync(directory, 0o700);
}

function generateLocalTlsPair(keyPath: string, certificatePath: string): void {
  const openssl = findExecutable("openssl");
  if (openssl) {
    execFileSync(openssl, [
      "req", "-x509", "-newkey", "rsa:2048", "-nodes",
      "-keyout", keyPath,
      "-out", certificatePath,
      "-days", "1",
      "-subj", "/CN=portal.localhost",
      "-addext", "subjectAltName=DNS:portal.localhost,DNS:hub.localhost,IP:127.0.0.1"
    ], { stdio: "ignore" });
    return;
  }

  const powershell = process.platform === "win32" ? findExecutable("pwsh") : undefined;
  if (!powershell) throw new Error("No supported local TLS generator is available.");

  const script = String.raw`
$ErrorActionPreference = 'Stop'
$rsa = [System.Security.Cryptography.RSA]::Create(2048)
$request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=portal.localhost', $rsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
$subjectAltNames = [System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
$subjectAltNames.AddDnsName('portal.localhost')
$subjectAltNames.AddDnsName('hub.localhost')
$subjectAltNames.AddIpAddress([System.Net.IPAddress]::Loopback)
$request.CertificateExtensions.Add($subjectAltNames.Build())
$certificate = $request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-1), [DateTimeOffset]::UtcNow.AddHours(1))
[System.IO.File]::WriteAllText($env:BIELOS_E2E_CERT_PATH, $certificate.ExportCertificatePem(), [System.Text.Encoding]::ASCII)
[System.IO.File]::WriteAllText($env:BIELOS_E2E_KEY_PATH, $rsa.ExportPkcs8PrivateKeyPem(), [System.Text.Encoding]::ASCII)
$certificate.Dispose()
$rsa.Dispose()
`;

  execFileSync(powershell, ["-NoProfile", "-NonInteractive", "-Command", script], {
    env: { ...process.env, BIELOS_E2E_CERT_PATH: certificatePath, BIELOS_E2E_KEY_PATH: keyPath },
    stdio: "ignore"
  });
}

function findExecutable(name: string): string | undefined {
  const extensions = process.platform === "win32" ? (process.env.PATHEXT ?? ".EXE;.CMD;.BAT").split(";") : [""];
  for (const directory of (process.env.PATH ?? "").split(delimiter)) {
    if (!directory) continue;
    for (const extension of extensions) {
      const candidate = join(directory, `${name}${extension}`);
      if (existsSync(candidate)) return candidate;
    }
  }
  return undefined;
}
