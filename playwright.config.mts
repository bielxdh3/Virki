import { defineConfig } from "@playwright/test";
import { generateKeyPairSync, randomBytes, randomUUID, X509Certificate } from "node:crypto";
import { execFileSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { delimiter, join } from "node:path";
import { tmpdir } from "node:os";
import { buildChromiumEnvironment } from "./scripts/e2e/isolated-service.mjs";
import { reuseE2eEmailOutboxKey, reuseE2eRuntimeDirectory } from "./scripts/e2e/runtime-artifacts.mjs";

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
const runtimeReady = process.env.BIELOS_E2E_RUNTIME_READY === "true";
const inheritedTotpEncryptionKey = runtimeReady ? process.env.BIELOS_TOTP_ENCRYPTION_KEY : undefined;
if (runtimeReady && (!inheritedTotpEncryptionKey || !/^[0-9a-f]{64}$/iu.test(inheritedTotpEncryptionKey))) {
  throw new Error("Inherited E2E TOTP encryption key is invalid.");
}
const totpEncryptionKey = inheritedTotpEncryptionKey ?? randomBytes(32).toString("hex");
const csrfSigningKey = randomBytes(32).toString("hex");
const inheritedTlsDirectory = reuseE2eRuntimeDirectory(process.env);
if (runtimeReady && !inheritedTlsDirectory) throw new Error("Inherited E2E runtime artifacts are incomplete or outside the private temp directory.");
const ownsRuntimeArtifacts = !runtimeReady;
const tlsDirectory = inheritedTlsDirectory ?? mkdtempSync(join(tmpdir(), "bielos-e2e-tls-"));
const tlsKeyPath = join(tlsDirectory, "server-key.pem");
const tlsCertificatePath = join(tlsDirectory, "server-cert.pem");
const tlsCaKeyPath = join(tlsDirectory, "test-ca-key.pem");
const tlsCaCertificatePath = join(tlsDirectory, "test-ca-cert.pem");
const tlsCsrPath = join(tlsDirectory, "server.csr");
const tlsExtensionsPath = join(tlsDirectory, "server-extensions.cnf");
const accessSigningKeyPath = join(tlsDirectory, "access-signing-key.json");
const oidcPrivateConfigPath = join(tlsDirectory, "issuer-config.json");
const chromiumHomePath = join(tlsDirectory, "chromium-home");
const chromiumNssDbPath = join(chromiumHomePath, ".pki", "nssdb");
const inheritedEmailOutboxKey = reuseE2eEmailOutboxKey(process.env);
if (runtimeReady && (!inheritedEmailOutboxKey || !/^[A-Za-z0-9_-]{43}$/u.test(inheritedEmailOutboxKey) || Buffer.from(inheritedEmailOutboxKey, "base64url").length !== 32)) {
  throw new Error("Inherited E2E outbox key is invalid.");
}
const emailOutboxKey = inheritedEmailOutboxKey ?? randomBytes(32).toString("base64url");

try {
  if (ownsRuntimeArtifacts) {
    restrictTemporaryDirectory(tlsDirectory);
    generateLocalTlsPair(tlsKeyPath, tlsCertificatePath, tlsCaKeyPath, tlsCaCertificatePath, tlsCsrPath, tlsExtensionsPath);
  }
  assertLocalTlsPair(tlsCertificatePath, tlsCaCertificatePath);
  if (process.platform === "linux") {
    // Chromium trusts only this run's CA through a private NSS database.
    for (const path of [chromiumHomePath, join(chromiumHomePath, ".pki"), chromiumNssDbPath]) {
      mkdirSync(path, { recursive: true, mode: 0o700 });
      chmodSync(path, 0o700);
    }
    const database = `sql:${chromiumNssDbPath}`;
    if (!existsSync(join(chromiumNssDbPath, "cert9.db"))) {
      execFileSync("certutil", ["-N", "--empty-password", "-d", database], { stdio: "ignore" });
    }
    const certificates = execFileSync("certutil", ["-L", "-d", database], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
    if (!certificates.includes("BielOS E2E Test CA")) {
      execFileSync("certutil", ["-A", "-d", database, "-n", "BielOS E2E Test CA", "-t", "C,,", "-i", tlsCaCertificatePath], { stdio: "ignore" });
    }
  }
  if (ownsRuntimeArtifacts) {
    const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const kid = randomUUID();
    const publicJwk = { ...publicKey.export({ format: "jwk" }), kid, use: "sig", alg: "RS256" };
    writeFileSync(accessSigningKeyPath, JSON.stringify({ kid, publicJwk, privateKey: privateKey.export({ format: "pem", type: "pkcs8" }) }), { encoding: "utf8", flag: "wx", mode: 0o600 });
  }
} catch {
  if (ownsRuntimeArtifacts) rmSync(tlsDirectory, { recursive: true, force: true });
  throw new Error("E2E requires local TLS, Chromium CA trust, and signing-key generation support.");
}

if (ownsRuntimeArtifacts) process.once("exit", () => rmSync(tlsDirectory, { recursive: true, force: true }));

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
  BIELOS_E2E_ACCESS_DIAGNOSTICS: "true",
  BIELOS_TOTP_ENCRYPTION_KEY: totpEncryptionKey,
  BIELOS_CSRF_SIGNING_KEY: csrfSigningKey,
  NODE_EXTRA_CA_CERTS: tlsCaCertificatePath,
  BIELOS_E2E_JWKS_REGISTRATION_TOKEN: "",
  BIELOS_E2E_JWKS_REGISTRATION_TOKEN_INITIALIZED: "",
  BIELOS_EMAIL_OUTBOX_KEY: emailOutboxKey,
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
process.env.BIELOS_TOTP_ENCRYPTION_KEY = totpEncryptionKey;
process.env.BIELOS_E2E_TLS_KEY_PATH = tlsKeyPath;
process.env.BIELOS_E2E_TLS_CERTIFICATE_PATH = tlsCertificatePath;
process.env.BIELOS_E2E_TLS_CA_CERTIFICATE_PATH = tlsCaCertificatePath;
process.env.BIELOS_E2E_OIDC_PRIVATE_CONFIG_FILE = oidcPrivateConfigPath;
process.env.BIELOS_E2E_ACCESS_SIGNING_KEY_FILE = accessSigningKeyPath;
process.env.BIELOS_EMAIL_OUTBOX_KEY = emailOutboxKey;
process.env.BIELOS_E2E_RUNTIME_DIRECTORY = tlsDirectory;
process.env.BIELOS_E2E_RUNTIME_READY = "true";
process.env[registrationTokenEnv] = jwksRegistrationToken;
process.env[registrationTokenInitializedEnv] = "true";

export default defineConfig({
  testDir: "./e2e",
  globalSetup: e2eDatabaseUrl ? "./scripts/e2e/global-setup.mts" : undefined,
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: "list",
  use: {
    browserName: "chromium",
    launchOptions: {
      env: buildChromiumEnvironment(process.env, process.platform, chromiumHomePath),
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
      stdout: "pipe",
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

function generateLocalTlsPair(keyPath: string, certificatePath: string, caKeyPath: string, caCertificatePath: string, csrPath: string, extensionsPath: string): void {
  const openssl = findExecutable("openssl");
  if (openssl) {
    execFileSync(openssl, [
      "req", "-x509", "-newkey", "rsa:2048", "-nodes",
      "-keyout", caKeyPath,
      "-out", caCertificatePath,
      "-days", "1",
      "-sha256",
      "-subj", "/CN=BielOS E2E Root CA",
      "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
      "-addext", "keyUsage=critical,keyCertSign,cRLSign",
      "-addext", "subjectKeyIdentifier=hash"
    ], { stdio: "ignore" });
    execFileSync(openssl, [
      "req", "-new", "-newkey", "rsa:2048", "-nodes",
      "-keyout", keyPath,
      "-out", csrPath,
      "-sha256",
      "-subj", "/CN=portal.localhost",
      "-addext", "subjectAltName=DNS:portal.localhost,DNS:hub.localhost,IP:127.0.0.1"
    ], { stdio: "ignore" });
    writeFileSync(extensionsPath, [
      "[server_cert]",
      "basicConstraints=critical,CA:FALSE",
      "keyUsage=critical,digitalSignature,keyEncipherment",
      "extendedKeyUsage=serverAuth",
      "subjectAltName=DNS:portal.localhost,DNS:hub.localhost,IP:127.0.0.1",
      "subjectKeyIdentifier=hash",
      "authorityKeyIdentifier=keyid,issuer",
      ""
    ].join("\n"), { encoding: "ascii", flag: "wx", mode: 0o600 });
    execFileSync(openssl, [
      "x509", "-req", "-in", csrPath,
      "-CA", caCertificatePath,
      "-CAkey", caKeyPath,
      "-CAcreateserial",
      "-out", certificatePath,
      "-days", "1",
      "-sha256",
      "-extfile", extensionsPath,
      "-extensions", "server_cert"
    ], { stdio: "ignore" });
    return;
  }

  const powershell = process.platform === "win32" ? findExecutable("pwsh") : undefined;
  if (!powershell) throw new Error("No supported local TLS generator is available.");

  const script = String.raw`
$ErrorActionPreference = 'Stop'
$rootRsa = [System.Security.Cryptography.RSA]::Create(2048)
$rootRequest = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=BielOS E2E Root CA', $rootRsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
$rootRequest.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true, $false, 0, $true))
$rootRequest.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new([System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign -bor [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::CrlSign, $true))
$rootCertificate = $rootRequest.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-1), [DateTimeOffset]::UtcNow.AddDays(1))
$rsa = [System.Security.Cryptography.RSA]::Create(2048)
$request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=portal.localhost', $rsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
$subjectAltNames = [System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
$subjectAltNames.AddDnsName('portal.localhost')
$subjectAltNames.AddDnsName('hub.localhost')
$subjectAltNames.AddIpAddress([System.Net.IPAddress]::Loopback)
$request.CertificateExtensions.Add($subjectAltNames.Build())
$request.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($false, $false, 0, $true))
$request.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new([System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature -bor [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyEncipherment, $true))
$serverUsages = [System.Security.Cryptography.OidCollection]::new()
$null = $serverUsages.Add([System.Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.1'))
$request.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($serverUsages, $true))
$serial = [byte[]]::new(16)
$random = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$random.GetBytes($serial)
$serial[0] = $serial[0] -band 0x7f
$serial[15] = $serial[15] -bor 1
$signatureGenerator = [System.Security.Cryptography.X509Certificates.X509SignatureGenerator]::CreateForRSA($rootRsa, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
$certificate = $request.Create($rootCertificate.SubjectName, $signatureGenerator, [DateTimeOffset]::UtcNow.AddMinutes(-1), [DateTimeOffset]::UtcNow.AddDays(1), $serial)
[System.IO.File]::WriteAllText($env:BIELOS_E2E_CERT_PATH, $certificate.ExportCertificatePem(), [System.Text.Encoding]::ASCII)
[System.IO.File]::WriteAllText($env:BIELOS_E2E_KEY_PATH, $rsa.ExportPkcs8PrivateKeyPem(), [System.Text.Encoding]::ASCII)
[System.IO.File]::WriteAllText($env:BIELOS_E2E_CA_CERT_PATH, $rootCertificate.ExportCertificatePem(), [System.Text.Encoding]::ASCII)
$certificate.Dispose()
$rootCertificate.Dispose()
$rootRsa.Dispose()
$random.Dispose()
$rsa.Dispose()
`;

  execFileSync(powershell, ["-NoProfile", "-NonInteractive", "-Command", script], {
    env: { ...process.env, BIELOS_E2E_CERT_PATH: certificatePath, BIELOS_E2E_KEY_PATH: keyPath, BIELOS_E2E_CA_CERT_PATH: caCertificatePath },
    stdio: "ignore"
  });
}

function assertLocalTlsPair(certificatePath: string, caCertificatePath: string): void {
  const certificate = new X509Certificate(readFileSync(certificatePath));
  const caCertificate = new X509Certificate(readFileSync(caCertificatePath));
  if (certificate.ca || !caCertificate.ca || !certificate.verify(caCertificate.publicKey) || !certificate.checkHost("portal.localhost")) {
    throw new Error("Generated E2E TLS certificate is not a valid server leaf signed by the test CA.");
  }
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
