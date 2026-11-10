import { defineConfig } from "@playwright/test";
import { generateKeyPairSync, randomBytes, randomUUID, X509Certificate } from "node:crypto";
import { execFileSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { delimiter, join } from "node:path";
import { tmpdir } from "node:os";
import { buildChromiumEnvironment } from "./scripts/e2e/isolated-service.mjs";
import { createWindowsCaTrust } from "./scripts/e2e/windows-ca-trust.mjs";
import { reuseE2eEmailOutboxKey, reuseE2eRuntimeDirectory } from "./scripts/e2e/runtime-artifacts.mjs";
import { createE2eOidcPrivateConfiguration } from "./scripts/e2e/oidc-private-config.mjs";
import { assertDirectPlaywrightPlatform } from "./scripts/e2e/run-e2e.mjs";

// @ts-expect-error This JavaScript safety helper has no declaration file.
import { CORE_TEST_DATABASE_CONFIRMATION } from "./scripts/core-test-database-safety.mjs";

const discoveryOnly = process.argv.includes("--list");
assertDirectPlaywrightPlatform(process.platform, discoveryOnly);

const productionHubMode = process.env.VIRKI_E2E_HUB_MODE === "production";
const nativeHubGate = process.env.VIRKI_E2E_NATIVE_HUB === "required";
if (process.env.VIRKI_E2E_NATIVE_HUB && !nativeHubGate) {
  throw new Error("Native Hub E2E requires the exact explicit 'required' opt-in.");
}
if (nativeHubGate && (productionHubMode || !process.env.VIRKI_E2E_DATABASE_URL ||
    process.env.VIRKI_CORE_TEST_DATABASE_CONFIRM !== "disposable" ||
    !process.env.VIRKI_E2E_AUDIT_CLEANUP_DATABASE_URL)) {
  throw new Error("Native Hub E2E requires a non-production, confirmed disposable PostgreSQL fixture.");
}
// Enrolling ADMIN test passkeys needs a separate explicit opt-in. Do not
// silently enable the real privileged feature in production-mode rehearsals.
if (process.env.VIRKI_E2E_ADMIN_PASSKEYS === "true" &&
    (productionHubMode || process.env.VIRKI_E2E_PASSKEYS !== "true")) {
  throw new Error("ADMIN passkey E2E requires explicit USER passkeys and a non-production Hub.");
}
const portalUrl = productionHubMode ? "https://portal.localhost" : "https://portal.localhost:3001";
const hubUrl = productionHubMode ? "https://hub.localhost" : "https://hub.localhost:3001";
const hubListenerPort = productionHubMode ? 443 : 3001;
const accessTeamDomain = productionHubMode ? "https://access.e2e.invalid" : "http://127.0.0.1:3010";
const accessAudience = "virki-e2e-access-audience";
const registrationTokenEnv = "VIRKI_E2E_JWKS_REGISTRATION_TOKEN";
const registrationTokenInitializedEnv = "VIRKI_E2E_JWKS_REGISTRATION_TOKEN_INITIALIZED";
const initializedRegistrationToken = process.env[registrationTokenInitializedEnv] === "true"
  ? process.env[registrationTokenEnv]
  : undefined;
if (process.env[registrationTokenInitializedEnv] === "true" && !initializedRegistrationToken) {
  throw new Error("E2E JWKS registration token initialization is incomplete.");
}
const jwksRegistrationToken = initializedRegistrationToken ?? randomBytes(32).toString("base64url");
const e2eDatabaseUrl = process.env.VIRKI_E2E_DATABASE_URL;
const runtimeReady = process.env.VIRKI_E2E_RUNTIME_READY === "true";
const inheritedTotpEncryptionKey = runtimeReady ? process.env.VIRKI_TOTP_ENCRYPTION_KEY : undefined;
if (runtimeReady && (!inheritedTotpEncryptionKey || !/^[0-9a-f]{64}$/iu.test(inheritedTotpEncryptionKey))) {
  throw new Error("Inherited E2E TOTP encryption key is invalid.");
}
const totpEncryptionKey = inheritedTotpEncryptionKey ?? randomBytes(32).toString("hex");
const csrfSigningKey = randomBytes(32).toString("hex");
const rateLimitHashSecret = randomBytes(32).toString("hex");
const auditHashSecret = randomBytes(32).toString("hex");
const inheritedTlsDirectory = reuseE2eRuntimeDirectory(process.env);
if (runtimeReady && !inheritedTlsDirectory) throw new Error("Inherited E2E runtime artifacts are incomplete or outside the private temp directory.");
const ownsRuntimeArtifacts = !runtimeReady;
const tlsDirectory = inheritedTlsDirectory ?? mkdtempSync(join(tmpdir(), "virki-e2e-tls-"));
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
let windowsCaTrust: ReturnType<typeof createWindowsCaTrust> | undefined;

try {
  if (!discoveryOnly) {
    if (ownsRuntimeArtifacts) {
      restrictTemporaryDirectory(tlsDirectory);
      generateLocalTlsPair(tlsKeyPath, tlsCertificatePath, tlsCaKeyPath, tlsCaCertificatePath, tlsCsrPath, tlsExtensionsPath);
    }
    assertLocalTlsPair(tlsCertificatePath, tlsCaCertificatePath);
    if (process.platform === "win32") {
      const caThumbprint = new X509Certificate(readFileSync(tlsCaCertificatePath)).fingerprint.replaceAll(":", "");
      windowsCaTrust = createWindowsCaTrust({ platform: process.platform, certificatePath: tlsCaCertificatePath, thumbprint: caThumbprint });
      windowsCaTrust.install();
      process.env.VIRKI_E2E_TLS_CA_THUMBPRINT = caThumbprint;
      const cleanupOnInterrupt = () => {
        try {
          windowsCaTrust?.cleanup();
        } catch {
          process.stderr.write("Windows E2E test CA cleanup failed.\n");
          process.exitCode = 1;
        }
      };
      process.once("SIGINT", cleanupOnInterrupt);
      process.once("SIGTERM", cleanupOnInterrupt);
    }
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
      if (!certificates.includes("Virki E2E Test CA")) {
        execFileSync("certutil", ["-A", "-d", database, "-n", "Virki E2E Test CA", "-t", "C,,", "-i", tlsCaCertificatePath], { stdio: "ignore" });
      }
    }
    if (ownsRuntimeArtifacts) {
      const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
      const kid = randomUUID();
      const publicJwk = { ...publicKey.export({ format: "jwk" }), kid, use: "sig", alg: "RS256" };
      writeFileSync(accessSigningKeyPath, JSON.stringify({ kid, publicJwk, privateKey: privateKey.export({ format: "pem", type: "pkcs8" }) }), { encoding: "utf8", flag: "wx", mode: 0o600 });
      // Playwright starts webServer processes before globalSetup; the Hub reads
      // the adapter key before the database fixtures are seeded.
      createE2eOidcPrivateConfiguration(oidcPrivateConfigPath);
    }
  }
} catch {
  try {
    windowsCaTrust?.cleanup();
  } catch {
    process.stderr.write("Windows E2E test CA cleanup failed.\n");
  }
  if (ownsRuntimeArtifacts) rmSync(tlsDirectory, { recursive: true, force: true });
  throw new Error("E2E requires local TLS, Chromium CA trust, and signing-key generation support.");
}

if (ownsRuntimeArtifacts) process.once("exit", () => rmSync(tlsDirectory, { recursive: true, force: true }));

const localOnlyEnv = {
  NODE_OPTIONS: "",
  NODE_PATH: "",
  NODE_ENV: "development",
  NEXT_TELEMETRY_DISABLED: "1",
  VIRKI_HUB_HOSTNAME: "hub.localhost",
  VIRKI_PORTAL_HOSTNAME: "portal.localhost",
  VIRKI_HUB_URL: hubUrl,
  VIRKI_PORTAL_URL: portalUrl,
  VIRKI_OIDC_PROXY_URL: "http://127.0.0.1:3003",
  CLOUDFLARE_ACCESS_JWT_REQUIRED: "true",
  CLOUDFLARE_ACCESS_AUDIENCE: accessAudience,
  CLOUDFLARE_TEAM_DOMAIN: accessTeamDomain,
  VIRKI_E2E_ACCESS_DIAGNOSTICS: "true",
  ...(process.env.VIRKI_E2E_LOW05_DIAGNOSTICS === "true" ? { VIRKI_E2E_LOW05_DIAGNOSTICS: "true" } : {}),
  VIRKI_TOTP_ENCRYPTION_KEY: totpEncryptionKey,
  VIRKI_CSRF_SIGNING_KEY: csrfSigningKey,
  VIRKI_RATE_LIMIT_HASH_SECRET: rateLimitHashSecret,
  VIRKI_AUDIT_HASH_SECRET: auditHashSecret,
  NODE_EXTRA_CA_CERTS: tlsCaCertificatePath,
  VIRKI_E2E_JWKS_REGISTRATION_TOKEN: "",
  VIRKI_E2E_JWKS_REGISTRATION_TOKEN_INITIALIZED: "",
  VIRKI_EMAIL_OUTBOX_KEY: emailOutboxKey,
  VIRKI_CORE_TEST_DATABASE_CONFIRM: CORE_TEST_DATABASE_CONFIRMATION,
  DATABASE_URL: e2eDatabaseUrl ?? "postgresql://127.0.0.1:1/virki_e2e_test?connect_timeout=1"
};
const publicSiteEnv = {
  NODE_OPTIONS: "",
  NODE_PATH: "",
  VIRKI_E2E_AUDIT_CLEANUP_DATABASE_URL: "",
  NODE_ENV: "development",
  NEXT_TELEMETRY_DISABLED: "1",
  VIRKI_PORTAL_URL: portalUrl
};
const hubEnv = {
  ...localOnlyEnv,
  ...(nativeHubGate ? { VIRKI_HUB_PERIMETER_MODE: "native" } : {}),
  VIRKI_E2E_AUDIT_CLEANUP_DATABASE_URL: "",
  // The isolated Hub launcher extracts only adapterKey and omits this path from its child env.
  VIRKI_E2E_OIDC_PRIVATE_CONFIG_FILE: oidcPrivateConfigPath,
  VIRKI_E2E_TLS_KEY_PATH: tlsKeyPath,
  VIRKI_E2E_TLS_CERTIFICATE_PATH: tlsCertificatePath,
  ...(process.env.VIRKI_E2E_PASSKEYS === "true" && !productionHubMode
    ? { VIRKI_PASSKEYS_ENABLED: "true", VIRKI_PASSKEYS_LOCAL_TESTING: "true" }
    : {}),
  ...(process.env.VIRKI_E2E_ADMIN_PASSKEYS === "true" && !productionHubMode
    ? { VIRKI_E2E_ADMIN_PASSKEYS: "true", VIRKI_ADMIN_PASSKEYS_ENABLED: "true" }
    : {}),
  ...(process.env.VIRKI_E2E_HUB_MODE === "production" ? { NODE_ENV: "production", VIRKI_E2E_HUB_MODE: "production" } : {})
};
process.env.VIRKI_E2E_ACCESS_AUDIENCE = accessAudience;
process.env.VIRKI_E2E_ACCESS_ISSUER = accessTeamDomain;
process.env.VIRKI_TOTP_ENCRYPTION_KEY = totpEncryptionKey;
process.env.VIRKI_RATE_LIMIT_HASH_SECRET = rateLimitHashSecret;
process.env.VIRKI_AUDIT_HASH_SECRET = auditHashSecret;
process.env.VIRKI_E2E_TLS_KEY_PATH = tlsKeyPath;
process.env.VIRKI_E2E_TLS_CERTIFICATE_PATH = tlsCertificatePath;
process.env.VIRKI_E2E_TLS_CA_CERTIFICATE_PATH = tlsCaCertificatePath;
process.env.NODE_EXTRA_CA_CERTS = tlsCaCertificatePath;
process.env.VIRKI_E2E_OIDC_PRIVATE_CONFIG_FILE = oidcPrivateConfigPath;
process.env.VIRKI_E2E_ACCESS_SIGNING_KEY_FILE = accessSigningKeyPath;
process.env.VIRKI_EMAIL_OUTBOX_KEY = emailOutboxKey;
process.env.VIRKI_E2E_RUNTIME_DIRECTORY = tlsDirectory;
process.env.VIRKI_E2E_RUNTIME_READY = "true";
process.env[registrationTokenEnv] = jwksRegistrationToken;
process.env[registrationTokenInitializedEnv] = "true";

export default defineConfig({
  testDir: "./e2e",
  // Never mix native Hub and Access-JWT test processes: each has its own
  // webServer lifecycle, isolated TLS material and browser fixture.
  ...(nativeHubGate
    ? { testMatch: "**/native-hub-perimeter.spec.mts" }
    : { testIgnore: "**/native-hub-perimeter.spec.mts" }),
  globalTeardown: "./scripts/e2e/global-teardown.mts",
  globalSetup: e2eDatabaseUrl ? "./scripts/e2e/global-setup.mts" : undefined,
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: "list",
  use: {
    browserName: "chromium",
    launchOptions: {
      executablePath: process.env.VIRKI_E2E_CHROMIUM_EXECUTABLE_PATH || undefined,
      env: buildChromiumEnvironment(process.env, process.platform, chromiumHomePath),
      args: [
        "--disable-background-networking",
        "--disable-component-update",
        "--disable-sync",
        "--no-default-browser-check",
        "--disable-extensions",
        "--host-resolver-rules=MAP portal.localhost 127.0.0.1,MAP hub.localhost 127.0.0.1,MAP access.e2e.invalid 127.0.0.1"
      ]
    }
  },
  webServer: [
    // No synthetic Access/JWKS service exists during the native-only run.
    // A hidden dependency on Cloudflare-style assertion verification must
    // fail this browser gate instead of being satisfied by a test server.
    ...(!nativeHubGate ? [{
      command: "node scripts/e2e/isolated-service.mjs jwks",
      url: `${productionHubMode ? "http://127.0.0.1:3010" : accessTeamDomain}/cdn-cgi/access/certs`,
      reuseExistingServer: false,
      timeout: 30_000,
      stdout: "pipe" as const,
      env: {
        NODE_OPTIONS: "",
        NODE_PATH: "",
        VIRKI_E2E_AUDIT_CLEANUP_DATABASE_URL: "",
        VIRKI_E2E_JWKS_REGISTRATION_TOKEN: jwksRegistrationToken
      }
    }] : []),
    {
      command: "node scripts/e2e/isolated-service.mjs public-site",
      url: "http://127.0.0.1:3000",
      reuseExistingServer: false,
      timeout: 120_000,
      env: publicSiteEnv
    },
    {
      command: "node scripts/e2e/isolated-service.mjs hub",
      // Playwright's webServer URL probe cannot consume this run's private CA. Check the listener only;
      // the browser navigation below still performs normal TLS verification against its private NSS DB.
      port: hubListenerPort,
      reuseExistingServer: false,
      timeout: 120_000,
      stdout: process.env.VIRKI_E2E_LOW05_DIAGNOSTICS === "true" ? "pipe" : "ignore",
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
      "-subj", "/CN=Virki E2E Root CA",
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
      "-addext", "subjectAltName=DNS:portal.localhost,DNS:hub.localhost,DNS:access.e2e.invalid,IP:127.0.0.1"
    ], { stdio: "ignore" });
    writeFileSync(extensionsPath, [
      "[server_cert]",
      "basicConstraints=critical,CA:FALSE",
      "keyUsage=critical,digitalSignature,keyEncipherment",
      "extendedKeyUsage=serverAuth",
      "subjectAltName=DNS:portal.localhost,DNS:hub.localhost,DNS:access.e2e.invalid,IP:127.0.0.1",
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
$rootRequest = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=Virki E2E Root CA', $rootRsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
$rootRequest.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true, $false, 0, $true))
$rootRequest.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new([System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign -bor [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::CrlSign, $true))
$rootCertificate = $rootRequest.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-1), [DateTimeOffset]::UtcNow.AddDays(1))
$rsa = [System.Security.Cryptography.RSA]::Create(2048)
$request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=portal.localhost', $rsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
$subjectAltNames = [System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
$subjectAltNames.AddDnsName('portal.localhost')
$subjectAltNames.AddDnsName('hub.localhost')
$subjectAltNames.AddDnsName('access.e2e.invalid')
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
[System.IO.File]::WriteAllText($env:VIRKI_E2E_CERT_PATH, $certificate.ExportCertificatePem(), [System.Text.Encoding]::ASCII)
[System.IO.File]::WriteAllText($env:VIRKI_E2E_KEY_PATH, $rsa.ExportPkcs8PrivateKeyPem(), [System.Text.Encoding]::ASCII)
[System.IO.File]::WriteAllText($env:VIRKI_E2E_CA_CERT_PATH, $rootCertificate.ExportCertificatePem(), [System.Text.Encoding]::ASCII)
$certificate.Dispose()
$rootCertificate.Dispose()
$rootRsa.Dispose()
$random.Dispose()
$rsa.Dispose()
`;

  execFileSync(powershell, ["-NoProfile", "-NonInteractive", "-Command", script], {
    env: { ...process.env, VIRKI_E2E_CERT_PATH: certificatePath, VIRKI_E2E_KEY_PATH: keyPath, VIRKI_E2E_CA_CERT_PATH: caCertificatePath },
    stdio: "ignore"
  });
}

function assertLocalTlsPair(certificatePath: string, caCertificatePath: string): void {
  const certificate = new X509Certificate(readFileSync(certificatePath));
  const caCertificate = new X509Certificate(readFileSync(caCertificatePath));
  if (certificate.ca || !caCertificate.ca || !certificate.verify(caCertificate.publicKey) || !certificate.checkHost("portal.localhost") || !certificate.checkHost("access.e2e.invalid")) {
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
