import { execFileSync } from "node:child_process";

const storeLocation = "CurrentUser\\Root";

export function createWindowsCaTrust({ platform = process.platform, certificatePath, thumbprint, alreadyInstalled = false, runStoreCommand = runPowerShellStoreCommand }) {
  if (platform !== "win32") return { install() {}, cleanup() {} };
  if (!certificatePath || !/^[A-F0-9]{40}$/iu.test(thumbprint ?? "")) {
    throw new Error("Windows E2E test CA identity is invalid.");
  }

  let installed = alreadyInstalled;
  return {
    install() {
      if (installed) return;
      installed = true;
      try {
        runStoreCommand("add", storeLocation, thumbprint, certificatePath);
      } catch {
        throw new Error("Windows E2E test CA installation failed.");
      }
    },
    cleanup() {
      if (!installed) return;
      try {
        runStoreCommand("remove", storeLocation, thumbprint);
        installed = false;
      } catch {
        throw new Error("Windows E2E test CA cleanup failed.");
      }
    }
  };
}

function runPowerShellStoreCommand(operation, scope, thumbprint, certificatePath) {
  const script = String.raw`
$ErrorActionPreference = 'Stop'
$store = [System.Security.Cryptography.X509Certificates.X509Store]::new('Root', 'CurrentUser')
$store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
try {
  $foundCertificates = @($store.Certificates | Where-Object { $_.Thumbprint -eq $env:VIRKI_E2E_CA_THUMBPRINT })
  if ($env:VIRKI_E2E_CA_OPERATION -eq 'add') {
    $certificateBytes = [Convert]::FromBase64String(([System.IO.File]::ReadAllText($env:VIRKI_E2E_CA_CERTIFICATE_PATH) -replace '-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s', ''))
    $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certificateBytes)
    try {
      if ($certificate.Thumbprint -ne $env:VIRKI_E2E_CA_THUMBPRINT) { throw 'CA identity mismatch' }
      if ($foundCertificates.Count -eq 0) { $store.Add($certificate) }
    } finally { $certificate.Dispose() }
  } else {
    foreach ($certificate in $foundCertificates) { $store.Remove($certificate) }
  }
} finally { $store.Close(); $store.Dispose() }
`;
  try {
    execFileSync("powershell.exe", ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script], {
      env: {
        ...process.env,
        VIRKI_E2E_CA_OPERATION: operation,
        VIRKI_E2E_CA_CERTIFICATE_PATH: certificatePath ?? "",
        VIRKI_E2E_CA_THUMBPRINT: thumbprint
      },
      stdio: "ignore",
      windowsHide: true
    });
  } catch {
    throw new Error(operation === "add" ? "Windows E2E test CA installation failed." : "Windows E2E test CA cleanup failed.");
  }
}
