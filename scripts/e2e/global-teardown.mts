import { createWindowsCaTrust } from "./windows-ca-trust.mjs";

export default function globalTeardown(): void {
  if (process.platform !== "win32") return;
  const thumbprint = process.env.VIRKI_E2E_TLS_CA_THUMBPRINT;
  const certificatePath = process.env.VIRKI_E2E_TLS_CA_CERTIFICATE_PATH;
  if (!thumbprint || !certificatePath) return;

  const trust = createWindowsCaTrust({
    platform: process.platform,
    certificatePath,
    thumbprint,
    alreadyInstalled: true
  });
  try {
    trust.cleanup();
  } catch {
    process.stderr.write("Windows E2E test CA cleanup failed.\n");
    process.exitCode = 1;
  }
}
