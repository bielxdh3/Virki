#!/usr/bin/env node
/**
 * Non-mutating local PG18 stage probe: approved secret-injected Node22 WSL
 * operator context only. Never a public HTTP endpoint. A PASS alone does not
 * prove the Hub already running behind Cloudflare is using the same database.
 */
import { assertStagingMfaLocalProbeEnvironment } from "./lib/staging-mfa-bootstrap-guard.mjs";
import { probeStagingMfaLocalDatabase } from "./lib/staging-mfa-local-db-probe.mjs";

async function main() {
  if (process.platform !== "linux" || Number(process.versions.node.split(".")[0]) !== 22 ||
      process.argv.length !== 2 || process.env.VIRKI_STAGING_MFA_LOCAL_DB_PROBE !== "read-only") {
    throw new Error("BLOCK");
  }
  const expected = assertStagingMfaLocalProbeEnvironment(process.env);
  const { prisma } = await import("@virki/database");
  try {
    await probeStagingMfaLocalDatabase(prisma, expected);
    process.stdout.write("STAGING_MFA_LOCAL_DB_PROBE=PASS\n");
  } finally {
    await prisma.$disconnect();
  }
}

main().catch(() => {
  // Never expose database URLs, passwords, driver errors or record values.
  process.stderr.write("STAGING_MFA_LOCAL_DB_PROBE=BLOCK\n");
  process.exitCode = 1;
});
