import { prisma } from "@virki/database";
import { cleanupExpiredAuditLogs, writeAuditCleanupResultIfNeeded } from "./audit";
import { runAuthCommand } from "./command-output";

async function main() {
  const result = await cleanupExpiredAuditLogs();

  await writeAuditCleanupResultIfNeeded(result);

  console.log(`Deleted expired audit logs: ${result.deletedCount}`);
}

void runAuthCommand("audit-cleanup", main, () => prisma.$disconnect());
