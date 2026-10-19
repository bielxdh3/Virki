import { prisma } from "@virki/database";
import { cleanupExpiredAuditLogs } from "./audit";
import { runAuthCommand } from "./command-output";

async function main() {
  const result = await cleanupExpiredAuditLogs();
  console.log(`Deleted expired audit logs: ${result.deletedCount}`);
}

void runAuthCommand("audit-cleanup", main, () => prisma.$disconnect());
