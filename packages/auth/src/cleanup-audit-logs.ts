import { prisma } from "@bielos/database";
import { cleanupExpiredAuditLogs, writeAuditLogForMaintenanceRequired } from "./audit";
import { runAuthCommand } from "./command-output";

async function main() {
  const result = await cleanupExpiredAuditLogs();

  await writeAuditLogForMaintenanceRequired({
    eventType: "AUTH_AUDIT_LOG_CLEANUP",
    result: "SUCCESS",
    resource: "audit-log",
    message: "Expired audit logs cleaned up.",
    metadata: {
      source: "audit-log-cleanup",
      deletedCount: result.deletedCount,
      retentionDays: result.retentionDays
    }
  });

  console.log(`Deleted expired audit logs: ${result.deletedCount}`);
}

void runAuthCommand("audit-cleanup", main, () => prisma.$disconnect());
