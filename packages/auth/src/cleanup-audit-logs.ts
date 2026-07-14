import { prisma } from "@bielos/database";
import { cleanupExpiredAuditLogs, writeAuditLog } from "./audit";
import { getSafeAuthCommandFailureMessage } from "./command-output";

async function main() {
  const result = await cleanupExpiredAuditLogs();

  await writeAuditLog({
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

main()
  .catch(() => {
    console.error(getSafeAuthCommandFailureMessage("audit-cleanup"));
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
