import { prisma } from "@bielos/database";
import { cleanupInactiveSessions } from "./index";
import { writeAuditLog } from "./audit";
import { getSafeAuthCommandFailureMessage } from "./command-output";

async function main() {
  const deletedCount = await cleanupInactiveSessions();
  await writeAuditLog({
    eventType: "AUTH_SESSION_CLEANUP",
    result: "SUCCESS",
    resource: "session",
    message: "Inactive sessions cleaned up.",
    metadata: {
      source: "sessions-cleanup",
      deletedCount
    }
  });
  console.log(`Deleted inactive sessions: ${deletedCount}`);
}

main()
  .catch(() => {
    console.error(getSafeAuthCommandFailureMessage("session-cleanup"));
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
