import { prisma } from "@virki/database";
import { cleanupExpiredLoginRateLimits, cleanupInactiveSessions } from "./index";
import { writeAuditLog } from "./audit";
import { runAuthCommand } from "./command-output";

async function main() {
  const deletedCount = await cleanupInactiveSessions();
  const deletedRateLimitCount = await cleanupExpiredLoginRateLimits();
  // A no-op worker run must not pollute an otherwise virgin first-install DB
  // with an audit row before the initial administrator exists.
  if (deletedCount > 0 || deletedRateLimitCount > 0) {
    await writeAuditLog({
      eventType: "AUTH_SESSION_CLEANUP",
      result: "SUCCESS",
      resource: "session",
      message: "Inactive sessions cleaned up.",
      metadata: {
        source: "sessions-cleanup",
        deletedCount,
        deletedRateLimitCount
      }
    });
  }
  console.log(`Deleted inactive sessions: ${deletedCount}`);
}

void runAuthCommand("session-cleanup", main, () => prisma.$disconnect());
