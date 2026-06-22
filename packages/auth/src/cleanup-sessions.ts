import { prisma } from "@bielos/database";
import { cleanupInactiveSessions } from "./index";

async function main() {
  const deletedCount = await cleanupInactiveSessions();
  console.log(`Deleted inactive sessions: ${deletedCount}`);
}

main()
  .catch((error: unknown) => {
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
