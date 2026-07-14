import { prisma } from "@bielos/database";
import { runAuthCommand } from "./command-output";

const DEFAULT_LIMIT = 20;
const MAX_LIMIT = 50;

async function main() {
  const limit = getLimit();
  const logs = await prisma.auditLog.findMany({
    orderBy: { createdAt: "desc" },
    take: limit,
    select: {
      createdAt: true,
      eventType: true,
      result: true,
      resource: true,
      message: true,
      actorUserId: true,
      actorEmailHash: true
    }
  });

  if (logs.length === 0) {
    console.log("No audit logs found.");
    return;
  }

  for (const log of logs) {
    console.log(
      [
        log.createdAt.toISOString(),
        log.eventType,
        log.result,
        log.resource ?? "-",
        log.message ?? "-",
        log.actorUserId ? `user:${log.actorUserId}` : "-",
        log.actorEmailHash ? `emailHash:${log.actorEmailHash.slice(0, 16)}` : "-"
      ].join(" | ")
    );
  }
}

function getLimit(): number {
  const raw = Number(process.env.BIELOS_AUDIT_RECENT_LIMIT ?? DEFAULT_LIMIT);

  if (!Number.isFinite(raw) || raw < 1) {
    return DEFAULT_LIMIT;
  }

  return Math.min(Math.floor(raw), MAX_LIMIT);
}

void runAuthCommand("audit-recent", main, () => prisma.$disconnect());
