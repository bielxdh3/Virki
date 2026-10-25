import { prisma, type Prisma } from "@virki/database";
import { hashAuditSessionReference, writeAuditLogInTransaction } from "./audit";

export class AccountSessionRevocationError extends Error {
  constructor() {
    super("Account session revocation rejected.");
    this.name = "AccountSessionRevocationError";
  }
}

export async function revokeOtherAccountSessions(userId: string, currentSessionId: string): Promise<number> {
  return prisma.$transaction(async (transaction) => {
    await lockCurrentUserSession(transaction, userId, currentSessionId);
    const now = new Date();
    await assertCurrentUserSession(transaction, userId, currentSessionId, now);
    const result = await transaction.session.updateMany({
      where: { userId, id: { not: currentSessionId }, revokedAt: null, expiresAt: { gt: now } },
      data: { revokedAt: now }
    });
    if (result.count > 0) {
      await writeAuditLogInTransaction(transaction, {
        eventType: "AUTH_SESSION_REVOKED",
        result: "SUCCESS",
        actorUserId: userId,
        actorRole: "USER",
        sessionRef: hashAuditSessionReference(currentSessionId),
        resource: "session",
        message: "Other active account sessions revoked.",
        metadata: { revokedCount: result.count }
      });
    }
    // A target Session UPDATE or the audit INSERT can wait on unrelated row/
    // table locks after the first current-session check. Revalidate with a
    // fresh clock at the end so expiry rolls back BOTH revocations and audit.
    await assertCurrentUserSession(transaction, userId, currentSessionId, new Date());
    return result.count;
  });
}

async function lockCurrentUserSession(transaction: Prisma.TransactionClient, userId: string, sessionId: string): Promise<void> {
  const rows = await transaction.$queryRaw<Array<{ id: string }>>`
    SELECT s."id" FROM "User" u JOIN "Session" s ON s."userId" = u."id"
    WHERE u."id" = ${userId} AND u."role" = 'USER'::"UserRole"
      AND u."isActive" = TRUE AND u."accountStatus" = 'ACTIVE'::"AccountStatus"
      AND s."id" = ${sessionId} AND s."revokedAt" IS NULL
    FOR UPDATE OF u, s
  `;
  if (rows.length !== 1) throw new AccountSessionRevocationError();
}

async function assertCurrentUserSession(transaction: Prisma.TransactionClient, userId: string, sessionId: string, now: Date): Promise<void> {
  // Prisma DateTime is stored as a UTC timestamp without time zone. Comparing it
  // to a raw Date parameter can coerce through the PostgreSQL session time zone.
  const current = await transaction.session.findFirst({
    where: {
      id: sessionId,
      userId,
      revokedAt: null,
      expiresAt: { gt: now },
      user: { is: { role: "USER", isActive: true, accountStatus: "ACTIVE" } }
    },
    select: { id: true }
  });
  if (!current) throw new AccountSessionRevocationError();
}
