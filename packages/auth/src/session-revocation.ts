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
    return result.count;
  });
}

async function lockCurrentUserSession(transaction: Prisma.TransactionClient, userId: string, sessionId: string): Promise<void> {
  const now = new Date();
  const rows = await transaction.$queryRaw<Array<{ id: string }>>`
    SELECT s."id" FROM "User" u JOIN "Session" s ON s."userId" = u."id"
    WHERE u."id" = ${userId} AND u."role" = 'USER'::"UserRole"
      AND u."isActive" = TRUE AND u."accountStatus" = 'ACTIVE'::"AccountStatus"
      AND s."id" = ${sessionId} AND s."revokedAt" IS NULL AND s."expiresAt" > ${now}
    FOR UPDATE OF u, s
  `;
  if (rows.length !== 1) throw new AccountSessionRevocationError();
}

async function assertCurrentUserSession(transaction: Prisma.TransactionClient, userId: string, sessionId: string, now: Date): Promise<void> {
  const rows = await transaction.$queryRaw<Array<{ id: string }>>`
    SELECT s."id" FROM "User" u JOIN "Session" s ON s."userId" = u."id"
    WHERE u."id" = ${userId} AND u."role" = 'USER'::"UserRole"
      AND u."isActive" = TRUE AND u."accountStatus" = 'ACTIVE'::"AccountStatus"
      AND s."id" = ${sessionId} AND s."revokedAt" IS NULL AND s."expiresAt" > ${now}
  `;
  if (rows.length !== 1) throw new AccountSessionRevocationError();
}
