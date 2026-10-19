import type { Prisma } from "@virki/database";
import type { ElevationScope } from "./elevation-scopes";

export class AdministrationMutationError extends Error {
  constructor() {
    super("Administrative security mutation rejected.");
    this.name = "AdministrationMutationError";
  }
}

export async function lockAdminSessionInTransaction(transaction: Prisma.TransactionClient, userId: string, sessionId: string, now: Date): Promise<void> {
  const rows = await transaction.$queryRaw<Array<{ id: string }>>`
    SELECT u."id" FROM "User" u JOIN "Session" s ON s."userId" = u."id"
    WHERE u."id" = ${userId} AND u."role" = 'ADMIN'::"UserRole"
      AND u."isActive" = TRUE AND u."accountStatus" = 'ACTIVE'::"AccountStatus"
      AND s."id" = ${sessionId} AND s."revokedAt" IS NULL AND s."expiresAt" > ${now}
    FOR UPDATE OF u, s
  `;
  if (rows.length !== 1) throw new AdministrationMutationError();
  await assertAdminSessionCurrentInTransaction(transaction, userId, sessionId, new Date());
}

export async function requireSecurityElevationInTransaction(
  transaction: Prisma.TransactionClient,
  userId: string,
  sessionId: string,
  scope: ElevationScope,
  now: Date
): Promise<void> {
  await lockAdminSessionInTransaction(transaction, userId, sessionId, now);
  // Lock the proof too, so revocation and the protected mutation have one order.
  const lockedRows = await transaction.$queryRaw<Array<{ id: string }>>`
    SELECT "id" FROM "SecurityElevation"
    WHERE "userId" = ${userId} AND "sessionId" = ${sessionId} AND "scope" = ${scope}
      AND "status" = 'ACTIVE'::"SecurityElevationStatus"
    FOR UPDATE
  `;
  if (lockedRows.length === 0) throw new AdministrationMutationError();

  // Both rows are now locked. Recheck time after any lock wait, so an elevation or session
  // that expired while this transaction was blocked cannot authorize the following write.
  const checkedAt = new Date();
  await assertAdminSessionCurrentInTransaction(transaction, userId, sessionId, checkedAt);
  const activeRows = await transaction.$queryRaw<Array<{ id: string }>>`
    SELECT "id" FROM "SecurityElevation"
    WHERE "userId" = ${userId} AND "sessionId" = ${sessionId} AND "scope" = ${scope}
      AND "status" = 'ACTIVE'::"SecurityElevationStatus"
      AND ("manualUntilRevoked" = TRUE OR "expiresAt" > ${checkedAt})
  `;
  if (activeRows.length === 0) throw new AdministrationMutationError();
}

async function assertAdminSessionCurrentInTransaction(transaction: Prisma.TransactionClient, userId: string, sessionId: string, checkedAt: Date): Promise<void> {
  const rows = await transaction.$queryRaw<Array<{ id: string }>>`
    SELECT s."id" FROM "User" u JOIN "Session" s ON s."userId" = u."id"
    WHERE u."id" = ${userId} AND u."role" = 'ADMIN'::"UserRole"
      AND u."isActive" = TRUE AND u."accountStatus" = 'ACTIVE'::"AccountStatus"
      AND s."id" = ${sessionId} AND s."revokedAt" IS NULL AND s."expiresAt" > ${checkedAt}
  `;
  if (rows.length !== 1) throw new AdministrationMutationError();
}
