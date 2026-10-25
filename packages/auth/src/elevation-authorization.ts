import type { Prisma } from "@virki/database";
import type { ElevationScope } from "./elevation-scopes";

export class AdministrationMutationError extends Error {
  constructor() {
    super("Administrative security mutation rejected.");
    this.name = "AdministrationMutationError";
  }
}

export async function lockAdminSessionInTransaction(transaction: Prisma.TransactionClient, userId: string, sessionId: string, now: Date): Promise<void> {
  // Password recovery locks User before touching sessions or the administrative
  // credential. Take the same first lock for every administrative mutation.
  const users = await transaction.$queryRaw<Array<{ id: string }>>`
    SELECT "id" FROM "User" WHERE "id" = ${userId} FOR UPDATE
  `;
  if (users.length !== 1) throw new AdministrationMutationError();
  const rows = await transaction.$queryRaw<Array<{ id: string }>>`
    SELECT u."id" FROM "User" u JOIN "Session" s ON s."userId" = u."id"
    WHERE u."id" = ${userId} AND u."role" = 'ADMIN'::"UserRole"
      AND u."isActive" = TRUE AND u."accountStatus" = 'ACTIVE'::"AccountStatus"
      AND s."id" = ${sessionId} AND s."revokedAt" IS NULL AND s."expiresAt" > (${now} AT TIME ZONE 'UTC')
    FOR UPDATE OF u, s
  `;
  if (rows.length !== 1) throw new AdministrationMutationError();
  await assertAdminSessionCurrentInTransaction(transaction, userId, sessionId, new Date());
}

export async function lockAdministrativeCredentialInTransaction(transaction: Prisma.TransactionClient, userId: string) {
  const rows = await transaction.$queryRaw<Array<{ passwordHash: string; keyVersion: number; status: string; revokedAt: Date | null }>>`
    SELECT "passwordHash", "keyVersion", "status"::text AS "status", "revokedAt"
    FROM "AdministrativeCredential" WHERE "userId" = ${userId} FOR UPDATE
  `;
  if (rows.length > 1) throw new AdministrationMutationError();
  return rows[0] ?? null;
}

export async function requireSecurityElevationInTransaction(
  transaction: Prisma.TransactionClient,
  userId: string,
  sessionId: string,
  scope: ElevationScope,
  now: Date
): Promise<void> {
  await lockAdminSessionInTransaction(transaction, userId, sessionId, now);
  const credential = await lockAdministrativeCredentialInTransaction(transaction, userId);
  if (credential?.status !== "ACTIVE" || credential.revokedAt || !Number.isSafeInteger(credential.keyVersion) || credential.keyVersion < 1) throw new AdministrationMutationError();
  // Lock the proof too, so revocation and the protected mutation have one order.
  const lockedRows = await transaction.$queryRaw<Array<{ id: string; credentialKeyVersion: number | null }>>`
    SELECT "id", "credentialKeyVersion" FROM "SecurityElevation"
    WHERE "userId" = ${userId} AND "sessionId" = ${sessionId} AND "scope" = ${scope}
      AND "status" = 'ACTIVE'::"SecurityElevationStatus"
      AND "revokedAt" IS NULL
    FOR UPDATE
  `;
  if (lockedRows.length === 0 || !lockedRows.some((row) => row.credentialKeyVersion === credential.keyVersion)) throw new AdministrationMutationError();

  // Both rows are now locked. Recheck time after any lock wait, so an elevation or session
  // that expired while this transaction was blocked cannot authorize the following write.
  const checkedAt = new Date();
  await assertAdminSessionCurrentInTransaction(transaction, userId, sessionId, checkedAt);
  const activeRows = await transaction.$queryRaw<Array<{ id: string }>>`
    SELECT "id" FROM "SecurityElevation"
    WHERE "userId" = ${userId} AND "sessionId" = ${sessionId} AND "scope" = ${scope}
      AND "status" = 'ACTIVE'::"SecurityElevationStatus"
      AND "revokedAt" IS NULL
      AND "credentialKeyVersion" = ${credential.keyVersion}
      AND ("manualUntilRevoked" = TRUE OR "expiresAt" > (${checkedAt} AT TIME ZONE 'UTC'))
  `;
  if (activeRows.length === 0) throw new AdministrationMutationError();
}

async function assertAdminSessionCurrentInTransaction(transaction: Prisma.TransactionClient, userId: string, sessionId: string, checkedAt: Date): Promise<void> {
  const rows = await transaction.$queryRaw<Array<{ id: string }>>`
    SELECT s."id" FROM "User" u JOIN "Session" s ON s."userId" = u."id"
    WHERE u."id" = ${userId} AND u."role" = 'ADMIN'::"UserRole"
      AND u."isActive" = TRUE AND u."accountStatus" = 'ACTIVE'::"AccountStatus"
      AND s."id" = ${sessionId} AND s."revokedAt" IS NULL AND s."expiresAt" > (${checkedAt} AT TIME ZONE 'UTC')
  `;
  if (rows.length !== 1) throw new AdministrationMutationError();
}
