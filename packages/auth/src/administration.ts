import { randomBytes, timingSafeEqual } from "node:crypto";
import { enqueueEmailMessageForClient, type EmailLocale } from "./email";
import { decryptTotpSecret, generateRecoveryCode, generateNumericCode, hashRecoveryCode, hashSecurityCode, revokeUserAuthenticationProofsInTransaction, revokeUserOidcArtifactsInTransaction, verifySecurityCode, verifyTotpCode } from "./security";
import { consumeRateLimitAttemptInTransaction, hashAuditIdentifier, hashAuditSessionReference, hashPassword, verifyPassword, writeAuditLogInTransaction, type AuditLogInput } from "./index";
import { prisma, type Prisma } from "@virki/database";
import { hashOidcIdentifier } from "./oidc-secrets";
import { ELEVATION_SCOPES, type ElevationScope } from "./elevation-scopes";
import { AdministrationMutationError, assertAdminSessionCurrentInTransaction, lockAdminSessionInTransaction, lockAdministrativeCredentialInTransaction, requireSecurityElevationInTransaction } from "./elevation-authorization";

export { ELEVATION_SCOPES, ELEVATION_SCOPE_ACTIONS, UI_ELEVATION_SCOPES } from "./elevation-scopes";
export type { ElevationScope } from "./elevation-scopes";
export { AdministrationMutationError, assertAdminSessionCurrentInTransaction, lockAdminSessionInTransaction, requireSecurityElevationInTransaction } from "./elevation-authorization";

export const ELEVATION_PROTOCOL_VERSION = 1;
export type ElevationDuration = { kind: "TIMED"; minutes: 15 | 60 | 240 | 1440 } | { kind: "MANUAL"; confirmed: boolean };

const ADMIN_MIN_PASSWORD_LENGTH = 16;
const RECOVERY_CODE_COUNT = 10;
const ELEVATION_CEREMONY_TTL_MS = 10 * 60 * 1000;
const MANUAL_EXPIRY = new Date("9999-12-31T23:59:59.000Z");
const ADMIN_CREDENTIAL_SETUP_SCOPE = "ADMIN_CREDENTIAL_SETUP";
// This ceremony is deliberately NOT an ElevationScope: a recovery OTP must
// never be exchangeable for an active action-scoped ADMIN elevation.
const ADMIN_CREDENTIAL_EMAIL_RECOVERY_SCOPE = "ADMIN_CREDENTIAL_EMAIL_RECOVERY";

export class AdministrativePasswordReuseError extends AdministrationMutationError {
  constructor() {
    super();
    this.name = "AdministrativePasswordReuseError";
  }
}

export async function startAdministrativeCredentialSetup(input: {
  actor: { id: string; role: string };
  sessionId: string;
  normalPassword: string;
  locale: EmailLocale;
  now?: Date;
}): Promise<string> {
  const now = input.now ?? new Date();
  const admin = await requireAdminSession(input.actor, input.sessionId, now);
  await consumeAdminCredentialSetupStartAttempt(input.actor.id, now);
  if (!admin.passwordHash || !await verifyPassword(admin.passwordHash, input.normalPassword) || !admin.emailVerifiedAt) throw new AdministrationMutationError();
  const existing = await prisma.administrativeCredential.findUnique({ where: { userId: input.actor.id }, select: { status: true } });
  if (existing?.status === "ACTIVE") throw new AdministrationMutationError();
  return createEmailElevationCeremony({ userId: input.actor.id, sessionId: input.sessionId, scope: ADMIN_CREDENTIAL_SETUP_SCOPE, kind: "ADMIN_EMAIL_VERIFICATION", recipientEmail: admin.email, displayName: admin.displayName, locale: input.locale, now });
}

export async function completeAdministrativeCredentialSetup(input: {
  actor: { id: string; role: string };
  sessionId: string;
  requestKey: string;
  code: string;
  newPassword: string;
  now?: Date;
}): Promise<string[]> {
  const now = input.now ?? new Date();
  const admin = await requireAdminSession(input.actor, input.sessionId, now);
  assertAdminPassword(input.newPassword);
  await consumeAdministrativeProofAttempts(input.actor.id, input.requestKey, now);
  await assertNotNormalPassword(admin.passwordHash, input.newPassword);
  const passwordHash = await hashPassword(input.newPassword);
  const recoveryCodes = await prisma.$transaction(async (transaction) => {
    // Lock the session together with the ADMIN row. A revoked/expired session
    // after the preliminary password check must not activate a credential.
    await lockAdminSessionInTransaction(transaction, input.actor.id, input.sessionId, now);
    const lockedAdmin = await transaction.$queryRaw<Array<{ id: string; passwordHash: string | null }>>`
      SELECT "id", "passwordHash"
      FROM "User"
      WHERE "id" = ${input.actor.id}
        AND "role" = 'ADMIN'::"UserRole"
        AND "isActive" = TRUE
        AND "accountStatus" = 'ACTIVE'::"AccountStatus"
      FOR UPDATE
    `;
    if (lockedAdmin.length !== 1) throw new AdministrationMutationError();
    await assertNotNormalPassword(lockedAdmin[0]!.passwordHash, input.newPassword);
    const credential = await lockAdministrativeCredentialInTransaction(transaction, input.actor.id);
    if (credential?.status === "ACTIVE") throw new AdministrationMutationError();

    const ceremony = await getPendingCeremony(transaction, input.requestKey, input.actor.id, input.sessionId, ADMIN_CREDENTIAL_SETUP_SCOPE, now);
    // A pending challenge can be locked by a concurrent writer. Under
    // Serializable, an unchanged locked row does not force a retry when its
    // OTP deadline passes, so validate fresh time only AFTER acquiring it.
    const locked = await transaction.$queryRaw<Array<{ id: string }>>`
      SELECT "id" FROM "SecurityElevation" WHERE "id" = ${ceremony.id} FOR UPDATE
    `;
    if (locked.length !== 1) throw new AdministrationMutationError();
    const checkedAt = new Date(Math.max(now.getTime(), Date.now()));
    await assertAdminSessionCurrentInTransaction(transaction, input.actor.id, input.sessionId, checkedAt);
    const currentCeremony = await getPendingCeremony(transaction, input.requestKey, input.actor.id, input.sessionId, ADMIN_CREDENTIAL_SETUP_SCOPE, checkedAt);
    if (currentCeremony.id !== ceremony.id || !verifySecurityCode(input.code, currentCeremony.challengeHash)) throw new AdministrationMutationError();
    const consumed = await transaction.securityElevation.updateMany({ where: { id: ceremony.id, status: "PENDING" }, data: { status: "CONSUMED", consumedAt: checkedAt } });
    if (consumed.count !== 1) throw new AdministrationMutationError();
    await transaction.securityElevation.updateMany({
      where: { userId: input.actor.id, scope: ADMIN_CREDENTIAL_SETUP_SCOPE, status: "PENDING", id: { not: ceremony.id } },
      data: { status: "REVOKED", revokedAt: now }
    });

    const recoveryCodes = Array.from({ length: RECOVERY_CODE_COUNT }, generateRecoveryCode);
    if (credential) {
      const activated = await transaction.administrativeCredential.updateMany({
        where: { userId: input.actor.id, status: { in: ["NOT_CONFIGURED", "REVOKED"] } },
        data: { passwordHash, status: "ACTIVE", keyVersion: { increment: 1 }, revokedAt: null }
      });
      if (activated.count !== 1) throw new AdministrationMutationError();
    } else {
      await transaction.administrativeCredential.create({ data: { userId: input.actor.id, passwordHash, status: "ACTIVE" } });
    }
    await transaction.administrativeRecoveryCode.deleteMany({ where: { userId: input.actor.id } });
    await transaction.administrativeRecoveryCode.createMany({ data: recoveryCodes.map((value) => ({ userId: input.actor.id, codeHash: hashRecoveryCode(value) })) });
    // Cleanup of existing recovery codes can itself wait on their row locks.
    // Keep the initial OTP and Session valid through the final credential
    // mutation; any failure here rolls back the whole setup transaction.
    const finalCheckedAt = new Date(Math.max(checkedAt.getTime(), Date.now()));
    await assertAdminSessionCurrentInTransaction(transaction, input.actor.id, input.sessionId, finalCheckedAt);
    if (!isElevationCeremonyOpen(currentCeremony, finalCheckedAt)) throw new AdministrationMutationError();
    await writeAuditLogInTransaction(transaction, { eventType: "ADMIN_CREDENTIAL_SETUP", result: "SUCCESS", actorUserId: input.actor.id, actorRole: "ADMIN", sessionRef: hashAuditSessionReference(input.sessionId), resource: "identity.admin", message: "Administrative credential configured." });
    return recoveryCodes;
  }, { isolationLevel: "Serializable" });
  return recoveryCodes;
}

export async function startSecurityElevation(input: {
  actor: { id: string; role: string };
  sessionId: string;
  normalPassword: string;
  administrativePassword: string;
  scope: ElevationScope;
  duration: ElevationDuration;
  locale: EmailLocale;
  now?: Date;
}): Promise<{ requestKey: string; manualUntilRevoked: boolean; expiresAt: Date }> {
  const now = input.now ?? new Date();
  const admin = await requireAdminSession(input.actor, input.sessionId, now);
  await consumeAdminElevationStartAttempt(input.actor.id, now);
  assertScope(input.scope);
  const duration = resolveElevationDuration(input.duration, now);
  if (!admin.emailVerifiedAt) throw new AdministrationMutationError();
  const credential = await prisma.administrativeCredential.findUnique({ where: { userId: input.actor.id }, select: { passwordHash: true, status: true, keyVersion: true, revokedAt: true } });
  if (!admin.passwordHash || !await verifyPassword(admin.passwordHash, input.normalPassword) || credential?.status !== "ACTIVE" || credential.revokedAt || !Number.isSafeInteger(credential.keyVersion) || credential.keyVersion < 1 || !await verifyPassword(credential.passwordHash, input.administrativePassword)) throw new AdministrationMutationError();
  // Legacy admins may still share one password; only the credential change flow may run so they can fix it.
  if (passwordsMatch(input.normalPassword, input.administrativePassword) && input.scope !== "ADMIN_CREDENTIAL_CHANGE") throw new AdministrativePasswordReuseError();
  const requestKey = await createEmailElevationCeremony({ userId: input.actor.id, sessionId: input.sessionId, scope: input.scope, kind: "ADMIN_EMAIL_VERIFICATION", recipientEmail: admin.email, displayName: admin.displayName, locale: input.locale, now, expiresAt: duration.expiresAt, manualUntilRevoked: duration.manualUntilRevoked, credentialKeyVersion: credential.keyVersion, audit: { eventType: "ADMIN_ELEVATION_STARTED", result: "INFO", actorUserId: input.actor.id, actorRole: "ADMIN", sessionRef: hashAuditSessionReference(input.sessionId), resource: "identity.elevation", message: "Administrative elevation started.", metadata: { scope: input.scope } } });
  return { requestKey, manualUntilRevoked: duration.manualUntilRevoked, expiresAt: duration.expiresAt };
}

export async function verifySecurityElevation(input: { actor: { id: string; role: string }; sessionId: string; requestKey: string; code: string; now?: Date }): Promise<void> {
  const now = input.now ?? new Date();
  await requireAdminSession(input.actor, input.sessionId, now);
  await consumeAdministrativeProofAttempts(input.actor.id, input.requestKey, now);
  await prisma.$transaction(async (transaction) => {
    await lockAdminSessionInTransaction(transaction, input.actor.id, input.sessionId, now);
    const ceremony = await getPendingCeremony(transaction, input.requestKey, input.actor.id, input.sessionId, undefined, now);
    if (!isAllowedScope(ceremony.scope)) throw new AdministrationMutationError();
    if (typeof ceremony.credentialKeyVersion !== "number" || !Number.isSafeInteger(ceremony.credentialKeyVersion) || ceremony.credentialKeyVersion < 1) throw new AdministrationMutationError();
    await lockActiveAdministrativeCredentialVersion(transaction, input.actor.id, ceremony.credentialKeyVersion);
    // The challenge must be locked before observing its deadline: a wait on
    // User, Session, credential, or the challenge itself must not extend an OTP.
    const locked = await transaction.$queryRaw<Array<{ id: string }>>`
      SELECT "id" FROM "SecurityElevation" WHERE "id" = ${ceremony.id} FOR UPDATE
    `;
    if (locked.length !== 1) throw new AdministrationMutationError();
    const checkedAt = new Date(Math.max(now.getTime(), Date.now()));
    // The session was checked before the credential/challenge locks. A later
    // wait may cross session expiry, so revalidate without changing lock order.
    await assertAdminSessionCurrentInTransaction(transaction, input.actor.id, input.sessionId, checkedAt);
    const currentCeremony = await getPendingCeremony(transaction, input.requestKey, input.actor.id, input.sessionId, undefined, checkedAt);
    if (currentCeremony.id !== ceremony.id || currentCeremony.scope !== ceremony.scope ||
        currentCeremony.credentialKeyVersion !== ceremony.credentialKeyVersion) throw new AdministrationMutationError();
    if (!verifySecurityCode(input.code, currentCeremony.challengeHash)) throw new AdministrationMutationError();
    // Timed elevations last their full duration from activation, not from the moment the code was emailed.
    const activeExpiresAt = currentCeremony.manualUntilRevoked ? MANUAL_EXPIRY : new Date(checkedAt.getTime() + (currentCeremony.expiresAt.getTime() - currentCeremony.createdAt.getTime()));
    const updated = await transaction.securityElevation.updateMany({
      where: { id: ceremony.id, status: "PENDING", expiresAt: { gt: checkedAt }, createdAt: { gt: getElevationCeremonyOpenedAfter(checkedAt), lte: checkedAt } },
      data: { status: "ACTIVE", activatedAt: checkedAt, expiresAt: activeExpiresAt }
    });
    if (updated.count !== 1) throw new AdministrationMutationError();
    await writeAuditLogInTransaction(transaction, { eventType: "ADMIN_ELEVATION_ACTIVATED", result: "SUCCESS", actorUserId: input.actor.id, actorRole: "ADMIN", sessionRef: hashAuditSessionReference(input.sessionId), resource: "identity.elevation", message: "Administrative elevation activated.", metadata: { requestRef: hashAuditIdentifier(input.requestKey) } });
  });
}

export async function listActiveSecurityElevations(actor: { id: string; role: string }, sessionId: string, now = new Date()) {
  await requireAdminSession(actor, sessionId, now);
  await expireSecurityElevations(now);
  return prisma.$queryRaw<Array<{ requestKey: string; scope: string; manualUntilRevoked: boolean; expiresAt: Date; activatedAt: Date | null }>>`
    SELECT e."requestKey", e."scope", e."manualUntilRevoked", e."expiresAt", e."activatedAt"
    FROM "SecurityElevation" e
    JOIN "User" u ON u."id" = e."userId"
    JOIN "AdministrativeCredential" c ON c."userId" = e."userId"
    JOIN "Session" s ON s."id" = e."sessionId" AND s."userId" = e."userId"
    WHERE e."userId" = ${actor.id} AND e."sessionId" = ${sessionId}
      AND e."status" = 'ACTIVE'::"SecurityElevationStatus" AND e."revokedAt" IS NULL
      AND e."credentialKeyVersion" = c."keyVersion" AND c."keyVersion" > 0
      AND c."status" = 'ACTIVE'::"AdministrativeCredentialStatus" AND c."revokedAt" IS NULL
      AND u."role" = 'ADMIN'::"UserRole" AND u."isActive" = TRUE AND u."accountStatus" = 'ACTIVE'::"AccountStatus"
      AND s."revokedAt" IS NULL AND s."expiresAt" > (${now} AT TIME ZONE 'UTC')
      AND (e."manualUntilRevoked" = TRUE OR e."expiresAt" > (${now} AT TIME ZONE 'UTC'))
    ORDER BY e."createdAt" DESC LIMIT 20
  `;
}

export async function getAdministrativeCredentialState(userId: string) {
  return prisma.administrativeCredential.findUnique({ where: { userId }, select: { status: true, keyVersion: true, updatedAt: true } });
}

export async function hasActiveSecurityElevation(userId: string, sessionId: string, scope: string, now = new Date()): Promise<boolean> {
  if (!isDatabaseId(userId) || !isDatabaseId(sessionId) || !isAllowedScope(scope)) return false;
  await expireSecurityElevations(now);
  const rows = await prisma.$queryRaw<Array<{ id: string }>>`
    SELECT e."id" FROM "SecurityElevation" e
    JOIN "User" u ON u."id" = e."userId"
    JOIN "Session" s ON s."id" = e."sessionId" AND s."userId" = u."id"
    JOIN "AdministrativeCredential" c ON c."userId" = u."id"
    WHERE e."userId" = ${userId} AND e."sessionId" = ${sessionId} AND e."scope" = ${scope}
      AND e."status" = 'ACTIVE'::"SecurityElevationStatus"
      AND e."revokedAt" IS NULL
      AND e."credentialKeyVersion" = c."keyVersion"
      AND c."keyVersion" > 0
      AND c."status" = 'ACTIVE'::"AdministrativeCredentialStatus" AND c."revokedAt" IS NULL
      AND u."role" = 'ADMIN'::"UserRole" AND u."isActive" = TRUE AND u."accountStatus" = 'ACTIVE'::"AccountStatus"
      AND s."revokedAt" IS NULL AND s."expiresAt" > (${now} AT TIME ZONE 'UTC')
      AND (e."manualUntilRevoked" = TRUE OR e."expiresAt" > (${now} AT TIME ZONE 'UTC'))
    LIMIT 1
  `;
  return rows.length === 1;
}

export async function requireSecurityElevation(userId: string, sessionId: string, scope: ElevationScope, now = new Date()): Promise<void> {
  if (!await hasActiveSecurityElevation(userId, sessionId, scope, now)) throw new AdministrationMutationError();
}

export async function revokeSecurityElevation(actor: { id: string; role: string }, sessionId: string, requestKey?: string, now = new Date()): Promise<void> {
  await requireAdminSession(actor, sessionId, now);
  if (requestKey && !isRequestKey(requestKey)) throw new AdministrationMutationError();
  await prisma.$transaction(async (transaction) => {
    await lockAdminSessionInTransaction(transaction, actor.id, sessionId, now);
    await transaction.securityElevation.updateMany({ where: { userId: actor.id, sessionId, status: { in: ["PENDING", "ACTIVE"] }, ...(requestKey ? { requestKey } : {}) }, data: { status: "REVOKED", revokedAt: now } });
    await writeAuditLogInTransaction(transaction, { eventType: "ADMIN_ELEVATION_REVOKED", result: "SUCCESS", actorUserId: actor.id, actorRole: "ADMIN", sessionRef: hashAuditSessionReference(sessionId), resource: "identity.elevation", message: "Administrative elevation revoked.", metadata: { requestRef: requestKey ? hashAuditIdentifier(requestKey) : null } });
  });
}

export async function expireSecurityElevations(now = new Date()): Promise<number> {
  const result = await prisma.securityElevation.updateMany({ where: { status: "ACTIVE", manualUntilRevoked: false, expiresAt: { lte: now } }, data: { status: "EXPIRED" } });
  return result.count;
}

export async function changeAdministrativePassword(actor: { id: string; role: string }, sessionId: string, newPassword: string, now = new Date()): Promise<void> {
  const admin = await requireAdminSession(actor, sessionId, now);
  await requireSecurityElevation(actor.id, sessionId, "ADMIN_CREDENTIAL_CHANGE", now);
  assertAdminPassword(newPassword);
  // Budget the comparison so this path is not an unthrottled oracle for the normal password.
  const attempt = await prisma.$transaction((transaction) => consumeRateLimitAttemptInTransaction(transaction, `admin-credential-change:${actor.id}`, now));
  if (!attempt.allowed) throw new AdministrationMutationError();
  await assertNotNormalPassword(admin.passwordHash, newPassword);
  const passwordHash = await hashPassword(newPassword);
  await prisma.$transaction(async (transaction) => {
    await requireSecurityElevationInTransaction(transaction, actor.id, sessionId, "ADMIN_CREDENTIAL_CHANGE", now);
    const currentAdmin = await transaction.user.findUnique({ where: { id: actor.id }, select: { passwordHash: true } });
    await assertNotNormalPassword(currentAdmin?.passwordHash ?? null, newPassword);
    const changed = await transaction.administrativeCredential.updateMany({ where: { userId: actor.id, status: "ACTIVE", revokedAt: null }, data: { passwordHash, keyVersion: { increment: 1 } } });
    if (changed.count !== 1) throw new AdministrationMutationError();
    await transaction.securityElevation.updateMany({ where: { userId: actor.id, status: { in: ["PENDING", "ACTIVE"] } }, data: { status: "REVOKED", revokedAt: now } });
    await writeAuditLogInTransaction(transaction, { eventType: "ADMIN_CREDENTIAL_CHANGED", result: "SUCCESS", actorUserId: actor.id, actorRole: "ADMIN", sessionRef: hashAuditSessionReference(sessionId), resource: "identity.admin", message: "Administrative credential changed." });
  });
}

export async function regenerateAdministrativeRecoveryCodes(actor: { id: string; role: string }, sessionId: string, now = new Date()): Promise<string[]> {
  await requireAdminSession(actor, sessionId, now);
  await requireSecurityElevation(actor.id, sessionId, "ADMIN_RECOVERY_REGENERATE", now);
  const recoveryCodes = Array.from({ length: RECOVERY_CODE_COUNT }, generateRecoveryCode);
  await prisma.$transaction(async (transaction) => {
    await requireSecurityElevationInTransaction(transaction, actor.id, sessionId, "ADMIN_RECOVERY_REGENERATE", now);
    await transaction.administrativeRecoveryCode.deleteMany({ where: { userId: actor.id } });
    await transaction.administrativeRecoveryCode.createMany({ data: recoveryCodes.map((value) => ({ userId: actor.id, codeHash: hashRecoveryCode(value) })) });
    await writeAuditLogInTransaction(transaction, { eventType: "RECOVERY_CODES_REGENERATED", result: "SUCCESS", actorUserId: actor.id, actorRole: "ADMIN", sessionRef: hashAuditSessionReference(sessionId), resource: "identity.admin", message: "Administrative recovery codes regenerated." });
  });
  return recoveryCodes;
}

export async function recoverAdministrativeCredential(input: { actor: { id: string; role: string }; sessionId: string; normalPassword: string; recoveryCode: string; newPassword: string; now?: Date }): Promise<string[]> {
  const now = input.now ?? new Date();
  const admin = await requireAdminSession(input.actor, input.sessionId, now);
  assertAdminPassword(input.newPassword);
  const attempts = await prisma.$transaction(async (transaction) => {
    const accountAttempt = await consumeRateLimitAttemptInTransaction(transaction, `admin-recovery-user:${input.actor.id}`, now);
    const codeAttempt = await consumeRateLimitAttemptInTransaction(transaction, `admin-recovery-code:${input.actor.id}`, now);
    return { accountAllowed: accountAttempt.allowed, codeAllowed: codeAttempt.allowed };
  });
  if (!attempts.accountAllowed || !attempts.codeAllowed) throw new AdministrationMutationError();
  if (!admin.emailVerifiedAt || !admin.passwordHash || !await verifyPassword(admin.passwordHash, input.normalPassword)) throw new AdministrationMutationError();
  await assertNotNormalPassword(admin.passwordHash, input.newPassword);
  const passwordHash = await hashPassword(input.newPassword);
  const recoveryCodes = await prisma.$transaction(async (transaction) => {
    await lockAdminSessionInTransaction(transaction, input.actor.id, input.sessionId, now);
    await lockAdministrativeCredentialInTransaction(transaction, input.actor.id);
    const currentAdmin = await transaction.user.findUnique({ where: { id: input.actor.id }, select: { emailVerifiedAt: true, passwordHash: true } });
    if (!currentAdmin?.emailVerifiedAt || currentAdmin.passwordHash !== admin.passwordHash) throw new AdministrationMutationError();
    await assertNotNormalPassword(currentAdmin.passwordHash, input.newPassword);
    const code = await transaction.administrativeRecoveryCode.findFirst({ where: { userId: input.actor.id, codeHash: hashRecoveryCode(input.recoveryCode), usedAt: null }, select: { id: true } });
    if (!code) throw new AdministrationMutationError();
    const used = await transaction.administrativeRecoveryCode.updateMany({ where: { id: code.id, usedAt: null }, data: { usedAt: now } });
    if (used.count !== 1) throw new AdministrationMutationError();
    const recoveryCodes = Array.from({ length: RECOVERY_CODE_COUNT }, generateRecoveryCode);
    await transaction.administrativeCredential.upsert({ where: { userId: input.actor.id }, update: { passwordHash, status: "ACTIVE", keyVersion: { increment: 1 }, revokedAt: null }, create: { userId: input.actor.id, passwordHash, status: "ACTIVE" } });
    await transaction.administrativeRecoveryCode.deleteMany({ where: { userId: input.actor.id } });
    await transaction.administrativeRecoveryCode.createMany({ data: recoveryCodes.map((value) => ({ userId: input.actor.id, codeHash: hashRecoveryCode(value) })) });
    await transaction.securityElevation.updateMany({ where: { userId: input.actor.id, status: { in: ["PENDING", "ACTIVE"] } }, data: { status: "REVOKED", revokedAt: now } });
    // Every way of recovering the privileged credential must invalidate the
    // old ADMIN passkeys, not only TOTP recovery. They remain eligible proofs
    // in the separate normal-account recovery flow until revoked.
    await transaction.passkeyCredential.updateMany({ where: { userId: input.actor.id, revokedAt: null }, data: { revokedAt: now } });
    await transaction.passkeyChallenge.deleteMany({ where: { userId: input.actor.id, consumedAt: null } });
    // Updating a recovery code (or deleting sibling codes) can wait after the
    // initial User/Session locks. Recheck the live session before success;
    // rejection rolls back the code use, credential change, and recovery data.
    await assertAdminSessionCurrentInTransaction(transaction, input.actor.id, input.sessionId, new Date(Math.max(now.getTime(), Date.now())));
    await writeAuditLogInTransaction(transaction, { eventType: "ADMIN_CREDENTIAL_RECOVERED", result: "SUCCESS", actorUserId: input.actor.id, actorRole: "ADMIN", sessionRef: hashAuditSessionReference(input.sessionId), resource: "identity.admin", message: "Administrative credential recovered." });
    return recoveryCodes;
  });
  return recoveryCodes;
}

/** Recover the separate ADMIN credential with a fresh login password and an ACTIVE, one-use TOTP step. */
export async function recoverAdministrativeCredentialWithTotp(input: {
  actor: { id: string; role: string };
  sessionId: string;
  normalPassword: string;
  totpCode: string;
  newPassword: string;
  now?: Date;
}): Promise<string[]> {
  const now = input.now ?? new Date();
  const admin = await requireAdminSession(input.actor, input.sessionId, now);
  assertAdminPassword(input.newPassword);
  if (!isDatabaseId(input.actor.id) || !isDatabaseId(input.sessionId)) throw new AdministrationMutationError();
  // Consume attempts before password hashing or TOTP validation. A per-session
  // budget supplements the account-wide budget across multiple browser sessions.
  const attempts = await prisma.$transaction(async (transaction) => {
    const user = await consumeRateLimitAttemptInTransaction(transaction, `admin-totp-recovery-user:${input.actor.id}`, now);
    const session = await consumeRateLimitAttemptInTransaction(transaction, `admin-totp-recovery-session:${input.sessionId}`, now);
    return user.allowed && session.allowed;
  });
  if (!attempts || !/^\d{6}$/.test(input.totpCode) || !admin.passwordHash ||
      !await verifyPassword(admin.passwordHash, input.normalPassword)) throw new AdministrationMutationError();
  await assertNotNormalPassword(admin.passwordHash, input.newPassword);
  const passwordHash = await hashPassword(input.newPassword);

  return prisma.$transaction(async (transaction) => {
    // Every supported factor enrollment, reset and ADMIN credential mutation
    // uses the User lock first; also lock the current Session and credential.
    await lockAdminSessionInTransaction(transaction, input.actor.id, input.sessionId, now);
    const credential = await lockAdministrativeCredentialInTransaction(transaction, input.actor.id);
    if (credential?.status !== "ACTIVE" || credential.revokedAt ||
        !Number.isSafeInteger(credential.keyVersion) || credential.keyVersion < 1) throw new AdministrationMutationError();
    const currentAdmin = await transaction.user.findUnique({
      where: { id: input.actor.id },
      select: { passwordHash: true, secondFactorMethod: true }
    });
    // A password changed while Argon2 was running cannot authorize recovery.
    if (!currentAdmin?.passwordHash || currentAdmin.passwordHash !== admin.passwordHash ||
        currentAdmin.secondFactorMethod !== "TOTP") throw new AdministrationMutationError();
    await assertNotNormalPassword(currentAdmin.passwordHash, input.newPassword);
    const factor = await transaction.totpFactor.findUnique({
      where: { userId: input.actor.id },
      select: { id: true, status: true, confirmedAt: true, secretCiphertext: true, keyVersion: true, lastUsedStep: true }
    });
    if (factor?.status !== "ACTIVE" || !factor.confirmedAt ||
        !Number.isSafeInteger(factor.keyVersion) || factor.keyVersion < 1) throw new AdministrationMutationError();
    // Read the actual clock after acquiring all locks. A code that expires
    // while waiting must not become valid again through a stale caller time.
    const checkedAt = new Date(Math.max(now.getTime(), Date.now()));
    await assertAdminSessionCurrentInTransaction(transaction, input.actor.id, input.sessionId, checkedAt);
    const secret = decryptTotpSecret(factor.secretCiphertext);
    const usedStep = verifyTotpCode(secret, input.totpCode, checkedAt, factor.lastUsedStep);
    if (usedStep === null) throw new AdministrationMutationError();
    const consumed = await transaction.totpFactor.updateMany({
      where: {
        id: factor.id, status: "ACTIVE", confirmedAt: factor.confirmedAt,
        keyVersion: factor.keyVersion, secretCiphertext: factor.secretCiphertext,
        lastUsedStep: factor.lastUsedStep
      },
      data: { lastUsedStep: usedStep }
    });
    if (consumed.count !== 1) throw new AdministrationMutationError();
    const rotated = await transaction.administrativeCredential.updateMany({
      where: { userId: input.actor.id, status: "ACTIVE", revokedAt: null, keyVersion: credential.keyVersion },
      data: { passwordHash, keyVersion: { increment: 1 } }
    });
    if (rotated.count !== 1) throw new AdministrationMutationError();
    const recoveryCodes = Array.from({ length: RECOVERY_CODE_COUNT }, generateRecoveryCode);
    await transaction.administrativeRecoveryCode.deleteMany({ where: { userId: input.actor.id } });
    await transaction.administrativeRecoveryCode.createMany({
      data: recoveryCodes.map((value) => ({ userId: input.actor.id, codeHash: hashRecoveryCode(value) }))
    });
    await transaction.securityElevation.updateMany({
      where: { userId: input.actor.id, status: { in: ["PENDING", "ACTIVE"] } },
      data: { status: "REVOKED", revokedAt: checkedAt }
    });
    await transaction.session.updateMany({
      where: { userId: input.actor.id, id: { not: input.sessionId }, revokedAt: null },
      data: { revokedAt: checkedAt }
    });
    await revokeUserAuthenticationProofsInTransaction(transaction, input.actor.id, checkedAt);
    // A recovered privileged credential must not leave older ADMIN passkeys
    // usable as future account-recovery proofs. Keep the active TOTP for login,
    // but require freshly elevated enrollment to restore a hub passkey.
    await transaction.passkeyCredential.updateMany({
      where: { userId: input.actor.id, revokedAt: null },
      data: { revokedAt: checkedAt }
    });
    await transaction.passkeyChallenge.deleteMany({ where: { userId: input.actor.id, consumedAt: null } });
    await revokeUserOidcArtifactsInTransaction(transaction, input.actor.id);
    await writeAuditLogInTransaction(transaction, {
      eventType: "ADMIN_CREDENTIAL_TOTP_RECOVERED", result: "SUCCESS",
      actorUserId: input.actor.id, actorRole: "ADMIN",
      sessionRef: hashAuditSessionReference(input.sessionId),
      resource: "identity.admin",
      message: "Separate administrative credential recovered with normal password and active TOTP."
    });
    const finalCheckedAt = new Date(Math.max(checkedAt.getTime(), Date.now()));
    await assertAdminSessionCurrentInTransaction(transaction, input.actor.id, input.sessionId, finalCheckedAt);
    // If an unusually slow write crosses the accepted TOTP window, roll back
    // the code consumption, credential rotation, revocations and audit together.
    if (verifyTotpCode(secret, input.totpCode, finalCheckedAt, factor.lastUsedStep) !== usedStep) throw new AdministrationMutationError();
    return recoveryCodes;
  }, { isolationLevel: "Serializable" });
}

/** Start a distinct ADMIN credential-recovery proof without requiring saved backup codes. */
export async function startAdministrativeEmailRecovery(input: {
  actor: { id: string; role: string };
  sessionId: string;
  normalPassword: string;
  locale: EmailLocale;
  now?: Date;
}): Promise<string> {
  const now = input.now ?? new Date();
  const admin = await requireAdminSession(input.actor, input.sessionId, now);
  if (!isDatabaseId(input.actor.id)) throw new AdministrationMutationError();
  const attempt = await prisma.$transaction((transaction) =>
    consumeRateLimitAttemptInTransaction(transaction, `admin-email-recovery-start:${input.actor.id}`, now)
  );
  if (!attempt.allowed || !admin.emailVerifiedAt || !admin.passwordHash ||
      !await verifyPassword(admin.passwordHash, input.normalPassword)) throw new AdministrationMutationError();
  const credential = await prisma.administrativeCredential.findUnique({
    where: { userId: input.actor.id },
    select: { status: true, revokedAt: true, keyVersion: true }
  });
  if (credential?.status !== "ACTIVE" || credential.revokedAt ||
      !Number.isSafeInteger(credential.keyVersion) || credential.keyVersion < 1) throw new AdministrationMutationError();
  return createEmailElevationCeremony({
    userId: input.actor.id,
    sessionId: input.sessionId,
    scope: ADMIN_CREDENTIAL_EMAIL_RECOVERY_SCOPE,
    kind: "ADMIN_EMAIL_VERIFICATION",
    recipientEmail: admin.email,
    challengeBinding: admin.email.toLowerCase(),
    displayName: admin.displayName,
    locale: input.locale,
    credentialKeyVersion: credential.keyVersion,
    now,
    audit: {
      eventType: "ADMIN_CREDENTIAL_EMAIL_RECOVERY_STARTED", result: "INFO",
      actorUserId: input.actor.id, actorRole: "ADMIN",
      sessionRef: hashAuditSessionReference(input.sessionId), resource: "identity.admin",
      message: "Email proof for separate administrative credential recovery started."
    }
  });
}

/** Consume a session-bound, short-lived email proof once and rotate only the ADMIN credential. */
export async function completeAdministrativeEmailRecovery(input: {
  actor: { id: string; role: string };
  sessionId: string;
  requestKey: string;
  code: string;
  normalPassword: string;
  newPassword: string;
  now?: Date;
}): Promise<string[]> {
  const now = input.now ?? new Date();
  const admin = await requireAdminSession(input.actor, input.sessionId, now);
  assertAdminPassword(input.newPassword);
  await consumeAdministrativeProofAttempts(input.actor.id, input.requestKey, now);
  if (!admin.emailVerifiedAt || !admin.passwordHash || !await verifyPassword(admin.passwordHash, input.normalPassword)) throw new AdministrationMutationError();
  await assertNotNormalPassword(admin.passwordHash, input.newPassword);
  const newHash = await hashPassword(input.newPassword);
  return prisma.$transaction(async (transaction) => {
    // All credential mutations lock User -> Session -> Credential -> Ceremony.
    await lockAdminSessionInTransaction(transaction, input.actor.id, input.sessionId, now);
    const credential = await lockAdministrativeCredentialInTransaction(transaction, input.actor.id);
    if (credential?.status !== "ACTIVE" || credential.revokedAt ||
        !Number.isSafeInteger(credential.keyVersion) || credential.keyVersion < 1) throw new AdministrationMutationError();
    const currentAdmin = await transaction.user.findUnique({
      where: { id: input.actor.id }, select: { email: true, emailVerifiedAt: true, passwordHash: true }
    });
    if (!currentAdmin?.emailVerifiedAt || !currentAdmin.passwordHash || currentAdmin.passwordHash !== admin.passwordHash) throw new AdministrationMutationError();
    await assertNotNormalPassword(currentAdmin.passwordHash, input.newPassword);
    const ceremony = await getPendingCeremony(transaction, input.requestKey, input.actor.id, input.sessionId, ADMIN_CREDENTIAL_EMAIL_RECOVERY_SCOPE, now);
    if (ceremony.credentialKeyVersion !== credential.keyVersion || ceremony.manualUntilRevoked) throw new AdministrationMutationError();
    const locked = await transaction.$queryRaw<Array<{ id: string }>>`
      SELECT "id" FROM "SecurityElevation" WHERE "id" = ${ceremony.id} FOR UPDATE
    `;
    if (locked.length !== 1) throw new AdministrationMutationError();
    const checkedAt = new Date(Math.max(now.getTime(), Date.now()));
    await assertAdminSessionCurrentInTransaction(transaction, input.actor.id, input.sessionId, checkedAt);
    const currentCeremony = await getPendingCeremony(transaction, input.requestKey, input.actor.id, input.sessionId, ADMIN_CREDENTIAL_EMAIL_RECOVERY_SCOPE, checkedAt);
    if (currentCeremony.id !== ceremony.id || currentCeremony.credentialKeyVersion !== credential.keyVersion ||
        // The hashed proof binds to the recipient; a changed email cannot use an old inbox code.
        !verifySecurityCode(`${input.code}:${currentAdmin.email.toLowerCase()}`, currentCeremony.challengeHash)) throw new AdministrationMutationError();
    const consumed = await transaction.securityElevation.updateMany({
      where: { id: ceremony.id, status: "PENDING" },
      data: { status: "CONSUMED", consumedAt: checkedAt }
    });
    if (consumed.count !== 1) throw new AdministrationMutationError();
    const rotated = await transaction.administrativeCredential.updateMany({
      where: { userId: input.actor.id, status: "ACTIVE", keyVersion: credential.keyVersion, revokedAt: null },
      data: { passwordHash: newHash, keyVersion: { increment: 1 } }
    });
    if (rotated.count !== 1) throw new AdministrationMutationError();
    const recoveryCodes = Array.from({ length: RECOVERY_CODE_COUNT }, generateRecoveryCode);
    await transaction.administrativeRecoveryCode.deleteMany({ where: { userId: input.actor.id } });
    await transaction.administrativeRecoveryCode.createMany({
      data: recoveryCodes.map((value) => ({ userId: input.actor.id, codeHash: hashRecoveryCode(value) }))
    });
    await transaction.securityElevation.updateMany({
      where: { userId: input.actor.id, status: { in: ["PENDING", "ACTIVE"] } },
      data: { status: "REVOKED", revokedAt: checkedAt }
    });
    // A stolen older browser session cannot reuse a credential recovery.
    await transaction.session.updateMany({
      where: { userId: input.actor.id, id: { not: input.sessionId }, revokedAt: null },
      data: { revokedAt: checkedAt }
    });
    await transaction.trustedDevice.updateMany({
      where: { userId: input.actor.id, status: "TRUSTED" },
      data: { status: "REVOKED", revokedAt: checkedAt }
    });
    await transaction.passkeyCredential.updateMany({ where: { userId: input.actor.id, revokedAt: null }, data: { revokedAt: checkedAt } });
    await transaction.passkeyChallenge.deleteMany({ where: { userId: input.actor.id, consumedAt: null } });
    await assertAdminSessionCurrentInTransaction(transaction, input.actor.id, input.sessionId, new Date(Math.max(checkedAt.getTime(), Date.now())));
    await writeAuditLogInTransaction(transaction, {
      eventType: "ADMIN_CREDENTIAL_EMAIL_RECOVERED", result: "SUCCESS",
      actorUserId: input.actor.id, actorRole: "ADMIN", sessionRef: hashAuditSessionReference(input.sessionId),
      resource: "identity.admin", message: "Separate administrative credential recovered with normal password and verified email proof.",
      metadata: { requestRef: hashAuditIdentifier(input.requestKey) }
    });
    await enqueueEmailMessageForClient(transaction, {
      idempotencyKey: `admin-credential-email-recovered:${input.requestKey}`,
      kind: "ADMIN_CREDENTIAL_CHANGED",
      recipientEmail: currentAdmin.email,
      locale: "pt-BR",
      payload: { publicValues: {} }
    });
    const finalCheckedAt = new Date(Math.max(checkedAt.getTime(), Date.now()));
    await assertAdminSessionCurrentInTransaction(transaction, input.actor.id, input.sessionId, finalCheckedAt);
    if (!isElevationCeremonyOpen(currentCeremony, finalCheckedAt)) throw new AdministrationMutationError();
    return recoveryCodes;
  }, { isolationLevel: "Serializable" });
}

async function createEmailElevationCeremony(input: { userId: string; sessionId: string; scope: string; kind: "ADMIN_EMAIL_VERIFICATION"; recipientEmail: string; challengeBinding?: string; displayName: string | null; locale: EmailLocale; now: Date; expiresAt?: Date; manualUntilRevoked?: boolean; credentialKeyVersion?: number; audit?: AuditLogInput }): Promise<string> {
  // Initial ADMIN credential setup precedes existence of a credential and
  // legitimately has no version. Every other elevation must bind to the
  // currently locked credential key version, never write a silent null.
  if (input.scope === ADMIN_CREDENTIAL_SETUP_SCOPE) {
    if (input.credentialKeyVersion !== undefined) throw new AdministrationMutationError();
  } else if (!Number.isSafeInteger(input.credentialKeyVersion) ||
             typeof input.credentialKeyVersion !== "number" || input.credentialKeyVersion < 1) {
    throw new AdministrationMutationError();
  }
  const sendAttempt = await prisma.$transaction((transaction) => consumeRateLimitAttemptInTransaction(transaction, `admin-email-ceremony:${input.userId}`, input.now, 10));
  if (!sendAttempt.allowed) throw new AdministrationMutationError();
  const requestKey = randomBytes(24).toString("base64url");
  const code = generateNumericCode();
  const expiresAt = input.expiresAt ?? new Date(input.now.getTime() + ELEVATION_CEREMONY_TTL_MS);
  await prisma.$transaction(async (transaction) => {
    await lockAdminSessionInTransaction(transaction, input.userId, input.sessionId, input.now);
    if (input.credentialKeyVersion !== undefined) await lockActiveAdministrativeCredentialVersion(transaction, input.userId, input.credentialKeyVersion);
    await transaction.securityElevation.updateMany({ where: { userId: input.userId, sessionId: input.sessionId, status: "PENDING" }, data: { status: "REVOKED", revokedAt: input.now } });
    await transaction.securityElevation.create({ data: { requestKey, userId: input.userId, sessionId: input.sessionId, protocolVersion: ELEVATION_PROTOCOL_VERSION, credentialKeyVersion: input.credentialKeyVersion ?? null, scope: input.scope, challengeHash: hashSecurityCode(input.challengeBinding === undefined ? code : `${code}:${input.challengeBinding}`), status: "PENDING", manualUntilRevoked: input.manualUntilRevoked ?? false, expiresAt, createdAt: input.now } });
    await enqueueEmailMessageForClient(transaction, { idempotencyKey: `admin-elevation:${requestKey}`, kind: input.kind, recipientEmail: input.recipientEmail, locale: input.locale, payload: { publicValues: { displayName: input.displayName ?? "" }, protectedValues: { code } } });
    if (input.audit) await writeAuditLogInTransaction(transaction, { ...input.audit, metadata: { ...input.audit.metadata, requestRef: hashAuditIdentifier(requestKey) } });
  });
  return requestKey;
}

async function getPendingCeremony(transaction: Prisma.TransactionClient, requestKey: string, userId: string, sessionId: string, scope: string | undefined, now: Date) {
  if (!isRequestKey(requestKey)) throw new AdministrationMutationError();
  const ceremony = await transaction.securityElevation.findUnique({ where: { requestKey }, select: { id: true, challengeHash: true, scope: true, status: true, expiresAt: true, createdAt: true, manualUntilRevoked: true, credentialKeyVersion: true, userId: true, sessionId: true } });
  if (!ceremony || ceremony.status !== "PENDING" || ceremony.userId !== userId || ceremony.sessionId !== sessionId || (scope && ceremony.scope !== scope) || !isElevationCeremonyOpen(ceremony, now)) throw new AdministrationMutationError();
  return ceremony;
}

async function lockActiveAdministrativeCredentialVersion(transaction: Prisma.TransactionClient, userId: string, expectedKeyVersion: number): Promise<void> {
  const credential = await lockAdministrativeCredentialInTransaction(transaction, userId);
  if (credential?.status !== "ACTIVE" || credential.revokedAt || credential.keyVersion !== expectedKeyVersion) throw new AdministrationMutationError();
}

// expiresAt is the lifetime of the elevation once activated (up to 24h, or forever for MANUAL);
// the emailed code itself is only accepted for ELEVATION_CEREMONY_TTL_MS after it was sent.
export function isElevationCeremonyOpen(ceremony: { createdAt: Date; expiresAt: Date }, now: Date): boolean {
  return ceremony.expiresAt > now && ceremony.createdAt > getElevationCeremonyOpenedAfter(now) && ceremony.createdAt <= now;
}

function getElevationCeremonyOpenedAfter(now: Date): Date {
  return new Date(now.getTime() - ELEVATION_CEREMONY_TTL_MS);
}

async function consumeAdministrativeProofAttempts(userId: string, requestKey: string, now: Date): Promise<void> {
  if (!isDatabaseId(userId) || !isRequestKey(requestKey)) throw new AdministrationMutationError();
  const result = await prisma.$transaction(async (transaction) => {
    const account = await consumeRateLimitAttemptInTransaction(transaction, `admin-proof-user:${userId}`, now);
    if (!account.allowed) return false;
    const ceremony = await consumeRateLimitAttemptInTransaction(transaction, `admin-proof-ceremony:${requestKey}`, now);
    return ceremony.allowed;
  });
  if (!result) throw new AdministrationMutationError();
}

async function consumeAdminCredentialSetupStartAttempt(userId: string, now: Date): Promise<void> {
  if (!isDatabaseId(userId)) throw new AdministrationMutationError();
  const result = await prisma.$transaction((transaction) => consumeRateLimitAttemptInTransaction(transaction, `admin-credential-setup-start:${userId}`, now));
  if (!result.allowed) throw new AdministrationMutationError();
}

async function consumeAdminElevationStartAttempt(userId: string, now: Date): Promise<void> {
  if (!isDatabaseId(userId)) throw new AdministrationMutationError();
  const result = await prisma.$transaction((transaction) => consumeRateLimitAttemptInTransaction(transaction, `admin-elevation-start:${userId}`, now));
  if (!result.allowed) throw new AdministrationMutationError();
}

async function requireAdminSession(actor: { id: string; role: string }, sessionId: string, now: Date) {
  if (actor.role !== "ADMIN" || !isDatabaseId(sessionId)) throw new AdministrationMutationError();
  const admin = await prisma.user.findUnique({ where: { id: actor.id }, select: { email: true, displayName: true, passwordHash: true, emailVerifiedAt: true, role: true, isActive: true, accountStatus: true } });
  const session = await prisma.session.findUnique({ where: { id: sessionId }, select: { userId: true, revokedAt: true, expiresAt: true } });
  if (!admin?.isActive || admin.accountStatus !== "ACTIVE" || admin.role !== "ADMIN" || !session || session.userId !== actor.id || session.revokedAt || session.expiresAt <= now) throw new AdministrationMutationError();
  return admin;
}

export function resolveElevationDuration(duration: ElevationDuration, now = new Date()): { manualUntilRevoked: boolean; expiresAt: Date } {
  if (duration.kind === "MANUAL") {
    if (duration.confirmed !== true) throw new AdministrationMutationError();
    return { manualUntilRevoked: true, expiresAt: MANUAL_EXPIRY };
  }
  if (![15, 60, 240, 1440].includes(duration.minutes)) throw new AdministrationMutationError();
  return { manualUntilRevoked: false, expiresAt: new Date(now.getTime() + duration.minutes * 60 * 1000) };
}

async function assertNotNormalPassword(normalPasswordHash: string | null, value: string): Promise<void> {
  if (normalPasswordHash && await verifyPassword(normalPasswordHash, value)) throw new AdministrativePasswordReuseError();
}

function passwordsMatch(left: string, right: string): boolean {
  const leftBytes = Buffer.from(left, "utf8");
  const rightBytes = Buffer.from(right, "utf8");
  return leftBytes.length === rightBytes.length && timingSafeEqual(leftBytes, rightBytes);
}

function assertAdminPassword(value: string): void {
  let hasControlCharacter = false;
  for (const character of value) {
    const code = character.charCodeAt(0);
    if (code <= 0x1f || (code >= 0x7f && code <= 0x9f)) hasControlCharacter = true;
  }
  if (value.length < ADMIN_MIN_PASSWORD_LENGTH || value.length > 256 || hasControlCharacter) throw new AdministrationMutationError();
}
function assertScope(value: string): asserts value is ElevationScope { if (!isAllowedScope(value)) throw new AdministrationMutationError(); }
function isAllowedScope(value: string): value is ElevationScope { return (ELEVATION_SCOPES as readonly string[]).includes(value); }
function isRequestKey(value: string): boolean { return /^[A-Za-z0-9_-]{32,100}$/.test(value); }
function isDatabaseId(value: string): boolean { return /^[A-Za-z0-9_-]{8,80}$/.test(value); }

export async function grantProjectAccess(actor: { id: string; role: string }, sessionId: string, userId: string, connectionId: string, now = new Date()): Promise<void> {
  if (actor.role !== "ADMIN") throw new AdministrationMutationError();
  await prisma.$transaction(async (transaction) => {
    await requireSecurityElevationInTransaction(transaction, actor.id, sessionId, "PROJECT_ACCESS_CHANGE", now);
    const users = await transaction.$queryRaw<Array<{ id: string }>>`
      SELECT "id" FROM "User" WHERE "id" = ${userId} AND "role" = 'USER'::"UserRole"
        AND "isActive" = TRUE AND "accountStatus" = 'ACTIVE'::"AccountStatus" FOR UPDATE
    `;
    const connections = await transaction.$queryRaw<Array<{ id: string }>>`
      SELECT "id" FROM "ProjectConnection" WHERE "id" = ${connectionId} AND "enabled" = TRUE FOR UPDATE
    `;
    if (users.length !== 1 || connections.length !== 1) throw new AdministrationMutationError();
    await transaction.userProjectGrant.upsert({ where: { userId_connectionId: { userId, connectionId } }, create: { userId, connectionId, grantedByUserId: actor.id }, update: { revokedAt: null, grantedByUserId: actor.id } });
    await writeAuditLogInTransaction(transaction, { eventType: "PROJECT_ACCESS_GRANTED", result: "SUCCESS", actorUserId: actor.id, actorRole: "ADMIN", sessionRef: hashAuditSessionReference(sessionId), resource: "project.access", message: "Project access granted.", metadata: { userRef: hashOidcIdentifier(userId), connectionRef: hashOidcIdentifier(connectionId) } });
  }, { isolationLevel: "Serializable" });
}

export async function revokeProjectAccess(actor: { id: string; role: string }, sessionId: string, grantId: string, now = new Date()): Promise<void> {
  if (actor.role !== "ADMIN") throw new AdministrationMutationError();
  // A waiting duplicate must observe the first revocation and exit without a second audit.
  await prisma.$transaction(async (transaction) => {
    await requireSecurityElevationInTransaction(transaction, actor.id, sessionId, "PROJECT_ACCESS_CHANGE", now);
    const grant = await transaction.userProjectGrant.findUnique({ where: { id: grantId }, select: { userId: true, connectionId: true, connection: { select: { clientId: true } } } });
    if (!grant) throw new AdministrationMutationError();
    const changed = await transaction.userProjectGrant.updateMany({ where: { id: grantId, revokedAt: null }, data: { revokedAt: now } });
    if (changed.count === 0) return;
    await transaction.oidcArtifact.deleteMany({ where: { clientIdHash: hashOidcIdentifier(grant.connection.clientId), accountIdHash: hashOidcIdentifier(grant.userId) } });
    await writeAuditLogInTransaction(transaction, { eventType: "PROJECT_ACCESS_REVOKED", result: "SUCCESS", actorUserId: actor.id, actorRole: "ADMIN", sessionRef: hashAuditSessionReference(sessionId), resource: "project.access", message: "Project access revoked and OIDC artifacts cleared.", metadata: { userRef: hashOidcIdentifier(grant.userId), connectionRef: hashOidcIdentifier(grant.connectionId) } });
  }, { isolationLevel: "ReadCommitted" });
}
