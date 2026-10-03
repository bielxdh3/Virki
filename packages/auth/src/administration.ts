import { randomBytes } from "node:crypto";
import { enqueueEmailMessageForClient, type EmailLocale } from "./email";
import { generateRecoveryCode, generateNumericCode, hashRecoveryCode, hashSecurityCode, verifySecurityCode } from "./security";
import { consumeRateLimitAttemptInTransaction, hashAuditIdentifier, hashPassword, verifyPassword, writeAuditLogInTransaction, type AuditLogInput } from "./index";
import { prisma, type Prisma } from "@bielos/database";
import { ELEVATION_SCOPES, type ElevationScope } from "./elevation-scopes";

export { ELEVATION_SCOPES, ELEVATION_SCOPE_ACTIONS, UI_ELEVATION_SCOPES } from "./elevation-scopes";
export type { ElevationScope } from "./elevation-scopes";

export const ELEVATION_PROTOCOL_VERSION = 1;
export type ElevationDuration = { kind: "TIMED"; minutes: 15 | 60 | 240 | 1440 } | { kind: "MANUAL"; confirmed: boolean };

const ADMIN_MIN_PASSWORD_LENGTH = 16;
const RECOVERY_CODE_COUNT = 10;
const ELEVATION_CEREMONY_TTL_MS = 10 * 60 * 1000;
const MANUAL_EXPIRY = new Date("9999-12-31T23:59:59.000Z");
const ADMIN_CREDENTIAL_SETUP_SCOPE = "ADMIN_CREDENTIAL_SETUP";

export class AdministrationMutationError extends Error {
  constructor() {
    super("Administrative security mutation rejected.");
    this.name = "AdministrationMutationError";
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
  await requireAdminSession(input.actor, input.sessionId, now);
  assertAdminPassword(input.newPassword);
  await consumeAdministrativeProofAttempts(input.actor.id, input.requestKey, now);
  const passwordHash = await hashPassword(input.newPassword);
  const recoveryCodes = await prisma.$transaction(async (transaction) => {
    const ceremony = await getPendingCeremony(transaction, input.requestKey, input.actor.id, input.sessionId, ADMIN_CREDENTIAL_SETUP_SCOPE, now);
    if (!verifySecurityCode(input.code, ceremony.challengeHash)) throw new AdministrationMutationError();
    const consumed = await transaction.securityElevation.updateMany({ where: { id: ceremony.id, status: "PENDING" }, data: { status: "CONSUMED", consumedAt: now } });
    if (consumed.count !== 1) throw new AdministrationMutationError();
    const recoveryCodes = Array.from({ length: RECOVERY_CODE_COUNT }, generateRecoveryCode);
    await transaction.administrativeCredential.upsert({ where: { userId: input.actor.id }, update: { passwordHash, status: "ACTIVE", keyVersion: { increment: 1 }, revokedAt: null }, create: { userId: input.actor.id, passwordHash, status: "ACTIVE" } });
    await transaction.administrativeRecoveryCode.deleteMany({ where: { userId: input.actor.id } });
    await transaction.administrativeRecoveryCode.createMany({ data: recoveryCodes.map((value) => ({ userId: input.actor.id, codeHash: hashRecoveryCode(value) })) });
    await writeAuditLogInTransaction(transaction, { eventType: "ADMIN_CREDENTIAL_SETUP", result: "SUCCESS", actorUserId: input.actor.id, resource: "identity.admin", message: "Administrative credential configured." });
    return recoveryCodes;
  });
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
  const credential = await prisma.administrativeCredential.findUnique({ where: { userId: input.actor.id }, select: { passwordHash: true, status: true } });
  if (!admin.passwordHash || !await verifyPassword(admin.passwordHash, input.normalPassword) || credential?.status !== "ACTIVE" || !await verifyPassword(credential.passwordHash, input.administrativePassword)) throw new AdministrationMutationError();
  const requestKey = await createEmailElevationCeremony({ userId: input.actor.id, sessionId: input.sessionId, scope: input.scope, kind: "ADMIN_EMAIL_VERIFICATION", recipientEmail: admin.email, displayName: admin.displayName, locale: input.locale, now, expiresAt: duration.expiresAt, manualUntilRevoked: duration.manualUntilRevoked, audit: { eventType: "ADMIN_ELEVATION_STARTED", result: "INFO", actorUserId: input.actor.id, resource: "identity.elevation", message: "Administrative elevation started.", metadata: { scope: input.scope } } });
  return { requestKey, manualUntilRevoked: duration.manualUntilRevoked, expiresAt: duration.expiresAt };
}

export async function verifySecurityElevation(input: { actor: { id: string; role: string }; sessionId: string; requestKey: string; code: string; now?: Date }): Promise<void> {
  const now = input.now ?? new Date();
  await requireAdminSession(input.actor, input.sessionId, now);
  await consumeAdministrativeProofAttempts(input.actor.id, input.requestKey, now);
  await prisma.$transaction(async (transaction) => {
    const ceremony = await getPendingCeremony(transaction, input.requestKey, input.actor.id, input.sessionId, undefined, now);
    if (!isAllowedScope(ceremony.scope)) throw new AdministrationMutationError();
    if (!verifySecurityCode(input.code, ceremony.challengeHash)) throw new AdministrationMutationError();
    const updated = await transaction.securityElevation.updateMany({ where: { id: ceremony.id, status: "PENDING", expiresAt: { gt: now } }, data: { status: "ACTIVE", activatedAt: now } });
    if (updated.count !== 1) throw new AdministrationMutationError();
    await writeAuditLogInTransaction(transaction, { eventType: "ADMIN_ELEVATION_ACTIVATED", result: "SUCCESS", actorUserId: input.actor.id, resource: "identity.elevation", message: "Administrative elevation activated.", metadata: { requestRef: hashAuditIdentifier(input.requestKey) } });
  });
}

export async function listActiveSecurityElevations(actor: { id: string; role: string }, sessionId: string, now = new Date()) {
  await requireAdminSession(actor, sessionId, now);
  await expireSecurityElevations(now);
  return prisma.securityElevation.findMany({ where: { userId: actor.id, sessionId, status: "ACTIVE", OR: [{ manualUntilRevoked: true }, { expiresAt: { gt: now } }] }, orderBy: { createdAt: "desc" }, take: 20, select: { requestKey: true, scope: true, manualUntilRevoked: true, expiresAt: true, activatedAt: true } });
}

export async function getAdministrativeCredentialState(userId: string) {
  return prisma.administrativeCredential.findUnique({ where: { userId }, select: { status: true, keyVersion: true, updatedAt: true } });
}

export async function hasActiveSecurityElevation(userId: string, sessionId: string, scope: string, now = new Date()): Promise<boolean> {
  if (!isDatabaseId(userId) || !isDatabaseId(sessionId) || !isAllowedScope(scope)) return false;
  await expireSecurityElevations(now);
  const [row, session] = await Promise.all([
    prisma.securityElevation.findFirst({ where: { userId, sessionId, scope, status: "ACTIVE", user: { isActive: true }, OR: [{ manualUntilRevoked: true }, { expiresAt: { gt: now } }] }, select: { id: true } }),
    prisma.session.findUnique({ where: { id: sessionId }, select: { userId: true, revokedAt: true, expiresAt: true } })
  ]);
  return Boolean(row && session?.userId === userId && !session.revokedAt && session.expiresAt > now);
}

export async function requireSecurityElevation(userId: string, sessionId: string, scope: ElevationScope, now = new Date()): Promise<void> {
  if (!await hasActiveSecurityElevation(userId, sessionId, scope, now)) throw new AdministrationMutationError();
}

export async function revokeSecurityElevation(actor: { id: string; role: string }, sessionId: string, requestKey?: string, now = new Date()): Promise<void> {
  await requireAdminSession(actor, sessionId, now);
  if (requestKey && !isRequestKey(requestKey)) throw new AdministrationMutationError();
  await prisma.$transaction(async (transaction) => {
    await transaction.securityElevation.updateMany({ where: { userId: actor.id, sessionId, status: "ACTIVE", ...(requestKey ? { requestKey } : {}) }, data: { status: "REVOKED", revokedAt: now } });
    await writeAuditLogInTransaction(transaction, { eventType: "ADMIN_ELEVATION_REVOKED", result: "SUCCESS", actorUserId: actor.id, resource: "identity.elevation", message: "Administrative elevation revoked.", metadata: { requestRef: requestKey ? hashAuditIdentifier(requestKey) : null } });
  });
}

export async function expireSecurityElevations(now = new Date()): Promise<number> {
  const result = await prisma.securityElevation.updateMany({ where: { status: "ACTIVE", manualUntilRevoked: false, expiresAt: { lte: now } }, data: { status: "EXPIRED" } });
  return result.count;
}

export async function changeAdministrativePassword(actor: { id: string; role: string }, sessionId: string, newPassword: string, now = new Date()): Promise<void> {
  await requireSecurityElevation(actor.id, sessionId, "ADMIN_CREDENTIAL_CHANGE", now);
  assertAdminPassword(newPassword);
  const passwordHash = await hashPassword(newPassword);
  await prisma.$transaction(async (transaction) => {
    await transaction.administrativeCredential.update({ where: { userId: actor.id }, data: { passwordHash, status: "ACTIVE", keyVersion: { increment: 1 }, revokedAt: null } });
    await transaction.securityElevation.updateMany({ where: { userId: actor.id, status: { in: ["PENDING", "ACTIVE"] } }, data: { status: "REVOKED", revokedAt: now } });
    await writeAuditLogInTransaction(transaction, { eventType: "ADMIN_CREDENTIAL_CHANGED", result: "SUCCESS", actorUserId: actor.id, resource: "identity.admin", message: "Administrative credential changed." });
  });
}

export async function regenerateAdministrativeRecoveryCodes(actor: { id: string; role: string }, sessionId: string, now = new Date()): Promise<string[]> {
  await requireSecurityElevation(actor.id, sessionId, "ADMIN_RECOVERY_REGENERATE", now);
  const recoveryCodes = Array.from({ length: RECOVERY_CODE_COUNT }, generateRecoveryCode);
  await prisma.$transaction(async (transaction) => {
    await transaction.administrativeRecoveryCode.deleteMany({ where: { userId: actor.id } });
    await transaction.administrativeRecoveryCode.createMany({ data: recoveryCodes.map((value) => ({ userId: actor.id, codeHash: hashRecoveryCode(value) })) });
    await writeAuditLogInTransaction(transaction, { eventType: "RECOVERY_CODES_REGENERATED", result: "SUCCESS", actorUserId: actor.id, resource: "identity.admin", message: "Administrative recovery codes regenerated." });
  });
  return recoveryCodes;
}

export async function recoverAdministrativeCredential(input: { actor: { id: string; role: string }; normalPassword: string; recoveryCode: string; newPassword: string; now?: Date }): Promise<string[]> {
  const now = input.now ?? new Date();
  if (input.actor.role !== "ADMIN") throw new AdministrationMutationError();
  assertAdminPassword(input.newPassword);
  const attempts = await prisma.$transaction(async (transaction) => {
    const accountAttempt = await consumeRateLimitAttemptInTransaction(transaction, `admin-recovery-user:${input.actor.id}`, now);
    const codeAttempt = await consumeRateLimitAttemptInTransaction(transaction, `admin-recovery-code:${input.actor.id}`, now);
    return { accountAllowed: accountAttempt.allowed, codeAllowed: codeAttempt.allowed };
  });
  if (!attempts.accountAllowed || !attempts.codeAllowed) throw new AdministrationMutationError();
  const admin = await prisma.user.findUnique({ where: { id: input.actor.id }, select: { emailVerifiedAt: true, passwordHash: true, role: true, isActive: true } });
  if (!admin?.isActive || admin.role !== "ADMIN" || !admin.emailVerifiedAt || !admin.passwordHash || !await verifyPassword(admin.passwordHash, input.normalPassword)) throw new AdministrationMutationError();
  const passwordHash = await hashPassword(input.newPassword);
  const recoveryCodes = await prisma.$transaction(async (transaction) => {
    const code = await transaction.administrativeRecoveryCode.findFirst({ where: { userId: input.actor.id, codeHash: hashRecoveryCode(input.recoveryCode), usedAt: null }, select: { id: true } });
    if (!code) throw new AdministrationMutationError();
    const used = await transaction.administrativeRecoveryCode.updateMany({ where: { id: code.id, usedAt: null }, data: { usedAt: now } });
    if (used.count !== 1) throw new AdministrationMutationError();
    const recoveryCodes = Array.from({ length: RECOVERY_CODE_COUNT }, generateRecoveryCode);
    await transaction.administrativeCredential.upsert({ where: { userId: input.actor.id }, update: { passwordHash, status: "ACTIVE", keyVersion: { increment: 1 }, revokedAt: null }, create: { userId: input.actor.id, passwordHash, status: "ACTIVE" } });
    await transaction.administrativeRecoveryCode.deleteMany({ where: { userId: input.actor.id } });
    await transaction.administrativeRecoveryCode.createMany({ data: recoveryCodes.map((value) => ({ userId: input.actor.id, codeHash: hashRecoveryCode(value) })) });
    await transaction.securityElevation.updateMany({ where: { userId: input.actor.id, status: { in: ["PENDING", "ACTIVE"] } }, data: { status: "REVOKED", revokedAt: now } });
    await writeAuditLogInTransaction(transaction, { eventType: "ADMIN_CREDENTIAL_RECOVERED", result: "SUCCESS", actorUserId: input.actor.id, resource: "identity.admin", message: "Administrative credential recovered." });
    return recoveryCodes;
  });
  return recoveryCodes;
}

async function createEmailElevationCeremony(input: { userId: string; sessionId: string; scope: string; kind: "ADMIN_EMAIL_VERIFICATION"; recipientEmail: string; displayName: string | null; locale: EmailLocale; now: Date; expiresAt?: Date; manualUntilRevoked?: boolean; audit?: AuditLogInput }): Promise<string> {
  const sendAttempt = await prisma.$transaction((transaction) => consumeRateLimitAttemptInTransaction(transaction, `admin-email-ceremony:${input.userId}`, input.now, 10));
  if (!sendAttempt.allowed) throw new AdministrationMutationError();
  const requestKey = randomBytes(24).toString("base64url");
  const code = generateNumericCode();
  const expiresAt = input.expiresAt ?? new Date(input.now.getTime() + ELEVATION_CEREMONY_TTL_MS);
  await prisma.$transaction(async (transaction) => {
    await transaction.securityElevation.updateMany({ where: { userId: input.userId, sessionId: input.sessionId, status: "PENDING" }, data: { status: "REVOKED", revokedAt: input.now } });
    await transaction.securityElevation.create({ data: { requestKey, userId: input.userId, sessionId: input.sessionId, protocolVersion: ELEVATION_PROTOCOL_VERSION, scope: input.scope, challengeHash: hashSecurityCode(code), status: "PENDING", manualUntilRevoked: input.manualUntilRevoked ?? false, expiresAt } });
    await enqueueEmailMessageForClient(transaction, { idempotencyKey: `admin-elevation:${requestKey}`, kind: input.kind, recipientEmail: input.recipientEmail, locale: input.locale, payload: { publicValues: { displayName: input.displayName ?? "" }, protectedValues: { code } } });
    if (input.audit) await writeAuditLogInTransaction(transaction, { ...input.audit, metadata: { ...input.audit.metadata, requestRef: hashAuditIdentifier(requestKey) } });
  });
  return requestKey;
}

async function getPendingCeremony(transaction: Prisma.TransactionClient, requestKey: string, userId: string, sessionId: string, scope: string | undefined, now: Date) {
  if (!isRequestKey(requestKey)) throw new AdministrationMutationError();
  const ceremony = await transaction.securityElevation.findUnique({ where: { requestKey }, select: { id: true, challengeHash: true, scope: true, status: true, expiresAt: true, userId: true, sessionId: true } });
  if (!ceremony || ceremony.status !== "PENDING" || ceremony.userId !== userId || ceremony.sessionId !== sessionId || (scope && ceremony.scope !== scope) || ceremony.expiresAt <= now) throw new AdministrationMutationError();
  return ceremony;
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

async function consumeAdminElevationStartAttempt(userId: string, now: Date): Promise<void> {
  if (!isDatabaseId(userId)) throw new AdministrationMutationError();
  const result = await prisma.$transaction((transaction) => consumeRateLimitAttemptInTransaction(transaction, `admin-elevation-start:${userId}`, now));
  if (!result.allowed) throw new AdministrationMutationError();
}

async function requireAdminSession(actor: { id: string; role: string }, sessionId: string, now: Date) {
  if (actor.role !== "ADMIN" || !isDatabaseId(sessionId)) throw new AdministrationMutationError();
  const admin = await prisma.user.findUnique({ where: { id: actor.id }, select: { email: true, displayName: true, passwordHash: true, emailVerifiedAt: true, role: true, isActive: true } });
  const session = await prisma.session.findUnique({ where: { id: sessionId }, select: { userId: true, revokedAt: true, expiresAt: true } });
  if (!admin?.isActive || admin.role !== "ADMIN" || !session || session.userId !== actor.id || session.revokedAt || session.expiresAt <= now) throw new AdministrationMutationError();
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

function assertAdminPassword(value: string): void {
  if (value.length < ADMIN_MIN_PASSWORD_LENGTH || value.length > 256) throw new AdministrationMutationError();
}
function assertScope(value: string): asserts value is ElevationScope { if (!isAllowedScope(value)) throw new AdministrationMutationError(); }
function isAllowedScope(value: string): value is ElevationScope { return (ELEVATION_SCOPES as readonly string[]).includes(value); }
function isRequestKey(value: string): boolean { return /^[A-Za-z0-9_-]{32,100}$/.test(value); }
function isDatabaseId(value: string): boolean { return /^[A-Za-z0-9_-]{8,80}$/.test(value); }
