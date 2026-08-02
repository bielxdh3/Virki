import { randomBytes, timingSafeEqual } from "node:crypto";
import { enqueueEmailMessageForClient, type EmailLocale } from "./email";
import { generateRecoveryCode, generateNumericCode, hashRecoveryCode, hashSecurityCode } from "./security";
import { hashPassword, verifyPassword } from "./index";
import { prisma, type Prisma } from "@bielos/database";

export const ELEVATION_PROTOCOL_VERSION = 1;
export const ELEVATION_SCOPES = [
  "ACCOUNT_APPLICATION_REVIEW",
  "ACCOUNT_ACTIVATION_REISSUE",
  "MODULE_ACCESS_CHANGE",
  "FEATURE_PERMISSION_CHANGE",
  "ACCOUNT_STATE_CHANGE",
  "GLOBAL_ROLE_CHANGE",
  "MODULE_CATALOG_CHANGE",
  "ADMIN_CREDENTIAL_CHANGE",
  "ADMIN_RECOVERY_REGENERATE",
  "PROJECT_OWNER_ACCESS_CHANGE",
  "CORE_PROJECT_ARCHIVE"
] as const;
export type ElevationScope = (typeof ELEVATION_SCOPES)[number];
export type ElevationDuration = { kind: "TIMED"; minutes: 15 | 60 | 240 | 1440 } | { kind: "MANUAL"; confirmed: true };

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
  const owner = await requireOwnerSession(input.actor, input.sessionId, now);
  if (!owner.passwordHash || !await verifyPassword(owner.passwordHash, input.normalPassword) || !owner.emailVerifiedAt) throw new AdministrationMutationError();
  const existing = await prisma.administrativeCredential.findUnique({ where: { userId: input.actor.id }, select: { status: true } });
  if (existing?.status === "ACTIVE") throw new AdministrationMutationError();
  return createEmailElevationCeremony({ userId: input.actor.id, sessionId: input.sessionId, scope: ADMIN_CREDENTIAL_SETUP_SCOPE, kind: "ADMIN_EMAIL_VERIFICATION", recipientEmail: owner.email, displayName: owner.displayName, locale: input.locale, now });
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
  await requireOwnerSession(input.actor, input.sessionId, now);
  assertAdminPassword(input.newPassword);
  const passwordHash = await hashPassword(input.newPassword);
  return prisma.$transaction(async (transaction) => {
    const ceremony = await getPendingCeremony(transaction, input.requestKey, input.actor.id, input.sessionId, ADMIN_CREDENTIAL_SETUP_SCOPE, now);
    if (!safeEqual(hashSecurityCode(input.code), ceremony.challengeHash)) throw new AdministrationMutationError();
    const consumed = await transaction.securityElevation.updateMany({ where: { id: ceremony.id, status: "PENDING" }, data: { status: "CONSUMED", consumedAt: now } });
    if (consumed.count !== 1) throw new AdministrationMutationError();
    const recoveryCodes = Array.from({ length: RECOVERY_CODE_COUNT }, generateRecoveryCode);
    await transaction.administrativeCredential.upsert({ where: { userId: input.actor.id }, update: { passwordHash, status: "ACTIVE", keyVersion: { increment: 1 }, revokedAt: null }, create: { userId: input.actor.id, passwordHash, status: "ACTIVE" } });
    await transaction.administrativeRecoveryCode.deleteMany({ where: { userId: input.actor.id } });
    await transaction.administrativeRecoveryCode.createMany({ data: recoveryCodes.map((value) => ({ userId: input.actor.id, codeHash: hashRecoveryCode(value) })) });
    return recoveryCodes;
  });
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
  const owner = await requireOwnerSession(input.actor, input.sessionId, now);
  assertScope(input.scope);
  const duration = resolveElevationDuration(input.duration, now);
  if (!owner.emailVerifiedAt) throw new AdministrationMutationError();
  const credential = await prisma.administrativeCredential.findUnique({ where: { userId: input.actor.id }, select: { passwordHash: true, status: true } });
  if (!owner.passwordHash || !await verifyPassword(owner.passwordHash, input.normalPassword) || credential?.status !== "ACTIVE" || !await verifyPassword(credential.passwordHash, input.administrativePassword)) throw new AdministrationMutationError();
  const requestKey = await createEmailElevationCeremony({ userId: input.actor.id, sessionId: input.sessionId, scope: input.scope, kind: "ADMIN_EMAIL_VERIFICATION", recipientEmail: owner.email, displayName: owner.displayName, locale: input.locale, now, expiresAt: duration.expiresAt, manualUntilRevoked: duration.manualUntilRevoked });
  return { requestKey, manualUntilRevoked: duration.manualUntilRevoked, expiresAt: duration.expiresAt };
}

export async function verifySecurityElevation(input: { actor: { id: string; role: string }; sessionId: string; requestKey: string; code: string; now?: Date }): Promise<void> {
  const now = input.now ?? new Date();
  await requireOwnerSession(input.actor, input.sessionId, now);
  await prisma.$transaction(async (transaction) => {
    const ceremony = await getPendingCeremony(transaction, input.requestKey, input.actor.id, input.sessionId, undefined, now);
    if (!isAllowedScope(ceremony.scope)) throw new AdministrationMutationError();
    if (!safeEqual(hashSecurityCode(input.code), ceremony.challengeHash)) throw new AdministrationMutationError();
    const updated = await transaction.securityElevation.updateMany({ where: { id: ceremony.id, status: "PENDING", expiresAt: { gt: now } }, data: { status: "ACTIVE", activatedAt: now } });
    if (updated.count !== 1) throw new AdministrationMutationError();
  });
}

export async function listActiveSecurityElevations(actor: { id: string; role: string }, sessionId: string, now = new Date()) {
  await requireOwnerSession(actor, sessionId, now);
  await expireSecurityElevations(now);
  return prisma.securityElevation.findMany({ where: { userId: actor.id, sessionId, status: "ACTIVE", OR: [{ manualUntilRevoked: true }, { expiresAt: { gt: now } }] }, orderBy: { createdAt: "desc" }, take: 20, select: { requestKey: true, scope: true, manualUntilRevoked: true, expiresAt: true, activatedAt: true } });
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
  await requireOwnerSession(actor, sessionId, now);
  if (requestKey && !isRequestKey(requestKey)) throw new AdministrationMutationError();
  await prisma.securityElevation.updateMany({ where: { userId: actor.id, sessionId, status: "ACTIVE", ...(requestKey ? { requestKey } : {}) }, data: { status: "REVOKED", revokedAt: now } });
}

export async function expireSecurityElevations(now = new Date()): Promise<number> {
  const result = await prisma.securityElevation.updateMany({ where: { status: "ACTIVE", manualUntilRevoked: false, expiresAt: { lte: now } }, data: { status: "EXPIRED" } });
  return result.count;
}

export async function changeAdministrativePassword(actor: { id: string; role: string }, sessionId: string, newPassword: string, now = new Date()): Promise<void> {
  await requireSecurityElevation(actor.id, sessionId, "ADMIN_CREDENTIAL_CHANGE", now);
  assertAdminPassword(newPassword);
  await prisma.administrativeCredential.update({ where: { userId: actor.id }, data: { passwordHash: await hashPassword(newPassword), status: "ACTIVE", keyVersion: { increment: 1 }, revokedAt: null } });
}

export async function regenerateAdministrativeRecoveryCodes(actor: { id: string; role: string }, sessionId: string, now = new Date()): Promise<string[]> {
  await requireSecurityElevation(actor.id, sessionId, "ADMIN_RECOVERY_REGENERATE", now);
  const recoveryCodes = Array.from({ length: RECOVERY_CODE_COUNT }, generateRecoveryCode);
  await prisma.$transaction(async (transaction) => {
    await transaction.administrativeRecoveryCode.deleteMany({ where: { userId: actor.id } });
    await transaction.administrativeRecoveryCode.createMany({ data: recoveryCodes.map((value) => ({ userId: actor.id, codeHash: hashRecoveryCode(value) })) });
  });
  return recoveryCodes;
}

export async function recoverAdministrativeCredential(input: { actor: { id: string; role: string }; normalPassword: string; recoveryCode: string; newPassword: string; now?: Date }): Promise<string[]> {
  const now = input.now ?? new Date();
  if (input.actor.role !== "OWNER") throw new AdministrationMutationError();
  assertAdminPassword(input.newPassword);
  const owner = await prisma.user.findUnique({ where: { id: input.actor.id }, select: { emailVerifiedAt: true, passwordHash: true, role: true, isActive: true } });
  if (!owner?.isActive || owner.role !== "OWNER" || !owner.emailVerifiedAt || !owner.passwordHash || !await verifyPassword(owner.passwordHash, input.normalPassword)) throw new AdministrationMutationError();
  const passwordHash = await hashPassword(input.newPassword);
  return prisma.$transaction(async (transaction) => {
    const code = await transaction.administrativeRecoveryCode.findFirst({ where: { userId: input.actor.id, codeHash: hashRecoveryCode(input.recoveryCode), usedAt: null }, select: { id: true } });
    if (!code) throw new AdministrationMutationError();
    const used = await transaction.administrativeRecoveryCode.updateMany({ where: { id: code.id, usedAt: null }, data: { usedAt: now } });
    if (used.count !== 1) throw new AdministrationMutationError();
    const recoveryCodes = Array.from({ length: RECOVERY_CODE_COUNT }, generateRecoveryCode);
    await transaction.administrativeCredential.upsert({ where: { userId: input.actor.id }, update: { passwordHash, status: "ACTIVE", keyVersion: { increment: 1 }, revokedAt: null }, create: { userId: input.actor.id, passwordHash, status: "ACTIVE" } });
    await transaction.administrativeRecoveryCode.deleteMany({ where: { userId: input.actor.id } });
    await transaction.administrativeRecoveryCode.createMany({ data: recoveryCodes.map((value) => ({ userId: input.actor.id, codeHash: hashRecoveryCode(value) })) });
    await transaction.securityElevation.updateMany({ where: { userId: input.actor.id, status: { in: ["PENDING", "ACTIVE"] } }, data: { status: "REVOKED", revokedAt: now } });
    return recoveryCodes;
  });
}

async function createEmailElevationCeremony(input: { userId: string; sessionId: string; scope: string; kind: "ADMIN_EMAIL_VERIFICATION"; recipientEmail: string; displayName: string | null; locale: EmailLocale; now: Date; expiresAt?: Date; manualUntilRevoked?: boolean }): Promise<string> {
  const requestKey = randomBytes(24).toString("base64url");
  const code = generateNumericCode();
  const expiresAt = input.expiresAt ?? new Date(input.now.getTime() + ELEVATION_CEREMONY_TTL_MS);
  await prisma.$transaction(async (transaction) => {
    await transaction.securityElevation.updateMany({ where: { userId: input.userId, sessionId: input.sessionId, status: "PENDING" }, data: { status: "REVOKED", revokedAt: input.now } });
    await transaction.securityElevation.create({ data: { requestKey, userId: input.userId, sessionId: input.sessionId, protocolVersion: ELEVATION_PROTOCOL_VERSION, scope: input.scope, challengeHash: hashSecurityCode(code), status: "PENDING", manualUntilRevoked: input.manualUntilRevoked ?? false, expiresAt } });
    await enqueueEmailMessageForClient(transaction, { idempotencyKey: `admin-elevation:${requestKey}`, kind: input.kind, recipientEmail: input.recipientEmail, locale: input.locale, payload: { publicValues: { displayName: input.displayName ?? "" }, protectedValues: { code } } });
  });
  return requestKey;
}

async function getPendingCeremony(transaction: Prisma.TransactionClient, requestKey: string, userId: string, sessionId: string, scope: string | undefined, now: Date) {
  if (!isRequestKey(requestKey)) throw new AdministrationMutationError();
  const ceremony = await transaction.securityElevation.findUnique({ where: { requestKey }, select: { id: true, challengeHash: true, scope: true, status: true, expiresAt: true, userId: true, sessionId: true } });
  if (!ceremony || ceremony.status !== "PENDING" || ceremony.userId !== userId || ceremony.sessionId !== sessionId || (scope && ceremony.scope !== scope) || ceremony.expiresAt <= now) throw new AdministrationMutationError();
  return ceremony;
}

async function requireOwnerSession(actor: { id: string; role: string }, sessionId: string, now: Date) {
  if (actor.role !== "OWNER" || !isDatabaseId(sessionId)) throw new AdministrationMutationError();
  const owner = await prisma.user.findUnique({ where: { id: actor.id }, select: { email: true, displayName: true, passwordHash: true, emailVerifiedAt: true, role: true, isActive: true } });
  const session = await prisma.session.findUnique({ where: { id: sessionId }, select: { userId: true, revokedAt: true, expiresAt: true } });
  if (!owner?.isActive || owner.role !== "OWNER" || !session || session.userId !== actor.id || session.revokedAt || session.expiresAt <= now) throw new AdministrationMutationError();
  return owner;
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
function safeEqual(left: string, right: string): boolean {
  const a = Buffer.from(left, "utf8");
  const b = Buffer.from(right, "utf8");
  return a.length === b.length && timingSafeEqual(a, b);
}
