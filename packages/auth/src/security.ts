import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  randomBytes,
  timingSafeEqual
} from "node:crypto";
import { enqueueEmailMessageForClient, type EmailLocale } from "./email";
import { getSessionExpiresAt, generateSessionToken, hashSessionToken } from "./index";
import { prisma, type Prisma } from "@bielos/database";

export const DEVICE_COOKIE_NAME = "bielos_device";
export const SECURITY_CEREMONY_TTL_MS = 10 * 60 * 1000;
export const DEVICE_TRUST_TTL_MS = 180 * 24 * 60 * 60 * 1000;

const TOTP_KEY_VERSION = 1;
const TOTP_STEP_SECONDS = 30;
const TOTP_DIGITS = 6;
const RECOVERY_CODE_COUNT = 10;
const RECOVERY_CODE_BYTES = 9;
const RECOVERY_REQUEST_TTL_MS = 30 * 60 * 1000;

export type LoginCeremonyStart = {
  ceremonyId: string;
  factor: "EMAIL" | "TOTP";
  newDevice: boolean;
  deviceToken: string;
};

export class SecurityMutationError extends Error {
  constructor() {
    super("Security mutation rejected.");
    this.name = "SecurityMutationError";
  }
}

export function generateDeviceToken(): string {
  return randomBytes(32).toString("base64url");
}

export function hashDeviceToken(deviceToken: string): string {
  return createHash("sha256").update(deviceToken, "utf8").digest("hex");
}

export function generateNumericCode(): string {
  return String(randomBytes(4).readUInt32BE(0) % 1_000_000).padStart(6, "0");
}

export function hashSecurityCode(code: string): string {
  return createHash("sha256").update(code.trim(), "utf8").digest("hex");
}

export function generateRecoveryCode(): string {
  return randomBytes(RECOVERY_CODE_BYTES).toString("hex").toUpperCase();
}

export function hashRecoveryCode(code: string): string {
  return hashSecurityCode(code.replace(/[-\s]/g, "").toUpperCase());
}

export function createTotpSecret(): string {
  return encodeBase32(randomBytes(20));
}

export function createTotpUri(email: string, secret: string): string {
  return `otpauth://totp/BielOS:${encodeURIComponent(email)}?secret=${secret}&issuer=BielOS&algorithm=SHA1&digits=6&period=30`;
}

export function encryptTotpSecret(secret: string, env: NodeJS.ProcessEnv = process.env): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", getTotpKey(env), iv);
  const ciphertext = Buffer.concat([cipher.update(secret, "utf8"), cipher.final()]);
  return `v${TOTP_KEY_VERSION}:${iv.toString("base64url")}:${cipher.getAuthTag().toString("base64url")}:${ciphertext.toString("base64url")}`;
}

export function decryptTotpSecret(value: string, env: NodeJS.ProcessEnv = process.env): string {
  const [version, ivValue, tagValue, ciphertextValue] = value.split(":");
  if (version !== `v${TOTP_KEY_VERSION}` || !ivValue || !tagValue || !ciphertextValue) throw new SecurityMutationError();
  const decipher = createDecipheriv("aes-256-gcm", getTotpKey(env), Buffer.from(ivValue, "base64url"));
  decipher.setAuthTag(Buffer.from(tagValue, "base64url"));
  return Buffer.concat([decipher.update(Buffer.from(ciphertextValue, "base64url")), decipher.final()]).toString("utf8");
}

export function verifyTotpCode(secret: string, code: string, now = new Date(), lastUsedStep: number | null = null): number | null {
  if (!/^\d{6}$/.test(code)) return null;
  const currentStep = Math.floor(now.getTime() / 1_000 / TOTP_STEP_SECONDS);
  const candidate = Number(code);
  for (const step of [currentStep - 1, currentStep, currentStep + 1]) {
    if (step === lastUsedStep) continue;
    if (totpValue(secret, step) === candidate) return step;
  }
  return null;
}

export async function startTotpEnrollment(userId: string, email: string): Promise<{ secret: string; uri: string }> {
  const secret = createTotpSecret();
  await prisma.totpFactor.upsert({
    where: { userId },
    update: { secretCiphertext: encryptTotpSecret(secret), keyVersion: TOTP_KEY_VERSION, status: "PENDING", confirmedAt: null, lastUsedStep: null },
    create: { userId, secretCiphertext: encryptTotpSecret(secret), keyVersion: TOTP_KEY_VERSION, status: "PENDING" }
  });
  return { secret, uri: createTotpUri(email, secret) };
}

export async function confirmTotpEnrollment(userId: string, code: string, now = new Date()): Promise<string[]> {
  if (!/^\d{6}$/.test(code)) throw new SecurityMutationError();
  return prisma.$transaction(async (transaction) => {
    const factor = await transaction.totpFactor.findUnique({ where: { userId }, select: { id: true, secretCiphertext: true, status: true, lastUsedStep: true } });
    if (!factor || factor.status !== "PENDING") throw new SecurityMutationError();
    const step = verifyTotpCode(decryptTotpSecret(factor.secretCiphertext), code, now, factor.lastUsedStep);
    if (step === null) throw new SecurityMutationError();
    const recoveryCodes = Array.from({ length: RECOVERY_CODE_COUNT }, generateRecoveryCode);
    await transaction.recoveryCode.deleteMany({ where: { userId } });
    await transaction.recoveryCode.createMany({ data: recoveryCodes.map((value) => ({ userId, codeHash: hashRecoveryCode(value) })) });
    await transaction.totpFactor.update({ where: { id: factor.id }, data: { status: "ACTIVE", confirmedAt: now, lastUsedStep: step } });
    await transaction.user.update({ where: { id: userId }, data: { secondFactorMethod: "TOTP" } });
    return recoveryCodes;
  });
}

export async function disableTotp(userId: string): Promise<void> {
  await prisma.$transaction(async (transaction) => {
    await transaction.totpFactor.updateMany({ where: { userId, status: "ACTIVE" }, data: { status: "REVOKED" } });
    await transaction.user.update({ where: { id: userId }, data: { secondFactorMethod: "EMAIL" } });
    await transaction.recoveryCode.deleteMany({ where: { userId } });
  });
}

export async function regenerateRecoveryCodes(userId: string): Promise<string[]> {
  const recoveryCodes = Array.from({ length: RECOVERY_CODE_COUNT }, generateRecoveryCode);
  await prisma.$transaction(async (transaction) => {
    const factor = await transaction.totpFactor.findUnique({ where: { userId }, select: { status: true } });
    if (factor?.status !== "ACTIVE") throw new SecurityMutationError();
    await transaction.recoveryCode.deleteMany({ where: { userId } });
    await transaction.recoveryCode.createMany({ data: recoveryCodes.map((value) => ({ userId, codeHash: hashRecoveryCode(value) })) });
  });
  return recoveryCodes;
}

export async function verifyRecoveryCode(userId: string, code: string): Promise<boolean> {
  const normalizedHash = hashRecoveryCode(code);
  return prisma.$transaction(async (transaction) => {
    const row = await transaction.recoveryCode.findFirst({ where: { userId, codeHash: normalizedHash, usedAt: null }, select: { id: true } });
    if (!row) return false;
    const consumed = await transaction.recoveryCode.updateMany({ where: { id: row.id, usedAt: null }, data: { usedAt: new Date() } });
    return consumed.count === 1;
  });
}

export async function startLoginCeremony(
  userId: string,
  deviceToken: string | undefined,
  locale: EmailLocale,
  now = new Date()
): Promise<LoginCeremonyStart> {
  const token = deviceToken && /^[A-Za-z0-9_-]{32,100}$/.test(deviceToken) ? deviceToken : generateDeviceToken();
  const deviceIdHash = hashDeviceToken(token);
  try {
    return await prisma.$transaction(async (transaction) => {
      const user = await transaction.user.findUnique({ where: { id: userId }, select: { id: true, email: true, displayName: true, isActive: true, secondFactorMethod: true, totpFactor: { select: { status: true } } } });
      if (!user?.isActive) throw new SecurityMutationError();
      const trusted = await transaction.trustedDevice.findUnique({ where: { userId_deviceIdHash: { userId, deviceIdHash } }, select: { status: true } });
      const isTrusted = trusted?.status === "TRUSTED";
      const requiresTotp = user.secondFactorMethod === "TOTP" && user.totpFactor?.status === "ACTIVE";
      const code = requiresTotp && isTrusted ? "totp-only" : generateNumericCode();
      const ceremonyId = randomBytes(24).toString("base64url");
      await transaction.deviceChallenge.updateMany({ where: { userId, deviceIdHash, status: { in: ["PENDING", "VERIFIED"] } }, data: { status: "REVOKED" } });
      await transaction.deviceChallenge.create({ data: { userId, ceremonyId, deviceIdHash, codeHash: hashSecurityCode(code), requiresTotp, expiresAt: new Date(now.getTime() + SECURITY_CEREMONY_TTL_MS) } });
      if (!(requiresTotp && isTrusted)) {
        await enqueueEmailMessageForClient(transaction, {
          idempotencyKey: `security-ceremony:${ceremonyId}`,
          kind: isTrusted ? "EMAIL_TWO_FACTOR" : "NEW_DEVICE_VERIFICATION",
          recipientEmail: user.email,
          locale,
          payload: { publicValues: { displayName: user.displayName ?? "" }, protectedValues: { code } }
        });
      }
      return { ceremonyId, factor: requiresTotp && isTrusted ? "TOTP" : "EMAIL", newDevice: !isTrusted, deviceToken: token };
    }, { isolationLevel: "Serializable" });
  } catch {
    throw new SecurityMutationError();
  }
}

export async function verifyLoginEmailCode(ceremonyId: string, code: string, now = new Date()): Promise<{ requiresTotp: boolean; session: CreatedLoginSession | null }> {
  if (!isCeremonyId(ceremonyId) || !/^\d{6}$/.test(code)) throw new SecurityMutationError();
  try {
    return await prisma.$transaction(async (transaction) => {
      const challenge = await transaction.deviceChallenge.findUnique({ where: { ceremonyId }, select: { id: true, userId: true, deviceIdHash: true, codeHash: true, requiresTotp: true, status: true, expiresAt: true, consumedAt: true, user: { select: { isActive: true } } } });
      if (!challenge || !challenge.user.isActive || challenge.status !== "PENDING" || challenge.consumedAt || challenge.expiresAt <= now || !safeEqual(hashSecurityCode(code), challenge.codeHash)) throw new SecurityMutationError();
      await transaction.deviceChallenge.updateMany({ where: { id: challenge.id, status: "PENDING", consumedAt: null }, data: { status: "VERIFIED" } });
      await transaction.trustedDevice.upsert({ where: { userId_deviceIdHash: { userId: challenge.userId, deviceIdHash: challenge.deviceIdHash } }, update: { status: "TRUSTED", revokedAt: null, lastSeenAt: now }, create: { userId: challenge.userId, deviceIdHash: challenge.deviceIdHash, status: "TRUSTED", lastSeenAt: now } });
      if (challenge.requiresTotp) return { requiresTotp: true, session: null };
      return { requiresTotp: false, session: await consumeChallengeAndCreateSession(transaction, challenge.id, challenge.userId, now) };
    }, { isolationLevel: "Serializable" });
  } catch {
    throw new SecurityMutationError();
  }
}

export async function verifyLoginTotpCode(ceremonyId: string, code: string, now = new Date()): Promise<CreatedLoginSession> {
  if (!isCeremonyId(ceremonyId)) throw new SecurityMutationError();
  try {
    return await prisma.$transaction(async (transaction) => {
      const challenge = await transaction.deviceChallenge.findUnique({ where: { ceremonyId }, select: { id: true, userId: true, requiresTotp: true, status: true, expiresAt: true, consumedAt: true, user: { select: { isActive: true, totpFactor: { select: { id: true, secretCiphertext: true, status: true, lastUsedStep: true } } } } } });
      if (!challenge || !challenge.requiresTotp || !challenge.user.isActive || !["PENDING", "VERIFIED"].includes(challenge.status) || challenge.consumedAt || challenge.expiresAt <= now || challenge.user.totpFactor?.status !== "ACTIVE") throw new SecurityMutationError();
      const factor = challenge.user.totpFactor;
      const step = verifyTotpCode(decryptTotpSecret(factor.secretCiphertext), code, now, factor.lastUsedStep);
      if (step === null) throw new SecurityMutationError();
      const claimed = await transaction.totpFactor.updateMany({ where: { id: factor.id, status: "ACTIVE", OR: [{ lastUsedStep: null }, { lastUsedStep: { not: step } }] }, data: { lastUsedStep: step } });
      if (claimed.count !== 1) throw new SecurityMutationError();
      return consumeChallengeAndCreateSession(transaction, challenge.id, challenge.userId, now);
    }, { isolationLevel: "Serializable" });
  } catch {
    throw new SecurityMutationError();
  }
}

export async function listTrustedDevices(userId: string) {
  return prisma.trustedDevice.findMany({ where: { userId, status: "TRUSTED" }, orderBy: { lastSeenAt: "desc" }, take: 25, select: { id: true, label: true, lastSeenAt: true, createdAt: true } });
}

export async function revokeTrustedDevice(userId: string, deviceId: string): Promise<void> {
  if (!isDatabaseId(deviceId)) throw new SecurityMutationError();
  await prisma.trustedDevice.updateMany({ where: { id: deviceId, userId, status: "TRUSTED" }, data: { status: "REVOKED", revokedAt: new Date() } });
}

export async function requestAccountRecovery(email: string, locale: EmailLocale, now = new Date()): Promise<void> {
  const normalizedEmail = email.trim().toLowerCase();
  if (!/^\S+@\S+$/.test(normalizedEmail)) return;
  const user = await prisma.user.findUnique({ where: { emailNormalized: normalizedEmail }, select: { id: true, email: true, displayName: true, isActive: true, accountStatus: true, emailVerifiedAt: true } });
  if (!user?.isActive || user.accountStatus !== "ACTIVE" || !user.emailVerifiedAt) return;
  const requestKey = randomBytes(24).toString("base64url");
  const code = generateNumericCode();
  try {
    await prisma.$transaction(async (transaction) => {
      await transaction.accountRecoveryRequest.updateMany({ where: { userId: user.id, status: "PENDING" }, data: { status: "EXPIRED" } });
      await transaction.accountRecoveryRequest.create({ data: { requestKey, userId: user.id, emailChallengeHash: hashSecurityCode(code), expiresAt: new Date(now.getTime() + RECOVERY_REQUEST_TTL_MS) } });
      await enqueueEmailMessageForClient(transaction, { idempotencyKey: `account-recovery:${requestKey}`, kind: "ACCOUNT_RECOVERY", recipientEmail: user.email, locale, payload: { publicValues: { displayName: user.displayName ?? "", actionUrl: `/recover?request=${requestKey}` }, protectedValues: { code } } });
    });
  } catch {
    throw new SecurityMutationError();
  }
}

export async function verifyAccountRecoveryEmail(requestKey: string, code: string, now = new Date()): Promise<void> {
  if (!isCeremonyId(requestKey) || !/^\d{6}$/.test(code)) throw new SecurityMutationError();
  const result = await prisma.$transaction(async (transaction) => {
    const request = await transaction.accountRecoveryRequest.findUnique({ where: { requestKey }, select: { id: true, emailChallengeHash: true, status: true, expiresAt: true } });
    if (!request || request.status !== "PENDING" || request.expiresAt <= now || !safeEqual(hashSecurityCode(code), request.emailChallengeHash)) throw new SecurityMutationError();
    return transaction.accountRecoveryRequest.updateMany({ where: { id: request.id, status: "PENDING", emailVerifiedAt: null }, data: { emailVerifiedAt: now } });
  });
  if (result.count !== 1) throw new SecurityMutationError();
}

export async function listPendingAccountRecoveries(actor: { id: string; role: string }) {
  await requireOwner(actor);
  return prisma.accountRecoveryRequest.findMany({
    where: { status: "PENDING", emailVerifiedAt: { not: null } },
    orderBy: { createdAt: "asc" },
    take: 50,
    select: { requestKey: true, createdAt: true, expiresAt: true, emailVerifiedAt: true, user: { select: { emailNormalized: true, displayName: true } } }
  });
}

export async function approveAccountRecovery(actor: { id: string; role: string }, requestKey: string, now = new Date()): Promise<void> {
  await requireOwner(actor);
  if (!isCeremonyId(requestKey)) throw new SecurityMutationError();
  const result = await prisma.$transaction(async (transaction) => {
    const request = await transaction.accountRecoveryRequest.findUnique({ where: { requestKey }, select: { id: true, status: true, emailVerifiedAt: true, expiresAt: true } });
    if (!request || request.status !== "PENDING" || !request.emailVerifiedAt || request.expiresAt <= now) throw new SecurityMutationError();
    return transaction.accountRecoveryRequest.updateMany({ where: { id: request.id, status: "PENDING", emailVerifiedAt: { not: null } }, data: { status: "APPROVED", reviewedByUserId: actor.id, approvedAt: now } });
  });
  if (result.count !== 1) throw new SecurityMutationError();
}

export async function consumeApprovedAccountRecovery(requestKey: string, newPasswordHash: string, now = new Date()): Promise<void> {
  if (!isCeremonyId(requestKey) || newPasswordHash.length < 20) throw new SecurityMutationError();
  const result = await prisma.$transaction(async (transaction) => {
    const request = await transaction.accountRecoveryRequest.findUnique({ where: { requestKey }, select: { id: true, userId: true, status: true, expiresAt: true } });
    if (!request || request.status !== "APPROVED" || request.expiresAt <= now) throw new SecurityMutationError();
    await transaction.user.update({ where: { id: request.userId }, data: { passwordHash: newPasswordHash } });
    await transaction.session.updateMany({ where: { userId: request.userId, revokedAt: null }, data: { revokedAt: now } });
    return transaction.accountRecoveryRequest.updateMany({ where: { id: request.id, status: "APPROVED" }, data: { status: "CONSUMED", consumedAt: now } });
  });
  if (result.count !== 1) throw new SecurityMutationError();
}

async function consumeChallengeAndCreateSession(transaction: Prisma.TransactionClient, challengeId: string, userId: string, now: Date): Promise<CreatedLoginSession> {
  const consumed = await transaction.deviceChallenge.updateMany({ where: { id: challengeId, status: { in: ["PENDING", "VERIFIED"] }, consumedAt: null }, data: { status: "VERIFIED", consumedAt: now } });
  if (consumed.count !== 1) throw new SecurityMutationError();
  const token = generateSessionToken();
  const expiresAt = getSessionExpiresAt(now);
  await transaction.session.create({ data: { userId, tokenHash: hashSessionToken(token), expiresAt } });
  return { token, expiresAt };
}

export type CreatedLoginSession = { token: string; expiresAt: Date };

function getTotpKey(env: NodeJS.ProcessEnv): Buffer {
  const configured = env.BIELOS_TOTP_ENCRYPTION_KEY?.trim();
  if (configured && /^[0-9a-f]{64}$/i.test(configured)) return Buffer.from(configured, "hex");
  if (env.NODE_ENV === "test") return createHash("sha256").update("bielos-test-totp-key", "utf8").digest();
  throw new SecurityMutationError();
}

async function requireOwner(actor: { id: string; role: string }): Promise<void> {
  if (actor.role !== "OWNER") throw new SecurityMutationError();
  const persisted = await prisma.user.findUnique({ where: { id: actor.id }, select: { role: true, isActive: true } });
  if (!persisted?.isActive || persisted.role !== "OWNER") throw new SecurityMutationError();
}

function totpValue(secret: string, step: number): number {
  const digest = createHmac("sha1", decodeBase32(secret)).update(Buffer.from(step.toString(16).padStart(16, "0"), "hex")).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  return (digest.readUInt32BE(offset) & 0x7fffffff) % 10 ** TOTP_DIGITS;
}

function encodeBase32(value: Buffer): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let buffer = 0;
  let output = "";
  for (const byte of value) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += alphabet[(buffer >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += alphabet[(buffer << (5 - bits)) & 31];
  return output;
}

function decodeBase32(value: string): Buffer {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let buffer = 0;
  const bytes: number[] = [];
  for (const char of value.replace(/=+$/, "").toUpperCase()) {
    const index = alphabet.indexOf(char);
    if (index < 0) throw new SecurityMutationError();
    buffer = (buffer << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bytes.push((buffer >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

function safeEqual(left: string, right: string): boolean {
  const a = Buffer.from(left, "utf8");
  const b = Buffer.from(right, "utf8");
  return a.length === b.length && timingSafeEqual(a, b);
}

function isCeremonyId(value: string): boolean { return /^[A-Za-z0-9_-]{24,100}$/.test(value); }
function isDatabaseId(value: string): boolean { return /^[A-Za-z0-9_-]{8,80}$/.test(value); }
