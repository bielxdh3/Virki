import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  randomBytes,
  randomInt,
  timingSafeEqual
} from "node:crypto";
import { isIP } from "node:net";
import { enqueueEmailMessageForClient, type EmailLocale } from "./email";
import { hashOidcIdentifier } from "./oidc-secrets";
import {
  consumeRateLimitAttemptInTransaction,
  refundRateLimitAttemptInTransaction,
  generateSessionToken,
  getSessionExpiresAt,
  hashPassword,
  hashAuditIdentifier,
  hashSessionToken,
  lockRateLimitIdentifierInTransaction,
  verifyPassword,
  writeAuditLogInTransaction
} from "./index";
import { prisma, type Prisma } from "@virki/database";
import { requireSecurityElevationInTransaction } from "./elevation-authorization";

export { DEVICE_COOKIE_NAME } from "./constants";
export const SECURITY_CEREMONY_TTL_MS = 10 * 60 * 1000;
export const DEVICE_TRUST_TTL_MS = 180 * 24 * 60 * 60 * 1000;
export const REMEMBERED_BROWSER_TTL_MS = 7 * 24 * 60 * 60 * 1000;
export const RECOVERY_REQUEST_COOLDOWN_MS = 60 * 1000;
// Anonymous recovery requests take at least this long whether or not the account exists.
export const RECOVERY_REQUEST_RESPONSE_FLOOR_MS = 500;
// Email-sending login ceremonies a password-correct caller may start per 15-minute window.
export const LOGIN_EMAIL_CEREMONY_ACCOUNT_LIMIT = 6;
export const LOGIN_EMAIL_CEREMONY_SOURCE_LIMIT = 20;
// A repeated start for the same browser within this window reuses the pending ceremony instead of mailing a new code.
export const LOGIN_EMAIL_CEREMONY_REUSE_MS = 60 * 1000;

const TOTP_KEY_VERSION = 1;
const TOTP_STEP_SECONDS = 30;
const TOTP_DIGITS = 6;
const RECOVERY_CODE_COUNT = 10;
const RECOVERY_CODE_BYTES = 9;
const RECOVERY_REQUEST_TTL_MS = 30 * 60 * 1000;

export type LoginCeremonyStart =
  | {
      kind: "CEREMONY";
      ceremonyId: string;
      factor: "EMAIL" | "TOTP";
      newDevice: boolean;
      deviceToken: string;
    }
  | {
      kind: "SESSION";
      deviceToken: string;
      session: CreatedLoginSession;
    };

export class SecurityMutationError extends Error {
  constructor() {
    super("Security mutation rejected.");
    this.name = "SecurityMutationError";
  }
}

export type LoginCeremonyFailureStage =
  | "transaction-start"
  | "account-lookup"
  | "account-state"
  | "account-lock-query"
  | "account-lock-no-match"
  | "trusted-device-lookup"
  | "remembered-challenges-revoke"
  | "remembered-session-create"
  | "ceremony-rate-limited"
  | "challenge-revoke"
  | "challenge-code-hash"
  | "challenge-create"
  | "outbox-enqueue"
  | "transaction-commit";

export class LoginCeremonyStartError extends SecurityMutationError {
  constructor(readonly stage: LoginCeremonyFailureStage) {
    super();
  }
}

export function getLoginCeremonyFailureStage(error: unknown): LoginCeremonyFailureStage | undefined {
  return error instanceof LoginCeremonyStartError ? error.stage : undefined;
}

export type AccountRecoveryRole = "USER" | "ADMIN";
export type RequiredLoginRole = "USER" | "ADMIN";
export type AccountRecoveryIdentity = { id: string; role: string; isActive: boolean; accountStatus: string };

export function isAcceptableRecoveryPassword(role: AccountRecoveryRole, password: string): boolean {
  const minimumLength = role === "ADMIN" ? 16 : 12;
  if (password.length < minimumLength || password.length > 256) return false;
  for (const character of password) {
    const code = character.charCodeAt(0);
    if (code <= 0x1f || (code >= 0x7f && code <= 0x9f)) return false;
  }
  return true;
}

export function isAccountRecoveryEligible(user: Omit<AccountRecoveryIdentity, "id"> | null | undefined, expectedRole: AccountRecoveryRole): boolean {
  return Boolean(user && user.role === expectedRole && user.isActive && user.accountStatus === "ACTIVE");
}

export function isPublicAccountRecoveryEligible(user: Omit<AccountRecoveryIdentity, "id"> | null | undefined): boolean {
  return isAccountRecoveryEligible(user, "USER");
}

export function canApproveAccountRecovery(actor: { id: string; role: string }, target: AccountRecoveryIdentity): boolean {
  return actor.role === "ADMIN" && actor.id !== target.id && isAccountRecoveryRole(target.role) && target.isActive && target.accountStatus === "ACTIVE";
}

export function generateDeviceToken(): string {
  return randomBytes(32).toString("base64url");
}

export function hashDeviceToken(deviceToken: string): string {
  return createHash("sha256").update(deviceToken, "utf8").digest("hex");
}

export function resolveLoginDeviceToken(
  candidate: string | undefined,
  trustedDevice: { status: string; revokedAt: Date | null } | null
): { deviceToken: string; isTrusted: boolean } {
  if (candidate && isDeviceToken(candidate) && trustedDevice?.status === "TRUSTED" && trustedDevice.revokedAt === null) {
    return { deviceToken: candidate, isTrusted: true };
  }
  return { deviceToken: generateDeviceToken(), isTrusted: false };
}

export function generateNumericCode(): string {
  return String(randomInt(0, 1_000_000)).padStart(6, "0");
}

export function hashSecurityCode(code: string, env: NodeJS.ProcessEnv = process.env): string {
  const key = createHmac("sha256", getTotpKey(env)).update("Virki security code hash v2", "utf8").digest();
  return `h2:${createHmac("sha256", key).update(code.trim(), "utf8").digest("hex")}`;
}

// Only keyed (h2) hashes are accepted. Unkeyed SHA-256 codes predate h2 and every code TTL (at most 72 h).
export function verifySecurityCode(code: string, storedHash: string, env: NodeJS.ProcessEnv = process.env): boolean {
  return storedHash.startsWith("h2:") && safeEqual(hashSecurityCode(code, env), storedHash);
}

export function generateRecoveryCode(): string {
  return randomBytes(RECOVERY_CODE_BYTES).toString("hex").toUpperCase();
}

export function hashRecoveryCode(code: string): string {
  return createHash("sha256").update(code.replace(/[-\s]/g, "").toUpperCase(), "utf8").digest("hex");
}

export function normalizeRecoveryCodeInput(code: string): string {
  return code.replace(/[-\s]/gu, "").toUpperCase();
}

export function isValidRecoveryCodeInput(code: string): boolean {
  return code.length <= 32 && /^[A-F0-9]{18}$/u.test(normalizeRecoveryCodeInput(code));
}

export function createTotpSecret(): string {
  return encodeBase32(randomBytes(20));
}

export function createTotpUri(email: string, secret: string): string {
  return `otpauth://totp/Virki:${encodeURIComponent(email)}?secret=${secret}&issuer=Virki&algorithm=SHA1&digits=6&period=30`;
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
    if (lastUsedStep !== null && step <= lastUsedStep) continue;
    if (totpValue(secret, step) === candidate) return step;
  }
  return null;
}

export async function startTotpEnrollment(userId: string, email: string): Promise<{ secret: string; uri: string }> {
  const secret = createTotpSecret();
  await prisma.$transaction(async (transaction) => {
    if (!await lockActiveLoginAccountInTransaction(transaction, userId)) throw new SecurityMutationError();
    const current = await transaction.totpFactor.findUnique({ where: { userId }, select: { status: true } });
    if (current?.status === "ACTIVE") throw new SecurityMutationError();
    await invalidateRememberedLoginGrants(transaction, userId);
    await revokeLoginChallenges(transaction, userId);
    await transaction.totpFactor.upsert({
      where: { userId },
      update: { secretCiphertext: encryptTotpSecret(secret), keyVersion: TOTP_KEY_VERSION, status: "PENDING", confirmedAt: null, lastUsedStep: null },
      create: { userId, secretCiphertext: encryptTotpSecret(secret), keyVersion: TOTP_KEY_VERSION, status: "PENDING" }
    });
    await writeAuditLogInTransaction(transaction, { eventType: "SECOND_FACTOR_ENROLLMENT_STARTED", result: "SUCCESS", actorUserId: userId, resource: "identity.2fa", message: "TOTP enrollment started." });
  }, { isolationLevel: "Serializable" });
  return { secret, uri: createTotpUri(email, secret) };
}

export async function confirmTotpEnrollment(userId: string, code: string, now = new Date()): Promise<string[]> {
  await consumeSecurityProofAttempt(userId, now);
  if (!/^\d{6}$/.test(code)) throw new SecurityMutationError();
  const recoveryCodes = await prisma.$transaction(async (transaction) => {
    if (!await lockActiveLoginAccountInTransaction(transaction, userId)) throw new SecurityMutationError();
    const factor = await transaction.totpFactor.findUnique({ where: { userId }, select: { id: true, secretCiphertext: true, status: true, lastUsedStep: true } });
    if (!factor || factor.status !== "PENDING") throw new SecurityMutationError();
    const step = verifyTotpCode(decryptTotpSecret(factor.secretCiphertext), code, now, factor.lastUsedStep);
    if (step === null) throw new SecurityMutationError();
    const recoveryCodes = Array.from({ length: RECOVERY_CODE_COUNT }, generateRecoveryCode);
    const confirmed = await transaction.totpFactor.updateMany({ where: { id: factor.id, status: "PENDING", lastUsedStep: factor.lastUsedStep }, data: { status: "ACTIVE", confirmedAt: now, lastUsedStep: step } });
    if (confirmed.count !== 1) throw new SecurityMutationError();
    await transaction.recoveryCode.deleteMany({ where: { userId } });
    await transaction.recoveryCode.createMany({ data: recoveryCodes.map((value) => ({ userId, codeHash: hashRecoveryCode(value) })) });
    await transaction.user.update({ where: { id: userId }, data: { secondFactorMethod: "TOTP" } });
    await invalidateRememberedLoginGrants(transaction, userId);
    await revokeLoginChallenges(transaction, userId);
    await writeAuditLogInTransaction(transaction, { eventType: "SECOND_FACTOR_ENROLLED", result: "SUCCESS", actorUserId: userId, resource: "identity.2fa", message: "TOTP second factor enrolled." });
    return recoveryCodes;
  }, { isolationLevel: "Serializable" });
  return recoveryCodes;
}

export async function disableTotp(userId: string, code: string, now = new Date()): Promise<void> {
  await consumeSecurityProofAttempt(userId, now);
  if (!/^\d{6}$/.test(code)) throw new SecurityMutationError();
  await prisma.$transaction(async (transaction) => {
    if (!await lockActiveLoginAccountInTransaction(transaction, userId)) throw new SecurityMutationError();
    const factor = await transaction.totpFactor.findUnique({ where: { userId }, select: { id: true, secretCiphertext: true, status: true, lastUsedStep: true } });
    if (!factor || factor.status !== "ACTIVE") throw new SecurityMutationError();
    const step = verifyTotpCode(decryptTotpSecret(factor.secretCiphertext), code, now, factor.lastUsedStep);
    if (step === null) throw new SecurityMutationError();
    const consumed = await transaction.totpFactor.updateMany({ where: { id: factor.id, status: "ACTIVE", lastUsedStep: factor.lastUsedStep }, data: { status: "REVOKED", lastUsedStep: step } });
    if (consumed.count !== 1) throw new SecurityMutationError();
    await transaction.user.update({ where: { id: userId }, data: { secondFactorMethod: "EMAIL" } });
    await transaction.recoveryCode.deleteMany({ where: { userId } });
    await invalidateRememberedLoginGrants(transaction, userId);
    await revokeLoginChallenges(transaction, userId);
    await transaction.securityElevation.updateMany({ where: { userId, status: { in: ["PENDING", "ACTIVE"] } }, data: { status: "REVOKED", revokedAt: now } });
    await transaction.session.updateMany({ where: { userId, revokedAt: null }, data: { revokedAt: now } });
    await revokeUserOidcArtifactsInTransaction(transaction, userId);
    await writeAuditLogInTransaction(transaction, { eventType: "SECOND_FACTOR_DISABLED", result: "SUCCESS", actorUserId: userId, resource: "identity.2fa", message: "TOTP second factor disabled." });
  });
}

export async function getAccountSecurityState(userId: string, now = new Date()) {
  const trustedSince = new Date(now.getTime() - DEVICE_TRUST_TTL_MS);
  const user = await prisma.user.findUnique({ where: { id: userId }, select: { secondFactorMethod: true, emailVerifiedAt: true, totpFactor: { select: { status: true, confirmedAt: true } }, _count: { select: { recoveryCodes: { where: { usedAt: null } }, trustedDevices: { where: { status: "TRUSTED", revokedAt: null, createdAt: { gt: trustedSince } } } } } } });
  return user ? { secondFactorMethod: user.secondFactorMethod, emailVerified: Boolean(user.emailVerifiedAt), totpStatus: user.totpFactor?.status ?? "NOT_CONFIGURED", totpConfirmedAt: user.totpFactor?.confirmedAt ?? null, recoveryCodeCount: user._count.recoveryCodes, trustedDeviceCount: user._count.trustedDevices } : null;
}

export async function regenerateRecoveryCodes(userId: string, code: string, now = new Date()): Promise<string[]> {
  await consumeSecurityProofAttempt(userId, now);
  if (!/^\d{6}$/.test(code)) throw new SecurityMutationError();
  const recoveryCodes = Array.from({ length: RECOVERY_CODE_COUNT }, generateRecoveryCode);
  await prisma.$transaction(async (transaction) => {
    const factor = await transaction.totpFactor.findUnique({ where: { userId }, select: { id: true, secretCiphertext: true, status: true, lastUsedStep: true } });
    if (!factor || factor.status !== "ACTIVE") throw new SecurityMutationError();
    const step = verifyTotpCode(decryptTotpSecret(factor.secretCiphertext), code, now, factor.lastUsedStep);
    if (step === null) throw new SecurityMutationError();
    const consumed = await transaction.totpFactor.updateMany({ where: { id: factor.id, status: "ACTIVE", lastUsedStep: factor.lastUsedStep }, data: { lastUsedStep: step } });
    if (consumed.count !== 1) throw new SecurityMutationError();
    await transaction.recoveryCode.deleteMany({ where: { userId } });
    await transaction.recoveryCode.createMany({ data: recoveryCodes.map((value) => ({ userId, codeHash: hashRecoveryCode(value) })) });
    await writeAuditLogInTransaction(transaction, { eventType: "RECOVERY_CODES_REGENERATED", result: "SUCCESS", actorUserId: userId, resource: "identity.recovery", message: "Recovery codes regenerated." });
  });
  return recoveryCodes;
}

export async function verifyRecoveryCode(userId: string, code: string): Promise<boolean> {
  await consumeSecurityProofAttempt(userId);
  if (code.length > 64) throw new SecurityMutationError();
  const normalizedHash = hashRecoveryCode(code);
  return prisma.$transaction(async (transaction) => {
    const row = await transaction.recoveryCode.findFirst({ where: { userId, codeHash: normalizedHash, usedAt: null }, select: { id: true } });
    if (!row) return false;
    const consumed = await transaction.recoveryCode.updateMany({ where: { id: row.id, usedAt: null }, data: { usedAt: new Date() } });
    return consumed.count === 1;
  });
}

export async function consumeSecurityProofAttempt(userId: string, now = new Date()): Promise<void> {
  if (!isDatabaseId(userId)) throw new SecurityMutationError();
  const result = await prisma.$transaction((transaction) => consumeRateLimitAttemptInTransaction(transaction, `account-security-proof:${userId}`, now));
  if (!result.allowed) throw new SecurityMutationError();
}

export async function startLoginCeremony(
  userId: string,
  deviceToken: string | undefined,
  locale: EmailLocale,
  now = new Date(),
  forceFreshProof = false,
  expectedRole?: RequiredLoginRole,
  trustedClientAddress?: string
): Promise<LoginCeremonyStart> {
  const candidateToken = deviceToken && isDeviceToken(deviceToken) ? deviceToken : undefined;
  let stage: LoginCeremonyFailureStage = "transaction-start";
  try {
    return await prisma.$transaction(async (transaction) => {
      stage = "account-lookup";
      const user = await transaction.user.findUnique({ where: { id: userId }, select: { id: true, email: true, emailNormalized: true, emailVerifiedAt: true, displayName: true, role: true, isActive: true, accountStatus: true, secondFactorMethod: true, totpFactor: { select: { status: true } } } });
      stage = "account-state";
      if (!user?.isActive || user.accountStatus !== "ACTIVE" || (expectedRole && user.role !== expectedRole)) throw new SecurityMutationError();
      stage = "account-lock-query";
      const accountLocked = await lockActiveLoginAccountInTransaction(transaction, userId, expectedRole);
      if (!accountLocked) {
        stage = "account-lock-no-match";
        throw new SecurityMutationError();
      }
      stage = "trusted-device-lookup";
      await transaction.trustedDevice.updateMany({ where: { userId, status: "TRUSTED", createdAt: { lte: new Date(now.getTime() - DEVICE_TRUST_TTL_MS) } }, data: { status: "REVOKED", revokedAt: now, rememberedUntil: null, strongVerifiedAt: null } });
      const candidateHash = candidateToken ? hashDeviceToken(candidateToken) : undefined;
      const trusted = candidateHash ? await transaction.trustedDevice.findUnique({ where: { userId_deviceIdHash: { userId, deviceIdHash: candidateHash } }, select: { status: true, revokedAt: true, rememberedUntil: true, strongVerifiedAt: true } }) : null;
      const resolvedDevice = resolveLoginDeviceToken(candidateToken, trusted);
      const resolvedDeviceToken = resolvedDevice.deviceToken;
      const deviceIdHash = hashDeviceToken(resolvedDeviceToken);
      const isTrusted = resolvedDevice.isTrusted;
      if (user.secondFactorMethod === "TOTP" && user.totpFactor?.status !== "ACTIVE") throw new SecurityMutationError();
      const requiresTotp = user.secondFactorMethod === "TOTP";
      // ADMIN logins always complete a fresh second factor; a remembered browser never yields a password-only ADMIN session.
      const hasRememberedGrant = user.role !== "ADMIN" && Boolean(user.emailVerifiedAt) && isTrusted && isRememberedGrantActive(trusted, now);

      if (hasRememberedGrant && !forceFreshProof) {
        stage = "remembered-challenges-revoke";
        await revokeLoginChallenges(transaction, userId, deviceIdHash);
        stage = "remembered-session-create";
        const session = await createSessionInTransaction(transaction, userId, now);
        stage = "transaction-commit";
        return {
          kind: "SESSION",
          deviceToken: resolvedDeviceToken,
          session
        };
      }

      const totpOnly = Boolean(user.emailVerifiedAt) && requiresTotp && isTrusted;
      if (!totpOnly) {
        stage = "challenge-revoke";
        const recent = await transaction.deviceChallenge.findFirst({
          where: { userId, deviceIdHash, requiresTotp, status: "PENDING", emailVerifiedAt: null, consumedAt: null, expiresAt: { gt: now }, createdAt: { gt: new Date(now.getTime() - LOGIN_EMAIL_CEREMONY_REUSE_MS), lte: now } },
          orderBy: { createdAt: "desc" },
          select: { ceremonyId: true }
        });
        if (recent) {
          stage = "transaction-commit";
          return { kind: "CEREMONY", ceremonyId: recent.ceremonyId, factor: "EMAIL", newDevice: !isTrusted, deviceToken: resolvedDeviceToken };
        }
        stage = "ceremony-rate-limited";
        if (!await consumeLoginEmailCeremonyQuota(transaction, userId, isTrusted ? deviceIdHash : null, now, trustedClientAddress)) throw new SecurityMutationError();
      }
      const code = totpOnly ? "totp-only" : generateNumericCode();
      const ceremonyId = randomBytes(24).toString("base64url");
      stage = "challenge-revoke";
      await transaction.deviceChallenge.updateMany({ where: { userId, deviceIdHash, status: { in: ["PENDING", "VERIFIED"] } }, data: { status: "REVOKED" } });
      stage = "challenge-code-hash";
      const codeHash = hashSecurityCode(code);
      stage = "challenge-create";
      await transaction.deviceChallenge.create({ data: { userId, ceremonyId, deviceIdHash, emailAddressHash: hashEmailAddress(user.emailNormalized ?? user.email), codeHash, requiresTotp, status: totpOnly ? "VERIFIED" : "PENDING", expiresAt: new Date(now.getTime() + SECURITY_CEREMONY_TTL_MS), createdAt: now } });
      if (!totpOnly) {
        stage = "outbox-enqueue";
        await enqueueEmailMessageForClient(transaction, {
          idempotencyKey: `security-ceremony:${ceremonyId}`,
          kind: isTrusted ? "EMAIL_TWO_FACTOR" : "NEW_DEVICE_VERIFICATION",
          recipientEmail: user.email,
          locale,
          payload: { publicValues: { displayName: user.displayName ?? "" }, protectedValues: { code } }
        });
      }
      stage = "transaction-commit";
      return { kind: "CEREMONY", ceremonyId, factor: totpOnly ? "TOTP" : "EMAIL", newDevice: !isTrusted, deviceToken: resolvedDeviceToken };
    }, { isolationLevel: "Serializable" });
  } catch {
    throw new LoginCeremonyStartError(stage);
  }
}

// Persistent budget for login ceremonies that mail a code, charged even after a correct password so a
// password holder cannot mail unbounded codes. A trusted device spends its own bucket, so someone who has
// the password but not the owner's device token cannot exhaust the owner's budget; untrusted browsers
// share the per-account bucket. The per-source bucket applies when the client address is known.
async function consumeLoginEmailCeremonyQuota(transaction: Prisma.TransactionClient, userId: string, trustedDeviceIdHash: string | null, now: Date, trustedClientAddress?: string): Promise<boolean> {
  const bucket = trustedDeviceIdHash ? `login-email-ceremony-device:${userId}:${trustedDeviceIdHash}` : `login-email-ceremony-account:${userId}`;
  const account = await consumeRateLimitAttemptInTransaction(transaction, bucket, now, LOGIN_EMAIL_CEREMONY_ACCOUNT_LIMIT);
  if (!account.allowed) return false;
  if (!isTrustedClientAddress(trustedClientAddress)) return true;
  const source = await consumeRateLimitAttemptInTransaction(transaction, `login-email-ceremony-source:${trustedClientAddress}`, now, LOGIN_EMAIL_CEREMONY_SOURCE_LIMIT);
  return source.allowed;
}

function loginAuditSource(expectedRole?: RequiredLoginRole): string {
  return expectedRole === "ADMIN" ? "hub-login" : expectedRole === "USER" ? "portal-login" : "local-login";
}

export async function verifyLoginEmailCode(ceremonyId: string, code: string, deviceToken: string, now = new Date(), expectedRole?: RequiredLoginRole): Promise<{ requiresTotp: boolean; session: CreatedLoginSession | null }> {
  if (!isCeremonyId(ceremonyId) || !isDeviceToken(deviceToken) || !/^\d{6}$/.test(code)) throw new SecurityMutationError();
  try {
    const result = await prisma.$transaction(async (transaction) => {
      const challenge = await transaction.deviceChallenge.findUnique({ where: { ceremonyId }, select: { id: true, userId: true, deviceIdHash: true, emailAddressHash: true, codeHash: true, requiresTotp: true, status: true, expiresAt: true, consumedAt: true, user: { select: { email: true, emailNormalized: true, role: true, isActive: true, accountStatus: true, secondFactorMethod: true, totpFactor: { select: { status: true } } } } } });
      const requiresTotpNow = challenge?.user.secondFactorMethod === "TOTP" && challenge.user.totpFactor?.status === "ACTIVE";
      if (!challenge || (expectedRole && challenge.user.role !== expectedRole) || challenge.deviceIdHash !== hashDeviceToken(deviceToken) || challenge.emailAddressHash !== hashEmailAddress(challenge.user.emailNormalized ?? challenge.user.email) || !challenge.user.isActive || challenge.user.accountStatus !== "ACTIVE" || challenge.requiresTotp !== requiresTotpNow || challenge.status !== "PENDING" || challenge.consumedAt || challenge.expiresAt <= now || !await lockActiveLoginAccountInTransaction(transaction, challenge.userId, expectedRole)) throw new SecurityMutationError();
      const accountAttempt = await consumeRateLimitAttemptInTransaction(transaction, `login-verification-user:${challenge.userId}`, now);
      const ceremonyAttempt = await consumeRateLimitAttemptInTransaction(transaction, `login-verification:${challenge.id}`, now);
      if (!accountAttempt.allowed || !ceremonyAttempt.allowed) return { kind: "REJECTED" as const };
      if (!verifySecurityCode(code, challenge.codeHash)) return { kind: "INVALID" as const };
      await refundRateLimitAttemptInTransaction(transaction, `login-verification-user:${challenge.userId}`, accountAttempt.windowStartedAt, 5);
      await refundRateLimitAttemptInTransaction(transaction, `login-verification:${challenge.id}`, ceremonyAttempt.windowStartedAt, 5);
      const verified = await transaction.deviceChallenge.updateMany({ where: { id: challenge.id, deviceIdHash: challenge.deviceIdHash, emailAddressHash: challenge.emailAddressHash, status: "PENDING", consumedAt: null, expiresAt: { gt: now } }, data: { status: "VERIFIED", emailVerifiedAt: now } });
      if (verified.count !== 1) throw new SecurityMutationError();
      await transaction.user.update({ where: { id: challenge.userId }, data: { emailVerifiedAt: now } });
      // A TOTP account's device is trusted only after the TOTP step completes (verifyLoginTotpCode).
      if (!challenge.requiresTotp) await trustLoginDevice(transaction, challenge.userId, challenge.deviceIdHash, now);
      const session = challenge.requiresTotp
        ? null
        : await consumeChallengeAndCreateSession(transaction, challenge.id, challenge.userId, challenge.deviceIdHash, now, ["pwd", "otp", "mfa"]);
      await writeAuditLogInTransaction(transaction, {
        eventType: "DEVICE_VERIFIED",
        result: "SUCCESS",
        actorUserId: challenge.userId,
        resource: "identity.device",
        message: "Login security ceremony verified.",
        metadata: { source: loginAuditSource(expectedRole), ceremonyRef: hashAuditIdentifier(ceremonyId) }
      });
      return { kind: "SUCCESS" as const, value: { requiresTotp: challenge.requiresTotp, session } };
    }, { isolationLevel: "Serializable" });
    if (result.kind !== "SUCCESS") throw new SecurityMutationError();
    return result.value;
  } catch {
    throw new SecurityMutationError();
  }
}

export async function verifyLoginTotpCode(ceremonyId: string, code: string, deviceToken: string, now = new Date(), expectedRole?: RequiredLoginRole): Promise<CreatedLoginSession> {
  if (!isCeremonyId(ceremonyId) || !isDeviceToken(deviceToken)) throw new SecurityMutationError();
  try {
    const result = await prisma.$transaction(async (transaction) => {
      const challenge = await transaction.deviceChallenge.findUnique({ where: { ceremonyId }, select: { id: true, userId: true, deviceIdHash: true, emailAddressHash: true, emailVerifiedAt: true, requiresTotp: true, status: true, expiresAt: true, consumedAt: true, user: { select: { email: true, emailNormalized: true, role: true, isActive: true, accountStatus: true, totpFactor: { select: { id: true, secretCiphertext: true, status: true, lastUsedStep: true } } } } } });
      if (!challenge || (expectedRole && challenge.user.role !== expectedRole) || challenge.deviceIdHash !== hashDeviceToken(deviceToken) || challenge.emailAddressHash !== hashEmailAddress(challenge.user.emailNormalized ?? challenge.user.email) || !challenge.requiresTotp || !challenge.user.isActive || challenge.user.accountStatus !== "ACTIVE" || challenge.status !== "VERIFIED" || challenge.consumedAt || challenge.expiresAt <= now || challenge.user.totpFactor?.status !== "ACTIVE" || !await lockActiveLoginAccountInTransaction(transaction, challenge.userId, expectedRole)) throw new SecurityMutationError();
      const accountAttempt = await consumeRateLimitAttemptInTransaction(transaction, `login-verification-user:${challenge.userId}`, now);
      const ceremonyAttempt = await consumeRateLimitAttemptInTransaction(transaction, `login-verification:${challenge.id}`, now);
      if (!accountAttempt.allowed || !ceremonyAttempt.allowed) return { kind: "REJECTED" as const };
      const factor = challenge.user.totpFactor;
      const step = verifyTotpCode(decryptTotpSecret(factor.secretCiphertext), code, now, factor.lastUsedStep);
      if (step === null) return { kind: "INVALID" as const };
      await refundRateLimitAttemptInTransaction(transaction, `login-verification-user:${challenge.userId}`, accountAttempt.windowStartedAt, 5);
      await refundRateLimitAttemptInTransaction(transaction, `login-verification:${challenge.id}`, ceremonyAttempt.windowStartedAt, 5);
      const claimed = await transaction.totpFactor.updateMany({ where: { id: factor.id, status: "ACTIVE", lastUsedStep: factor.lastUsedStep }, data: { lastUsedStep: step } });
      if (claimed.count !== 1) throw new SecurityMutationError();
      await trustLoginDevice(transaction, challenge.userId, challenge.deviceIdHash, now);
      const methods = ["pwd", "otp", "mfa"];
      const session = await consumeChallengeAndCreateSession(transaction, challenge.id, challenge.userId, challenge.deviceIdHash, now, methods);
      await writeAuditLogInTransaction(transaction, {
        eventType: "DEVICE_VERIFIED",
        result: "SUCCESS",
        actorUserId: challenge.userId,
        resource: "identity.2fa",
        message: "TOTP login verification succeeded.",
        metadata: { source: loginAuditSource(expectedRole), ceremonyRef: hashAuditIdentifier(ceremonyId) }
      });
      return { kind: "SUCCESS" as const, value: session };
    }, { isolationLevel: "Serializable" });
    if (result.kind !== "SUCCESS") throw new SecurityMutationError();
    return result.value;
  } catch {
    throw new SecurityMutationError();
  }
}

export async function verifyLoginRecoveryCode(ceremonyId: string, code: string, deviceToken: string, now = new Date(), expectedRole?: RequiredLoginRole): Promise<{ kind: "EMAIL_REQUIRED" } | { kind: "RECOVERED"; session: CreatedLoginSession }> {
  if (!isCeremonyId(ceremonyId) || !isDeviceToken(deviceToken) || code.length > 32) throw new SecurityMutationError();
  const normalizedCode = normalizeRecoveryCodeInput(code);
  try {
    const result = await prisma.$transaction(async (transaction) => {
      const challenge = await transaction.deviceChallenge.findUnique({ where: { ceremonyId }, select: { id: true, userId: true, deviceIdHash: true, emailAddressHash: true, emailVerifiedAt: true, requiresTotp: true, status: true, expiresAt: true, consumedAt: true, user: { select: { email: true, emailNormalized: true, displayName: true, role: true, isActive: true, accountStatus: true, secondFactorMethod: true, totpFactor: { select: { id: true, status: true, lastUsedStep: true } } } } } });
      if (!challenge || (expectedRole && challenge.user.role !== expectedRole) || challenge.deviceIdHash !== hashDeviceToken(deviceToken) || challenge.emailAddressHash !== hashEmailAddress(challenge.user.emailNormalized ?? challenge.user.email) || !challenge.requiresTotp || challenge.user.secondFactorMethod !== "TOTP" || !challenge.user.isActive || challenge.user.accountStatus !== "ACTIVE" || challenge.user.totpFactor?.status !== "ACTIVE" || challenge.status !== "VERIFIED" || challenge.consumedAt || challenge.expiresAt <= now || !await lockActiveLoginAccountInTransaction(transaction, challenge.userId, expectedRole)) throw new SecurityMutationError();

      if (!challenge.emailVerifiedAt) {
        // No recovery code is checked in this step, so it spends the email-ceremony budget, not verification attempts.
        // This step is reachable only from a TOTP-only ceremony, i.e. a device that is already trusted.
        if (!isValidRecoveryCodeInput(code)) throw new SecurityMutationError();
        if (!await consumeLoginEmailCeremonyQuota(transaction, challenge.userId, challenge.deviceIdHash, now)) return { kind: "REJECTED" as const };
        const emailCode = generateNumericCode();
        const reopened = await transaction.deviceChallenge.updateMany({ where: { id: challenge.id, deviceIdHash: challenge.deviceIdHash, status: "VERIFIED", emailVerifiedAt: null, consumedAt: null, expiresAt: { gt: now } }, data: { codeHash: hashSecurityCode(emailCode), status: "PENDING" } });
        if (reopened.count !== 1) throw new SecurityMutationError();
        await enqueueEmailMessageForClient(transaction, {
          idempotencyKey: `security-ceremony-email-proof:${randomBytes(18).toString("base64url")}`,
          kind: "EMAIL_TWO_FACTOR",
          recipientEmail: challenge.user.email,
          locale: "pt-BR",
          payload: { publicValues: { displayName: challenge.user.displayName ?? "" }, protectedValues: { code: emailCode } }
        });
        return { kind: "EMAIL_REQUIRED" as const };
      }

      const accountAttempt = await consumeRateLimitAttemptInTransaction(transaction, `login-verification-user:${challenge.userId}`, now);
      const ceremonyAttempt = await consumeRateLimitAttemptInTransaction(transaction, `login-verification:${challenge.id}`, now);
      if (!accountAttempt.allowed || !ceremonyAttempt.allowed) return { kind: "REJECTED" as const };
      if (!isValidRecoveryCodeInput(code)) return { kind: "INVALID" as const };

      const factor = challenge.user.totpFactor;
      const recoveryCode = await transaction.recoveryCode.findFirst({ where: { userId: challenge.userId, codeHash: hashRecoveryCode(normalizedCode), usedAt: null }, select: { id: true } });
      if (!recoveryCode) return { kind: "INVALID" as const };
      const consumedCode = await transaction.recoveryCode.updateMany({ where: { id: recoveryCode.id, usedAt: null }, data: { usedAt: now } });
      if (consumedCode.count !== 1) return { kind: "INVALID" as const };

      await refundRateLimitAttemptInTransaction(transaction, `login-verification-user:${challenge.userId}`, accountAttempt.windowStartedAt, 5);
      await refundRateLimitAttemptInTransaction(transaction, `login-verification:${challenge.id}`, ceremonyAttempt.windowStartedAt, 5);
      const disabled = await transaction.totpFactor.updateMany({ where: { id: factor.id, status: "ACTIVE", lastUsedStep: factor.lastUsedStep }, data: { status: "REVOKED" } });
      if (disabled.count !== 1) throw new SecurityMutationError();
      await transaction.user.update({ where: { id: challenge.userId }, data: { secondFactorMethod: "EMAIL" } });
      await transaction.recoveryCode.deleteMany({ where: { userId: challenge.userId } });
      await transaction.securityElevation.updateMany({ where: { userId: challenge.userId, status: { in: ["PENDING", "ACTIVE"] } }, data: { status: "REVOKED", revokedAt: now } });
      await transaction.session.updateMany({ where: { userId: challenge.userId, revokedAt: null }, data: { revokedAt: now } });
      await transaction.trustedDevice.updateMany({ where: { userId: challenge.userId, status: "TRUSTED" }, data: { status: "REVOKED", revokedAt: now, rememberedUntil: null, strongVerifiedAt: null } });
      await revokeUserOidcArtifactsInTransaction(transaction, challenge.userId);
      await revokeLoginChallenges(transaction, challenge.userId, undefined, challenge.id);
      await writeAuditLogInTransaction(transaction, { eventType: "SECOND_FACTOR_RECOVERED", result: "SUCCESS", actorUserId: challenge.userId, resource: "identity.2fa", message: "Lost authenticator recovered with email proof and a one-time recovery code.", metadata: { targetRef: hashAuditIdentifier(challenge.userId), ceremonyRef: hashAuditIdentifier(ceremonyId) } });
      const session = await consumeChallengeAndCreateSession(transaction, challenge.id, challenge.userId, challenge.deviceIdHash, now, ["pwd", "otp", "mfa"], false);
      return { kind: "RECOVERED" as const, session };
    }, { isolationLevel: "Serializable" });

    if (result.kind === "EMAIL_REQUIRED") return result;
    if (result.kind !== "RECOVERED") throw new SecurityMutationError();
    return result;
  } catch {
    throw new SecurityMutationError();
  }
}

export async function listTrustedDevices(userId: string, now = new Date()) {
  return prisma.trustedDevice.findMany({ where: { userId, status: "TRUSTED", revokedAt: null, createdAt: { gt: new Date(now.getTime() - DEVICE_TRUST_TTL_MS) } }, orderBy: { lastSeenAt: "desc" }, take: 25, select: { deviceKey: true, label: true, lastSeenAt: true, createdAt: true } });
}

export async function revokeTrustedDevice(userId: string, deviceKey: string): Promise<void> {
  if (!isCeremonyId(deviceKey)) throw new SecurityMutationError();
  const now = new Date();
  await prisma.$transaction(async (transaction) => {
    const device = await transaction.trustedDevice.findFirst({ where: { deviceKey, userId }, select: { deviceIdHash: true } });
    const revoked = await transaction.trustedDevice.updateMany({ where: { deviceKey, userId, status: "TRUSTED" }, data: { status: "REVOKED", revokedAt: now, rememberedUntil: null, strongVerifiedAt: null } });
    if (!device || revoked.count !== 1) throw new SecurityMutationError();
    await revokeLoginChallenges(transaction, userId, device.deviceIdHash);
    await writeAuditLogInTransaction(transaction, { eventType: "TRUSTED_DEVICE_REVOKED", result: "SUCCESS", actorUserId: userId, resource: "identity.device", message: "Trusted device revoked.", metadata: { deviceRef: hashAuditIdentifier(deviceKey) } });
  });
}

export async function requestAccountRecovery(email: string, locale: EmailLocale, now = new Date(), trustedClientAddress?: string): Promise<void> {
  return withResponseFloor(() => requestAccountRecoveryForRole("USER", email, locale, now, trustedClientAddress));
}

export async function requestAdministrativeAccountRecovery(email: string, locale: EmailLocale, now = new Date(), trustedClientAddress?: string): Promise<void> {
  return withResponseFloor(() => requestAccountRecoveryForRole("ADMIN", email, locale, now, trustedClientAddress));
}

// Hides the extra database work done for an existing account behind a fixed minimum duration.
async function withResponseFloor(operation: () => Promise<void>): Promise<void> {
  const startedAt = Date.now();
  try {
    await operation();
  } finally {
    const remaining = startedAt + RECOVERY_REQUEST_RESPONSE_FLOOR_MS - Date.now();
    if (remaining > 0) await new Promise((resolve) => setTimeout(resolve, remaining));
  }
}

async function requestAccountRecoveryForRole(expectedRole: AccountRecoveryRole, email: string, locale: EmailLocale, now: Date, trustedClientAddress?: string): Promise<void> {
  if (process.env.NODE_ENV === "production" && !isTrustedClientAddress(trustedClientAddress)) return;
  if (trustedClientAddress) {
    if (!isTrustedClientAddress(trustedClientAddress)) return;
    const sourceAttempt = await prisma.$transaction((transaction) => consumeRateLimitAttemptInTransaction(transaction, `recovery-source:${expectedRole}:${trustedClientAddress}`, now, 30));
    if (!sourceAttempt.allowed) return;
  }
  const normalizedEmail = email.trim().toLowerCase();
  if (normalizedEmail.length > 320 || !/^\S+@\S+$/.test(normalizedEmail)) return;
  const addressAttempt = await prisma.$transaction((transaction) =>
    consumeRateLimitAttemptInTransaction(transaction, `account-recovery-address:${expectedRole}:${normalizedEmail}`, now)
  );
  if (!addressAttempt.allowed) return;
  const actionBase = getRecoveryActionBaseUrl(expectedRole);
  if (!actionBase) return;
  const user = await prisma.user.findUnique({ where: { emailNormalized: normalizedEmail }, select: { id: true, email: true, emailNormalized: true, displayName: true, role: true, isActive: true, accountStatus: true } });
  if (!user || !isAccountRecoveryEligible(user, expectedRole)) return;
  try {
    const requested = await prisma.$transaction(async (transaction) => {
      const rateLimitIdentifier = `account-recovery:${expectedRole}:${normalizedEmail}`;
      await lockRateLimitIdentifierInTransaction(transaction, rateLimitIdentifier);
      if (!await lockActiveRecoveryAccountInTransaction(transaction, user.id, expectedRole)) return false;
      const latestRequest = await transaction.accountRecoveryRequest.findFirst({ where: { userId: user.id }, orderBy: { createdAt: "desc" }, select: { createdAt: true } });
      if (latestRequest && latestRequest.createdAt.getTime() + RECOVERY_REQUEST_COOLDOWN_MS > now.getTime()) return false;
      // An anonymous request never expires another request. While the owner holds an email-verified
      // request (awaiting approval or approved), a new request is not created at all; the owner
      // continues with the emailed approval link. Unverified requests coexist until one is verified.
      const ownerProven = await transaction.accountRecoveryRequest.findFirst({ where: { userId: user.id, emailVerifiedAt: { not: null }, status: { in: ["PENDING", "APPROVED"] }, expiresAt: { gt: now } }, select: { id: true } });
      if (ownerProven) return false;
      const attempt = await consumeRateLimitAttemptInTransaction(transaction, rateLimitIdentifier, now);
      if (!attempt.allowed) return false;
      const requestKey = randomBytes(24).toString("base64url");
      const code = generateNumericCode();
      const recoveryRequest = await transaction.accountRecoveryRequest.create({ data: { requestKeyHash: hashRecoveryRequestKey(requestKey), emailAddressHash: hashEmailAddress(user.emailNormalized ?? user.email), userId: user.id, emailChallengeHash: hashSecurityCode(code), expiresAt: new Date(now.getTime() + RECOVERY_REQUEST_TTL_MS), purpose: "RECOVERY" } });
      const actionUrl = new URL(`/recover/open?request=${encodeURIComponent(requestKey)}`, actionBase).toString();
      await enqueueEmailMessageForClient(transaction, { idempotencyKey: `account-recovery:${randomBytes(24).toString("base64url")}`, kind: "ACCOUNT_RECOVERY", recipientEmail: user.email, locale, payload: { publicValues: { displayName: user.displayName ?? "" }, protectedValues: { code, actionUrl } } });
      await writeAuditLogInTransaction(transaction, { eventType: "ACCOUNT_RECOVERY_REQUESTED", result: "SUCCESS", resource: "identity.recovery", message: "Account recovery requested.", metadata: { targetRef: hashAuditIdentifier(user.id), requestRef: hashAuditIdentifier(recoveryRequest.id) } });
      return true;
    }, { isolationLevel: "Serializable" });
    if (!requested) return;
  } catch {
    throw new SecurityMutationError();
  }
}

export async function getAccountRecoveryRequestId(requestKey: string, now = new Date(), expectedRole: AccountRecoveryRole = "USER"): Promise<{ id: string; expiresAt: Date; purpose: "RECOVERY" | "INVITATION" } | null> {
  if (!isCeremonyId(requestKey)) return null;
  const request = await prisma.accountRecoveryRequest.findUnique({ where: { requestKeyHash: hashRecoveryRequestKey(requestKey) }, select: { id: true, status: true, expiresAt: true, purpose: true, user: { select: { role: true, isActive: true, accountStatus: true } } } });
  if (!request || !isAccountRecoveryEligible(request.user, expectedRole) || request.status === "CONSUMED" || request.status === "REJECTED" || request.status === "EXPIRED" || request.expiresAt <= now) return null;
  return { id: request.id, expiresAt: request.expiresAt, purpose: request.purpose };
}

export async function getAccountRecoveryState(requestId: string, requestKey: string, now = new Date(), expectedRole: AccountRecoveryRole = "USER") {
  if (!isDatabaseId(requestId) || !isCeremonyId(requestKey)) return null;
  const request = await prisma.accountRecoveryRequest.findUnique({ where: { id: requestId }, select: { id: true, requestKeyHash: true, emailAddressHash: true, status: true, emailVerifiedAt: true, expiresAt: true, purpose: true, user: { select: { emailNormalized: true, email: true, role: true, isActive: true, accountStatus: true } } } });
  if (!request || !safeEqual(request.requestKeyHash, hashRecoveryRequestKey(requestKey)) || request.emailAddressHash !== hashEmailAddress(request.user.emailNormalized ?? request.user.email) || !isAccountRecoveryEligible(request.user, expectedRole) || request.expiresAt <= now || request.status === "CONSUMED" || request.status === "REJECTED" || request.status === "EXPIRED") return null;
  return { id: request.id, status: request.status, emailVerified: Boolean(request.emailVerifiedAt), expiresAt: request.expiresAt, purpose: request.purpose };
}

export async function verifyAccountRecoveryEmail(requestId: string, requestKey: string, code: string, now = new Date(), expectedRole: AccountRecoveryRole = "USER"): Promise<void> {
  if (!isDatabaseId(requestId) || !isCeremonyId(requestKey) || !/^\d{6}$/.test(code)) throw new SecurityMutationError();
  try {
    const result = await prisma.$transaction(async (transaction) => {
      const initial = await transaction.accountRecoveryRequest.findUnique({ where: { id: requestId }, select: { userId: true, user: { select: { role: true } } } });
      if (!initial || initial.user.role !== expectedRole || !await lockActiveRecoveryAccountInTransaction(transaction, initial.userId, expectedRole)) throw new SecurityMutationError();
      const request = await transaction.accountRecoveryRequest.findUnique({ where: { id: requestId }, select: { id: true, userId: true, requestKeyHash: true, emailAddressHash: true, emailChallengeHash: true, emailVerifiedAt: true, status: true, expiresAt: true, user: { select: { email: true, emailNormalized: true, role: true, isActive: true, accountStatus: true } } } });
      if (!request || !safeEqual(request.requestKeyHash, hashRecoveryRequestKey(requestKey)) || request.status !== "PENDING" || request.emailVerifiedAt || request.expiresAt <= now || request.emailAddressHash !== hashEmailAddress(request.user.emailNormalized ?? request.user.email) || !isAccountRecoveryEligible(request.user, expectedRole)) throw new SecurityMutationError();
      const accountAttempt = await consumeRateLimitAttemptInTransaction(transaction, `account-recovery-verification-user:${request.userId}`, now);
      const requestAttempt = await consumeRateLimitAttemptInTransaction(transaction, `account-recovery-verification:${request.id}`, now);
      if (!accountAttempt.allowed || !requestAttempt.allowed) return { kind: "REJECTED" as const };
      if (!verifySecurityCode(code, request.emailChallengeHash)) return { kind: "INVALID" as const };
      const verified = await transaction.accountRecoveryRequest.updateMany({ where: { id: request.id, requestKeyHash: request.requestKeyHash, status: "PENDING", emailVerifiedAt: null, expiresAt: { gt: now } }, data: { emailVerifiedAt: now } });
      if (verified.count !== 1) throw new SecurityMutationError();
      await transaction.accountRecoveryRequest.updateMany({ where: { userId: request.userId, id: { not: request.id }, status: "PENDING", emailVerifiedAt: null }, data: { status: "EXPIRED" } });
      await transaction.user.update({ where: { id: request.userId }, data: { emailVerifiedAt: now } });
      await writeAuditLogInTransaction(transaction, { eventType: "ACCOUNT_RECOVERY_EMAIL_VERIFIED", result: "SUCCESS", resource: "identity.recovery", message: "Account recovery email verified.", metadata: { requestRef: hashAuditIdentifier(requestId) } });
      return { kind: "SUCCESS" as const };
    });
    if (result.kind !== "SUCCESS") throw new SecurityMutationError();
  } catch {
    throw new SecurityMutationError();
  }
}

export async function listPendingAccountRecoveries(actor: { id: string; role: string }) {
  await requireAdmin(actor);
  return prisma.accountRecoveryRequest.findMany({
    where: getPendingAccountRecoveryQueueWhere(new Date(), actor.id),
    orderBy: { createdAt: "asc" },
    take: 50,
    select: { id: true, createdAt: true, expiresAt: true, emailVerifiedAt: true, user: { select: { emailNormalized: true, displayName: true, role: true } } }
  });
}

export function getPendingAccountRecoveryQueueWhere(now: Date, excludeTargetUserId?: string): Prisma.AccountRecoveryRequestWhereInput {
  return { status: "PENDING", emailVerifiedAt: { not: null }, expiresAt: { gt: now }, user: { role: { in: ["USER", "ADMIN"] }, isActive: true, accountStatus: "ACTIVE", ...(excludeTargetUserId ? { id: { not: excludeTargetUserId } } : {}) } };
}

export function getApprovedAccountRecoveryExpiry(now: Date): Date {
  return new Date(now.getTime() + RECOVERY_REQUEST_TTL_MS);
}

export async function approveAccountRecovery(actor: { id: string; role: string }, sessionId: string, requestId: string, now = new Date()): Promise<void> {
  await requireAdmin(actor);
  if (!isDatabaseId(requestId)) throw new SecurityMutationError();
  const requestKey = randomBytes(24).toString("base64url");
  const result = await prisma.$transaction(async (transaction) => {
    await requireSecurityElevationInTransaction(transaction, actor.id, sessionId, "ACCOUNT_STATE_CHANGE", now);
    const initial = await transaction.accountRecoveryRequest.findUnique({ where: { id: requestId }, select: { userId: true, user: { select: { role: true } } } });
    if (!initial || !isAccountRecoveryRole(initial.user.role) || !await lockActiveRecoveryAccountInTransaction(transaction, initial.userId, initial.user.role)) throw new SecurityMutationError();
    const request = await transaction.accountRecoveryRequest.findUnique({ where: { id: requestId }, select: { id: true, requestKeyHash: true, emailAddressHash: true, userId: true, status: true, emailVerifiedAt: true, expiresAt: true, user: { select: { email: true, emailNormalized: true, displayName: true, role: true, isActive: true, accountStatus: true } } } });
    if (!request || request.status !== "PENDING" || !request.emailVerifiedAt || request.expiresAt <= now || request.emailAddressHash !== hashEmailAddress(request.user.emailNormalized ?? request.user.email) || !canApproveAccountRecovery(actor, { id: request.userId, ...request.user })) throw new SecurityMutationError();
    const actionBase = getRecoveryActionBaseUrl(request.user.role);
    if (!actionBase) throw new SecurityMutationError();
    const approved = await transaction.accountRecoveryRequest.updateMany({ where: { id: request.id, requestKeyHash: request.requestKeyHash, status: "PENDING", emailVerifiedAt: { not: null }, expiresAt: { gt: now } }, data: { status: "APPROVED", requestKeyHash: hashRecoveryRequestKey(requestKey), reviewedByUserId: actor.id, approvedAt: now, expiresAt: getApprovedAccountRecoveryExpiry(now) } });
    if (approved.count !== 1) return approved;
    await transaction.accountRecoveryRequest.updateMany({ where: { userId: request.userId, id: { not: request.id }, status: "PENDING" }, data: { status: "EXPIRED" } });
    const actionUrl = new URL(`/recover/open?request=${encodeURIComponent(requestKey)}`, actionBase).toString();
    await enqueueEmailMessageForClient(transaction, { idempotencyKey: `account-recovery-approved:${randomBytes(24).toString("base64url")}`, kind: "ACCOUNT_RECOVERY", recipientEmail: request.user.email, locale: "pt-BR", payload: { publicValues: { displayName: request.user.displayName ?? "" }, protectedValues: { actionUrl } } });
    await writeAuditLogInTransaction(transaction, { eventType: "ACCOUNT_RECOVERY_APPROVED", result: "SUCCESS", actorUserId: actor.id, resource: "identity.recovery", message: "Account recovery approved.", metadata: { requestRef: hashAuditIdentifier(requestId) } });
    return approved;
  }, { isolationLevel: "Serializable" });
  if (result.count !== 1) throw new SecurityMutationError();
}

export async function consumeApprovedAccountRecovery(requestId: string, requestKey: string, newPassword: string, now = new Date(), expectedRole: AccountRecoveryRole = "USER"): Promise<void> {
  if (!isDatabaseId(requestId) || !isCeremonyId(requestKey) || !isAcceptableRecoveryPassword(expectedRole, newPassword)) throw new SecurityMutationError();
  const requestKeyHash = hashRecoveryRequestKey(requestKey);
  const request = await prisma.accountRecoveryRequest.findUnique({ where: { id: requestId }, select: { id: true, requestKeyHash: true, userId: true, emailAddressHash: true, status: true, expiresAt: true, user: { select: { email: true, emailNormalized: true, role: true, isActive: true, accountStatus: true } } } });
  if (!request || !isAccountRecoveryEligible(request.user, expectedRole) || !safeEqual(request.requestKeyHash, requestKeyHash) || request.status !== "APPROVED" || request.expiresAt <= now || request.emailAddressHash !== hashEmailAddress(request.user.emailNormalized ?? request.user.email)) throw new SecurityMutationError();
  const attempts = await prisma.$transaction(async (transaction) => {
    const account = await consumeRateLimitAttemptInTransaction(transaction, `account-recovery-completion-user:${request.userId}`, now);
    const ceremony = await consumeRateLimitAttemptInTransaction(transaction, `account-recovery-completion:${request.id}`, now);
    return account.allowed && ceremony.allowed;
  });
  if (!attempts) throw new SecurityMutationError();
  if (expectedRole === "ADMIN") {
    // The normal ADMIN password must stay independent from the administrative credential.
    const administrative = await prisma.administrativeCredential.findUnique({ where: { userId: request.userId }, select: { passwordHash: true, status: true } });
    if (administrative?.status === "ACTIVE" && await verifyPassword(administrative.passwordHash, newPassword)) throw new SecurityMutationError();
  }
  const newPasswordHash = await hashPassword(newPassword);
  await prisma.$transaction(async (transaction) => {
    if (!await lockActiveRecoveryAccountInTransaction(transaction, request.userId, expectedRole)) throw new SecurityMutationError();
    await lockAndExpireSiblingAccountRecoveriesInTransaction(transaction, request.userId, request.id);
    const current = await transaction.accountRecoveryRequest.findUnique({ where: { id: request.id }, select: { userId: true, requestKeyHash: true, emailAddressHash: true, status: true, expiresAt: true, user: { select: { email: true, emailNormalized: true, displayName: true, role: true, isActive: true, accountStatus: true } } } });
    if (!current || current.userId !== request.userId || !safeEqual(current.requestKeyHash, requestKeyHash) || current.emailAddressHash !== hashEmailAddress(current.user.emailNormalized ?? current.user.email) || current.status !== "APPROVED" || current.expiresAt <= now || !isAccountRecoveryEligible(current.user, expectedRole)) throw new SecurityMutationError();
    const claimed = await transaction.accountRecoveryRequest.updateMany({ where: { id: request.id, requestKeyHash, emailAddressHash: request.emailAddressHash, status: "APPROVED", expiresAt: { gt: now } }, data: { status: "CONSUMED", consumedAt: now } });
    if (claimed.count !== 1) throw new SecurityMutationError();
    await transaction.user.update({ where: { id: request.userId }, data: { passwordHash: newPasswordHash, emailVerifiedAt: now } });
    await enqueueEmailMessageForClient(transaction, { idempotencyKey: `account-recovery-password-changed:${request.id}`, kind: "PASSWORD_CHANGED", recipientEmail: current.user.email, locale: "pt-BR", payload: { publicValues: { displayName: current.user.displayName ?? "" }, protectedValues: {} } });
    await transaction.session.updateMany({ where: { userId: request.userId, revokedAt: null }, data: { revokedAt: now } });
    await transaction.securityElevation.updateMany({ where: { userId: request.userId, status: { in: ["PENDING", "ACTIVE"] } }, data: { status: "REVOKED", revokedAt: now } });
    await transaction.trustedDevice.updateMany({ where: { userId: request.userId, status: "TRUSTED" }, data: { status: "REVOKED", revokedAt: now, rememberedUntil: null, strongVerifiedAt: null } });
    await revokeLoginChallenges(transaction, request.userId);
    await revokeUserOidcArtifactsInTransaction(transaction, request.userId);
    await writeAuditLogInTransaction(transaction, { eventType: "ACCOUNT_RECOVERY_CONSUMED", result: "SUCCESS", resource: "identity.recovery", message: "Account recovery consumed.", metadata: { requestRef: hashAuditIdentifier(requestId) } });
  }, { isolationLevel: "Serializable" });
}

async function consumeChallengeAndCreateSession(transaction: Prisma.TransactionClient, challengeId: string, userId: string, deviceIdHash: string, now: Date, authenticationMethods: string[] = ["pwd"], rememberDevice = true): Promise<CreatedLoginSession> {
  const consumed = await transaction.deviceChallenge.updateMany({ where: { id: challengeId, status: "VERIFIED", consumedAt: null, expiresAt: { gt: now } }, data: { consumedAt: now } });
  if (consumed.count !== 1) throw new SecurityMutationError();
  if (rememberDevice) await establishRememberedLoginGrant(transaction, userId, deviceIdHash, now);
  return createSessionInTransaction(transaction, userId, now, authenticationMethods);
}

async function createSessionInTransaction(transaction: Prisma.TransactionClient, userId: string, now: Date, authenticationMethods: string[] = ["pwd"]): Promise<CreatedLoginSession> {
  const token = generateSessionToken();
  const expiresAt = getSessionExpiresAt(now);
  const session = await transaction.session.create({ data: { sessionKey: randomBytes(24).toString("base64url"), userId, tokenHash: hashSessionToken(token), authenticationMethods, expiresAt, createdAt: now }, select: { id: true } });
  return { id: session.id, userId, token, expiresAt };
}

export type CreatedLoginSession = { id: string; userId: string; token: string; expiresAt: Date };

export async function invalidateRememberedLoginGrantsForUser(userId: string): Promise<void> {
  await prisma.$transaction(async (transaction) => {
    await invalidateRememberedLoginGrants(transaction, userId);
    await revokeLoginChallenges(transaction, userId);
  });
}

export async function invalidateRememberedLoginGrants(transaction: Prisma.TransactionClient, userId: string): Promise<void> {
  await transaction.trustedDevice.updateMany({ where: { userId }, data: { rememberedUntil: null, strongVerifiedAt: null } });
}

async function trustLoginDevice(transaction: Prisma.TransactionClient, userId: string, deviceIdHash: string, now: Date): Promise<void> {
  await transaction.trustedDevice.upsert({ where: { userId_deviceIdHash: { userId, deviceIdHash } }, update: { status: "TRUSTED", revokedAt: null, lastSeenAt: now, rememberedUntil: null, strongVerifiedAt: null }, create: { deviceKey: randomBytes(24).toString("base64url"), userId, deviceIdHash, status: "TRUSTED", lastSeenAt: now } });
}

async function establishRememberedLoginGrant(transaction: Prisma.TransactionClient, userId: string, deviceIdHash: string, now: Date): Promise<void> {
  const updated = await transaction.trustedDevice.updateMany({
    where: { userId, deviceIdHash, status: "TRUSTED", revokedAt: null },
    data: { rememberedUntil: new Date(now.getTime() + REMEMBERED_BROWSER_TTL_MS), strongVerifiedAt: now, lastSeenAt: now }
  });
  if (updated.count !== 1) throw new SecurityMutationError();
}

export async function revokeLoginChallenges(transaction: Prisma.TransactionClient, userId: string, deviceIdHash?: string, exceptChallengeId?: string): Promise<void> {
  await transaction.deviceChallenge.updateMany({
    where: {
      userId,
      ...(deviceIdHash ? { deviceIdHash } : {}),
      ...(exceptChallengeId ? { id: { not: exceptChallengeId } } : {}),
      status: { in: ["PENDING", "VERIFIED"] }
    },
    data: { status: "REVOKED" }
  });
}

// Deletes every stored OIDC artifact (provider sessions, grants, codes, opaque tokens) for the account.
// Callers hold the account row lock, and the issuer adapter requires the grant row to still exist when
// it stores a code or token, so an exchange racing this revocation cannot persist a fresh artifact.
// Already-issued signed ID tokens cannot be recalled; they expire on their own TTL.
export async function revokeUserOidcArtifactsInTransaction(transaction: Prisma.TransactionClient, userId: string): Promise<number> {
  const result = await transaction.oidcArtifact.deleteMany({ where: { accountIdHash: hashOidcIdentifier(userId) } });
  return result.count;
}

export async function revokeUserAuthenticationProofsInTransaction(transaction: Prisma.TransactionClient, userId: string, now: Date): Promise<void> {
  await transaction.trustedDevice.updateMany({
    where: { userId, status: "TRUSTED" },
    data: { status: "REVOKED", revokedAt: now, rememberedUntil: null, strongVerifiedAt: null }
  });
  await revokeLoginChallenges(transaction, userId);
  await transaction.accountRecoveryRequest.updateMany({
    where: { userId, status: { in: ["PENDING", "APPROVED"] } },
    data: { status: "EXPIRED" }
  });
}

export async function lockActiveRecoveryAccountInTransaction(transaction: Prisma.TransactionClient, userId: string, expectedRole: AccountRecoveryRole = "USER"): Promise<boolean> {
  const accounts = await transaction.$queryRaw<Array<{ id: string }>>`
    SELECT "id"
    FROM "User"
    WHERE "id" = ${userId}
      AND "role" = ${expectedRole}::"UserRole"
      AND "isActive" = TRUE
      AND "accountStatus" = 'ACTIVE'
    FOR UPDATE
  `;
  return accounts.length === 1;
}

export async function lockActiveLoginAccountInTransaction(transaction: Prisma.TransactionClient, userId: string, expectedRole?: RequiredLoginRole): Promise<boolean> {
  const accounts = expectedRole
    ? await transaction.$queryRaw<Array<{ id: string }>>`
      SELECT "id"
      FROM "User"
      WHERE "id" = ${userId}
        AND "role" = ${expectedRole}::"UserRole"
        AND "isActive" = TRUE
        AND "accountStatus" = 'ACTIVE'
      FOR UPDATE
    `
    : await transaction.$queryRaw<Array<{ id: string }>>`
      SELECT "id"
      FROM "User"
      WHERE "id" = ${userId}
        AND "isActive" = TRUE
        AND "accountStatus" = 'ACTIVE'
      FOR UPDATE
    `;
  return accounts.length === 1;
}

export async function lockAndExpireSiblingAccountRecoveriesInTransaction(transaction: Prisma.TransactionClient, userId: string, requestId: string): Promise<void> {
  await lockRateLimitIdentifierInTransaction(transaction, `account-recovery-completion-user:${userId}`);
  await transaction.accountRecoveryRequest.updateMany({
    where: { userId, id: { not: requestId }, status: { in: ["PENDING", "APPROVED"] } },
    data: { status: "EXPIRED" }
  });
}

function isRememberedGrantActive(
  trusted: { status: string; revokedAt: Date | null; rememberedUntil: Date | null; strongVerifiedAt: Date | null } | null,
  now: Date
): boolean {
  if (trusted?.status !== "TRUSTED" || trusted.revokedAt !== null || !trusted.rememberedUntil || !trusted.strongVerifiedAt) {
    return false;
  }

  return (
    trusted.strongVerifiedAt <= now &&
    trusted.rememberedUntil > now &&
    trusted.rememberedUntil.getTime() <= trusted.strongVerifiedAt.getTime() + REMEMBERED_BROWSER_TTL_MS
  );
}

function getTotpKey(env: NodeJS.ProcessEnv): Buffer {
  const configured = env.VIRKI_TOTP_ENCRYPTION_KEY?.trim();
  if (configured && /^[0-9a-f]{64}$/i.test(configured)) return Buffer.from(configured, "hex");
  if (env.NODE_ENV === "test") return createHash("sha256").update("virki-test-totp-key", "utf8").digest();
  throw new SecurityMutationError();
}

async function requireAdmin(actor: { id: string; role: string }): Promise<void> {
  if (actor.role !== "ADMIN") throw new SecurityMutationError();
  const persisted = await prisma.user.findUnique({ where: { id: actor.id }, select: { role: true, isActive: true, accountStatus: true } });
  if (!persisted?.isActive || persisted.accountStatus !== "ACTIVE" || persisted.role !== "ADMIN") throw new SecurityMutationError();
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
  const normalized = value.toUpperCase();
  let end = normalized.length;
  while (end > 0 && normalized.charCodeAt(end - 1) === 61) end -= 1;
  for (let position = 0; position < end; position += 1) {
    const char = normalized[position];
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

export function hashEmailAddress(email: string): string {
  return createHash("sha256").update(email.trim().toLowerCase(), "utf8").digest("hex");
}

export function hashRecoveryRequestKey(requestKey: string): string {
  return createHash("sha256").update(requestKey, "utf8").digest("hex");
}

function isDeviceToken(value: string): boolean {
  return /^[A-Za-z0-9_-]{32,100}$/u.test(value);
}

function isTrustedClientAddress(value: string | undefined): value is string {
  return Boolean(value && value.length <= 64 && value === value.trim() && !value.includes(",") && isIP(value));
}

export function getRecoveryActionBaseUrl(role: AccountRecoveryRole): URL | null {
  const configured = (role === "ADMIN" ? process.env.VIRKI_HUB_URL : process.env.VIRKI_PORTAL_URL)?.trim();
  if (!configured) return null;
  try {
    const url = new URL(configured);
    const expectedHost = (role === "ADMIN" ? process.env.VIRKI_HUB_HOSTNAME ?? "hub.biel.dev.br" : process.env.VIRKI_PORTAL_HOSTNAME ?? "portal.biel.dev.br").toLowerCase();
    const production = process.env.NODE_ENV === "production";
    if ((url.protocol !== "https:" && (production || url.protocol !== "http:")) || url.username || url.password || url.search || url.hash || (url.pathname !== "/" && url.pathname !== "") || (production && (url.hostname.toLowerCase() !== expectedHost || url.port !== ""))) return null;
    return url;
  } catch {
    return null;
  }
}

function isAccountRecoveryRole(value: string): value is AccountRecoveryRole {
  return value === "USER" || value === "ADMIN";
}

function isDatabaseId(value: string): boolean {
  return /^[A-Za-z0-9_-]{8,64}$/u.test(value);
}

function isCeremonyId(value: string): boolean { return /^[A-Za-z0-9_-]{24,100}$/.test(value); }
