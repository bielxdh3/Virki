import { Prisma, prisma } from "@virki/database";
import { consumeRateLimitAttemptInTransaction, hashAuditIdentifier, writeAuditLogInTransaction } from "./index";
import { isSingleMailboxAddress } from "./email-address";
import { enqueueEmailMessageForClient, getEmailEnqueueStatus } from "./email";
import {
  generateNumericCode, hashEmailAddress, hashSecurityCode,
  lockActiveRecoveryAccountInTransaction, verifySecurityCode
} from "./security";

export type RecoveryEmailRebindActor = {
  id: string;
  createdAt: Date;
  expiresAt: Date;
  authenticationMethods: string[];
  user: { id: string; email: string; role: string };
};

export const RECOVERY_EMAIL_REBIND_WINDOW_MS = 20 * 60_000;
const CODE_TTL_MS = 10 * 60_000;
const ERROR = new Error("Recovery email verification rejected.");

// The regular session TTL is longer. Only the newly created recovery session
// may perform this one-time migration, and only during its first 20 minutes.
export function isRecoveryEmailRebindSession(session: RecoveryEmailRebindActor, now = new Date()): boolean {
  return (session.user.role === "USER" || session.user.role === "ADMIN") &&
    session.authenticationMethods.includes("recovery") &&
    session.createdAt instanceof Date && session.expiresAt instanceof Date &&
    Number.isFinite(session.createdAt.getTime()) &&
    session.createdAt <= now && session.expiresAt > now &&
    session.createdAt.getTime() + RECOVERY_EMAIL_REBIND_WINDOW_MS > now.getTime();
}

export function normalizeNewRecoveryEmail(value: string): string | null {
  const normalized = value.trim().toLowerCase();
  return isSingleMailboxAddress(normalized) ? normalized : null;
}

async function requireBoundRecoverySession(tx: Prisma.TransactionClient, actor: RecoveryEmailRebindActor) {
  if (!isRecoveryEmailRebindSession(actor)) throw ERROR;
  if (!await lockActiveRecoveryAccountInTransaction(tx, actor.user.id, actor.user.role as "USER" | "ADMIN")) throw ERROR;
  // Use User -> Session lock order, as in all other account mutations.
  const locked = await tx.$queryRaw<Array<{ id: string }>>`
    SELECT "id" FROM "Session"
    WHERE "id" = ${actor.id} AND "userId" = ${actor.user.id}
      AND "revokedAt" IS NULL
      AND "expiresAt" > (clock_timestamp() AT TIME ZONE 'UTC')
      AND "createdAt" <= (clock_timestamp() AT TIME ZONE 'UTC')
      AND "createdAt" > (clock_timestamp() AT TIME ZONE 'UTC') - INTERVAL '20 minutes'
    FOR UPDATE
  `;
  if (locked.length !== 1) throw ERROR;
  const [session, user] = await Promise.all([
    tx.session.findUnique({ where: { id: actor.id }, select: {
      userId: true, createdAt: true, expiresAt: true, revokedAt: true, authenticationMethods: true
    } }),
    tx.user.findUnique({ where: { id: actor.user.id }, select: {
      id: true, email: true, emailNormalized: true, role: true, isActive: true, accountStatus: true, displayName: true
    } })
  ]);
  const freshNow = new Date();
  if (!session || !user || session.userId !== actor.user.id ||
    session.createdAt.getTime() !== actor.createdAt.getTime() ||
    session.revokedAt || !isRecoveryEmailRebindSession({ ...actor, createdAt: session.createdAt, expiresAt: session.expiresAt, authenticationMethods: session.authenticationMethods }, freshNow) ||
    !user.isActive || user.accountStatus !== "ACTIVE" || user.role !== actor.user.role ||
    user.email !== actor.user.email) throw ERROR;
  // Match the explicit one-to-one recovery origin. The database may record
  // the consumption clock separately from the session's creation time.
  // Proving the original EMAIL mailbox never authorizes replacing that mailbox
  // from a recovery bootstrap. For lost-mailbox recoveries, the replacement
  // must already be verified and applied atomically BEFORE password reset.
  // The old post-reset path remains only for legacy non-EMAIL origins without
  // any replacement-mailbox attempt; modern consumed recoveries cannot match.
  const provenance = await tx.accountRecoveryRequest.findFirst({ where: {
    userId: user.id, recoveryRole: user.role, purpose: "RECOVERY", status: "CONSUMED",
    consumedAt: { not: null }, bootstrapSessionId: actor.id,
    recoveryProofs: { isEmpty: false },
    NOT: { recoveryProofs: { has: "EMAIL" } },
    recoveryNewEmail: null, recoveryNewEmailChallengeHash: null,
    recoveryNewEmailExpiresAt: null, recoveryNewEmailVerifiedAt: null
  }, select: { id: true } });
  if (!provenance) throw ERROR;
  return { user, session };
}

async function consumeRebindLimit(actor: RecoveryEmailRebindActor, stage: "start" | "verify", additional: string): Promise<void> {
  const now = new Date();
  const allowed = await prisma.$transaction(async (tx) => {
    const user = await consumeRateLimitAttemptInTransaction(tx, `email-rebind-${stage}-user:${actor.user.id}`, now);
    const subject = await consumeRateLimitAttemptInTransaction(tx, `email-rebind-${stage}-subject:${additional}`, now);
    return user.allowed && subject.allowed;
  });
  if (!allowed) throw ERROR;
}

export async function startRecoveryEmailRebind(actor: RecoveryEmailRebindActor, proposedEmail: string): Promise<void> {
  const newEmail = normalizeNewRecoveryEmail(proposedEmail);
  if (!newEmail || !isRecoveryEmailRebindSession(actor) || getEmailEnqueueStatus().state !== "configured") throw ERROR;
  await consumeRebindLimit(actor, "start", hashEmailAddress(newEmail));
  await prisma.$transaction(async (tx) => {
    const { user, session } = await requireBoundRecoverySession(tx, actor);
    const original = user.emailNormalized ?? user.email.trim().toLowerCase();
    if (original === newEmail || await tx.user.count({ where: { OR: [{ email: newEmail }, { emailNormalized: newEmail }] } }) !== 0) throw ERROR;
    const now = new Date();
    const expiresAt = new Date(Math.min(now.getTime() + CODE_TTL_MS, session.createdAt.getTime() + RECOVERY_EMAIL_REBIND_WINDOW_MS));
    if (expiresAt <= now) throw ERROR;
    const code = generateNumericCode();
    await tx.recoveryEmailRebind.updateMany({ where: {
      userId: user.id, sessionId: actor.id, consumedAt: null, revokedAt: null
    }, data: { revokedAt: now } });
    const rebind = await tx.recoveryEmailRebind.create({ data: {
      userId: user.id, sessionId: actor.id, role: user.role, oldEmailHash: hashEmailAddress(original),
      newEmail, codeHash: hashSecurityCode(code), expiresAt, createdAt: now
    } });
    await enqueueEmailMessageForClient(tx, {
      idempotencyKey: `recovery-email-rebind:${rebind.id}`, kind: "RECOVERY_EMAIL_REBIND",
      recipientEmail: newEmail, locale: "pt-BR",
      payload: { publicValues: { displayName: user.displayName ?? "" }, protectedValues: { code } }
    });
    await writeAuditLogInTransaction(tx, {
      eventType: "ACCOUNT_RECOVERY_EMAIL_REBIND_STARTED", result: "SUCCESS",
      actorUserId: user.id, actorRole: user.role, resource: "identity.recovery",
      metadata: { requestRef: hashAuditIdentifier(rebind.id) },
      message: "New mailbox verification requested after recovery."
    });
    if (!isRecoveryEmailRebindSession({ ...actor, createdAt: session.createdAt, expiresAt: session.expiresAt }, new Date())) throw ERROR;
  }, { isolationLevel: "ReadCommitted" });
}

export async function completeRecoveryEmailRebind(actor: RecoveryEmailRebindActor, code: string): Promise<void> {
  if (!/^\d{6}$/u.test(code) || !isRecoveryEmailRebindSession(actor)) throw ERROR;
  await consumeRebindLimit(actor, "verify", actor.id);
  await prisma.$transaction(async (tx) => {
    const { user, session } = await requireBoundRecoverySession(tx, actor);
    const request = await tx.recoveryEmailRebind.findFirst({ where: {
      userId: user.id, sessionId: actor.id, role: user.role,
      consumedAt: null, revokedAt: null, expiresAt: { gt: new Date() }
    }, orderBy: [{ createdAt: "desc" }, { id: "desc" }] });
    if (!request || request.oldEmailHash !== hashEmailAddress(user.emailNormalized ?? user.email) ||
      !verifySecurityCode(code, request.codeHash)) throw ERROR;
    if (request.newEmail === (user.emailNormalized ?? user.email.trim().toLowerCase())) throw ERROR;
    if (await tx.user.count({ where: { OR: [{ email: request.newEmail }, { emailNormalized: request.newEmail }] } }) !== 0) throw ERROR;
    const now = new Date();
    // Prisma DateTime columns are TIMESTAMP WITHOUT TIME ZONE (UTC). Normalize
    // the live PostgreSQL clock explicitly to UTC, rather than relying on the
    // connection's session timezone for expiry/consumption comparisons.
    const claimed = await tx.$executeRaw`
      UPDATE "RecoveryEmailRebind"
      SET "consumedAt" = (clock_timestamp() AT TIME ZONE 'UTC')
      WHERE "id" = ${request.id} AND "userId" = ${user.id}
        AND "sessionId" = ${actor.id} AND "role" = ${user.role}::"UserRole"
        AND "codeHash" = ${request.codeHash}
        AND "oldEmailHash" = ${request.oldEmailHash}
        AND "consumedAt" IS NULL AND "revokedAt" IS NULL
        AND "expiresAt" > (clock_timestamp() AT TIME ZONE 'UTC')
    `;
    if (claimed !== 1) throw ERROR;
    const swapped = await tx.user.updateMany({ where: {
      id: user.id, role: user.role, isActive: true, accountStatus: "ACTIVE",
      email: user.email, emailNormalized: user.emailNormalized
    }, data: { email: request.newEmail, emailNormalized: request.newEmail, emailVerifiedAt: now } });
    if (swapped.count !== 1) throw ERROR;
    // Every old-inbox challenge and pending recovery becomes invalid.
    await tx.deviceChallenge.updateMany({ where: { userId: user.id, consumedAt: null },
      data: { status: "REVOKED", consumedAt: now } });
    await tx.accountRecoveryRequest.updateMany({ where: {
      userId: user.id, status: { in: ["PENDING", "APPROVED"] }
    }, data: { status: "EXPIRED" } });
    await tx.recoveryEmailRebind.updateMany({ where: {
      userId: user.id, id: { not: request.id }, consumedAt: null, revokedAt: null
    }, data: { revokedAt: now } });
    // Best-effort delivery is asynchronous; the original mailbox may be lost.
    await enqueueEmailMessageForClient(tx, {
      idempotencyKey: `recovery-email-rebind-notice:${request.id}`,
      kind: "RECOVERY_EMAIL_REBIND_NOTICE", recipientEmail: user.email, locale: "pt-BR",
      payload: { publicValues: { displayName: user.displayName ?? "" } }
    });
    // A recovery bootstrap is one-time. Normal login must use the new email.
    await tx.session.updateMany({ where: { userId: user.id, revokedAt: null }, data: { revokedAt: now } });
    await writeAuditLogInTransaction(tx, {
      eventType: "ACCOUNT_RECOVERY_EMAIL_REBOUND", result: "SUCCESS",
      actorUserId: user.id, actorRole: user.role, resource: "identity.recovery",
      metadata: { requestRef: hashAuditIdentifier(request.id) },
      message: "Verified mailbox rebound; recovery sessions revoked."
    });
    if (request.expiresAt <= new Date() ||
      session.createdAt.getTime() + RECOVERY_EMAIL_REBIND_WINDOW_MS <= Date.now() ||
      session.expiresAt <= new Date()) throw ERROR;
  }, { isolationLevel: "ReadCommitted" });
}
