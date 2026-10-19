import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { after, test } from "node:test";
import { prisma } from "@virki/database";
import { hashAuditIdentifier } from "./audit";
import { createTestUser, integrationOptions, queuedEmails, requestKeyFromActionUrl, seedAdminSessionWithElevation } from "./integration-fixtures";
import {
  approveAccountRecovery,
  consumeApprovedAccountRecovery,
  getAccountRecoveryRequestId,
  getAccountRecoveryState,
  requestAccountRecovery,
  RECOVERY_REQUEST_COOLDOWN_MS,
  verifyAccountRecoveryEmail
} from "./security";
import { lockRateLimitIdentifierInTransaction, verifyPassword } from "./index";

after(() => prisma.$disconnect());

async function openLatestRecovery(email: string, now: Date) {
  const emails = (await queuedEmails(email)).filter((message) => message.kind === "ACCOUNT_RECOVERY");
  const latest = emails.at(-1);
  const requestKey = requestKeyFromActionUrl(latest?.actionUrl);
  const opened = await getAccountRecoveryRequestId(requestKey, now);
  assert.ok(opened, "the newest emailed recovery link opens");
  assert.equal((await getAccountRecoveryState(opened.id, requestKey, now))?.purpose, "RECOVERY");
  return { requestId: opened.id, requestKey, code: latest?.code };
}

async function countRecoveryAudit(eventType: string, userId: string): Promise<number> {
  const rows = await prisma.auditLog.findMany({ where: { eventType }, select: { metadata: true } });
  return rows.filter((row) => (row.metadata as { targetRef?: string } | null)?.targetRef === hashAuditIdentifier(userId)).length;
}

async function waitForBlockedPostgresQuery(blockerPid: number, queryFragment: string, minimumWaiters = 1): Promise<void> {
  const deadline = Date.now() + 5_000;
  while (Date.now() < deadline) {
    const blocked = await prisma.$queryRaw<Array<{ waiters: number }>>`
      SELECT count(*)::int AS waiters
      FROM pg_stat_activity
      WHERE
        wait_event_type = 'Lock'
        AND pg_blocking_pids(pid) @> ARRAY[${blockerPid}]::integer[]
        AND query LIKE ${`%${queryFragment}%`}
    `;
    if ((blocked[0]?.waiters ?? 0) >= minimumWaiters) return;
    await new Promise<void>((resolve) => setImmediate(resolve));
  }
  throw new Error(`Timed out waiting for PostgreSQL lock wait on ${queryFragment}.`);
}

function uniqueTrustedSource(): string {
  const uuid = randomUUID().replaceAll("-", "");
  return `2001:db8:${uuid.slice(0, 4)}:${uuid.slice(4, 8)}:${uuid.slice(8, 12)}:${uuid.slice(12, 16)}:${uuid.slice(16, 20)}:${uuid.slice(20, 24)}`;
}

test("an anonymous request cannot expire a verified recovery awaiting approval", integrationOptions, async () => {
  const owner = await createTestUser({ label: "recovery-owner" });
  const admin = await createTestUser({ role: "ADMIN", label: "recovery-admin" });
  const start = new Date();
  const { sessionId } = await seedAdminSessionWithElevation(admin.id, "ACCOUNT_STATE_CHANGE", start);
  await requestAccountRecovery(owner.email, "pt-BR", start);
  const legit = await openLatestRecovery(owner.email, start);
  await verifyAccountRecoveryEmail(legit.requestId, legit.requestKey, legit.code ?? "", start);

  const attackerTime = new Date(start.getTime() + RECOVERY_REQUEST_COOLDOWN_MS + 1_000);
  await requestAccountRecovery(owner.email, "pt-BR", attackerTime);

  const state = await getAccountRecoveryState(legit.requestId, legit.requestKey, attackerTime);
  assert.equal(state?.status, "PENDING");
  assert.equal(state?.emailVerified, true);
  await approveAccountRecovery({ id: admin.id, role: "ADMIN" }, sessionId, legit.requestId, attackerTime);
});

test("an anonymous request after approval cannot expire the approved recovery", integrationOptions, async () => {
  const owner = await createTestUser({ label: "recovery-approved" });
  const admin = await createTestUser({ role: "ADMIN", label: "recovery-approver" });
  const start = new Date();
  const { sessionId } = await seedAdminSessionWithElevation(admin.id, "ACCOUNT_STATE_CHANGE", start);
  await requestAccountRecovery(owner.email, "pt-BR", start);
  const legit = await openLatestRecovery(owner.email, start);
  await verifyAccountRecoveryEmail(legit.requestId, legit.requestKey, legit.code ?? "", start);
  await approveAccountRecovery({ id: admin.id, role: "ADMIN" }, sessionId, legit.requestId, start);
  const approved = await openLatestRecovery(owner.email, start);
  assert.equal(approved.requestId, legit.requestId);

  const attackerTime = new Date(start.getTime() + RECOVERY_REQUEST_COOLDOWN_MS + 1_000);
  await requestAccountRecovery(owner.email, "pt-BR", attackerTime);

  const newPassword = "integration-new-password-1";
  await consumeApprovedAccountRecovery(approved.requestId, approved.requestKey, newPassword, attackerTime);
  const stored = await prisma.user.findUniqueOrThrow({ where: { id: owner.id }, select: { passwordHash: true } });
  assert.equal(await verifyPassword(stored.passwordHash ?? "", newPassword), true);
  await assert.rejects(consumeApprovedAccountRecovery(approved.requestId, approved.requestKey, "integration-replayed-password", attackerTime));
});


test("a revoked elevation prevents recovery approval when revocation commits first", integrationOptions, async () => {
  const owner = await createTestUser({ label: "recovery-revoked-owner" });
  const admin = await createTestUser({ role: "ADMIN", label: "recovery-revoked-admin" });
  const now = new Date();
  const { sessionId, elevationId } = await seedAdminSessionWithElevation(admin.id, "ACCOUNT_STATE_CHANGE", now);
  await requestAccountRecovery(owner.email, "pt-BR", now);
  const pending = await openLatestRecovery(owner.email, now);
  await verifyAccountRecoveryEmail(pending.requestId, pending.requestKey, pending.code ?? "", now);
  const before = await prisma.emailOutboxMessage.count({ where: { recipientEmail: owner.email, kind: "ACCOUNT_RECOVERY" } });
  let locked!: () => void;
  let release!: () => void;
  const ready = new Promise<void>((resolve) => { locked = resolve; });
  const gate = new Promise<void>((resolve) => { release = resolve; });
  let blockerPid = 0;
  const revocation = prisma.$transaction(async (transaction) => {
    [{ pid: blockerPid }] = await transaction.$queryRaw<Array<{ pid: number }>>`SELECT pg_backend_pid() AS pid`;
    await transaction.securityElevation.update({ where: { id: elevationId }, data: { status: "REVOKED", revokedAt: now } });
    locked();
    await gate;
  });
  await ready;
  const approving = approveAccountRecovery({ id: admin.id, role: "ADMIN" }, sessionId, pending.requestId, now);
  const rejected = assert.rejects(approving);
  try {
    await waitForBlockedPostgresQuery(blockerPid, 'FROM "SecurityElevation"');
  } finally {
    release();
  }
  await revocation;
  await rejected;
  assert.equal((await prisma.accountRecoveryRequest.findUniqueOrThrow({ where: { id: pending.requestId }, select: { status: true } })).status, "PENDING");
  assert.equal(await prisma.emailOutboxMessage.count({ where: { recipientEmail: owner.email, kind: "ACCOUNT_RECOVERY" } }), before);
  assert.equal(await prisma.auditLog.count({ where: { actorUserId: admin.id, eventType: "ACCOUNT_RECOVERY_APPROVED" } }), 0);
});

test("concurrent recovery completion changes the credential once and records one success", integrationOptions, async () => {
  const owner = await createTestUser({ label: "recovery-single-use" });
  const admin = await createTestUser({ role: "ADMIN", label: "recovery-single-use-admin" });
  const now = new Date();
  const { sessionId } = await seedAdminSessionWithElevation(admin.id, "ACCOUNT_STATE_CHANGE", now);
  await requestAccountRecovery(owner.email, "pt-BR", now);
  const pending = await openLatestRecovery(owner.email, now);
  await verifyAccountRecoveryEmail(pending.requestId, pending.requestKey, pending.code ?? "", now);
  await approveAccountRecovery({ id: admin.id, role: "ADMIN" }, sessionId, pending.requestId, now);
  const approved = await openLatestRecovery(owner.email, now);
  let locked!: () => void;
  let release!: () => void;
  const ready = new Promise<void>((resolve) => { locked = resolve; });
  const gate = new Promise<void>((resolve) => { release = resolve; });
  let blockerPid = 0;
  const ownerLock = prisma.$transaction(async (transaction) => {
    [{ pid: blockerPid }] = await transaction.$queryRaw<Array<{ pid: number }>>`SELECT pg_backend_pid() AS pid`;
    await transaction.$queryRaw`SELECT "id" FROM "User" WHERE "id" = ${owner.id} FOR UPDATE`;
    locked();
    await gate;
  });
  await ready;
  const completionResults = Promise.allSettled([
    consumeApprovedAccountRecovery(approved.requestId, approved.requestKey, "first-concurrent-recovery-password", now),
    consumeApprovedAccountRecovery(approved.requestId, approved.requestKey, "second-concurrent-recovery-password", now)
  ]);
  try {
    await waitForBlockedPostgresQuery(blockerPid, 'FROM "User"');
  } finally {
    release();
  }
  await ownerLock;
  const successes = await completionResults;
  assert.equal(successes.filter((result) => result.status === "fulfilled").length, 1);
  assert.equal(successes.filter((result) => result.status === "rejected").length, 1);
  assert.equal((await prisma.accountRecoveryRequest.findUniqueOrThrow({ where: { id: approved.requestId }, select: { status: true } })).status, "CONSUMED");
  const stored = await prisma.user.findUniqueOrThrow({ where: { id: owner.id }, select: { passwordHash: true } });
  const acceptedPasswords = await Promise.all(["first-concurrent-recovery-password", "second-concurrent-recovery-password"].map((password) => verifyPassword(stored.passwordHash ?? "", password)));
  assert.equal(acceptedPasswords.filter(Boolean).length, 1);
  const auditRows = await prisma.auditLog.findMany({ where: { eventType: "ACCOUNT_RECOVERY_CONSUMED", resource: "identity.recovery" }, select: { metadata: true } });
  assert.equal(auditRows.filter((row) => (row.metadata as { requestRef?: string } | null)?.requestRef === hashAuditIdentifier(approved.requestId)).length, 1);
  assert.equal(await prisma.emailOutboxMessage.count({ where: { recipientEmail: owner.email, kind: "PASSWORD_CHANGED" } }), 1);
  await assert.rejects(consumeApprovedAccountRecovery(approved.requestId, approved.requestKey, "third-concurrent-recovery-password", now));
});

test("portal recovery abuse does not spend the hub address or source budget", integrationOptions, async () => {
  const admin = await createTestUser({ role: "ADMIN", label: "recovery-isolation" });
  const security = await import("./security");
  const { createRateLimitIdentifierHash } = await import("./rate-limit-config");
  const base = new Date();
  const uuid = randomUUID().replaceAll("-", "");
  const source = `2001:db8:${uuid.slice(0, 4)}:${uuid.slice(4, 8)}:${uuid.slice(8, 12)}:${uuid.slice(12, 16)}:${uuid.slice(16, 20)}:${uuid.slice(20, 24)}`;
  const rateLimitAttempts = async (identifier: string) => (await prisma.loginRateLimit.findUnique({
    where: { identifierHash: createRateLimitIdentifierHash(identifier) },
    select: { attempts: true }
  }))?.attempts ?? null;
  for (let index = 0; index < 6; index += 1) await security.requestAccountRecovery(admin.email, "pt-BR", new Date(base.getTime() + index * 1000), source);

  assert.equal(await rateLimitAttempts(`recovery-source:USER:${source}`), 6);
  assert.equal(await rateLimitAttempts(`recovery-source:ADMIN:${source}`), null);
  assert.equal(await rateLimitAttempts(`account-recovery-address:USER:${admin.email.toLowerCase()}`), 5);
  assert.equal(await rateLimitAttempts(`account-recovery-address:ADMIN:${admin.email.toLowerCase()}`), null);

  await security.requestAdministrativeAccountRecovery(admin.email, "pt-BR", new Date(base.getTime() + 7000), source);

  assert.equal(await rateLimitAttempts(`recovery-source:USER:${source}`), 6);
  assert.equal(await rateLimitAttempts(`recovery-source:ADMIN:${source}`), 1);
  assert.equal(await rateLimitAttempts(`account-recovery-address:USER:${admin.email.toLowerCase()}`), 5);
  assert.equal(await rateLimitAttempts(`account-recovery-address:ADMIN:${admin.email.toLowerCase()}`), 1);
  assert.equal(await prisma.accountRecoveryRequest.count({ where: { userId: admin.id } }), 1);
});

test("recovery source quota serializes competing accounts and separates sources", integrationOptions, async () => {
  const first = await createTestUser({ label: "recovery-source-first" });
  const second = await createTestUser({ label: "recovery-source-second" });
  const third = await createTestUser({ label: "recovery-source-third" });
  const now = new Date();
  const source = uniqueTrustedSource();
  const otherSource = uniqueTrustedSource();
  const { createRateLimitIdentifierHash } = await import("./rate-limit-config");
  const identifier = `recovery-source:USER:${source}`;
  const identifierHash = createRateLimitIdentifierHash(identifier);
  await prisma.loginRateLimit.create({ data: { identifierHash, attempts: 29, windowStartedAt: now, blockedUntil: null, expiresAt: new Date(now.getTime() + 24 * 60 * 60 * 1000) } });
  let locked!: () => void;
  let release!: () => void;
  const ready = new Promise<void>((resolve) => { locked = resolve; });
  const gate = new Promise<void>((resolve) => { release = resolve; });
  let blockerPid = 0;
  const sourceLock = prisma.$transaction(async (transaction) => {
    [{ pid: blockerPid }] = await transaction.$queryRaw<Array<{ pid: number }>>`SELECT pg_backend_pid() AS pid`;
    await lockRateLimitIdentifierInTransaction(transaction, identifier);
    locked();
    await gate;
  });
  await ready;
  const recoveryRequests = Promise.all([
    requestAccountRecovery(first.email, "pt-BR", now, source),
    requestAccountRecovery(second.email, "pt-BR", now, source)
  ]);
  try {
    await waitForBlockedPostgresQuery(blockerPid, "pg_advisory_xact_lock", 2);
  } finally {
    release();
  }
  await sourceLock;
  await recoveryRequests;

  const sourceBucket = await prisma.loginRateLimit.findUniqueOrThrow({ where: { identifierHash }, select: { attempts: true } });
  assert.equal(sourceBucket.attempts, 30);
  const firstRequests = await prisma.accountRecoveryRequest.count({ where: { userId: first.id } });
  const secondRequests = await prisma.accountRecoveryRequest.count({ where: { userId: second.id } });
  assert.equal(firstRequests + secondRequests, 1);
  assert.equal(await countRecoveryAudit("ACCOUNT_RECOVERY_REQUESTED", first.id) + await countRecoveryAudit("ACCOUNT_RECOVERY_REQUESTED", second.id), 1);

  await requestAccountRecovery(third.email, "pt-BR", now, otherSource);
  const otherHash = createRateLimitIdentifierHash(`recovery-source:USER:${otherSource}`);
  assert.equal((await prisma.loginRateLimit.findUniqueOrThrow({ where: { identifierHash: otherHash }, select: { attempts: true } })).attempts, 1);
  assert.equal(await prisma.accountRecoveryRequest.count({ where: { userId: third.id } }), 1);
});

test("recovery source quota denies silently and resets at the exact window boundary", integrationOptions, async () => {
  const owner = await createTestUser({ label: "recovery-source-reset" });
  const now = new Date();
  const source = uniqueTrustedSource();
  const { createRateLimitIdentifierHash } = await import("./rate-limit-config");
  const identifierHash = createRateLimitIdentifierHash(`recovery-source:USER:${source}`);
  await prisma.loginRateLimit.create({ data: { identifierHash, attempts: 30, windowStartedAt: now, blockedUntil: now, expiresAt: new Date(now.getTime() + 24 * 60 * 60 * 1000) } });

  await requestAccountRecovery(owner.email, "pt-BR", now, source);
  assert.equal(await prisma.accountRecoveryRequest.count({ where: { userId: owner.id } }), 0);
  assert.equal(await prisma.emailOutboxMessage.count({ where: { recipientEmail: owner.email, kind: "ACCOUNT_RECOVERY" } }), 0);
  assert.equal(await countRecoveryAudit("ACCOUNT_RECOVERY_REQUESTED", owner.id), 0);
  assert.equal((await prisma.loginRateLimit.findUniqueOrThrow({ where: { identifierHash }, select: { attempts: true } })).attempts, 30);

  const resetAt = new Date(now.getTime() + 15 * 60 * 1000);
  await requestAccountRecovery(owner.email, "pt-BR", resetAt, source);
  const resetBucket = await prisma.loginRateLimit.findUniqueOrThrow({ where: { identifierHash }, select: { attempts: true, windowStartedAt: true } });
  assert.equal(resetBucket.attempts, 1);
  assert.equal(resetBucket.windowStartedAt.getTime(), resetAt.getTime());
  assert.equal(await prisma.accountRecoveryRequest.count({ where: { userId: owner.id } }), 1);
});

test("unknown and known recovery addresses use the same silent response contract", integrationOptions, async () => {
  const owner = await createTestUser({ label: "recovery-anti-enumeration" });
  const now = new Date();
  const source = uniqueTrustedSource();
  await assert.doesNotReject(requestAccountRecovery("missing-recovery-account@integration.invalid", "pt-BR", now, source));
  await assert.doesNotReject(requestAccountRecovery(owner.email, "pt-BR", now, uniqueTrustedSource()));
  assert.equal(await prisma.emailOutboxMessage.count({ where: { recipientEmail: "missing-recovery-account@integration.invalid", kind: "ACCOUNT_RECOVERY" } }), 0);
  assert.equal(await prisma.accountRecoveryRequest.count({ where: { userId: owner.id } }), 1);
  assert.equal(await countRecoveryAudit("ACCOUNT_RECOVERY_REQUESTED", owner.id), 1);
});
