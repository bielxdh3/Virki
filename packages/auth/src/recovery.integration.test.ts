import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { after, test } from "node:test";
import { prisma, PrismaClient } from "@virki/database";
import { provisionInvitedUserAccount } from "./account-invitation";
import { hashAuditIdentifier } from "./audit";
import { createTestUser, integrationOptions, queuedEmails, requestKeyFromActionUrl, seedAdminSessionWithElevation } from "./integration-fixtures";
import {
  approveAccountRecovery,
  consumeApprovedAccountRecovery,
  generateRecoveryCode,
  getAccountRecoveryRequestId,
  getAccountRecoveryState,
  hashRecoveryCode,
  requestAccountRecovery,
  requestAdministrativeAccountRecovery,
  RECOVERY_REQUEST_COOLDOWN_MS,
  SecurityMutationError,
  verifyRecoveryCode,
  verifyAccountRecoveryEmail
} from "./security";
import { hashPassword, lockRateLimitIdentifierInTransaction, verifyPassword } from "./index";

// Lock probes need an independent connection while production recovery
// transactions contend for the three connections in the application pool.
const lockObserver = new PrismaClient();
after(async () => { await Promise.all([prisma.$disconnect(), lockObserver.$disconnect()]); });

async function openLatestRecovery(email: string, now: Date, role: "USER" | "ADMIN" = "USER") {
  const emails = (await queuedEmails(email)).filter((message) => message.kind === "ACCOUNT_RECOVERY");
  const latest = emails.at(-1);
  const requestKey = requestKeyFromActionUrl(latest?.actionUrl);
  const opened = await getAccountRecoveryRequestId(requestKey, now, role);
  assert.ok(opened, "the newest emailed recovery link opens");
  assert.equal((await getAccountRecoveryState(opened.id, requestKey, now, role))?.purpose, "RECOVERY");
  return { requestId: opened.id, requestKey, code: latest?.code };
}

async function countRecoveryAudit(eventType: string, userId: string): Promise<number> {
  const rows = await prisma.auditLog.findMany({ where: { eventType }, select: { metadata: true } });
  return rows.filter((row) => (row.metadata as { targetRef?: string } | null)?.targetRef === hashAuditIdentifier(userId)).length;
}

async function waitForBlockedPostgresQuery(blockerPid: number, queryFragment: string, minimumWaiters = 1): Promise<void> {
  const deadline = Date.now() + 5_000;
  while (Date.now() < deadline) {
    const blocked = await lockObserver.$queryRaw<Array<{ waiters: number }>>`
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
  const passkey = await prisma.passkeyCredential.create({ data: {
    userId: owner.id, credentialId: `synthetic-${randomUUID()}`, publicKey: Buffer.from("synthetic-public-key"),
    name: "Old device", backupEligible: false, backupState: false
  }, select: { id: true } });
  await prisma.totpFactor.create({ data: { userId: owner.id, secretCiphertext: "synthetic-encrypted-secret", keyVersion: 1, status: "ACTIVE" } });
  const oldCode = generateRecoveryCode();
  await prisma.recoveryCode.create({ data: { userId: owner.id, codeHash: hashRecoveryCode(oldCode) } });
  await prisma.user.update({ where: { id: owner.id }, data: { secondFactorMethod: "TOTP" } });
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
  assert.equal((await prisma.passkeyCredential.findUniqueOrThrow({ where: { id: passkey.id }, select: { revokedAt: true } })).revokedAt?.getTime(), attackerTime.getTime());
  assert.equal((await prisma.totpFactor.findUniqueOrThrow({ where: { userId: owner.id }, select: { status: true } })).status, "REVOKED");
  assert.equal((await prisma.user.findUniqueOrThrow({ where: { id: owner.id }, select: { secondFactorMethod: true } })).secondFactorMethod, "EMAIL");
  assert.equal(await prisma.recoveryCode.count({ where: { userId: owner.id } }), 0);
  await assert.rejects(consumeApprovedAccountRecovery(approved.requestId, approved.requestKey, "integration-replayed-password", attackerTime));
});

test("ADMIN normal-account recovery revokes login TOTP while preserving its distinct administrative credential", integrationOptions, async () => {
  const owner = await createTestUser({ role: "ADMIN", label: "admin-normal-recovery-mfa" });
  const reviewer = await createTestUser({ role: "ADMIN", label: "admin-normal-recovery-reviewer" });
  const now = new Date();
  const { sessionId } = await seedAdminSessionWithElevation(reviewer.id, "ACCOUNT_STATE_CHANGE", now);
  await prisma.administrativeCredential.create({ data: {
    userId: owner.id, passwordHash: await hashPassword("independent-admin-credential-1"), status: "ACTIVE"
  } });
  await prisma.totpFactor.create({ data: { userId: owner.id, secretCiphertext: "admin-synthetic-secret", keyVersion: 1, status: "ACTIVE" } });
  const retainedCodeHash = hashRecoveryCode(generateRecoveryCode());
  await prisma.recoveryCode.create({ data: { userId: owner.id, codeHash: retainedCodeHash } });
  await prisma.user.update({ where: { id: owner.id }, data: { secondFactorMethod: "TOTP" } });

  await requestAdministrativeAccountRecovery(owner.email, "pt-BR", now);
  const pending = await openLatestRecovery(owner.email, now, "ADMIN");
  await verifyAccountRecoveryEmail(pending.requestId, pending.requestKey, pending.code ?? "", now, "ADMIN");
  await approveAccountRecovery({ id: reviewer.id, role: "ADMIN" }, sessionId, pending.requestId, now);
  const approved = await openLatestRecovery(owner.email, now, "ADMIN");
  await consumeApprovedAccountRecovery(approved.requestId, approved.requestKey, "new-normal-admin-password-2", now, "ADMIN");

  assert.equal((await prisma.user.findUniqueOrThrow({ where: { id: owner.id }, select: { secondFactorMethod: true } })).secondFactorMethod, "EMAIL");
  assert.equal((await prisma.totpFactor.findUniqueOrThrow({ where: { userId: owner.id }, select: { status: true } })).status, "REVOKED");
  assert.equal(await prisma.recoveryCode.count({ where: { userId: owner.id, codeHash: retainedCodeHash } }), 0);
  assert.equal(await prisma.administrativeCredential.count({ where: { userId: owner.id, status: "ACTIVE" } }), 1);
});

test("concurrent anonymous recovery requests cannot race past a live invitation", integrationOptions, async () => {
  const admin = await createTestUser({ role: "ADMIN", label: "invite-recovery-race-admin" });
  const email = `${randomUUID()}@integration.invalid`;
  const createdAt = new Date();
  const { sessionId } = await seedAdminSessionWithElevation(admin.id, "ACCOUNT_STATE_CHANGE", createdAt);
  const { userId } = await provisionInvitedUserAccount({ id: admin.id }, sessionId, { email, displayName: "Convidado" }, createdAt);

  const afterCooldown = new Date(createdAt.getTime() + RECOVERY_REQUEST_COOLDOWN_MS + 1_000);
  let locked!: () => void;
  let release!: () => void;
  const ready = new Promise<void>((resolve) => { locked = resolve; });
  const gate = new Promise<void>((resolve) => { release = resolve; });
  let blockerPid = 0;
  const ownerLock = prisma.$transaction(async (transaction) => {
    [{ pid: blockerPid }] = await transaction.$queryRaw<Array<{ pid: number }>>`SELECT pg_backend_pid() AS pid`;
    await transaction.$queryRaw`SELECT "id" FROM "User" WHERE "id" = ${userId} FOR UPDATE`;
    locked();
    await gate;
  }, { timeout: 10_000 });
  await ready;

  const recoveries = Promise.allSettled([
    requestAccountRecovery(email, "pt-BR", afterCooldown),
    requestAccountRecovery(email, "pt-BR", afterCooldown)
  ]);
  let barrierError: unknown;
  try {
    await waitForBlockedPostgresQuery(blockerPid, 'FROM "User"');
  } catch (error) {
    barrierError = error;
  } finally {
    release();
  }
  await ownerLock;
  const outcomes = await recoveries;
  if (barrierError) throw barrierError;
  assert.ok(outcomes.every((result) => result.status === "fulfilled" || result.reason instanceof SecurityMutationError));

  const requests = await prisma.accountRecoveryRequest.findMany({ where: { userId }, select: { status: true, purpose: true } });
  assert.deepEqual(requests, [{ status: "APPROVED", purpose: "INVITATION" }]);
  assert.equal(await prisma.emailOutboxMessage.count({ where: { recipientEmail: email, kind: "ACCOUNT_RECOVERY" } }), 0);
});

test("successful recovery-code consumption is single-use and records only a safe account reference", integrationOptions, async () => {
  const user = await createTestUser({ label: "recovery-code-audit" });
  const code = generateRecoveryCode();
  const stored = await prisma.recoveryCode.create({ data: { userId: user.id, codeHash: hashRecoveryCode(code) }, select: { id: true } });

  assert.equal(await verifyRecoveryCode(user.id, code), true);
  assert.notEqual((await prisma.recoveryCode.findUniqueOrThrow({ where: { id: stored.id }, select: { usedAt: true } })).usedAt, null);
  const audit = await prisma.auditLog.findMany({ where: { eventType: "RECOVERY_CODE_CONSUMED", actorUserId: user.id }, select: { message: true, metadata: true } });
  assert.equal(audit.length, 1);
  assert.deepEqual(audit[0]?.metadata, { targetRef: hashAuditIdentifier(user.id) });
  assert.equal(JSON.stringify(audit[0]).includes(code), false);

  assert.equal(await verifyRecoveryCode(user.id, code), false);
  assert.equal(await prisma.auditLog.count({ where: { eventType: "RECOVERY_CODE_CONSUMED", actorUserId: user.id } }), 1);
});

test("recovery-code consumption rolls back when its success audit cannot be stored", integrationOptions, async () => {
  const user = await createTestUser({ label: "recovery-code-audit-rollback" });
  const code = generateRecoveryCode();
  const stored = await prisma.recoveryCode.create({ data: { userId: user.id, codeHash: hashRecoveryCode(code) }, select: { id: true } });
  const client = prisma as unknown as {
    $transaction: (callback: (transaction: object) => Promise<unknown>, options?: object) => Promise<unknown>;
  };
  const originalTransaction = client.$transaction;
  client.$transaction = (callback, options) => originalTransaction.call(prisma, (transaction) => callback(new Proxy(transaction, {
    get(target, property, receiver) {
      if (property !== "auditLog") return Reflect.get(target, property, receiver);
      const delegate = Reflect.get(target, property, target);
      return new Proxy(delegate, {
        get(delegateTarget, delegateProperty, delegateReceiver) {
          if (delegateProperty === "create") return async () => { throw new Error("synthetic audit storage failure"); };
          const value = Reflect.get(delegateTarget, delegateProperty, delegateReceiver);
          return typeof value === "function" ? value.bind(delegateTarget) : value;
        }
      });
    }
  })), options);

  try {
    await assert.rejects(verifyRecoveryCode(user.id, code), /synthetic audit storage failure/u);
  } finally {
    client.$transaction = originalTransaction;
  }

  assert.equal((await prisma.recoveryCode.findUniqueOrThrow({ where: { id: stored.id }, select: { usedAt: true } })).usedAt, null);
  assert.equal(await prisma.auditLog.count({ where: { eventType: "RECOVERY_CODE_CONSUMED", actorUserId: user.id } }), 0);
});

test("security proof quota deliberately charges valid and invalid code attempts", integrationOptions, async () => {
  const successful = await createTestUser({ label: "recovery-proof-quota-success" });
  const validCodes = Array.from({ length: 6 }, generateRecoveryCode);
  await prisma.recoveryCode.createMany({ data: validCodes.map((code) => ({ userId: successful.id, codeHash: hashRecoveryCode(code) })) });

  for (const code of validCodes.slice(0, 5)) assert.equal(await verifyRecoveryCode(successful.id, code), true);
  await assert.rejects(verifyRecoveryCode(successful.id, validCodes[5]!), SecurityMutationError,
    "five successful security proofs exhaust the shared operation quota");
  assert.equal((await prisma.recoveryCode.findFirstOrThrow({ where: { userId: successful.id, codeHash: hashRecoveryCode(validCodes[5]!) }, select: { usedAt: true } })).usedAt, null);

  const failed = await createTestUser({ label: "recovery-proof-quota-failure" });
  const validCode = generateRecoveryCode();
  const stored = await prisma.recoveryCode.create({ data: { userId: failed.id, codeHash: hashRecoveryCode(validCode) }, select: { id: true } });
  for (let attempt = 0; attempt < 5; attempt += 1) assert.equal(await verifyRecoveryCode(failed.id, "000000000000000000"), false);
  await assert.rejects(verifyRecoveryCode(failed.id, validCode), SecurityMutationError,
    "five failed security proofs still block a sixth valid operation");
  assert.equal((await prisma.recoveryCode.findUniqueOrThrow({ where: { id: stored.id }, select: { usedAt: true } })).usedAt, null);
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

test("normal ADMIN recovery rejects a credential committed while it waits for the account lock", integrationOptions, async () => {
  const owner = await createTestUser({ role: "ADMIN", label: "recovery-race-owner" });
  const approver = await createTestUser({ role: "ADMIN", label: "recovery-race-approver" });
  const now = new Date();
  const { sessionId } = await seedAdminSessionWithElevation(approver.id, "ACCOUNT_STATE_CHANGE", now);
  const initialHash = await hashPassword("initial-distinct-admin-password-1");
  await prisma.administrativeCredential.create({ data: { userId: owner.id, passwordHash: initialHash, status: "ACTIVE" } });
  await requestAdministrativeAccountRecovery(owner.email, "pt-BR", now);
  const pending = await openLatestRecovery(owner.email, now, "ADMIN");
  await verifyAccountRecoveryEmail(pending.requestId, pending.requestKey, pending.code ?? "", now, "ADMIN");
  await approveAccountRecovery({ id: approver.id, role: "ADMIN" }, sessionId, pending.requestId, now);
  const approved = await openLatestRecovery(owner.email, now, "ADMIN");
  const candidate = "shared-after-admin-rotation-1";
  const candidateHash = await hashPassword(candidate);
  let blockerPid = 0;
  let locked!: () => void;
  let release!: () => void;
  const ready = new Promise<void>((resolve) => { locked = resolve; });
  const gate = new Promise<void>((resolve) => { release = resolve; });
  const rotation = prisma.$transaction(async (transaction) => {
    [{ pid: blockerPid }] = await transaction.$queryRaw<Array<{ pid: number }>>`SELECT pg_backend_pid() AS pid`;
    await transaction.$queryRaw`SELECT "id" FROM "User" WHERE "id" = ${owner.id} FOR UPDATE`;
    await transaction.administrativeCredential.update({ where: { userId: owner.id }, data: { passwordHash: candidateHash, keyVersion: { increment: 1 } } });
    locked();
    await gate;
  }, { timeout: 10000 });
  await ready;
  const completion = consumeApprovedAccountRecovery(approved.requestId, approved.requestKey, candidate, now, "ADMIN").then(() => ({ ok: true as const }), (error: unknown) => ({ ok: false as const, error }));
  try {
    await waitForBlockedPostgresQuery(blockerPid, 'FROM "User"');
  } finally {
    release();
  }
  await rotation;
  const outcome = await completion;
  assert.equal(outcome.ok, false);
  const normal = await prisma.user.findUniqueOrThrow({ where: { id: owner.id }, select: { passwordHash: true } });
  const administrative = await prisma.administrativeCredential.findUniqueOrThrow({ where: { userId: owner.id }, select: { passwordHash: true } });
  assert.equal(await verifyPassword(normal.passwordHash ?? "", candidate), false);
  assert.equal(await verifyPassword(administrative.passwordHash, candidate), true);
  assert.equal((await prisma.accountRecoveryRequest.findUniqueOrThrow({ where: { id: approved.requestId } })).status, "APPROVED");
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
