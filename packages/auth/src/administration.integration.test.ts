import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { after, test } from "node:test";
import { prisma } from "@virki/database";
import {
  AdministrationMutationError,
  AdministrativePasswordReuseError,
  changeAdministrativePassword,
  completeAdministrativeCredentialSetup,
  hasActiveSecurityElevation,
  requireSecurityElevationInTransaction,
  recoverAdministrativeCredential,
  regenerateAdministrativeRecoveryCodes,
  startAdministrativeCredentialSetup,
  startSecurityElevation,
  verifySecurityElevation
} from "./administration";
import { createTestUser, integrationOptions, queuedEmails } from "./integration-fixtures";
import { cleanupInactiveSessions, hashAuditSessionReference, hashPassword, verifyPassword } from "./index";
import { hashRecoveryCode } from "./security";

after(() => prisma.$disconnect());

const MINUTE = 60 * 1000;
const DAY = 24 * 60 * MINUTE;
const NORMAL_PASSWORD = "integration-normal-login-1";
const ADMIN_PASSWORD = "integration-admin-separate-1";
const LOCALE = "pt-BR" as const;

async function setupAdmin(options: { adminPassword?: string; credential?: boolean; accountStatus?: "ACTIVE" | "BLOCKED" } = {}) {
  const admin = await createTestUser({ role: "ADMIN", label: "admin-elevation", password: NORMAL_PASSWORD });
  const now = new Date();
  const session = await prisma.session.create({
    data: { userId: admin.id, tokenHash: randomBytes(32).toString("base64url"), expiresAt: new Date(now.getTime() + 2 * DAY) },
    select: { id: true }
  });
  if (options.credential !== false) {
    await prisma.administrativeCredential.create({
      data: { userId: admin.id, passwordHash: await hashPassword(options.adminPassword ?? ADMIN_PASSWORD), status: "ACTIVE" }
    });
  }
  if (options.accountStatus) await prisma.user.update({ where: { id: admin.id }, data: { accountStatus: options.accountStatus } });
  return { actor: { id: admin.id, role: "ADMIN" }, sessionId: session.id, email: admin.email };
}

async function latestEmailCode(email: string, kind: string): Promise<string> {
  const code = (await queuedEmails(email)).filter((message) => message.kind === kind).at(-1)?.code;
  assert.ok(code, "the newest emailed code is available");
  return code;
}

async function waitForBlockedPostgresQuery(blockerPid: number, queryFragment: string): Promise<void> {
  const deadline = Date.now() + 5_000;
  while (Date.now() < deadline) {
    const blocked = await prisma.$queryRaw<Array<{ waiters: number }>>`
      SELECT count(*)::int AS waiters
      FROM pg_stat_activity
      WHERE wait_event_type = 'Lock'
        AND pg_blocking_pids(pid) @> ARRAY[${blockerPid}]::integer[]
        AND query LIKE ${`%${queryFragment}%`}
    `;
    if ((blocked[0]?.waiters ?? 0) >= 1) return;
    await new Promise<void>((resolve) => setImmediate(resolve));
  }
  throw new Error(`Timed out waiting for PostgreSQL lock wait on ${queryFragment}.`);
}

test("a timed elevation lasts its full duration from activation, not from when the code was sent", integrationOptions, async () => {
  const admin = await setupAdmin();
  const start = new Date();
  const started = await startSecurityElevation({
    actor: admin.actor,
    sessionId: admin.sessionId,
    normalPassword: NORMAL_PASSWORD,
    administrativePassword: ADMIN_PASSWORD,
    scope: "PROJECT_ACCESS_CHANGE",
    duration: { kind: "TIMED", minutes: 15 },
    locale: LOCALE,
    now: start
  });
  assert.equal(started.expiresAt.getTime(), start.getTime() + 15 * MINUTE);

  const code = await latestEmailCode(admin.email, "ADMIN_EMAIL_VERIFICATION");
  await verifySecurityElevation({ actor: admin.actor, sessionId: admin.sessionId, requestKey: started.requestKey, code, now: new Date(start.getTime() + 7 * MINUTE) });

  const row = await prisma.securityElevation.findUniqueOrThrow({ where: { requestKey: started.requestKey }, select: { status: true, expiresAt: true } });
  assert.equal(row.status, "ACTIVE");
  assert.equal(row.expiresAt.getTime(), start.getTime() + 22 * MINUTE);
  const auditEntries = await prisma.auditLog.findMany({
    where: { actorUserId: admin.actor.id, eventType: { in: ["ADMIN_ELEVATION_STARTED", "ADMIN_ELEVATION_ACTIVATED"] } },
    select: { eventType: true, actorRole: true, sessionRef: true }
  });
  assert.equal(auditEntries.length, 2);
  assert.ok(auditEntries.every((entry) => entry.actorRole === "ADMIN" && entry.sessionRef !== null));
  assert.ok(auditEntries.every((entry) => entry.sessionRef === hashAuditSessionReference(admin.sessionId)));
  assert.equal(await hasActiveSecurityElevation(admin.actor.id, admin.sessionId, "PROJECT_ACCESS_CHANGE", new Date(start.getTime() + 22 * MINUTE - 1000)), true);
  assert.equal(await hasActiveSecurityElevation(admin.actor.id, admin.sessionId, "PROJECT_ACCESS_CHANGE", new Date(start.getTime() + 22 * MINUTE)), false);
});

test("an elevation code cannot be verified after its ten-minute window", integrationOptions, async () => {
  const admin = await setupAdmin();
  const start = new Date();
  const started = await startSecurityElevation({
    actor: admin.actor,
    sessionId: admin.sessionId,
    normalPassword: NORMAL_PASSWORD,
    administrativePassword: ADMIN_PASSWORD,
    scope: "PROJECT_ACCESS_CHANGE",
    duration: { kind: "TIMED", minutes: 60 },
    locale: LOCALE,
    now: start
  });
  const code = await latestEmailCode(admin.email, "ADMIN_EMAIL_VERIFICATION");
  await assert.rejects(
    verifySecurityElevation({ actor: admin.actor, sessionId: admin.sessionId, requestKey: started.requestKey, code, now: new Date(start.getTime() + 10 * MINUTE) }),
    AdministrationMutationError
  );
  assert.equal(await hasActiveSecurityElevation(admin.actor.id, admin.sessionId, "PROJECT_ACCESS_CHANGE", new Date(start.getTime() + 11 * MINUTE)), false);
});

for (const lockTarget of ["User", "SecurityElevation"] as const) test(`administrative OTP expiring during ${lockTarget} lock wait must not activate elevation`, integrationOptions, async () => {
  const admin = await setupAdmin();
  const started = await startSecurityElevation({
    actor: admin.actor,
    sessionId: admin.sessionId,
    normalPassword: NORMAL_PASSWORD,
    administrativePassword: ADMIN_PASSWORD,
    scope: "PROJECT_ACCESS_CHANGE",
    duration: { kind: "TIMED", minutes: 15 },
    locale: LOCALE
  });
  const code = await latestEmailCode(admin.email, "ADMIN_EMAIL_VERIFICATION");
  // Preserve the timed elevation's later expiresAt: only the 10-minute OTP
  // ceremony age becomes nearly expired. The database remains the time source.
  const remainingMs = 3_000;
  const expiredAt = new Date(Date.now() + remainingMs);
  await prisma.securityElevation.update({
    where: { requestKey: started.requestKey },
    data: { createdAt: new Date(expiredAt.getTime() - 10 * MINUTE) }
  });

  let blockerPid = 0;
  let locked!: () => void;
  let release!: () => void;
  const ready = new Promise<void>((resolve) => { locked = resolve; });
  const gate = new Promise<void>((resolve) => { release = resolve; });
  const holder = prisma.$transaction(async (transaction) => {
    [{ pid: blockerPid }] = await transaction.$queryRaw<Array<{ pid: number }>>`SELECT pg_backend_pid() AS pid`;
    if (lockTarget === "User") {
      await transaction.$queryRaw`SELECT "id" FROM "User" WHERE "id" = ${admin.actor.id} FOR UPDATE`;
    } else {
      await transaction.$queryRaw`SELECT "id" FROM "SecurityElevation" WHERE "requestKey" = ${started.requestKey} FOR UPDATE`;
    }
    locked();
    await gate;
  }, { timeout: 10_000 });
  await ready;

  const verification = verifySecurityElevation({
    actor: admin.actor,
    sessionId: admin.sessionId,
    requestKey: started.requestKey,
    code
  }).then(() => ({ ok: true as const }), (error: unknown) => ({ ok: false as const, error }));
  try {
    await waitForBlockedPostgresQuery(blockerPid, lockTarget === "User" ? 'FROM "User" WHERE "id"' : 'FROM "SecurityElevation" WHERE "id"');
    assert.ok(Date.now() < expiredAt.getTime(), "the OTP must still be valid when the verifier starts waiting");
    await new Promise<void>((resolve) => setTimeout(resolve, Math.max(0, expiredAt.getTime() - Date.now() + 100)));
  } finally {
    release();
    await holder;
  }

  const outcome = await verification;
  assert.equal(outcome.ok, false, "the OTP must not activate an elevation after its 10-minute wall-clock deadline");
  if (!outcome.ok) assert.ok(outcome.error instanceof AdministrationMutationError);
  const ceremony = await prisma.securityElevation.findUniqueOrThrow({ where: { requestKey: started.requestKey }, select: { status: true } });
  assert.equal(ceremony.status, "PENDING");
  assert.equal(await prisma.auditLog.count({ where: { actorUserId: admin.actor.id, eventType: "ADMIN_ELEVATION_ACTIVATED" } }), 0);
});

test("an administrative password equal to the normal password is rejected when changed", integrationOptions, async () => {
  const admin = await setupAdmin();
  const start = new Date();
  const started = await startSecurityElevation({
    actor: admin.actor,
    sessionId: admin.sessionId,
    normalPassword: NORMAL_PASSWORD,
    administrativePassword: ADMIN_PASSWORD,
    scope: "ADMIN_CREDENTIAL_CHANGE",
    duration: { kind: "TIMED", minutes: 15 },
    locale: LOCALE,
    now: start
  });
  const code = await latestEmailCode(admin.email, "ADMIN_EMAIL_VERIFICATION");
  await verifySecurityElevation({ actor: admin.actor, sessionId: admin.sessionId, requestKey: started.requestKey, code, now: start });

  await assert.rejects(changeAdministrativePassword(admin.actor, admin.sessionId, NORMAL_PASSWORD, start), AdministrativePasswordReuseError);
  await changeAdministrativePassword(admin.actor, admin.sessionId, "integration-changed-admin-1", start);
});

test("an administrative password equal to the normal password is rejected when recovered", integrationOptions, async () => {
  const admin = await setupAdmin();
  const recoveryCode = `integration-recovery-${randomBytes(6).toString("hex")}`;
  await prisma.administrativeRecoveryCode.create({ data: { userId: admin.actor.id, codeHash: hashRecoveryCode(recoveryCode) } });

  await assert.rejects(
    recoverAdministrativeCredential({ actor: admin.actor, sessionId: admin.sessionId, normalPassword: NORMAL_PASSWORD, recoveryCode, newPassword: NORMAL_PASSWORD }),
    AdministrativePasswordReuseError
  );
  // The rejected attempt must not consume the single-use recovery code.
  const codes = await recoverAdministrativeCredential({ actor: admin.actor, sessionId: admin.sessionId, normalPassword: NORMAL_PASSWORD, recoveryCode, newPassword: "integration-recovered-admin-1" });
  assert.equal(codes.length, 10);
});

test("administrative password change rejects a normal password committed while it waits for the account lock", integrationOptions, async () => {
  const admin = await setupAdmin();
  await seedActiveElevation(admin, "ADMIN_CREDENTIAL_CHANGE");
  const candidate = "concurrent-shared-password-1";
  const candidateHash = await hashPassword(candidate);
  let blockerPid = 0;
  let locked!: () => void;
  let release!: () => void;
  const ready = new Promise<void>((resolve) => { locked = resolve; });
  const gate = new Promise<void>((resolve) => { release = resolve; });
  const rotation = prisma.$transaction(async (transaction) => {
    [{ pid: blockerPid }] = await transaction.$queryRaw<Array<{ pid: number }>>`SELECT pg_backend_pid() AS pid`;
    await transaction.user.update({ where: { id: admin.actor.id }, data: { passwordHash: candidateHash } });
    locked();
    await gate;
  }, { timeout: 10000 });
  await ready;
  const changing = changeAdministrativePassword(admin.actor, admin.sessionId, candidate).then(() => ({ ok: true as const }), (error: unknown) => ({ ok: false as const, error }));
  try {
    await waitForBlockedPostgresQuery(blockerPid, 'FROM "User"');
  } finally {
    release();
  }
  await rotation;
  const outcome = await changing;
  assert.equal(outcome.ok, false);
  if (!outcome.ok) assert.ok(outcome.error instanceof AdministrativePasswordReuseError);
  const normal = await prisma.user.findUniqueOrThrow({ where: { id: admin.actor.id }, select: { passwordHash: true } });
  const administrative = await prisma.administrativeCredential.findUniqueOrThrow({ where: { userId: admin.actor.id }, select: { passwordHash: true } });
  assert.equal(await verifyPassword(normal.passwordHash ?? "", candidate), true);
  assert.equal(await verifyPassword(administrative.passwordHash, candidate), false);
});

test("credential rotation, revocation and absent version invalidate an active elevation at read and mutation time", integrationOptions, async () => {
  for (const state of ["rotated", "revoked", "missing-version"] as const) {
    const admin = await setupAdmin();
    const elevation = await seedActiveElevation(admin, "ADMIN_RECOVERY_REGENERATE");
    if (state === "rotated") await prisma.administrativeCredential.update({ where: { userId: admin.actor.id }, data: { keyVersion: { increment: 1 } } });
    if (state === "revoked") await prisma.administrativeCredential.update({ where: { userId: admin.actor.id }, data: { status: "REVOKED", revokedAt: new Date() } });
    if (state === "missing-version") await prisma.securityElevation.update({ where: { id: elevation.id }, data: { credentialKeyVersion: null } });
    assert.equal(await hasActiveSecurityElevation(admin.actor.id, admin.sessionId, "ADMIN_RECOVERY_REGENERATE"), false, state);
    await assert.rejects(prisma.$transaction((transaction) => requireSecurityElevationInTransaction(transaction, admin.actor.id, admin.sessionId, "ADMIN_RECOVERY_REGENERATE", new Date())), AdministrationMutationError);
    await assert.rejects(regenerateAdministrativeRecoveryCodes(admin.actor, admin.sessionId), AdministrationMutationError);
    assert.equal(await prisma.administrativeRecoveryCode.count({ where: { userId: admin.actor.id } }), 0);
  }
});

test("credential rotation committed during a protected mutation's lock wait invalidates its elevation", integrationOptions, async () => {
  const admin = await setupAdmin();
  await seedActiveElevation(admin, "ADMIN_RECOVERY_REGENERATE");
  let blockerPid = 0;
  let locked!: () => void;
  let release!: () => void;
  const ready = new Promise<void>((resolve) => { locked = resolve; });
  const gate = new Promise<void>((resolve) => { release = resolve; });
  const rotation = prisma.$transaction(async (transaction) => {
    [{ pid: blockerPid }] = await transaction.$queryRaw<Array<{ pid: number }>>`SELECT pg_backend_pid() AS pid`;
    await transaction.$queryRaw`SELECT "id" FROM "User" WHERE "id" = ${admin.actor.id} FOR UPDATE`;
    await transaction.administrativeCredential.update({ where: { userId: admin.actor.id }, data: { keyVersion: { increment: 1 } } });
    locked(); await gate;
  }, { timeout: 10000 });
  await ready;
  const regeneration = regenerateAdministrativeRecoveryCodes(admin.actor, admin.sessionId).then(() => ({ ok: true as const }), (error: unknown) => ({ ok: false as const, error }));
  try {
    await waitForBlockedPostgresQuery(blockerPid, 'FROM "User"');
  } finally {
    release();
  }
  await rotation;
  const outcome = await regeneration;
  assert.equal(outcome.ok, false);
  if (!outcome.ok) assert.ok(outcome.error instanceof AdministrationMutationError);
  assert.equal(await prisma.administrativeRecoveryCode.count({ where: { userId: admin.actor.id } }), 0);
  assert.equal(await prisma.auditLog.count({ where: { actorUserId: admin.actor.id, eventType: "RECOVERY_CODES_REGENERATED" } }), 0);
});

test("administrative credential recovery rechecks its session after concurrent revocation", integrationOptions, async () => {
  const admin = await setupAdmin();
  const now = new Date();
  const recoveryCode = `integration-recovery-${randomBytes(6).toString("hex")}`;
  await prisma.administrativeRecoveryCode.create({ data: { userId: admin.actor.id, codeHash: hashRecoveryCode(recoveryCode) } });
  const credentialBefore = await prisma.administrativeCredential.findUniqueOrThrow({ where: { userId: admin.actor.id }, select: { passwordHash: true, keyVersion: true } });

  let blockerPid = 0;
  let locked!: () => void;
  let release!: () => void;
  const ready = new Promise<void>((resolve) => { locked = resolve; });
  const gate = new Promise<void>((resolve) => { release = resolve; });
  const revocation = prisma.$transaction(async (transaction) => {
    [{ pid: blockerPid }] = await transaction.$queryRaw<Array<{ pid: number }>>`SELECT pg_backend_pid() AS pid`;
    await transaction.session.update({ where: { id: admin.sessionId }, data: { revokedAt: now } });
    locked();
    await gate;
  }, { timeout: 10000 });
  await ready;

  const recovery = recoverAdministrativeCredential({
    actor: admin.actor,
    sessionId: admin.sessionId,
    normalPassword: NORMAL_PASSWORD,
    recoveryCode,
    newPassword: "integration-recovered-admin-2",
    now
  }).then(() => ({ ok: true as const }), (error: unknown) => ({ ok: false as const, error }));
  try {
    await waitForBlockedPostgresQuery(blockerPid, "FOR UPDATE OF u, s");
  } finally {
    release();
  }
  await revocation;
  const outcome = await recovery;
  assert.equal(outcome.ok, false, "recovery must fail after its bound session is revoked");
  if (!outcome.ok) assert.ok(outcome.error instanceof AdministrationMutationError);
  const credentialAfter = await prisma.administrativeCredential.findUniqueOrThrow({ where: { userId: admin.actor.id }, select: { passwordHash: true, keyVersion: true } });
  assert.deepEqual(credentialAfter, credentialBefore);
  assert.equal(await prisma.administrativeRecoveryCode.count({ where: { userId: admin.actor.id, usedAt: null } }), 1);
  assert.equal(await prisma.auditLog.count({ where: { actorUserId: admin.actor.id, eventType: "ADMIN_CREDENTIAL_RECOVERED" } }), 0);
});

test("an administrative password equal to the normal password is rejected during credential setup", integrationOptions, async () => {
  const admin = await setupAdmin({ credential: false });
  const start = new Date();
  const requestKey = await startAdministrativeCredentialSetup({ actor: admin.actor, sessionId: admin.sessionId, normalPassword: NORMAL_PASSWORD, locale: LOCALE, now: start });
  const code = await latestEmailCode(admin.email, "ADMIN_EMAIL_VERIFICATION");

  await assert.rejects(
    completeAdministrativeCredentialSetup({ actor: admin.actor, sessionId: admin.sessionId, requestKey, code, newPassword: NORMAL_PASSWORD, now: start }),
    AdministrativePasswordReuseError
  );
  const codes = await completeAdministrativeCredentialSetup({ actor: admin.actor, sessionId: admin.sessionId, requestKey, code, newPassword: ADMIN_PASSWORD, now: start });
  assert.equal(codes.length, 10);
});

test("administrative credential setup rejects a newly committed matching normal password", integrationOptions, async () => {
  const admin = await setupAdmin({ credential: false });
  const now = new Date();
  const requestKey = await startAdministrativeCredentialSetup({ actor: admin.actor, sessionId: admin.sessionId, normalPassword: NORMAL_PASSWORD, locale: LOCALE, now });
  const code = await latestEmailCode(admin.email, "ADMIN_EMAIL_VERIFICATION");
  const candidate = "concurrent-setup-shared-password-1";
  const candidateHash = await hashPassword(candidate);
  let blockerPid = 0;
  let locked!: () => void;
  let release!: () => void;
  const ready = new Promise<void>((resolve) => { locked = resolve; });
  const gate = new Promise<void>((resolve) => { release = resolve; });
  const rotation = prisma.$transaction(async (transaction) => {
    [{ pid: blockerPid }] = await transaction.$queryRaw<Array<{ pid: number }>>`SELECT pg_backend_pid() AS pid`;
    await transaction.user.update({ where: { id: admin.actor.id }, data: { passwordHash: candidateHash } });
    locked(); await gate;
  }, { timeout: 10000 });
  await ready;
  const setup = completeAdministrativeCredentialSetup({ actor: admin.actor, sessionId: admin.sessionId, requestKey, code, newPassword: candidate, now }).then(() => ({ ok: true as const }), (error: unknown) => ({ ok: false as const, error }));
  try {
    await waitForBlockedPostgresQuery(blockerPid, 'FROM "User"');
  } finally {
    release();
  }
  await rotation;
  assert.equal((await setup).ok, false);
  assert.equal(await prisma.administrativeCredential.count({ where: { userId: admin.actor.id } }), 0);
  assert.equal((await prisma.securityElevation.findUniqueOrThrow({ where: { requestKey } })).status, "PENDING");
});

test("administrative recovery rejects a newly committed matching normal password without using its code", integrationOptions, async () => {
  const admin = await setupAdmin();
  const recoveryCode = `race-recovery-${randomBytes(6).toString("hex")}`;
  await prisma.administrativeRecoveryCode.create({ data: { userId: admin.actor.id, codeHash: hashRecoveryCode(recoveryCode) } });
  const candidate = "concurrent-recovery-shared-password-1";
  const candidateHash = await hashPassword(candidate);
  let blockerPid = 0;
  let locked!: () => void;
  let release!: () => void;
  const ready = new Promise<void>((resolve) => { locked = resolve; });
  const gate = new Promise<void>((resolve) => { release = resolve; });
  const rotation = prisma.$transaction(async (transaction) => {
    [{ pid: blockerPid }] = await transaction.$queryRaw<Array<{ pid: number }>>`SELECT pg_backend_pid() AS pid`;
    await transaction.user.update({ where: { id: admin.actor.id }, data: { passwordHash: candidateHash } });
    locked(); await gate;
  }, { timeout: 10000 });
  await ready;
  const recovery = recoverAdministrativeCredential({ actor: admin.actor, sessionId: admin.sessionId, normalPassword: NORMAL_PASSWORD, recoveryCode, newPassword: candidate }).then(() => ({ ok: true as const }), (error: unknown) => ({ ok: false as const, error }));
  try {
    await waitForBlockedPostgresQuery(blockerPid, 'FROM "User"');
  } finally {
    release();
  }
  await rotation;
  assert.equal((await recovery).ok, false);
  assert.equal(await prisma.administrativeRecoveryCode.count({ where: { userId: admin.actor.id, usedAt: null } }), 1);
  const credential = await prisma.administrativeCredential.findUniqueOrThrow({ where: { userId: admin.actor.id }, select: { passwordHash: true } });
  assert.equal(await verifyPassword(credential.passwordHash, candidate), false);
});

test("a legacy admin with equal passwords may only start the credential change elevation", integrationOptions, async () => {
  const admin = await setupAdmin({ adminPassword: NORMAL_PASSWORD });
  const start = new Date();
  await assert.rejects(
    startSecurityElevation({
      actor: admin.actor,
      sessionId: admin.sessionId,
      normalPassword: NORMAL_PASSWORD,
      administrativePassword: NORMAL_PASSWORD,
      scope: "PROJECT_ACCESS_CHANGE",
      duration: { kind: "TIMED", minutes: 15 },
      locale: LOCALE,
      now: start
    }),
    AdministrativePasswordReuseError
  );
  const started = await startSecurityElevation({
    actor: admin.actor,
    sessionId: admin.sessionId,
    normalPassword: NORMAL_PASSWORD,
    administrativePassword: NORMAL_PASSWORD,
    scope: "ADMIN_CREDENTIAL_CHANGE",
    duration: { kind: "TIMED", minutes: 15 },
    locale: LOCALE,
    now: start
  });
  assert.ok(started.requestKey);
});

test("an elevation cannot be created from credentials rotated after password proof", integrationOptions, async () => {
  const admin = await setupAdmin();
  const now = new Date();
  const rotatedPasswordHash = await hashPassword("integration-rotated-admin-password-3");
  let blockerPid = 0;
  let locked!: () => void;
  let release!: () => void;
  const ready = new Promise<void>((resolve) => { locked = resolve; });
  const gate = new Promise<void>((resolve) => { release = resolve; });
  const rotation = prisma.$transaction(async (transaction) => {
    [{ pid: blockerPid }] = await transaction.$queryRaw<Array<{ pid: number }>>`SELECT pg_backend_pid() AS pid`;
    await transaction.$queryRaw`SELECT "id" FROM "User" WHERE "id" = ${admin.actor.id} FOR UPDATE`;
    locked();
    await gate;
    await transaction.administrativeCredential.update({ where: { userId: admin.actor.id }, data: { passwordHash: rotatedPasswordHash, keyVersion: { increment: 1 } } });
  }, { timeout: 10000 });
  await ready;

  const starting = startSecurityElevation({
    actor: admin.actor,
    sessionId: admin.sessionId,
    normalPassword: NORMAL_PASSWORD,
    administrativePassword: ADMIN_PASSWORD,
    scope: "PROJECT_ACCESS_CHANGE",
    duration: { kind: "TIMED", minutes: 15 },
    locale: LOCALE,
    now
  }).then(() => ({ ok: true as const }), (error: unknown) => ({ ok: false as const, error }));
  try {
    // The rotation holds the User row. The elevation writer acquires User
    // before Session, so its first lock wait is the User FOR UPDATE query.
    // Waiting for its later JOIN would time out before that query can run.
    await waitForBlockedPostgresQuery(blockerPid, 'FROM "User" WHERE "id"');
  } finally {
    release();
  }
  await rotation;
  const outcome = await starting;
  assert.equal(outcome.ok, false, "stale credential proof must not create an elevation ceremony");
  if (!outcome.ok) assert.ok(outcome.error instanceof AdministrationMutationError);
  assert.equal(await prisma.securityElevation.count({ where: { userId: admin.actor.id, status: "PENDING" } }), 0);
  assert.equal((await queuedEmails(admin.email)).length, 0);
});

test("a pending elevation cannot activate after its administrative credential version changes", integrationOptions, async () => {
  const admin = await setupAdmin();
  const now = new Date();
  const started = await startSecurityElevation({
    actor: admin.actor,
    sessionId: admin.sessionId,
    normalPassword: NORMAL_PASSWORD,
    administrativePassword: ADMIN_PASSWORD,
    scope: "PROJECT_ACCESS_CHANGE",
    duration: { kind: "TIMED", minutes: 15 },
    locale: LOCALE,
    now
  });
  const code = await latestEmailCode(admin.email, "ADMIN_EMAIL_VERIFICATION");
  await prisma.administrativeCredential.update({ where: { userId: admin.actor.id }, data: { keyVersion: { increment: 1 } } });

  await assert.rejects(
    verifySecurityElevation({ actor: admin.actor, sessionId: admin.sessionId, requestKey: started.requestKey, code, now }),
    AdministrationMutationError
  );
  assert.equal(await prisma.securityElevation.count({ where: { userId: admin.actor.id, sessionId: admin.sessionId, status: "ACTIVE" } }), 0);
  assert.equal(await prisma.auditLog.count({ where: { actorUserId: admin.actor.id, eventType: "ADMIN_ELEVATION_ACTIVATED" } }), 0);
});

test("an admin whose account is blocked cannot start an elevation even while the flag is active", integrationOptions, async () => {
  const admin = await setupAdmin({ accountStatus: "BLOCKED" });
  await assert.rejects(
    startSecurityElevation({
      actor: admin.actor,
      sessionId: admin.sessionId,
      normalPassword: NORMAL_PASSWORD,
      administrativePassword: ADMIN_PASSWORD,
      scope: "PROJECT_ACCESS_CHANGE",
      duration: { kind: "TIMED", minutes: 15 },
      locale: LOCALE
    }),
    AdministrationMutationError
  );
  assert.equal((await queuedEmails(admin.email)).length, 0);
});


async function seedActiveElevation(admin: Awaited<ReturnType<typeof setupAdmin>>, scope: string) {
  const credential = await prisma.administrativeCredential.findUniqueOrThrow({ where: { userId: admin.actor.id }, select: { keyVersion: true } });
  return prisma.securityElevation.create({ data: { userId: admin.actor.id, sessionId: admin.sessionId, requestKey: randomBytes(24).toString("base64url"), protocolVersion: 1, credentialKeyVersion: credential.keyVersion, scope, challengeHash: "fixture", status: "ACTIVE", expiresAt: new Date(Date.now() + DAY) }, select: { id: true } });
}

for (const sessionState of ["missing", "cross-user", "revoked", "expired"] as const) test(`active elevation linked to a ${sessionState} session cannot authorize a protected write`, integrationOptions, async () => {
  const admin = await setupAdmin();
  let sessionId = admin.sessionId;
  if (sessionState === "missing") {
    sessionId = "missing-session-1234567890";
  } else if (sessionState === "cross-user") {
    sessionId = (await setupAdmin()).sessionId;
  } else if (sessionState === "revoked") {
    await prisma.session.update({ where: { id: sessionId }, data: { revokedAt: new Date() } });
  } else {
    await prisma.session.update({ where: { id: sessionId }, data: { expiresAt: new Date(Date.now() - 1) } });
  }
  await prisma.securityElevation.create({ data: {
    userId: admin.actor.id,
    sessionId,
    requestKey: randomBytes(24).toString("base64url"),
    protocolVersion: 1,
    credentialKeyVersion: (await prisma.administrativeCredential.findUniqueOrThrow({ where: { userId: admin.actor.id } })).keyVersion,
    scope: "ADMIN_RECOVERY_REGENERATE",
    challengeHash: "integration-fixture",
    status: "ACTIVE",
    manualUntilRevoked: true,
    expiresAt: new Date(Date.now() + DAY)
  } });

  const before = await prisma.administrativeRecoveryCode.count({ where: { userId: admin.actor.id } });
  assert.equal(await hasActiveSecurityElevation(admin.actor.id, sessionId, "ADMIN_RECOVERY_REGENERATE"), false);
  await assert.rejects(prisma.$transaction(async (transaction) => {
    await requireSecurityElevationInTransaction(transaction, admin.actor.id, sessionId, "ADMIN_RECOVERY_REGENERATE", new Date());
    await transaction.administrativeRecoveryCode.create({ data: { userId: admin.actor.id, codeHash: hashRecoveryCode(randomBytes(18).toString("base64url")) } });
  }), AdministrationMutationError);
  assert.equal(await prisma.administrativeRecoveryCode.count({ where: { userId: admin.actor.id } }), before);
});

test("duplicate active elevations grant only their recorded scope and remain separate rows", integrationOptions, async () => {
  const admin = await setupAdmin();
  await seedActiveElevation(admin, "ADMIN_RECOVERY_REGENERATE");
  await seedActiveElevation(admin, "ADMIN_RECOVERY_REGENERATE");

  assert.equal(await hasActiveSecurityElevation(admin.actor.id, admin.sessionId, "ADMIN_RECOVERY_REGENERATE"), true);
  assert.equal(await hasActiveSecurityElevation(admin.actor.id, admin.sessionId, "ADMIN_CREDENTIAL_CHANGE"), false);
  assert.equal(await prisma.securityElevation.count({ where: { userId: admin.actor.id, sessionId: admin.sessionId, scope: "ADMIN_RECOVERY_REGENERATE", status: "ACTIVE" } }), 2);
});

test("session cleanup preserves elevation history but the orphan cannot authorize and cleanup writes no row-level event", integrationOptions, async () => {
  const admin = await setupAdmin();
  const now = new Date();
  await seedActiveElevation(admin, "ADMIN_RECOVERY_REGENERATE");
  await prisma.session.update({ where: { id: admin.sessionId }, data: { expiresAt: new Date(now.getTime() - 1) } });
  const auditCount = await prisma.auditLog.count({ where: { actorUserId: admin.actor.id, eventType: "AUTH_SESSION_CLEANUP" } });
  const cleanupEligibleCount = await prisma.session.count({ where: { OR: [{ expiresAt: { lt: now } }, { revokedAt: { not: null } }] } });

  assert.equal(await cleanupInactiveSessions(now), cleanupEligibleCount);
  assert.equal(await prisma.session.findUnique({ where: { id: admin.sessionId } }), null);
  assert.equal(await prisma.securityElevation.count({ where: { userId: admin.actor.id, sessionId: admin.sessionId, status: "ACTIVE" } }), 1);
  assert.equal(await hasActiveSecurityElevation(admin.actor.id, admin.sessionId, "ADMIN_RECOVERY_REGENERATE", now), false);
  await assert.rejects(prisma.$transaction((transaction) => requireSecurityElevationInTransaction(transaction, admin.actor.id, admin.sessionId, "ADMIN_RECOVERY_REGENERATE", now)), AdministrationMutationError);
  assert.equal(await prisma.auditLog.count({ where: { actorUserId: admin.actor.id, eventType: "AUTH_SESSION_CLEANUP" } }), auditCount);
});

test("demoted admins cannot use active elevation or regenerate administrative codes", integrationOptions, async () => {
  const admin = await setupAdmin();
  await seedActiveElevation(admin, "ADMIN_RECOVERY_REGENERATE");
  await prisma.user.update({ where: { id: admin.actor.id }, data: { role: "USER" } });
  assert.equal(await hasActiveSecurityElevation(admin.actor.id, admin.sessionId, "ADMIN_RECOVERY_REGENERATE"), false);
  await assert.rejects(regenerateAdministrativeRecoveryCodes(admin.actor, admin.sessionId), AdministrationMutationError);
  assert.equal(await prisma.administrativeRecoveryCode.count({ where: { userId: admin.actor.id } }), 0);
});

test("password change cannot reactivate an already revoked administrative credential", integrationOptions, async () => {
  const admin = await setupAdmin();
  await seedActiveElevation(admin, "ADMIN_CREDENTIAL_CHANGE");
  const revokedAt = new Date();
  await prisma.administrativeCredential.update({ where: { userId: admin.actor.id }, data: { status: "REVOKED", revokedAt } });
  await assert.rejects(changeAdministrativePassword(admin.actor, admin.sessionId, "new-distinct-admin-password-2"), AdministrationMutationError);
  const credential = await prisma.administrativeCredential.findUniqueOrThrow({ where: { userId: admin.actor.id } });
  assert.equal(credential.status, "REVOKED");
  assert.deepEqual(credential.revokedAt, revokedAt);
  assert.equal(await prisma.auditLog.count({ where: { actorUserId: admin.actor.id, eventType: "ADMIN_CREDENTIAL_CHANGED" } }), 0);
});

test("concurrent administrative credential revocation wins over password change", integrationOptions, async () => {
  const admin = await setupAdmin();
  await seedActiveElevation(admin, "ADMIN_CREDENTIAL_CHANGE");
  let locked!: () => void;
  let release!: () => void;
  const ready = new Promise<void>((resolve) => { locked = resolve; });
  const gate = new Promise<void>((resolve) => { release = resolve; });
  const revocation = prisma.$transaction(async (transaction) => {
    await transaction.administrativeCredential.update({ where: { userId: admin.actor.id }, data: { status: "REVOKED", revokedAt: new Date() } });
    locked(); await gate;
  }, { timeout: 10000 });
  await ready;
  const changing = changeAdministrativePassword(admin.actor, admin.sessionId, "new-concurrent-admin-password-2");
  const rejected = assert.rejects(changing, AdministrationMutationError);
  await new Promise((resolve) => setTimeout(resolve, 200));
  release(); await revocation; await rejected;
  assert.equal((await prisma.administrativeCredential.findUniqueOrThrow({ where: { userId: admin.actor.id } })).status, "REVOKED");
});


for (const state of ["demotion", "session-revocation"] as const) test(`administrative recovery regeneration rejects concurrent ${state}`, integrationOptions, async () => {
  const admin = await setupAdmin();
  await seedActiveElevation(admin, "ADMIN_RECOVERY_REGENERATE");
  let locked!: () => void; let release!: () => void;
  const ready = new Promise<void>((resolve) => { locked = resolve; });
  const gate = new Promise<void>((resolve) => { release = resolve; });
  const change = prisma.$transaction(async (transaction) => {
    if (state === "demotion") await transaction.user.update({ where: { id: admin.actor.id }, data: { role: "USER" } });
    else await transaction.session.update({ where: { id: admin.sessionId }, data: { revokedAt: new Date() } });
    locked(); await gate;
  });
  await ready;
  const regeneration = regenerateAdministrativeRecoveryCodes(admin.actor, admin.sessionId);
  const rejected = assert.rejects(regeneration, AdministrationMutationError);
  await new Promise((resolve) => setTimeout(resolve, 100));
  release(); await change; await rejected;
  assert.equal(await prisma.administrativeRecoveryCode.count({ where: { userId: admin.actor.id } }), 0);
  assert.equal(await prisma.auditLog.count({ where: { actorUserId: admin.actor.id, eventType: "RECOVERY_CODES_REGENERATED" } }), 0);
});

for (const lockTarget of ["session", "elevation"] as const) test(`administrative elevation rejects when the ${lockTarget} expires while locked`, integrationOptions, async () => {
  const admin = await setupAdmin();
  const now = new Date();
  const elevation = await seedActiveElevation(admin, "ADMIN_RECOVERY_REGENERATE");
  const expiresAt = new Date(now.getTime() + 500);
  if (lockTarget === "session") await prisma.session.update({ where: { id: admin.sessionId }, data: { expiresAt } });
  else await prisma.securityElevation.update({ where: { id: elevation.id }, data: { expiresAt } });

  let locked!: () => void;
  let release!: () => void;
  const ready = new Promise<void>((resolve) => { locked = resolve; });
  const gate = new Promise<void>((resolve) => { release = resolve; });
  const holder = prisma.$transaction(async (transaction) => {
    if (lockTarget === "session") {
      await transaction.$queryRaw`SELECT "id" FROM "Session" WHERE "id" = ${admin.sessionId} FOR UPDATE`;
    } else {
      await transaction.$queryRaw`SELECT "id" FROM "SecurityElevation" WHERE "id" = ${elevation.id} FOR UPDATE`;
    }
    locked();
    await gate;
  }, { timeout: 10000 });
  await ready;

  const mutation = prisma.$transaction(async (transaction) => {
    await requireSecurityElevationInTransaction(transaction, admin.actor.id, admin.sessionId, "ADMIN_RECOVERY_REGENERATE", now);
    await transaction.administrativeRecoveryCode.create({ data: { userId: admin.actor.id, codeHash: hashRecoveryCode(randomBytes(18).toString("base64url")) } });
  }, { timeout: 10000 });
  const rejection = assert.rejects(mutation, AdministrationMutationError);
  let settled = false;
  void mutation.then(() => { settled = true; }, () => { settled = true; });
  try {
    await new Promise((resolve) => setTimeout(resolve, 700));
    assert.equal(settled, false, "the helper is waiting on the locked authorization row");
  } finally {
    release();
    await holder;
  }
  await rejection;
  assert.equal(await prisma.administrativeRecoveryCode.count({ where: { userId: admin.actor.id } }), 0);
});
