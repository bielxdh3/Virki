import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { after, test } from "node:test";
import { prisma } from "@virki/database";
import {
  AdministrationMutationError,
  AdministrativePasswordReuseError,
  changeAdministrativePassword,
  completeAdministrativeEmailRecovery,
  completeAdministrativeCredentialSetup,
  hasActiveSecurityElevation,
  requireSecurityElevationInTransaction,
  recoverAdministrativeCredential,
  regenerateAdministrativeRecoveryCodes,
  startAdministrativeCredentialSetup,
  startAdministrativeEmailRecovery,
  startSecurityElevation,
  revokeSecurityElevation,
  verifySecurityElevation
} from "./administration";
import { createTestUser, integrationOptions, queuedEmails } from "./integration-fixtures";
import { cleanupInactiveSessions, hashAuditSessionReference, hashPassword, verifyPassword } from "./index";
import { createTotpSecret, generateNumericCode, generateRecoveryCode, hashEmailAddress, hashRecoveryCode, hashSecurityCode, startLoginCeremony, verifyLoginEmailCode } from "./security";
import { hashOidcIdentifier } from "./oidc-secrets";

after(() => prisma.$disconnect());

const MINUTE = 60 * 1000;
const DAY = 24 * 60 * MINUTE;
const NORMAL_PASSWORD = "integration-normal-login-1";
const ADMIN_PASSWORD = "integration-admin-separate-1";
const LOCALE = "pt-BR" as const;

async function setupAdmin(options: { adminPassword?: string; credential?: boolean; accountStatus?: "ACTIVE" | "BLOCKED"; totpSecret?: string } = {}) {
  const admin = await createTestUser({ role: "ADMIN", label: "admin-elevation", password: NORMAL_PASSWORD, ...(options.totpSecret ? { totpSecret: options.totpSecret } : {}) });
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

async function createOldHubPasskey(userId: string): Promise<string> {
  const credential = await prisma.passkeyCredential.create({
    data: {
      userId,
      credentialId: randomBytes(32).toString("base64url"),
      rpID: "hub.biel.dev.br",
      publicKey: randomBytes(65),
      backupEligible: false,
      backupState: false,
      name: "Prior administrative recovery passkey"
    },
    select: { id: true }
  });
  return credential.id;
}

async function latestEmailCode(email: string, kind: string): Promise<string> {
  const code = (await queuedEmails(email)).filter((message) => message.kind === kind).at(-1)?.code;
  assert.ok(code, "the newest emailed code is available");
  return code;
}

async function seedAdministrativeRecoveryProofs(admin: Awaited<ReturnType<typeof setupAdmin>>) {
  const userId = admin.actor.id;
  const user = await prisma.user.findUniqueOrThrow({ where: { id: userId }, select: { passwordHash: true, secondFactorMethod: true } });
  const factor = await prisma.totpFactor.findUniqueOrThrow({ where: { userId } });
  assert.equal(user.secondFactorMethod, "TOTP");
  const sibling = await prisma.session.create({ data: {
    userId, tokenHash: randomBytes(32).toString("base64url"), expiresAt: new Date(Date.now() + DAY)
  } });
  const trusted = await prisma.trustedDevice.create({ data: {
    userId, deviceIdHash: randomBytes(32).toString("hex"),
    strongVerifiedAt: new Date(), rememberedUntil: new Date(Date.now() + DAY)
  } });
  const login = await startLoginCeremony(userId, undefined, LOCALE, new Date(), false, "ADMIN");
  assert.equal(login.kind, "CEREMONY");
  if (login.kind !== "CEREMONY") throw new Error("Expected a pending email login ceremony");
  const loginCode = await latestEmailCode(admin.email, "NEW_DEVICE_VERIFICATION");
  const passkey = await prisma.passkeyChallenge.create({ data: {
    challengeHash: randomBytes(32).toString("hex"), ceremony: "AUTHENTICATION", userId,
    browserHash: randomBytes(32).toString("hex"),
    rpID: "hub.biel.dev.br", origin: "https://hub.biel.dev.br", expiresAt: new Date(Date.now() + DAY)
  } });
  const oidc = await prisma.oidcArtifact.create({ data: {
    model: "Grant", idHash: randomBytes(32).toString("hex"), accountIdHash: hashOidcIdentifier(userId),
    payloadCiphertext: "disposable-administrative-recovery-fixture"
  } });
  const pendingRecovery = await prisma.accountRecoveryRequest.create({ data: {
    userId, requestKeyHash: randomBytes(32).toString("hex"),
    emailAddressHash: hashEmailAddress(admin.email), emailChallengeHash: hashSecurityCode(generateNumericCode()),
    expiresAt: new Date(Date.now() + DAY)
  } });
  return { user, factor, sibling, trusted, login, loginCode, passkey, oidc, pendingRecovery };
}

async function assertAdministrativeRecoveryRevocations(
  admin: Awaited<ReturnType<typeof setupAdmin>>,
  before: Awaited<ReturnType<typeof seedAdministrativeRecoveryProofs>>
) {
  const userId = admin.actor.id;
  const normal = await prisma.user.findUniqueOrThrow({ where: { id: userId }, select: { passwordHash: true, secondFactorMethod: true } });
  assert.equal(normal.passwordHash, before.user.passwordHash, "normal login password hash must not rotate");
  assert.equal(await verifyPassword(normal.passwordHash!, NORMAL_PASSWORD), true);
  assert.equal(normal.secondFactorMethod, "TOTP", "normal second factor selection must remain active");
  const factor = await prisma.totpFactor.findUniqueOrThrow({ where: { userId } });
  assert.equal(factor.status, "ACTIVE");
  assert.equal(factor.secretCiphertext, before.factor.secretCiphertext);
  assert.equal(factor.keyVersion, before.factor.keyVersion);
  assert.deepEqual(factor.confirmedAt, before.factor.confirmedAt);
  assert.equal(factor.lastUsedStep, before.factor.lastUsedStep);
  assert.equal((await prisma.session.findUniqueOrThrow({ where: { id: admin.sessionId } })).revokedAt, null,
    "the initiating session remains available for recovery confirmation");
  assert.ok((await prisma.session.findUniqueOrThrow({ where: { id: before.sibling.id } })).revokedAt,
    "sibling session must be revoked");
  const device = await prisma.trustedDevice.findUniqueOrThrow({ where: { id: before.trusted.id } });
  assert.equal(device.status, "REVOKED");
  assert.ok(device.revokedAt);
  assert.equal(device.rememberedUntil, null);
  assert.equal(device.strongVerifiedAt, null);
  assert.equal((await prisma.deviceChallenge.findUniqueOrThrow({ where: { ceremonyId: before.login.ceremonyId } })).status, "REVOKED");
  await assert.rejects(verifyLoginEmailCode(before.login.ceremonyId, before.loginCode, before.login.deviceToken, new Date(), "ADMIN"),
    "a previously emailed login proof cannot authorize a new session");
  assert.equal(await prisma.passkeyChallenge.count({ where: { id: before.passkey.id } }), 0,
    "pending passkey assertion must be removed");
  assert.equal(await prisma.oidcArtifact.count({ where: { id: before.oidc.id } }), 0,
    "OIDC grant must not survive credential recovery");
  assert.equal((await prisma.accountRecoveryRequest.findUniqueOrThrow({ where: { id: before.pendingRecovery.id } })).status, "EXPIRED",
    "pending normal-account recovery cannot survive a privileged credential reset");
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

test("revoking a session's pending elevations invalidates the already-sent OTP and remains idempotent", integrationOptions, async () => {
  const admin = await setupAdmin();
  const now = new Date();
  const started = await startSecurityElevation({
    actor: admin.actor, sessionId: admin.sessionId,
    normalPassword: NORMAL_PASSWORD, administrativePassword: ADMIN_PASSWORD,
    scope: "PROJECT_ACCESS_CHANGE", duration: { kind: "TIMED", minutes: 60 }, locale: LOCALE, now
  });
  const code = await latestEmailCode(admin.email, "ADMIN_EMAIL_VERIFICATION");
  await revokeSecurityElevation(admin.actor, admin.sessionId, undefined, now);
  await revokeSecurityElevation(admin.actor, admin.sessionId, started.requestKey, now);
  assert.equal((await prisma.securityElevation.findUniqueOrThrow({ where: { requestKey: started.requestKey } })).status, "REVOKED");
  await assert.rejects(verifySecurityElevation({ actor: admin.actor, sessionId: admin.sessionId, requestKey: started.requestKey, code, now }), AdministrationMutationError);
  assert.equal(await hasActiveSecurityElevation(admin.actor.id, admin.sessionId, "PROJECT_ACCESS_CHANGE", now), false);
});

test("revoking a verified elevation after activation also cancels its active authorization", integrationOptions, async () => {
  const admin = await setupAdmin();
  const now = new Date();
  const started = await startSecurityElevation({
    actor: admin.actor, sessionId: admin.sessionId,
    normalPassword: NORMAL_PASSWORD, administrativePassword: ADMIN_PASSWORD,
    scope: "PROJECT_ACCESS_CHANGE", duration: { kind: "TIMED", minutes: 60 }, locale: LOCALE, now
  });
  const code = await latestEmailCode(admin.email, "ADMIN_EMAIL_VERIFICATION");
  await verifySecurityElevation({ actor: admin.actor, sessionId: admin.sessionId, requestKey: started.requestKey, code, now });
  assert.equal(await hasActiveSecurityElevation(admin.actor.id, admin.sessionId, "PROJECT_ACCESS_CHANGE", now), true);
  await revokeSecurityElevation(admin.actor, admin.sessionId, started.requestKey, now);
  assert.equal(await hasActiveSecurityElevation(admin.actor.id, admin.sessionId, "PROJECT_ACCESS_CHANGE", now), false);
  assert.equal((await prisma.securityElevation.findUniqueOrThrow({ where: { requestKey: started.requestKey } })).status, "REVOKED");
});

test("ADMIN proof and elevation-start quotas count both valid and failed operations", integrationOptions, async () => {
  const admin = await setupAdmin();
  const now = new Date();
  const credential = await prisma.administrativeCredential.findUniqueOrThrow({ where: { userId: admin.actor.id }, select: { keyVersion: true } });
  const validCeremonies = Array.from({ length: 6 }, () => ({ requestKey: randomBytes(24).toString("base64url"), code: generateNumericCode() }));
  await prisma.securityElevation.createMany({
    data: validCeremonies.map(({ requestKey, code }) => ({
      requestKey,
      userId: admin.actor.id,
      sessionId: admin.sessionId,
      protocolVersion: 1,
      credentialKeyVersion: credential.keyVersion,
      scope: "PROJECT_ACCESS_CHANGE",
      challengeHash: hashSecurityCode(code),
      status: "PENDING",
      manualUntilRevoked: false,
      expiresAt: new Date(now.getTime() + 60 * MINUTE),
      createdAt: new Date(now.getTime() - 1_000)
    }))
  });

  for (const ceremony of validCeremonies.slice(0, 5)) {
    await verifySecurityElevation({ actor: admin.actor, sessionId: admin.sessionId, requestKey: ceremony.requestKey, code: ceremony.code, now });
  }
  await assert.rejects(
    verifySecurityElevation({ actor: admin.actor, sessionId: admin.sessionId, requestKey: validCeremonies[5]!.requestKey, code: validCeremonies[5]!.code, now }),
    AdministrationMutationError,
    "five successful proofs spend the shared ADMIN proof-operation quota"
  );
  assert.equal((await prisma.securityElevation.findUniqueOrThrow({ where: { requestKey: validCeremonies[5]!.requestKey }, select: { status: true } })).status, "PENDING");

  const failedAdmin = await setupAdmin();
  const failedProofCode = "654321";
  const failedRequestKey = randomBytes(24).toString("base64url");
  await prisma.securityElevation.create({
    data: {
      requestKey: failedRequestKey,
      userId: failedAdmin.actor.id,
      sessionId: failedAdmin.sessionId,
      protocolVersion: 1,
      credentialKeyVersion: 1,
      scope: "PROJECT_ACCESS_CHANGE",
      challengeHash: hashSecurityCode(failedProofCode),
      status: "PENDING",
      manualUntilRevoked: false,
      expiresAt: new Date(now.getTime() + 60 * MINUTE),
      createdAt: new Date(now.getTime() - 1_000)
    }
  });
  for (let attempt = 0; attempt < 5; attempt += 1) {
    await assert.rejects(verifySecurityElevation({ actor: failedAdmin.actor, sessionId: failedAdmin.sessionId, requestKey: failedRequestKey, code: "000000", now }), AdministrationMutationError);
  }
  await assert.rejects(verifySecurityElevation({ actor: failedAdmin.actor, sessionId: failedAdmin.sessionId, requestKey: failedRequestKey, code: failedProofCode, now }), AdministrationMutationError);
  assert.equal((await prisma.securityElevation.findUniqueOrThrow({ where: { requestKey: failedRequestKey }, select: { status: true } })).status, "PENDING");

  const startAdmin = await setupAdmin();
  const validStart = await startSecurityElevation({
    actor: startAdmin.actor,
    sessionId: startAdmin.sessionId,
    normalPassword: NORMAL_PASSWORD,
    administrativePassword: ADMIN_PASSWORD,
    scope: "PROJECT_ACCESS_CHANGE",
    duration: { kind: "TIMED", minutes: 15 },
    locale: LOCALE,
    now
  });
  assert.ok(validStart.requestKey);
  for (let attempt = 0; attempt < 4; attempt += 1) {
    await assert.rejects(startSecurityElevation({
      actor: startAdmin.actor,
      sessionId: startAdmin.sessionId,
      normalPassword: "incorrect-normal-password",
      administrativePassword: ADMIN_PASSWORD,
      scope: "PROJECT_ACCESS_CHANGE",
      duration: { kind: "TIMED", minutes: 15 },
      locale: LOCALE,
      now
    }), AdministrationMutationError);
  }
  await assert.rejects(startSecurityElevation({
    actor: startAdmin.actor,
    sessionId: startAdmin.sessionId,
    normalPassword: NORMAL_PASSWORD,
    administrativePassword: ADMIN_PASSWORD,
    scope: "PROJECT_ACCESS_CHANGE",
    duration: { kind: "TIMED", minutes: 15 },
    locale: LOCALE,
    now
  }), AdministrationMutationError, "a valid start is denied after five successful/failed start operations");
  assert.equal(await prisma.securityElevation.count({ where: { userId: startAdmin.actor.id } }), 1);
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

for (const lockTarget of ["AdministrativeCredential", "SecurityElevation"] as const) test(`admin elevation rejects session expiry during ${lockTarget} lock wait`, integrationOptions, async () => {
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
  const expiresAt = new Date(Date.now() + 3_000);
  await prisma.session.update({ where: { id: admin.sessionId }, data: { expiresAt } });

  let blockerPid = 0;
  let locked!: () => void;
  let release!: () => void;
  const ready = new Promise<void>((resolve) => { locked = resolve; });
  const gate = new Promise<void>((resolve) => { release = resolve; });
  const holder = prisma.$transaction(async (transaction) => {
    [{ pid: blockerPid }] = await transaction.$queryRaw<Array<{ pid: number }>>`SELECT pg_backend_pid() AS pid`;
    if (lockTarget === "AdministrativeCredential") {
      await transaction.$queryRaw`SELECT "userId" FROM "AdministrativeCredential" WHERE "userId" = ${admin.actor.id} FOR UPDATE`;
    } else {
      await transaction.$queryRaw`SELECT "id" FROM "SecurityElevation" WHERE "requestKey" = ${started.requestKey} FOR UPDATE`;
    }
    locked();
    await gate;
  }, { timeout: 10_000 });
  await ready;

  const verifying = verifySecurityElevation({
    actor: admin.actor, sessionId: admin.sessionId, requestKey: started.requestKey, code
  }).then(() => ({ ok: true as const }), (error: unknown) => ({ ok: false as const, error }));
  try {
    await waitForBlockedPostgresQuery(blockerPid,
      lockTarget === "AdministrativeCredential" ? 'FROM "AdministrativeCredential"' : 'FROM "SecurityElevation" WHERE "id"');
    assert.ok(Date.now() < expiresAt.getTime(), "session must be valid when the verifier reaches the later lock");
    await new Promise<void>((resolve) => setTimeout(resolve, Math.max(0, expiresAt.getTime() - Date.now() + 100)));
  } finally {
    release();
    await holder;
  }

  const outcome = await verifying;
  assert.equal(outcome.ok, false, "an expired session must not activate a stale ADMIN elevation");
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
  const admin = await setupAdmin({ totpSecret: createTotpSecret() });
  const oldPasskeyId = await createOldHubPasskey(admin.actor.id);
  const recoveryCode = `integration-recovery-${randomBytes(6).toString("hex")}`;
  await prisma.administrativeRecoveryCode.create({ data: { userId: admin.actor.id, codeHash: hashRecoveryCode(recoveryCode) } });
  const oldProofs = await seedAdministrativeRecoveryProofs(admin);

  await assert.rejects(
    recoverAdministrativeCredential({ actor: admin.actor, sessionId: admin.sessionId, normalPassword: NORMAL_PASSWORD, recoveryCode, newPassword: NORMAL_PASSWORD }),
    AdministrativePasswordReuseError
  );
  // The rejected attempt must not consume the single-use recovery code.
  const codes = await recoverAdministrativeCredential({ actor: admin.actor, sessionId: admin.sessionId, normalPassword: NORMAL_PASSWORD, recoveryCode, newPassword: "integration-recovered-admin-1" });
  assert.equal(codes.length, 10);
  assert.ok((await prisma.passkeyCredential.findUniqueOrThrow({ where: { id: oldPasskeyId } })).revokedAt,
    "backup-code recovery must revoke old hub passkeys");
  await assertAdministrativeRecoveryRevocations(admin, oldProofs);
});

for (const state of ["revoked", "missing"] as const) {
  test(`saved-code administrative recovery cannot reactivate a ${state} privileged credential`, integrationOptions, async () => {
    const admin = await setupAdmin({ credential: state !== "missing" });
    const savedCode = generateRecoveryCode();
    const code = await prisma.administrativeRecoveryCode.create({ data: {
      userId: admin.actor.id, codeHash: hashRecoveryCode(savedCode)
    } });
    let previousCredential: { passwordHash: string; keyVersion: number; revokedAt: Date | null } | null = null;
    if (state === "revoked") {
      const revokedAt = new Date();
      const revoked = await prisma.administrativeCredential.update({
        where: { userId: admin.actor.id }, data: { status: "REVOKED", revokedAt },
        select: { passwordHash: true, keyVersion: true, revokedAt: true }
      });
      previousCredential = revoked;
    }
    await assert.rejects(recoverAdministrativeCredential({
      actor: admin.actor,
      sessionId: admin.sessionId,
      normalPassword: NORMAL_PASSWORD,
      recoveryCode: savedCode,
      newPassword: "different-privileged-password-2026"
    }), AdministrationMutationError);
    const current = await prisma.administrativeCredential.findUnique({
      where: { userId: admin.actor.id },
      select: { status: true, passwordHash: true, keyVersion: true, revokedAt: true }
    });
    if (state === "revoked") {
      assert.ok(current);
      assert.equal(current.status, "REVOKED");
      assert.deepEqual({
        passwordHash: current.passwordHash, keyVersion: current.keyVersion, revokedAt: current.revokedAt
      }, previousCredential);
    } else {
      assert.equal(current, null, "a missing credential must use its separate setup ceremony");
    }
    assert.equal((await prisma.administrativeRecoveryCode.findUniqueOrThrow({
      where: { id: code.id }, select: { usedAt: true }
    })).usedAt, null, "rejected code must stay unused");
    assert.equal(await prisma.auditLog.count({
      where: { actorUserId: admin.actor.id, eventType: "ADMIN_CREDENTIAL_RECOVERED" }
    }), 0);
    assert.equal((await prisma.session.findUniqueOrThrow({
      where: { id: admin.sessionId }, select: { revokedAt: true }
    })).revokedAt, null);
  });
}

test("email recovery rotates only the separate ADMIN credential, replaces backup codes and revokes old access", integrationOptions, async () => {
  const admin = await setupAdmin({ totpSecret: createTotpSecret() });
  const oldPasskeyId = await createOldHubPasskey(admin.actor.id);
  const oldCode = randomBytes(9).toString("hex");
  await prisma.administrativeRecoveryCode.create({ data: { userId: admin.actor.id, codeHash: hashRecoveryCode(oldCode) } });
  await seedActiveElevation(admin, "PROJECT_CONNECTION_MANAGE");
  const otherSession = await prisma.session.create({
    data: { userId: admin.actor.id, tokenHash: randomBytes(32).toString("base64url"), expiresAt: new Date(Date.now() + DAY) }
  });
  const device = await prisma.trustedDevice.create({ data: { userId: admin.actor.id, deviceIdHash: randomBytes(32).toString("hex") } });
  const oldProofs = await seedAdministrativeRecoveryProofs(admin);
  const start = new Date();
  const requestKey = await startAdministrativeEmailRecovery({
    actor: admin.actor, sessionId: admin.sessionId, normalPassword: NORMAL_PASSWORD, locale: LOCALE, now: start
  });
  const emailedCode = await latestEmailCode(admin.email, "ADMIN_EMAIL_VERIFICATION");
  const ceremony = await prisma.securityElevation.findUniqueOrThrow({ where: { requestKey }, select: { scope: true, status: true, credentialKeyVersion: true } });
  assert.equal(ceremony.scope, "ADMIN_CREDENTIAL_EMAIL_RECOVERY");
  assert.equal(ceremony.status, "PENDING");
  await assert.rejects(
    verifySecurityElevation({ actor: admin.actor, sessionId: admin.sessionId, requestKey, code: emailedCode }),
    AdministrationMutationError, "a recovery proof must not become an arbitrary elevation"
  );
  const replacementCredential = "new-admin-credential-email-2026";
  const codes = await completeAdministrativeEmailRecovery({
    actor: admin.actor, sessionId: admin.sessionId, requestKey, code: emailedCode,
    normalPassword: NORMAL_PASSWORD, newPassword: replacementCredential
  });
  assert.equal(codes.length, 10);
  assert.equal(new Set(codes).size, 10);
  const credential = await prisma.administrativeCredential.findUniqueOrThrow({ where: { userId: admin.actor.id } });
  assert.equal(credential.keyVersion, 2);
  assert.equal(await verifyPassword(credential.passwordHash, replacementCredential), true);
  assert.equal(await verifyPassword(credential.passwordHash, ADMIN_PASSWORD), false);
  const account = await prisma.user.findUniqueOrThrow({ where: { id: admin.actor.id } });
  assert.equal(await verifyPassword(account.passwordHash!, NORMAL_PASSWORD), true);
  assert.equal(await prisma.administrativeRecoveryCode.count({ where: { userId: admin.actor.id, usedAt: null } }), 10);
  assert.equal(await prisma.administrativeRecoveryCode.count({ where: { userId: admin.actor.id, codeHash: hashRecoveryCode(oldCode) } }), 0);
  assert.equal((await prisma.securityElevation.findUniqueOrThrow({ where: { requestKey } })).status, "CONSUMED");
  assert.equal(await prisma.securityElevation.count({ where: { userId: admin.actor.id, status: "ACTIVE" } }), 0);
  assert.equal((await prisma.session.findUniqueOrThrow({ where: { id: otherSession.id } })).revokedAt !== null, true);
  assert.equal((await prisma.session.findUniqueOrThrow({ where: { id: admin.sessionId } })).revokedAt, null);
  assert.equal((await prisma.trustedDevice.findUniqueOrThrow({ where: { id: device.id } })).status, "REVOKED");
  assert.ok((await prisma.passkeyCredential.findUniqueOrThrow({ where: { id: oldPasskeyId } })).revokedAt,
    "email recovery must revoke old hub passkeys");
  await assertAdministrativeRecoveryRevocations(admin, oldProofs);
  assert.equal(await prisma.auditLog.count({ where: { actorUserId: admin.actor.id, eventType: "ADMIN_CREDENTIAL_EMAIL_RECOVERY_STARTED", result: "INFO" } }), 1);
  assert.equal(await prisma.auditLog.count({ where: { actorUserId: admin.actor.id, eventType: "ADMIN_CREDENTIAL_EMAIL_RECOVERED", result: "SUCCESS" } }), 1);
  assert.ok((await queuedEmails(admin.email)).some((mail) => mail.kind === "ADMIN_CREDENTIAL_CHANGED"));
  await assert.rejects(
    completeAdministrativeEmailRecovery({ actor: admin.actor, sessionId: admin.sessionId, requestKey, code: emailedCode, normalPassword: NORMAL_PASSWORD, newPassword: "another-admin-email-password-2026" }),
    AdministrationMutationError,
    "the email code cannot be replayed"
  );
});

test("ADMIN email recovery rejects invalid normal password and missing verified email before sending", integrationOptions, async () => {
  const admin = await setupAdmin();
  await assert.rejects(
    startAdministrativeEmailRecovery({ actor: admin.actor, sessionId: admin.sessionId, normalPassword: "incorrect-normal-password", locale: LOCALE }),
    AdministrationMutationError
  );
  await prisma.user.update({ where: { id: admin.actor.id }, data: { emailVerifiedAt: null } });
  await assert.rejects(
    startAdministrativeEmailRecovery({ actor: admin.actor, sessionId: admin.sessionId, normalPassword: NORMAL_PASSWORD, locale: LOCALE }),
    AdministrationMutationError
  );
  assert.equal((await queuedEmails(admin.email)).length, 0);
});

for (const state of ["revoked", "missing"] as const) {
  test(`ADMIN email recovery rejects a ${state} credential both before OTP issuance and after an already-issued OTP`, integrationOptions, async () => {
    const beforeStart = await setupAdmin({ credential: state !== "missing" });
    if (state === "revoked") {
      await prisma.administrativeCredential.update({
        where: { userId: beforeStart.actor.id }, data: { status: "REVOKED", revokedAt: new Date() }
      });
    }
    await assert.rejects(startAdministrativeEmailRecovery({
      actor: beforeStart.actor, sessionId: beforeStart.sessionId,
      normalPassword: NORMAL_PASSWORD, locale: LOCALE
    }), AdministrationMutationError);
    assert.equal((await queuedEmails(beforeStart.email)).length, 0, "invalid administrative credential must not mint an OTP");
    assert.equal(await prisma.administrativeCredential.count({ where: { userId: beforeStart.actor.id, status: "ACTIVE" } }), 0);

    const afterStart = await setupAdmin();
    const requestKey = await startAdministrativeEmailRecovery({
      actor: afterStart.actor, sessionId: afterStart.sessionId,
      normalPassword: NORMAL_PASSWORD, locale: LOCALE
    });
    const code = await latestEmailCode(afterStart.email, "ADMIN_EMAIL_VERIFICATION");
    const previous = await prisma.administrativeCredential.findUniqueOrThrow({ where: { userId: afterStart.actor.id } });
    if (state === "revoked") {
      await prisma.administrativeCredential.update({
        where: { userId: afterStart.actor.id }, data: { status: "REVOKED", revokedAt: new Date() }
      });
    } else {
      await prisma.administrativeCredential.delete({ where: { userId: afterStart.actor.id } });
    }
    await assert.rejects(completeAdministrativeEmailRecovery({
      actor: afterStart.actor, sessionId: afterStart.sessionId, requestKey, code,
      normalPassword: NORMAL_PASSWORD, newPassword: "email-recovery-must-not-resurrect-2026"
    }), AdministrationMutationError);
    const current = await prisma.administrativeCredential.findUnique({ where: { userId: afterStart.actor.id } });
    if (state === "missing") {
      assert.equal(current, null, "the old OTP must not recreate an absent credential");
    } else {
      assert.equal(current?.status, "REVOKED");
      assert.ok(current?.revokedAt);
      assert.equal(current?.passwordHash, previous.passwordHash);
      assert.equal(current?.keyVersion, previous.keyVersion);
    }
    assert.equal((await prisma.securityElevation.findUniqueOrThrow({
      where: { requestKey }, select: { status: true }
    })).status, "PENDING", "a rejected OTP must not be marked consumed or authorize an elevation");
    assert.equal(await prisma.administrativeRecoveryCode.count({ where: { userId: afterStart.actor.id } }), 0);
    assert.equal(await prisma.auditLog.count({
      where: { actorUserId: afterStart.actor.id, eventType: "ADMIN_CREDENTIAL_EMAIL_RECOVERED" }
    }), 0);
    assert.equal((await prisma.session.findUniqueOrThrow({
      where: { id: afterStart.sessionId }, select: { revokedAt: true }
    })).revokedAt, null);
  });
}

test("ADMIN email recovery fails closed for a changed verified mailbox, wrong session, stale version, wrong password and expiry", integrationOptions, async () => {
  const cases = ["wrong-session", "changed-email", "rotated-credential", "wrong-password", "expired", "incorrect-code", "same-as-normal"] as const;
  for (const kind of cases) {
    const admin = await setupAdmin();
    const startedAt = new Date();
    const requestKey = await startAdministrativeEmailRecovery({ actor: admin.actor, sessionId: admin.sessionId, normalPassword: NORMAL_PASSWORD, locale: LOCALE, now: startedAt });
    const emailedCode = await latestEmailCode(admin.email, "ADMIN_EMAIL_VERIFICATION");
    let sessionId = admin.sessionId;
    let code = emailedCode;
    let candidateNormalPassword = NORMAL_PASSWORD;
    let newPassword = "admin-recovered-with-email-2026";
    let now = startedAt;
    if (kind === "wrong-session") {
      sessionId = (await prisma.session.create({ data: { userId: admin.actor.id, tokenHash: randomBytes(32).toString("base64url"), expiresAt: new Date(Date.now() + DAY) } })).id;
    } else if (kind === "changed-email") {
      const updated = `${randomBytes(8).toString("hex")}@integration.invalid`;
      await prisma.user.update({ where: { id: admin.actor.id }, data: { email: updated, emailNormalized: updated } });
    } else if (kind === "rotated-credential") {
      await prisma.administrativeCredential.update({ where: { userId: admin.actor.id }, data: { keyVersion: { increment: 1 } } });
    } else if (kind === "wrong-password") {
      candidateNormalPassword = "incorrect-normal-password";
    } else if (kind === "expired") {
      now = new Date(startedAt.getTime() + 10 * MINUTE);
    } else if (kind === "incorrect-code") {
      code = emailedCode === "000000" ? "000001" : "000000";
    } else if (kind === "same-as-normal") {
      newPassword = NORMAL_PASSWORD;
    }
    await assert.rejects(
      completeAdministrativeEmailRecovery({ actor: admin.actor, sessionId, requestKey, code, normalPassword: candidateNormalPassword, newPassword, now }),
      kind === "same-as-normal" ? AdministrativePasswordReuseError : AdministrationMutationError,
      `must reject ${kind}`
    );
    const credential = await prisma.administrativeCredential.findUniqueOrThrow({ where: { userId: admin.actor.id } });
    assert.equal(await verifyPassword(credential.passwordHash, ADMIN_PASSWORD), true, kind);
    assert.equal((await prisma.securityElevation.findUniqueOrThrow({ where: { requestKey } })).status, "PENDING", kind);
    assert.equal(await prisma.auditLog.count({ where: { actorUserId: admin.actor.id, eventType: "ADMIN_CREDENTIAL_EMAIL_RECOVERED" } }), 0, kind);
  }
});

test("starting another ADMIN email recovery invalidates the previous email OTP", integrationOptions, async () => {
  const admin = await setupAdmin();
  const firstKey = await startAdministrativeEmailRecovery({ actor: admin.actor, sessionId: admin.sessionId, normalPassword: NORMAL_PASSWORD, locale: LOCALE });
  const firstCode = await latestEmailCode(admin.email, "ADMIN_EMAIL_VERIFICATION");
  const secondKey = await startAdministrativeEmailRecovery({ actor: admin.actor, sessionId: admin.sessionId, normalPassword: NORMAL_PASSWORD, locale: LOCALE });
  assert.notEqual(firstKey, secondKey);
  assert.equal((await prisma.securityElevation.findUniqueOrThrow({ where: { requestKey: firstKey } })).status, "REVOKED");
  await assert.rejects(completeAdministrativeEmailRecovery({
    actor: admin.actor, sessionId: admin.sessionId, requestKey: firstKey, code: firstCode,
    normalPassword: NORMAL_PASSWORD, newPassword: "new-admin-old-email-proof"
  }), AdministrationMutationError);
  const secondCode = await latestEmailCode(admin.email, "ADMIN_EMAIL_VERIFICATION");
  const codes = await completeAdministrativeEmailRecovery({
    actor: admin.actor, sessionId: admin.sessionId, requestKey: secondKey, code: secondCode,
    normalPassword: NORMAL_PASSWORD, newPassword: "new-admin-latest-email-proof"
  });
  assert.equal(codes.length, 10);
});

test("competing ADMIN email recovery completions cannot rotate the credential twice", integrationOptions, async () => {
  const admin = await setupAdmin();
  const requestKey = await startAdministrativeEmailRecovery({ actor: admin.actor, sessionId: admin.sessionId, normalPassword: NORMAL_PASSWORD, locale: LOCALE });
  const code = await latestEmailCode(admin.email, "ADMIN_EMAIL_VERIFICATION");
  const attempts = await Promise.allSettled([
    completeAdministrativeEmailRecovery({ actor: admin.actor, sessionId: admin.sessionId, requestKey, code, normalPassword: NORMAL_PASSWORD, newPassword: "email-recovery-concurrent-a-2026" }),
    completeAdministrativeEmailRecovery({ actor: admin.actor, sessionId: admin.sessionId, requestKey, code, normalPassword: NORMAL_PASSWORD, newPassword: "email-recovery-concurrent-b-2026" })
  ]);
  assert.equal(attempts.filter((result) => result.status === "fulfilled").length, 1);
  assert.equal(attempts.filter((result) => result.status === "rejected").length, 1);
  assert.equal((await prisma.administrativeCredential.findUniqueOrThrow({ where: { userId: admin.actor.id } })).keyVersion, 2);
  assert.equal(await prisma.administrativeRecoveryCode.count({ where: { userId: admin.actor.id } }), 10);
  assert.equal(await prisma.auditLog.count({ where: { actorUserId: admin.actor.id, eventType: "ADMIN_CREDENTIAL_EMAIL_RECOVERED", result: "SUCCESS" } }), 1);
  assert.equal((await prisma.securityElevation.findUniqueOrThrow({ where: { requestKey } })).status, "CONSUMED");
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

test("ADMIN initial credential setup rejects OTP expired while blocked on challenge row", integrationOptions, async () => {
  const admin = await setupAdmin({ credential: false });
  const requestKey = await startAdministrativeCredentialSetup({
    actor: admin.actor, sessionId: admin.sessionId, normalPassword: NORMAL_PASSWORD, locale: LOCALE
  });
  const code = await latestEmailCode(admin.email, "ADMIN_EMAIL_VERIFICATION");
  const expiresAt = new Date(Date.now() + 3_000);
  await prisma.securityElevation.update({
    where: { requestKey },
    data: { createdAt: new Date(expiresAt.getTime() - 10 * MINUTE), expiresAt }
  });
  let blockerPid = 0;
  let locked!: () => void;
  let release!: () => void;
  const ready = new Promise<void>((resolve) => { locked = resolve; });
  const gate = new Promise<void>((resolve) => { release = resolve; });
  const blocker = prisma.$transaction(async (tx) => {
    [{ pid: blockerPid }] = await tx.$queryRaw<Array<{ pid: number }>>`SELECT pg_backend_pid() AS pid`;
    await tx.$queryRaw`SELECT "id" FROM "SecurityElevation" WHERE "requestKey" = ${requestKey} FOR UPDATE`;
    locked();
    await gate;
  }, { timeout: 10_000 });
  await ready;
  const completing = completeAdministrativeCredentialSetup({
    actor: admin.actor, sessionId: admin.sessionId, requestKey, code, newPassword: ADMIN_PASSWORD
  }).then(() => ({ ok: true as const }), (error: unknown) => ({ ok: false as const, error }));
  try {
    // Prisma may issue a SELECT/FOR UPDATE or UPDATE as its first waiter.
    // The blocker PID and PostgreSQL wait_event_type establish the actual lock wait.
    await waitForBlockedPostgresQuery(blockerPid, "");
    assert.ok(Date.now() < expiresAt.getTime(), "OTP must be valid at the start of the blocked write");
    await new Promise<void>((resolve) => setTimeout(resolve, Math.max(0, expiresAt.getTime() - Date.now() + 100)));
  } finally {
    release();
    await blocker;
  }
  const outcome = await completing;
  assert.equal(outcome.ok, false, "an expired OTP must not create an ADMIN credential");
  if (!outcome.ok) assert.ok(outcome.error instanceof AdministrationMutationError);
  assert.equal(await prisma.administrativeCredential.count({ where: { userId: admin.actor.id } }), 0);
  assert.equal((await prisma.securityElevation.findUniqueOrThrow({ where: { requestKey }, select: { status: true } })).status, "PENDING");
  assert.equal(await prisma.auditLog.count({ where: { actorUserId: admin.actor.id, eventType: "ADMIN_CREDENTIAL_SETUP", result: "SUCCESS" } }), 0);
});

test("ADMIN initial setup rejects OTP expiring during subsequent old recovery-code cleanup", integrationOptions, async () => {
  const admin = await setupAdmin({ credential: false });
  const requestKey = await startAdministrativeCredentialSetup({
    actor: admin.actor, sessionId: admin.sessionId, normalPassword: NORMAL_PASSWORD, locale: LOCALE
  });
  const code = await latestEmailCode(admin.email, "ADMIN_EMAIL_VERIFICATION");
  const oldCode = await prisma.administrativeRecoveryCode.create({
    data: { userId: admin.actor.id, codeHash: hashRecoveryCode(`old-recovery-${randomBytes(6).toString("hex")}`) },
    select: { id: true }
  });
  const expiresAt = new Date(Date.now() + 3_000);
  await prisma.securityElevation.update({
    where: { requestKey },
    data: { createdAt: new Date(expiresAt.getTime() - 10 * MINUTE), expiresAt }
  });
  let blockerPid = 0;
  let locked!: () => void;
  let release!: () => void;
  const ready = new Promise<void>((resolve) => { locked = resolve; });
  const gate = new Promise<void>((resolve) => { release = resolve; });
  const blocker = prisma.$transaction(async (tx) => {
    [{ pid: blockerPid }] = await tx.$queryRaw<Array<{ pid: number }>>`SELECT pg_backend_pid() AS pid`;
    await tx.$queryRaw`SELECT "id" FROM "AdministrativeRecoveryCode" WHERE "id" = ${oldCode.id} FOR UPDATE`;
    locked();
    await gate;
  }, { timeout: 10_000 });
  await ready;
  const completing = completeAdministrativeCredentialSetup({
    actor: admin.actor, sessionId: admin.sessionId, requestKey, code, newPassword: ADMIN_PASSWORD
  }).then(() => ({ ok: true as const }), (error: unknown) => ({ ok: false as const, error }));
  try {
    await waitForBlockedPostgresQuery(blockerPid, "");
    assert.ok(Date.now() < expiresAt.getTime(), "the OTP must be valid when the old recovery-code cleanup waits");
    await new Promise<void>((resolve) => setTimeout(resolve, Math.max(0, expiresAt.getTime() - Date.now() + 100)));
  } finally {
    release();
    await blocker;
  }
  const outcome = await completing;
  assert.equal(outcome.ok, false, "a setup must not commit after the bound OTP expires in later cleanup");
  if (!outcome.ok) assert.ok(outcome.error instanceof AdministrationMutationError);
  assert.equal(await prisma.administrativeCredential.count({ where: { userId: admin.actor.id } }), 0);
  assert.equal((await prisma.securityElevation.findUniqueOrThrow({ where: { requestKey }, select: { status: true } })).status, "PENDING");
  assert.ok(await prisma.administrativeRecoveryCode.findUnique({ where: { id: oldCode.id } }));
  assert.equal(await prisma.auditLog.count({ where: { actorUserId: admin.actor.id, eventType: "ADMIN_CREDENTIAL_SETUP", result: "SUCCESS" } }), 0);
});

test("ADMIN credential recovery rejects session expired while blocked on recovery-code row", integrationOptions, async () => {
  const admin = await setupAdmin();
  const recoveryCode = `expiry-recovery-${randomBytes(6).toString("hex")}`;
  const row = await prisma.administrativeRecoveryCode.create({
    data: { userId: admin.actor.id, codeHash: hashRecoveryCode(recoveryCode) },
    select: { id: true }
  });
  const credentialBefore = await prisma.administrativeCredential.findUniqueOrThrow({
    where: { userId: admin.actor.id }, select: { keyVersion: true, passwordHash: true }
  });
  const expiresAt = new Date(Date.now() + 3_000);
  await prisma.session.update({ where: { id: admin.sessionId }, data: { expiresAt } });
  let blockerPid = 0;
  let locked!: () => void;
  let release!: () => void;
  const ready = new Promise<void>((resolve) => { locked = resolve; });
  const gate = new Promise<void>((resolve) => { release = resolve; });
  const blocker = prisma.$transaction(async (tx) => {
    [{ pid: blockerPid }] = await tx.$queryRaw<Array<{ pid: number }>>`SELECT pg_backend_pid() AS pid`;
    await tx.$queryRaw`SELECT "id" FROM "AdministrativeRecoveryCode" WHERE "id" = ${row.id} FOR UPDATE`;
    locked();
    await gate;
  }, { timeout: 10_000 });
  await ready;
  const recovering = recoverAdministrativeCredential({
    actor: admin.actor, sessionId: admin.sessionId, normalPassword: NORMAL_PASSWORD, recoveryCode,
    newPassword: "integration-expired-session-recovery-1"
  }).then(() => ({ ok: true as const }), (error: unknown) => ({ ok: false as const, error }));
  try {
    await waitForBlockedPostgresQuery(blockerPid, "");
    assert.ok(Date.now() < expiresAt.getTime(), "session must be valid before the recovery code lock wait");
    await new Promise<void>((resolve) => setTimeout(resolve, Math.max(0, expiresAt.getTime() - Date.now() + 100)));
  } finally {
    release();
    await blocker;
  }
  const outcome = await recovering;
  assert.equal(outcome.ok, false, "an expired session must not rotate administrative credentials");
  if (!outcome.ok) assert.ok(outcome.error instanceof AdministrationMutationError);
  assert.deepEqual(await prisma.administrativeCredential.findUniqueOrThrow({
    where: { userId: admin.actor.id }, select: { keyVersion: true, passwordHash: true }
  }), credentialBefore);
  assert.equal((await prisma.administrativeRecoveryCode.findUniqueOrThrow({ where: { id: row.id }, select: { usedAt: true } })).usedAt, null);
  assert.equal(await prisma.auditLog.count({ where: { actorUserId: admin.actor.id, eventType: "ADMIN_CREDENTIAL_RECOVERED", result: "SUCCESS" } }), 0);
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
