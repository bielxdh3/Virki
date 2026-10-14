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
  recoverAdministrativeCredential,
  startAdministrativeCredentialSetup,
  startSecurityElevation,
  verifySecurityElevation
} from "./administration";
import { createTestUser, integrationOptions, queuedEmails } from "./integration-fixtures";
import { hashPassword } from "./index";
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
    recoverAdministrativeCredential({ actor: admin.actor, normalPassword: NORMAL_PASSWORD, recoveryCode, newPassword: NORMAL_PASSWORD }),
    AdministrativePasswordReuseError
  );
  // The rejected attempt must not consume the single-use recovery code.
  const codes = await recoverAdministrativeCredential({ actor: admin.actor, normalPassword: NORMAL_PASSWORD, recoveryCode, newPassword: "integration-recovered-admin-1" });
  assert.equal(codes.length, 10);
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
