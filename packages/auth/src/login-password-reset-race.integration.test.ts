import assert from "node:assert/strict";
import { after, test } from "node:test";
import { prisma } from "@virki/database";
import { authenticateUserWithRateLimit, hashPassword } from "./index";
import { createTestUser, integrationOptions, queuedEmails } from "./integration-fixtures";
import { startLoginCeremony } from "./security";

after(() => prisma.$disconnect());

test("ADMIN login rejects a password verified before a committed normal-password reset", integrationOptions, async () => {
  const admin = await createTestUser({ role: "ADMIN", label: "login-reset-race" });
  const source = "203.0.113.231";
  const verified = await authenticateUserWithRateLimit(admin.email, admin.password, new Date(), source, "ADMIN");
  assert.equal(verified.user?.id, admin.id, "old password must have been accepted before the reset");

  const replacement = "new-normal-admin-password-for-reset-race";
  const replacementHash = await hashPassword(replacement);
  // Commit the same account-row password rotation and login-proof invalidation
  // used by normal-password recovery in the gap before startLoginCeremony.
  await prisma.$transaction(async (transaction) => {
    await transaction.$queryRaw`SELECT "id" FROM "User" WHERE "id" = ${admin.id} FOR UPDATE`;
    await transaction.user.update({ where: { id: admin.id }, data: { passwordHash: replacementHash, secondFactorMethod: "EMAIL" } });
    await transaction.deviceChallenge.updateMany({ where: { userId: admin.id, status: { in: ["PENDING", "VERIFIED"] } }, data: { status: "REVOKED" } });
    await transaction.session.updateMany({ where: { userId: admin.id, revokedAt: null }, data: { revokedAt: new Date() } });
  });

  await assert.rejects(
    startLoginCeremony(admin.id, undefined, "pt-BR", new Date(), false, "ADMIN", source, "REGISTERED", admin.password),
    "a stale password may not create a fresh email MFA ceremony after the password reset"
  );
  assert.equal(await prisma.deviceChallenge.count({ where: { userId: admin.id } }), 0);
  assert.equal(await prisma.session.count({ where: { userId: admin.id, revokedAt: null } }), 0);

  const current = await authenticateUserWithRateLimit(admin.email, replacement, new Date(), source, "ADMIN");
  assert.equal(current.user?.id, admin.id, "the new password must remain accepted");
  const started = await startLoginCeremony(admin.id, undefined, "pt-BR", new Date(), false, "ADMIN", source, "REGISTERED", replacement);
  assert.equal(started.kind, "CEREMONY");
  if (started.kind !== "CEREMONY") return;
  assert.equal(started.factor, "EMAIL", "ADMIN always requires a fresh second factor after reset");
  const code = (await queuedEmails(admin.email)).filter((message) => message.kind === "NEW_DEVICE_VERIFICATION").at(-1)?.code;
  assert.match(code ?? "", /^\d{6}$/u);
  // This race regression proves the new password reaches fresh MFA; completion
  // and cookie issuance are exercised by the dedicated login ceremony tests.
});
