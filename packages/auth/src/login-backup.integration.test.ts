import assert from "node:assert/strict";
import { after, test } from "node:test";
import { prisma } from "@virki/database";
import { createTestUser, integrationOptions, queuedEmails } from "./integration-fixtures";
import {
  createTotpSecret, generateRecoveryCode, hashRecoveryCode, hashDeviceToken,
  getLoginBackupOption, getLoginChallengeFactor, LOGIN_TOTP_CEREMONY_ACCOUNT_LIMIT, selectLoginBackupFactor, startLoginCeremony,
  verifyLoginBackupCode, verifyLoginEmailCode, verifyLoginTotpCode, SecurityMutationError
} from "./security";

after(() => prisma.$disconnect());

async function startBackup(user: { id: string; email: string }, role: "USER" | "ADMIN" = "USER") {
  const started = await startLoginCeremony(user.id, undefined, "pt-BR", new Date(), false, role, "203.0.113.202", "REGISTERED");
  assert.equal(started.kind, "CEREMONY");
  assert.equal(started.factor, "TOTP");
  assert.equal(await getLoginBackupOption(started.ceremonyId, started.deviceToken, role), true);
  await selectLoginBackupFactor(started.ceremonyId, started.deviceToken, role);
  return started;
}

test("PostgreSQL: password + backup is one non-destructive second factor on an untrusted device", integrationOptions, async () => {
  const owner = await createTestUser({ totpSecret: createTotpSecret(), label: "backup-login-new-device" });
  const codes = [generateRecoveryCode(), generateRecoveryCode(), generateRecoveryCode()];
  await prisma.recoveryCode.createMany({ data: codes.map((code) => ({ userId: owner.id, codeHash: hashRecoveryCode(code) })) });
  const existing = await prisma.session.create({ data: { userId: owner.id, tokenHash: hashRecoveryCode(generateRecoveryCode()), expiresAt: new Date(Date.now() + 60_000) } });
  const beforeEmails = (await queuedEmails(owner.email)).length;
  const challenge = await startBackup(owner);
  await assert.rejects(verifyLoginTotpCode(challenge.ceremonyId, "000000", challenge.deviceToken, new Date(), "USER"), SecurityMutationError);
  await assert.rejects(verifyLoginEmailCode(challenge.ceremonyId, "000000", challenge.deviceToken, new Date(), "USER"), SecurityMutationError);
  // Native self-hosted login must also work without a Cloudflare client-IP header.
  const issued = await verifyLoginBackupCode(challenge.ceremonyId, codes[0]!, challenge.deviceToken, new Date(), "USER");
  assert.ok(issued.token);
  const session = await prisma.session.findUniqueOrThrow({ where: { id: issued.id } });
  assert.deepEqual(session.authenticationMethods, ["pwd", "otp", "mfa", "backup"]);
  assert.equal(await prisma.trustedDevice.count({ where: { userId: owner.id, deviceIdHash: hashDeviceToken(challenge.deviceToken), status: "TRUSTED" } }), 1);
  assert.equal((await prisma.session.findUniqueOrThrow({ where: { id: existing.id } })).revokedAt, null);
  assert.equal((await prisma.totpFactor.findUniqueOrThrow({ where: { userId: owner.id } })).status, "ACTIVE");
  assert.equal(await prisma.recoveryCode.count({ where: { userId: owner.id, usedAt: null } }), 2);
  assert.equal((await prisma.recoveryCode.findFirstOrThrow({ where: { userId: owner.id, codeHash: hashRecoveryCode(codes[0]!) } })).usedAt instanceof Date, true);
  assert.equal((await queuedEmails(owner.email)).length, beforeEmails);
  await assert.rejects(verifyLoginBackupCode(challenge.ceremonyId, codes[0]!, challenge.deviceToken, new Date(), "USER", "203.0.113.202"), SecurityMutationError);
});

test("PostgreSQL: bound role, device, active policy and selection enforce backup eligibility", integrationOptions, async () => {
  const owner = await createTestUser({ totpSecret: createTotpSecret(), role: "ADMIN", label: "backup-admin" });
  const code = generateRecoveryCode();
  await prisma.recoveryCode.create({ data: { userId: owner.id, codeHash: hashRecoveryCode(code) } });
  const challenge = await startLoginCeremony(owner.id, undefined, "pt-BR", new Date(), false, "ADMIN", "203.0.113.203", "REGISTERED");
  assert.equal(challenge.kind, "CEREMONY");
  assert.equal(challenge.factor, "TOTP");
  assert.equal(await getLoginBackupOption(challenge.ceremonyId, challenge.deviceToken, "USER"), false);
  await assert.rejects(selectLoginBackupFactor(challenge.ceremonyId, challenge.deviceToken, "USER"), SecurityMutationError);
  await assert.rejects(selectLoginBackupFactor(challenge.ceremonyId, "invalid-device", "ADMIN"), SecurityMutationError);
  await assert.rejects(verifyLoginBackupCode(challenge.ceremonyId, code, challenge.deviceToken, new Date(), "ADMIN", "203.0.113.203"), SecurityMutationError);
  await selectLoginBackupFactor(challenge.ceremonyId, challenge.deviceToken, "ADMIN");
  await assert.rejects(verifyLoginBackupCode(challenge.ceremonyId, code, "wrong-device", new Date(), "ADMIN", "203.0.113.203"), SecurityMutationError);
  await assert.rejects(verifyLoginBackupCode(challenge.ceremonyId, code, challenge.deviceToken, new Date(), "USER", "203.0.113.203"), SecurityMutationError);
  await verifyLoginBackupCode(challenge.ceremonyId, code, challenge.deviceToken, new Date(), "ADMIN", "203.0.113.203");
  const next = await startLoginCeremony(owner.id, challenge.deviceToken, "pt-BR", new Date(), false, "ADMIN", "203.0.113.203", "REGISTERED");
  assert.equal(next.kind, "CEREMONY", "ADMIN must never get remembered password-only login");
});

test("PostgreSQL: competing requests cannot spend one backup code twice", integrationOptions, async () => {
  const owner = await createTestUser({ totpSecret: createTotpSecret(), label: "backup-one-winner" });
  const code = generateRecoveryCode();
  await prisma.recoveryCode.create({ data: { userId: owner.id, codeHash: hashRecoveryCode(code) } });
  const challenge = await startBackup(owner);
  const beforeSessions = await prisma.session.count({ where: { userId: owner.id } });
  const outcomes = await Promise.allSettled([
    verifyLoginBackupCode(challenge.ceremonyId, code, challenge.deviceToken, new Date(), "USER", "203.0.113.204"),
    verifyLoginBackupCode(challenge.ceremonyId, code, challenge.deviceToken, new Date(), "USER", "203.0.113.204")
  ]);
  assert.equal(outcomes.filter((result) => result.status === "fulfilled").length, 1);
  assert.equal(outcomes.filter((result) => result.status === "rejected").length, 1);
  assert.equal(await prisma.session.count({ where: { userId: owner.id } }), beforeSessions + 1);
  assert.equal(await prisma.recoveryCode.count({ where: { userId: owner.id, usedAt: { not: null } } }), 1);
});

test("PostgreSQL: local native host may authenticate an ADMIN without role confusion", integrationOptions, async () => {
  const admin = await createTestUser({ role: "ADMIN", totpSecret: createTotpSecret(), label: "backup-local-admin" });
  const code = generateRecoveryCode();
  await prisma.recoveryCode.create({ data: { userId: admin.id, codeHash: hashRecoveryCode(code) } });
  const challenge = await startLoginCeremony(admin.id, undefined, "pt-BR", new Date(), false, undefined, undefined, "REGISTERED");
  assert.equal(challenge.kind, "CEREMONY");
  assert.equal(challenge.factor, "TOTP");
  assert.equal(await getLoginBackupOption(challenge.ceremonyId, challenge.deviceToken), true);
  await selectLoginBackupFactor(challenge.ceremonyId, challenge.deviceToken);
  const session = await verifyLoginBackupCode(challenge.ceremonyId, code, challenge.deviceToken, new Date());
  assert.equal(session.userId, admin.id);
  assert.equal((await prisma.session.findUniqueOrThrow({ where: { id: session.id } })).userId, admin.id);
  const next = await startLoginCeremony(admin.id, challenge.deviceToken, "pt-BR", new Date(), false, undefined, undefined, "REGISTERED");
  assert.equal(next.kind, "CEREMONY");
});

test("PostgreSQL: EMAIL account cannot select backup and an expired TOTP ceremony cannot switch", integrationOptions, async () => {
  const emailUser = await createTestUser({ label: "backup-email-denied" });
  const started = await startLoginCeremony(emailUser.id, undefined, "pt-BR", new Date(), false, "USER", "203.0.113.205", "REGISTERED");
  assert.equal(started.kind, "CEREMONY");
  assert.equal(started.factor, "EMAIL");
  assert.equal(await getLoginBackupOption(started.ceremonyId, started.deviceToken, "USER"), false);
  await assert.rejects(selectLoginBackupFactor(started.ceremonyId, started.deviceToken, "USER"), SecurityMutationError);
  const owner = await createTestUser({ totpSecret: createTotpSecret(), label: "backup-expiry" });
  await prisma.recoveryCode.create({ data: { userId: owner.id, codeHash: hashRecoveryCode(generateRecoveryCode()) } });
  const challenge = await startLoginCeremony(owner.id, undefined, "pt-BR", new Date(), false, "USER", "203.0.113.206", "REGISTERED");
  assert.equal(challenge.kind, "CEREMONY");
  await prisma.deviceChallenge.update({ where: { ceremonyId: challenge.ceremonyId }, data: { expiresAt: new Date(Date.now() - 1_000) } });
  assert.equal(await getLoginBackupOption(challenge.ceremonyId, challenge.deviceToken, "USER"), false);
  await assert.rejects(selectLoginBackupFactor(challenge.ceremonyId, challenge.deviceToken, "USER"), SecurityMutationError);
});

test("PostgreSQL: legacy NULL factors infer only the verified email or TOTP stage", integrationOptions, async () => {
  const owner = await createTestUser({ totpSecret: createTotpSecret(), label: "legacy-null-login-factor" });
  const started = await startLoginCeremony(owner.id, undefined, "pt-BR", new Date(), false, "USER", "203.0.113.208");
  assert.equal(started.kind, "CEREMONY");
  assert.equal(started.factor, "EMAIL");
  const legacy = await prisma.deviceChallenge.findUniqueOrThrow({ where: { ceremonyId: started.ceremonyId } });
  assert.equal(legacy.factorChoice, null);
  assert.equal(await getLoginChallengeFactor(started.ceremonyId, started.deviceToken, "USER"), "email");
  const emailCode = (await queuedEmails(owner.email)).find((mail) => mail.kind === "NEW_DEVICE_VERIFICATION")?.code;
  assert.ok(emailCode);
  const verified = await verifyLoginEmailCode(started.ceremonyId, emailCode, started.deviceToken, new Date(), "USER");
  assert.equal(verified.requiresTotp, true);
  assert.equal(await getLoginChallengeFactor(started.ceremonyId, started.deviceToken, "USER"), "totp");
  assert.equal(await getLoginBackupOption(started.ceremonyId, started.deviceToken, "USER"), false);
  await prisma.deviceChallenge.update({ where: { ceremonyId: started.ceremonyId }, data: { expiresAt: new Date(Date.now() - 1_000) } });
  assert.equal(await getLoginChallengeFactor(started.ceremonyId, started.deviceToken, "USER"), null);
});

test("PostgreSQL: correct password cannot flood registered TOTP ceremonies through rotating devices", integrationOptions, async () => {
  const owner = await createTestUser({ totpSecret: createTotpSecret(), label: "totp-start-account-quota" });
  const now = new Date();
  for (let index = 0; index < LOGIN_TOTP_CEREMONY_ACCOUNT_LIMIT; index += 1) {
    const result = await startLoginCeremony(owner.id, undefined, "pt-BR", now, false, "USER", "203.0.113.207", "REGISTERED");
    assert.equal(result.kind, "CEREMONY");
    assert.equal(result.factor, "TOTP");
  }
  await assert.rejects(startLoginCeremony(owner.id, undefined, "pt-BR", now, false, "USER", "203.0.113.207", "REGISTERED"));
  assert.equal(await prisma.deviceChallenge.count({ where: { userId: owner.id, factorChoice: "TOTP", status: "VERIFIED" } }), LOGIN_TOTP_CEREMONY_ACCOUNT_LIMIT);
});
