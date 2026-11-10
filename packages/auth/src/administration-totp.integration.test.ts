import assert from "node:assert/strict";
import { createHmac, randomBytes } from "node:crypto";
import { after, test } from "node:test";
import { prisma } from "@virki/database";
import { AdministrativePasswordReuseError, AdministrationMutationError, hasActiveSecurityElevation, recoverAdministrativeCredentialWithTotp, regenerateAdministrativeRecoveryCodes, startSecurityElevation, verifySecurityElevation } from "./administration";
import { createTestUser, integrationOptions, queuedEmails } from "./integration-fixtures";
import { hashPassword, verifyPassword } from "./index";
import { createTotpSecret, encryptTotpSecret, getLoginCeremonyFailureStage, hashRecoveryCode, startLoginCeremony, verifyLoginEmailCode, verifyLoginTotpCode } from "./security";
import { hashOidcIdentifier } from "./oidc-secrets";

after(() => prisma.$disconnect());

const NORMAL = "test-login-normal-credential-2026";
const ADMIN = "test-separate-admin-credential-2026";
const NEW_ADMIN = "test-new-admin-credential-2026";
const DAY = 86_400_000;

// Independent RFC 6238 calculator, not the application's verifier.
function totpAt(secret: string, at = new Date()): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bytes: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (const character of secret) {
    buffer = (buffer << 5) | alphabet.indexOf(character);
    bits += 5;
    if (bits >= 8) {
      bytes.push((buffer >>> (bits - 8)) & 255);
      bits -= 8;
      buffer &= (1 << bits) - 1;
    }
  }
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(at.getTime() / 30_000)));
  const digest = createHmac("sha1", Buffer.from(bytes)).update(counter).digest();
  const offset = digest[digest.length - 1]! & 15;
  return String((digest.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).padStart(6, "0");
}

async function createAdmin(withTotp = true) {
  const secret = createTotpSecret();
  const user = await createTestUser({
    role: "ADMIN", label: "admin-totp-credential-recovery", password: NORMAL,
    ...(withTotp ? { totpSecret: secret } : {})
  });
  const session = await prisma.session.create({
    data: { userId: user.id, tokenHash: randomBytes(32).toString("base64url"), expiresAt: new Date(Date.now() + DAY) }
  });
  await prisma.administrativeCredential.create({
    data: { userId: user.id, passwordHash: await hashPassword(ADMIN), status: "ACTIVE" }
  });
  return { userId: user.id, actor: { id: user.id, role: "ADMIN" }, sessionId: session.id, secret, email: user.email };
}

function recover(admin: Awaited<ReturnType<typeof createAdmin>>, code = totpAt(admin.secret), newPassword = NEW_ADMIN) {
  return recoverAdministrativeCredentialWithTotp({
    actor: admin.actor, sessionId: admin.sessionId, normalPassword: NORMAL,
    totpCode: code, newPassword
  });
}

test("TOTP recovery rotates only the administrative password, invalidates artifacts, keeps normal login/TOTP active", integrationOptions, async () => {
  const admin = await createAdmin();
  const oldCode = randomBytes(12).toString("hex");
  await prisma.administrativeRecoveryCode.create({ data: { userId: admin.userId, codeHash: hashRecoveryCode(oldCode) } });
  const otherSession = await prisma.session.create({
    data: { userId: admin.userId, tokenHash: randomBytes(32).toString("base64url"), expiresAt: new Date(Date.now() + DAY) }
  });
  const device = await prisma.trustedDevice.create({ data: { userId: admin.userId, deviceIdHash: randomBytes(32).toString("hex") } });
  const oidc = await prisma.oidcArtifact.create({
    data: { model: "Session", idHash: randomBytes(32).toString("hex"), accountIdHash: hashOidcIdentifier(admin.userId), payloadCiphertext: "disposable-integration-fixture" }
  });
  const oldPasskey = await prisma.passkeyCredential.create({
    data: {
      userId: admin.userId,
      credentialId: randomBytes(32).toString("base64url"),
      rpID: "hub.biel.dev.br",
      publicKey: randomBytes(65),
      backupEligible: false,
      backupState: false,
      name: "Revoked older hub recovery key"
    }
  });
  const normalBefore = (await prisma.user.findUniqueOrThrow({ where: { id: admin.userId } })).passwordHash;
  const codes = await recover(admin);
  assert.equal(codes.length, 10);
  assert.equal(new Set(codes).size, 10);
  const credential = await prisma.administrativeCredential.findUniqueOrThrow({ where: { userId: admin.userId } });
  assert.equal(credential.keyVersion, 2);
  assert.equal(await verifyPassword(credential.passwordHash, NEW_ADMIN), true);
  assert.equal(await verifyPassword(credential.passwordHash, ADMIN), false);
  const normal = await prisma.user.findUniqueOrThrow({ where: { id: admin.userId } });
  assert.equal(normal.passwordHash, normalBefore);
  assert.equal(await verifyPassword(normal.passwordHash!, NORMAL), true);
  assert.equal(normal.secondFactorMethod, "TOTP");
  const factor = await prisma.totpFactor.findUniqueOrThrow({ where: { userId: admin.userId } });
  assert.equal(factor.status, "ACTIVE");
  assert.ok(factor.confirmedAt);
  assert.ok(factor.lastUsedStep !== null);
  assert.equal(await prisma.administrativeRecoveryCode.count({ where: { userId: admin.userId, usedAt: null } }), 10);
  assert.equal(await prisma.administrativeRecoveryCode.count({ where: { userId: admin.userId, codeHash: hashRecoveryCode(oldCode) } }), 0);
  assert.notEqual((await prisma.session.findUniqueOrThrow({ where: { id: otherSession.id } })).revokedAt, null);
  assert.equal((await prisma.session.findUniqueOrThrow({ where: { id: admin.sessionId } })).revokedAt, null);
  assert.equal((await prisma.trustedDevice.findUniqueOrThrow({ where: { id: device.id } })).status, "REVOKED");
  assert.equal(await prisma.oidcArtifact.count({ where: { id: oidc.id } }), 0);
  const revokedPasskey = await prisma.passkeyCredential.findUniqueOrThrow({ where: { id: oldPasskey.id } });
  assert.ok(revokedPasskey.revokedAt, "older hub passkeys must not authorize subsequent recovery");
  const audit = await prisma.auditLog.findMany({ where: { actorUserId: admin.userId, eventType: "ADMIN_CREDENTIAL_TOTP_RECOVERED" } });
  assert.equal(audit.length, 1);
  assert.equal(audit[0]?.result, "SUCCESS");
  assert.doesNotMatch(JSON.stringify(audit), new RegExp(admin.secret));
  assert.equal((await queuedEmails(admin.email)).length, 0, "TOTP recovery has no email delivery dependency");
  // The ordinary login ceremony still works with the unchanged login password
  // and ACTIVE TOTP. An unused future step is needed because recovery consumed
  // the current step globally, as it should.
  const login = await startLoginCeremony(admin.userId, undefined, "pt-BR", new Date(), false, "ADMIN").catch((error: unknown) => {
    assert.fail(`ordinary login after TOTP recovery failed at ${getLoginCeremonyFailureStage(error) ?? "unknown stage"}`);
  });
  assert.equal(login.kind, "CEREMONY");
  if (login.kind !== "CEREMONY") throw new Error("Expected login ceremony");
  const loginCode = (await queuedEmails(admin.email)).find((message) => message.kind === "NEW_DEVICE_VERIFICATION")?.code;
  assert.ok(loginCode);
  const emailStep = await verifyLoginEmailCode(login.ceremonyId, loginCode, login.deviceToken, new Date(), "ADMIN");
  assert.equal(emailStep.requiresTotp, true);
  const futureStepAt = new Date(Date.now() + 60_000);
  const renewed = await verifyLoginTotpCode(login.ceremonyId, totpAt(admin.secret, futureStepAt), login.deviceToken, futureStepAt, "ADMIN");
  assert.ok(renewed.token);
  await assert.rejects(recover(admin), AdministrationMutationError, "the same TOTP step is single use across the login and ADMIN flows");
  assert.equal((await prisma.administrativeCredential.findUniqueOrThrow({ where: { userId: admin.userId } })).keyVersion, 2);

  // A hash comparison is not sufficient proof of recovery: old ADMIN credentials
  // must fail the real elevation entrypoint, and the new credential must pass
  // fresh email verification before any protected operation can succeed.
  const elevationInput = { actor: admin.actor, sessionId: admin.sessionId,
    normalPassword: NORMAL, scope: "ADMIN_RECOVERY_REGENERATE" as const,
    duration: { kind: "TIMED" as const, minutes: 15 as const }, locale: "pt-BR" as const };
  await assert.rejects(startSecurityElevation({ ...elevationInput, administrativePassword: ADMIN }),
    AdministrationMutationError, "old administrative password cannot regain privileges after TOTP recovery");
  assert.equal(await hasActiveSecurityElevation(admin.userId, admin.sessionId, "ADMIN_RECOVERY_REGENERATE"), false);
  const priorHashes = (await prisma.administrativeRecoveryCode.findMany({
    where: { userId: admin.userId }, select: { codeHash: true }
  })).map((item) => item.codeHash).sort();
  assert.equal(priorHashes.length, 10);
  const beforeAudit = await prisma.auditLog.count({ where: {
    actorUserId: admin.userId, eventType: "RECOVERY_CODES_REGENERATED", result: "SUCCESS"
  } });
  await assert.rejects(regenerateAdministrativeRecoveryCodes(admin.actor, admin.sessionId),
    AdministrationMutationError, "the protected mutation must deny missing fresh elevation");
  assert.deepEqual((await prisma.administrativeRecoveryCode.findMany({
    where: { userId: admin.userId }, select: { codeHash: true }
  })).map((item) => item.codeHash).sort(), priorHashes,
  "denied administrative operation must leave codes unchanged");
  const elevation = await startSecurityElevation({ ...elevationInput, administrativePassword: NEW_ADMIN });
  const elevationCode = (await queuedEmails(admin.email)).filter((mail) => mail.kind === "ADMIN_EMAIL_VERIFICATION").at(-1)?.code;
  assert.ok(elevationCode);
  await verifySecurityElevation({ actor: admin.actor, sessionId: admin.sessionId, requestKey: elevation.requestKey, code: elevationCode });
  assert.equal(await hasActiveSecurityElevation(admin.userId, admin.sessionId, "ADMIN_RECOVERY_REGENERATE"), true);
  const reauthorizedCodes = await regenerateAdministrativeRecoveryCodes(admin.actor, admin.sessionId);
  assert.equal(reauthorizedCodes.length, 10, "privileged code rotation must require fresh recovered elevation");
  assert.equal(new Set(reauthorizedCodes).size, 10);
  const persisted = (await prisma.administrativeRecoveryCode.findMany({
    where: { userId: admin.userId, usedAt: null }, select: { codeHash: true }
  })).map((item) => item.codeHash).sort();
  assert.deepEqual(persisted, reauthorizedCodes.map(hashRecoveryCode).sort());
  assert.equal(priorHashes.some((hash) => persisted.includes(hash)), false);
  assert.equal(await prisma.auditLog.count({ where: {
    actorUserId: admin.userId, eventType: "RECOVERY_CODES_REGENERATED", result: "SUCCESS"
  } }), beforeAudit + 1);
});

test("wrong, expired, replayed and inactive TOTP cannot recover an ADMIN credential", integrationOptions, async () => {
  const wrong = await createAdmin();
  await assert.rejects(recover(wrong, "not-six-digits"), AdministrationMutationError);
  await assert.rejects(recover(wrong, totpAt(wrong.secret, new Date(Date.now() - 300_000))), AdministrationMutationError);
  const disabled = await createAdmin(false);
  await assert.rejects(recover(disabled, "123456"), AdministrationMutationError);
  const inactive = await createAdmin();
  await prisma.totpFactor.update({ where: { userId: inactive.userId }, data: { status: "REVOKED" } });
  await assert.rejects(recover(inactive), AdministrationMutationError);
  for (const admin of [wrong, disabled, inactive]) {
    const credential = await prisma.administrativeCredential.findUniqueOrThrow({ where: { userId: admin.userId } });
    assert.equal(credential.keyVersion, 1);
    assert.equal(await verifyPassword(credential.passwordHash, ADMIN), true);
  }
});

for (const state of ["revoked", "missing"] as const) {
  test(`TOTP recovery never recreates or reactivates a ${state} administrative credential`, integrationOptions, async () => {
    const admin = await createAdmin();
    const beforeFactor = await prisma.totpFactor.findUniqueOrThrow({
      where: { userId: admin.userId }, select: { lastUsedStep: true }
    });
    const initialCredential = await prisma.administrativeCredential.findUniqueOrThrow({ where: { userId: admin.userId } });
    if (state === "revoked") {
      await prisma.administrativeCredential.update({
        where: { userId: admin.userId }, data: { status: "REVOKED", revokedAt: new Date() }
      });
    } else {
      await prisma.administrativeCredential.delete({ where: { userId: admin.userId } });
    }
    await assert.rejects(recover(admin), AdministrationMutationError);
    const credential = await prisma.administrativeCredential.findUnique({ where: { userId: admin.userId } });
    if (state === "missing") {
      assert.equal(credential, null, "a missing privileged credential must require the separate setup ceremony");
    } else {
      assert.equal(credential?.status, "REVOKED");
      assert.ok(credential?.revokedAt);
      assert.equal(credential?.keyVersion, initialCredential.keyVersion);
      assert.equal(credential?.passwordHash, initialCredential.passwordHash);
    }
    assert.equal((await prisma.totpFactor.findUniqueOrThrow({
      where: { userId: admin.userId }, select: { lastUsedStep: true }
    })).lastUsedStep, beforeFactor.lastUsedStep, "rejected credential recovery must not consume TOTP");
    assert.equal(await prisma.administrativeRecoveryCode.count({ where: { userId: admin.userId } }), 0);
    assert.equal(await prisma.auditLog.count({
      where: { actorUserId: admin.userId, eventType: "ADMIN_CREDENTIAL_TOTP_RECOVERED" }
    }), 0);
    assert.equal((await prisma.session.findUniqueOrThrow({ where: { id: admin.sessionId } })).revokedAt, null);
  });
}

test("TOTP recovery rejects wrong/changed login passwords, USER role, expired session and password reuse", integrationOptions, async () => {
  const admin = await createAdmin();
  await assert.rejects(recoverAdministrativeCredentialWithTotp({
    actor: admin.actor, sessionId: admin.sessionId, normalPassword: "incorrect-password",
    totpCode: totpAt(admin.secret), newPassword: NEW_ADMIN
  }), AdministrationMutationError);
  await assert.rejects(recover(admin, totpAt(admin.secret), NORMAL), AdministrativePasswordReuseError);
  await assert.rejects(recoverAdministrativeCredentialWithTotp({
    actor: { ...admin.actor, role: "USER" }, sessionId: admin.sessionId,
    normalPassword: NORMAL, totpCode: totpAt(admin.secret), newPassword: NEW_ADMIN
  }), AdministrationMutationError);
  await prisma.user.update({ where: { id: admin.userId }, data: { passwordHash: await hashPassword("different-normal-password-2026") } });
  await assert.rejects(recover(admin), AdministrationMutationError);
  const expired = await createAdmin();
  await prisma.session.update({ where: { id: expired.sessionId }, data: { expiresAt: new Date(Date.now() - 1_000) } });
  await assert.rejects(recover(expired), AdministrationMutationError);
});

test("rotated TOTP rejects old proof while retaining the new ACTIVE factor", integrationOptions, async () => {
  const admin = await createAdmin();
  const oldCode = totpAt(admin.secret);
  const newSecret = createTotpSecret();
  await prisma.totpFactor.update({
    where: { userId: admin.userId }, data: {
      secretCiphertext: encryptTotpSecret(newSecret), keyVersion: { increment: 1 }, lastUsedStep: null
    }
  });
  await assert.rejects(recover(admin, oldCode), AdministrationMutationError);
  const codes = await recover(admin, totpAt(newSecret));
  assert.equal(codes.length, 10);
});

test("parallel TOTP recovery attempts have one winner for the same code and ADMIN key version", integrationOptions, async () => {
  const admin = await createAdmin();
  const code = totpAt(admin.secret);
  const results = await Promise.allSettled([recover(admin, code, "admin-totp-parallel-winner-a"), recover(admin, code, "admin-totp-parallel-winner-b")]);
  assert.equal(results.filter((result) => result.status === "fulfilled").length, 1);
  assert.equal(results.filter((result) => result.status === "rejected").length, 1);
  assert.equal((await prisma.administrativeCredential.findUniqueOrThrow({ where: { userId: admin.userId } })).keyVersion, 2);
  assert.equal(await prisma.auditLog.count({ where: { actorUserId: admin.userId, eventType: "ADMIN_CREDENTIAL_TOTP_RECOVERED" } }), 1);
});
