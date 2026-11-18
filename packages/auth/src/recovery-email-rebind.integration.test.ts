import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { after, test } from "node:test";
import { prisma } from "@virki/database";
import { createTestUser, integrationOptions, uniqueEmail } from "./integration-fixtures";
import { canOfferRecoveryEmailRebind, completeRecoveryEmailRebind, isRecoveryEmailRebindSession, startRecoveryEmailRebind, type RecoveryEmailRebindActor } from "./recovery-email-rebind";
import { hashEmailAddress, hashSecurityCode } from "./security";

after(() => prisma.$disconnect());

async function consumedRecoveryFixture(input: { provenEmail: boolean; reboundBeforeReset: boolean }) {
  const account = await createTestUser({ label: "rebind-origin" });
  const originalEmail = account.email;
  const reboundEmail = input.reboundBeforeReset ? uniqueEmail("preverified-inbox") : null;
  const now = new Date();
  if (reboundEmail) {
    await prisma.user.update({ where: { id: account.id }, data: {
      email: reboundEmail, emailNormalized: reboundEmail, emailVerifiedAt: now
    } });
  }
  const session = await prisma.session.create({ data: {
    userId: account.id, tokenHash: randomBytes(32).toString("base64url"),
    authenticationMethods: input.provenEmail ? ["recovery", "email", "totp"] : ["recovery", "passkey", "totp"],
    expiresAt: new Date(now.getTime() + 60 * 60_000)
  } });
  await prisma.accountRecoveryRequest.create({ data: {
    userId: account.id, requestKeyHash: randomBytes(32).toString("hex"),
    emailAddressHash: hashEmailAddress(originalEmail), emailChallengeHash: hashSecurityCode("123456"),
    purpose: "RECOVERY", recoveryRole: "USER", status: "CONSUMED",
    recoveryProofs: input.provenEmail ? ["EMAIL", "TOTP"] : ["PASSKEY", "TOTP"],
    emailVerifiedAt: input.provenEmail ? now : null,
    recoveryPasskeyVerifiedAt: input.provenEmail ? null : now,
    recoveryTotpVerifiedAt: now,
    recoveryNewEmail: reboundEmail,
    recoveryNewEmailChallengeHash: reboundEmail ? hashSecurityCode("654321") : null,
    recoveryNewEmailExpiresAt: reboundEmail ? new Date(now.getTime() + 10 * 60_000) : null,
    recoveryNewEmailVerifiedAt: reboundEmail ? now : null,
    consumedAt: now, bootstrapSessionId: session.id,
    expiresAt: new Date(now.getTime() + 30 * 60_000)
  } });
  const actor: RecoveryEmailRebindActor = {
    id: session.id, createdAt: session.createdAt, expiresAt: session.expiresAt,
    authenticationMethods: session.authenticationMethods,
    user: { id: account.id, email: reboundEmail ?? originalEmail, role: "USER" }
  };
  return { actor, account, originalEmail, currentEmail: reboundEmail ?? originalEmail };
}

for (const scenario of [
  { label: "EMAIL-proven recovery", provenEmail: true, reboundBeforeReset: false },
  { label: "recovery already rebound to verified mailbox before reset", provenEmail: false, reboundBeforeReset: true }
]) {
  test(`post-reset rebind START rejects ${scenario.label} bootstrap provenance`, integrationOptions, async () => {
    const { actor, account, currentEmail } = await consumedRecoveryFixture(scenario);
    assert.equal(isRecoveryEmailRebindSession(actor), true, "session-only UI previously offered an impossible action");
    assert.equal(await canOfferRecoveryEmailRebind(actor), false, "modern recovery cannot offer legacy rebind UI");
    const proposed = uniqueEmail("post-reset-unauthorized");
    await assert.rejects(startRecoveryEmailRebind(actor, proposed));
    assert.equal((await prisma.user.findUniqueOrThrow({ where: { id: account.id } })).email, currentEmail);
    assert.equal(await prisma.recoveryEmailRebind.count({ where: { sessionId: actor.id } }), 0,
      "an ineligible bootstrap cannot even enqueue a replacement verification");
  });

  test(`post-reset rebind COMPLETE rejects ${scenario.label} bootstrap provenance`, integrationOptions, async () => {
    const { actor, account, currentEmail } = await consumedRecoveryFixture(scenario);
    const target = uniqueEmail("post-reset-unauthorized");
    const attempt = await prisma.recoveryEmailRebind.create({ data: {
      userId: account.id, sessionId: actor.id, role: "USER", oldEmailHash: hashEmailAddress(currentEmail),
      newEmail: target, codeHash: hashSecurityCode("456789"),
      expiresAt: new Date(Date.now() + 10 * 60_000)
    } });
    await assert.rejects(completeRecoveryEmailRebind(actor, "456789"));
    assert.equal((await prisma.user.findUniqueOrThrow({ where: { id: account.id } })).email, currentEmail,
      "recovered owner mailbox must remain the verified address");
    assert.equal((await prisma.recoveryEmailRebind.findUniqueOrThrow({ where: { id: attempt.id } })).consumedAt, null,
      "the forged stale rebind cannot spend its one-winner claim");
  });
}

test("legacy non-EMAIL consumed recovery alone may show rebind; revoked and expired sessions may not", integrationOptions, async () => {
  const { actor, account } = await consumedRecoveryFixture({ provenEmail: false, reboundBeforeReset: false });
  assert.equal(await canOfferRecoveryEmailRebind(actor), true);
  await startRecoveryEmailRebind(actor, uniqueEmail("legacy-new-mailbox"));
  assert.equal(await prisma.recoveryEmailRebind.count({ where: { userId: account.id, sessionId: actor.id } }), 1,
    "the positive legacy path must create a real bound verification attempt, not only show the form");
  assert.equal(await canOfferRecoveryEmailRebind({
    ...actor, createdAt: new Date(actor.createdAt.getTime() + 1000)
  }), false, "a stale session snapshot must not offer a mutation that requires the original creation timestamp");
  await prisma.session.update({ where: { id: actor.id }, data: { revokedAt: new Date() } });
  assert.equal(await canOfferRecoveryEmailRebind(actor), false, "revoked session must not show the form");
  await prisma.session.update({ where: { id: actor.id }, data: { revokedAt: null, expiresAt: new Date(0) } });
  assert.equal(await canOfferRecoveryEmailRebind(actor), false, "expired session must not show the form");
  assert.equal(await canOfferRecoveryEmailRebind({ ...actor, user: { ...actor.user, id: "foreign-user" } }), false);
  assert.equal((await prisma.user.findUniqueOrThrow({ where: { id: account.id } })).email, actor.user.email);
});
