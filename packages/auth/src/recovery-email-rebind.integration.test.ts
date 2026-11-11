import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { after, test } from "node:test";
import { prisma } from "@virki/database";
import { createTestUser, integrationOptions, uniqueEmail } from "./integration-fixtures";
import { completeRecoveryEmailRebind, startRecoveryEmailRebind, type RecoveryEmailRebindActor } from "./recovery-email-rebind";
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
