import assert from "node:assert/strict";
import { after, test } from "node:test";
import { prisma } from "@virki/database";
import { ACCOUNT_INVITATION_TTL_MS, provisionInvitedUserAccount } from "./account-invitation";
import { authenticateUser, verifyPassword } from "./index";
import { createTestUser, integrationOptions, queuedEmails, requestKeyFromActionUrl, uniqueEmail } from "./integration-fixtures";
import { consumeApprovedAccountRecovery, getAccountRecoveryRequestId } from "./security";

after(() => prisma.$disconnect());

async function invite(label: string) {
  const admin = await createTestUser({ role: "ADMIN", label: `${label}-admin` });
  const email = uniqueEmail(label);
  const now = new Date();
  const { userId } = await provisionInvitedUserAccount(admin, { email, displayName: "Convidado" }, now);
  const message = (await queuedEmails(email)).find((entry) => entry.kind === "ACCOUNT_INVITATION");
  assert.ok(message?.actionUrl, "the invitation e-mail carries an action link");
  return { admin, email, userId, now, requestKey: requestKeyFromActionUrl(message.actionUrl) };
}

test("an invited user has no password until the one-time link sets it", integrationOptions, async () => {
  const { admin, email, userId, now, requestKey } = await invite("invite-flow");
  const created = await prisma.user.findUniqueOrThrow({ where: { id: userId }, select: { passwordHash: true, emailVerifiedAt: true, role: true } });
  assert.equal(created.passwordHash, null);
  assert.equal(created.emailVerifiedAt, null);
  assert.equal(created.role, "USER");
  assert.equal(await authenticateUser(email, "any-password-123"), null);

  const opened = await getAccountRecoveryRequestId(requestKey, now);
  assert.ok(opened, "the emailed link opens the invitation");
  const request = await prisma.accountRecoveryRequest.findUniqueOrThrow({ where: { id: opened.id }, select: { status: true, reviewedByUserId: true, expiresAt: true, requestKeyHash: true } });
  assert.equal(request.status, "APPROVED");
  assert.equal(request.reviewedByUserId, admin.id);
  assert.equal(request.expiresAt.getTime(), now.getTime() + ACCOUNT_INVITATION_TTL_MS);
  assert.notEqual(request.requestKeyHash, requestKey);

  const password = "Chosen-by-the-user-42";
  await consumeApprovedAccountRecovery(opened.id, requestKey, password, now);
  const after = await prisma.user.findUniqueOrThrow({ where: { id: userId }, select: { passwordHash: true, emailVerifiedAt: true } });
  assert.ok(after.passwordHash && await verifyPassword(after.passwordHash, password));
  assert.ok(after.emailVerifiedAt);
  await assert.rejects(consumeApprovedAccountRecovery(opened.id, requestKey, "Another-password-4242", now));
  assert.equal(await getAccountRecoveryRequestId(requestKey, now), null);
});

test("an invitation expires after 72 hours", integrationOptions, async () => {
  const { now, requestKey } = await invite("invite-expiry");
  const opened = await getAccountRecoveryRequestId(requestKey, now);
  assert.ok(opened);
  const late = new Date(now.getTime() + ACCOUNT_INVITATION_TTL_MS + 1000);
  assert.equal(await getAccountRecoveryRequestId(requestKey, late), null);
  await assert.rejects(consumeApprovedAccountRecovery(opened.id, requestKey, "Late-password-4242", late));
});
