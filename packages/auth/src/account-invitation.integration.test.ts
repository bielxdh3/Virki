import assert from "node:assert/strict";
import { after, test } from "node:test";
import { prisma } from "@virki/database";
import { ACCOUNT_INVITATION_TTL_MS, provisionInvitedUserAccount } from "./account-invitation";
import { authenticateUser, verifyPassword } from "./index";
import { createTestUser, integrationOptions, queuedEmails, requestKeyFromActionUrl, seedAdminSessionWithElevation, uniqueEmail } from "./integration-fixtures";
import { hashAuditEmail } from "./audit";
import { consumeApprovedAccountRecovery, getAccountRecoveryRequestId, RECOVERY_REQUEST_COOLDOWN_MS, requestAccountRecovery } from "./security";

after(() => prisma.$disconnect());

test("invitation helper rejects control characters and overlong display names before any write", integrationOptions, async () => {
  const admin = await createTestUser({ role: "ADMIN", label: "invite-invalid-name-admin" });
  const now = new Date();
  const { sessionId } = await seedAdminSessionWithElevation(admin.id, "ACCOUNT_STATE_CHANGE", now);
  const inputs = [
    { email: uniqueEmail("invite-control-name"), displayName: "First line\nSecond line" },
    { email: uniqueEmail("invite-long-name"), displayName: "x".repeat(81) },
    { email: "alice@example.invalid,attacker@example.invalid", displayName: "Multiple recipients" },
    { email: "Alice <alice@example.invalid>", displayName: "Display name syntax" },
    { email: "alice@example.invalid;attacker@example.invalid", displayName: "Separator" }
  ];

  for (const input of inputs) {
    await assert.rejects(provisionInvitedUserAccount({ id: admin.id }, sessionId, input, now));
    assert.equal(await prisma.user.findUnique({ where: { emailNormalized: input.email }, select: { id: true } }), null);
    assert.equal(await prisma.emailOutboxMessage.count({ where: { recipientEmail: input.email } }), 0);
  }
});

async function invite(label: string) {
  const admin = await createTestUser({ role: "ADMIN", label: `${label}-admin` });
  const email = uniqueEmail(label);
  const now = new Date();
  const { sessionId } = await seedAdminSessionWithElevation(admin.id, "ACCOUNT_STATE_CHANGE", now);
  const { userId } = await provisionInvitedUserAccount({ id: admin.id }, sessionId, { email, displayName: "Convidado" }, now);
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

  const creationAudit = await prisma.auditLog.findFirst({ where: { actorUserId: admin.id, eventType: "ACCOUNT_CREATED", resource: "account" }, orderBy: { createdAt: "desc" }, select: { metadata: true } });
  const emailRef = (creationAudit?.metadata as { emailRef?: string } | null)?.emailRef;
  assert.equal(emailRef, hashAuditEmail(email));
  assert.equal(emailRef?.length, 89);
  assert.equal(JSON.stringify(creationAudit?.metadata ?? null).includes(email), false);

  const opened = await getAccountRecoveryRequestId(requestKey, now);
  assert.ok(opened, "the emailed link opens the invitation");
  const request = await prisma.accountRecoveryRequest.findUniqueOrThrow({ where: { id: opened.id }, select: { status: true, purpose: true, reviewedByUserId: true, expiresAt: true, requestKeyHash: true } });
  assert.equal(request.status, "APPROVED");
  assert.equal(request.purpose, "INVITATION");
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

test("a live approved invitation blocks anonymous recovery after the request cooldown", integrationOptions, async () => {
  const invited = await invite("invite-recovery-precedence");
  const opened = await getAccountRecoveryRequestId(invited.requestKey, invited.now);
  assert.ok(opened);

  const afterCooldown = new Date(invited.now.getTime() + RECOVERY_REQUEST_COOLDOWN_MS + 1_000);
  await requestAccountRecovery(invited.email, "pt-BR", afterCooldown);

  const requests = await prisma.accountRecoveryRequest.findMany({ where: { userId: invited.userId }, orderBy: { createdAt: "asc" }, select: { status: true, purpose: true, emailVerifiedAt: true } });
  assert.deepEqual(requests, [{ status: "APPROVED", purpose: "INVITATION", emailVerifiedAt: null }]);
  assert.equal(await prisma.emailOutboxMessage.count({ where: { recipientEmail: invited.email, kind: "ACCOUNT_RECOVERY" } }), 0);
  assert.equal((await prisma.user.findUniqueOrThrow({ where: { id: invited.userId }, select: { emailVerifiedAt: true } })).emailVerifiedAt, null);

  await consumeApprovedAccountRecovery(opened.id, invited.requestKey, "Invitation-owner-password-42", afterCooldown);
  assert.equal((await prisma.user.findUniqueOrThrow({ where: { id: invited.userId }, select: { emailVerifiedAt: true } })).emailVerifiedAt?.getTime(), afterCooldown.getTime());
});

test("an expired invitation no longer blocks a new recovery request", integrationOptions, async () => {
  const invited = await invite("invite-recovery-expired");
  const late = new Date(invited.now.getTime() + ACCOUNT_INVITATION_TTL_MS + 1_000);
  await requestAccountRecovery(invited.email, "pt-BR", late);

  const requests = await prisma.accountRecoveryRequest.findMany({ where: { userId: invited.userId }, orderBy: { createdAt: "asc" }, select: { id: true, status: true, purpose: true, expiresAt: true } });
  assert.equal(requests.length, 2);
  assert.equal(requests[0]?.purpose, "INVITATION");
  assert.equal(requests[0]?.status, "APPROVED");
  assert.ok(requests[0]!.expiresAt <= late);
  assert.equal(requests[1]?.purpose, "RECOVERY");
  assert.equal(requests[1]?.status, "PENDING");
  assert.equal(await getAccountRecoveryRequestId(invited.requestKey, late), null);
  assert.equal(await prisma.emailOutboxMessage.count({ where: { recipientEmail: invited.email, kind: "ACCOUNT_RECOVERY" } }), 1);
});

test("a client-supplied purpose query cannot change invitation or recovery purpose", integrationOptions, async () => {
  const invited = await invite("invite-purpose-spoof");
  const invitationMessage = (await queuedEmails(invited.email)).find((entry) => entry.kind === "ACCOUNT_INVITATION");
  assert.ok(invitationMessage?.actionUrl);
  const spoofedInvitationUrl = new URL(invitationMessage.actionUrl);
  spoofedInvitationUrl.searchParams.set("purpose", "RECOVERY");
  const invitationKey = requestKeyFromActionUrl(spoofedInvitationUrl.toString());
  const openedInvitation = await getAccountRecoveryRequestId(invitationKey, invited.now);
  assert.equal(openedInvitation?.purpose, "INVITATION");

  const recoveryUser = await createTestUser({ label: "recovery-purpose-spoof" });
  const now = new Date();
  await requestAccountRecovery(recoveryUser.email, "pt-BR", now);
  const recoveryMessage = (await queuedEmails(recoveryUser.email)).find((entry) => entry.kind === "ACCOUNT_RECOVERY");
  assert.ok(recoveryMessage?.actionUrl);
  const spoofedRecoveryUrl = new URL(recoveryMessage.actionUrl);
  spoofedRecoveryUrl.searchParams.set("purpose", "INVITATION");
  const recoveryKey = requestKeyFromActionUrl(spoofedRecoveryUrl.toString());
  const openedRecovery = await getAccountRecoveryRequestId(recoveryKey, now);
  assert.equal(openedRecovery?.purpose, "RECOVERY");
});

test("a revoked elevation prevents invitation writes when revocation commits first", integrationOptions, async () => {
  const admin = await createTestUser({ role: "ADMIN", label: "invite-revoked" });
  const now = new Date();
  const { sessionId, elevationId } = await seedAdminSessionWithElevation(admin.id, "ACCOUNT_STATE_CHANGE", now);
  const email = uniqueEmail("invite-revoked-target");
  let locked!: () => void;
  let release!: () => void;
  const ready = new Promise<void>((resolve) => { locked = resolve; });
  const gate = new Promise<void>((resolve) => { release = resolve; });
  const revocation = prisma.$transaction(async (transaction) => {
    await transaction.securityElevation.update({ where: { id: elevationId }, data: { status: "REVOKED", revokedAt: now } });
    locked();
    await gate;
  });
  await ready;
  const creating = provisionInvitedUserAccount({ id: admin.id }, sessionId, { email, displayName: "Convidado" }, now);
  const rejected = assert.rejects(creating);
  await new Promise((resolve) => setTimeout(resolve, 100));
  release();
  await revocation;
  await rejected;
  assert.equal(await prisma.user.findUnique({ where: { emailNormalized: email }, select: { id: true } }), null);
  assert.equal(await prisma.emailOutboxMessage.count({ where: { recipientEmail: email } }), 0);
});
