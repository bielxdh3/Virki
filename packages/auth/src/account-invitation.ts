import { randomBytes, randomInt } from "node:crypto";
import { prisma } from "@virki/database";
import { enqueueEmailMessageForClient } from "./email";
import { hashAuditEmail, hashAuditIdentifier, writeAuditLogInTransaction } from "./audit";
import { hashOidcIdentifier } from "./oidc-secrets";
import { getRecoveryActionBaseUrl, hashEmailAddress, hashRecoveryRequestKey, hashSecurityCode } from "./security";
import { requireSecurityElevationInTransaction } from "./elevation-authorization";

export const ACCOUNT_INVITATION_TTL_MS = 72 * 60 * 60 * 1000;

// Creates a USER with no password and a one-time invitation. The invitation is an APPROVED recovery
// request, so the person sets their own password through the existing /recover link and the admin
// never knows the credential. The account and its invitation e-mail are created atomically.
export async function provisionInvitedUserAccount(
  actor: { id: string },
  sessionId: string,
  input: { email: string; displayName: string | null },
  now = new Date()
): Promise<{ userId: string }> {
  const email = input.email.trim().toLowerCase();
  const actionBase = getRecoveryActionBaseUrl("USER");
  if (!actionBase) throw new Error("Account invitation link is unavailable.");
  const requestKey = randomBytes(24).toString("base64url");
  const actionUrl = new URL(`/recover/open?request=${encodeURIComponent(requestKey)}`, actionBase).toString();

  return prisma.$transaction(async (transaction) => {
    await requireSecurityElevationInTransaction(transaction, actor.id, sessionId, "ACCOUNT_STATE_CHANGE", now);
    const user = await transaction.user.create({
      data: { email, emailNormalized: email, displayName: input.displayName, passwordHash: null, role: "USER", isActive: true, accountStatus: "ACTIVE", emailVerifiedAt: null },
      select: { id: true }
    });
    const invitation = await transaction.accountRecoveryRequest.create({
      data: {
        userId: user.id,
        requestKeyHash: hashRecoveryRequestKey(requestKey),
        emailAddressHash: hashEmailAddress(email),
        emailChallengeHash: hashSecurityCode(String(randomInt(0, 1_000_000)).padStart(6, "0")),
        status: "APPROVED",
        purpose: "INVITATION",
        emailVerifiedAt: null,
        reviewedByUserId: actor.id,
        approvedAt: now,
        expiresAt: new Date(now.getTime() + ACCOUNT_INVITATION_TTL_MS)
      },
      select: { id: true }
    });
    await enqueueEmailMessageForClient(transaction, {
      idempotencyKey: `account-invitation:${invitation.id}`,
      kind: "ACCOUNT_INVITATION",
      recipientEmail: email,
      locale: "pt-BR",
      payload: { publicValues: { displayName: input.displayName ?? "" }, protectedValues: { actionUrl } },
      now
    });
    await writeAuditLogInTransaction(transaction, {
      eventType: "ACCOUNT_CREATED",
      result: "SUCCESS",
      actorUserId: actor.id,
      resource: "account",
      message: "User account provisioned.",
      metadata: { targetRef: hashOidcIdentifier(user.id), emailRef: hashAuditEmail(email), invitationRef: hashAuditIdentifier(invitation.id) }
    });
    return { userId: user.id };
  }, { isolationLevel: "Serializable" });
}
