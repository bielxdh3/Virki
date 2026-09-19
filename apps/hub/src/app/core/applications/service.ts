import { createHash, randomBytes } from "node:crypto";
import {
  hashAuditIdentifier,
  writeAuditLog,
  type AuthenticatedUser
} from "@bielos/auth";
import { enqueueEmailMessageForClient } from "@bielos/auth/email";
import { requireSecurityElevation } from "@bielos/auth/administration";
import { prisma, type Prisma } from "@bielos/database";

const ACTIVATION_TTL_MS = 24 * 60 * 60 * 1000;

export type ApplicationPrincipal = Pick<AuthenticatedUser, "id" | "role">;
export type ApplicationDecision = "APPROVED" | "REJECTED";

export class ApplicationMutationError extends Error {
  constructor() {
    super("Application mutation rejected.");
    this.name = "ApplicationMutationError";
  }
}

export async function listPendingApplications(actor: ApplicationPrincipal) {
  await requirePersistedOwner(actor);
  return prisma.accountApplication.findMany({
    where: {
      status: { in: ["EMAIL_VERIFIED", "IN_REVIEW", "PARTIALLY_APPROVED", "APPROVED"] }
    },
    orderBy: { createdAt: "asc" },
    take: 50,
    select: {
      id: true,
      emailNormalized: true,
      displayName: true,
      status: true,
      createdAt: true,
      moduleDecisions: {
        orderBy: { createdAt: "asc" },
        select: {
          id: true,
          moduleId: true,
          module: { select: { key: true, name: true } },
          reason: true,
          status: true,
          internalReason: true,
          userVisibleMessage: true,
          accessDurationKind: true,
          accessExpiresAt: true,
          retryAfterAt: true,
          indefinitelyBlocked: true
        }
      }
    }
  });
}

export async function reviewApplicationModule(input: {
  actor: ApplicationPrincipal;
  sessionId: string;
  applicationId: string;
  moduleDecisionId: string;
  decision: ApplicationDecision;
  internalReason: string;
  userVisibleMessage: string;
  accessDurationKind: "PERMANENT" | "TEMPORARY";
  accessExpiresAt: Date | null;
}) {
  await requireSecurityElevation(input.actor.id, input.sessionId, "ACCOUNT_APPLICATION_REVIEW");
  if (
    !isId(input.applicationId) ||
    !isId(input.moduleDecisionId) ||
    input.internalReason.length > 1_000 ||
    input.userVisibleMessage.length > 500 ||
    (input.accessDurationKind === "TEMPORARY" && !input.accessExpiresAt) ||
    (input.accessDurationKind === "PERMANENT" && input.accessExpiresAt)
  ) {
    throw new ApplicationMutationError();
  }

  let activationIssued = false;
  let rejectionMessage: string | null = null;
  try {
    await prisma.$transaction(async (transaction) => {
      await lockApplication(transaction, input.applicationId);
      const [actor, application, decision] = await Promise.all([
        transaction.user.findUnique({ where: { id: input.actor.id }, select: { role: true, isActive: true } }),
        transaction.accountApplication.findUnique({
          where: { id: input.applicationId },
          select: {
            id: true,
            emailNormalized: true,
            displayName: true,
            status: true,
            activation: { select: { id: true, consumedAt: true } }
          }
        }),
        transaction.applicationModuleDecision.findUnique({
          where: { id: input.moduleDecisionId },
          select: { id: true, applicationId: true, status: true }
        })
      ]);

      requireOwner(input.actor, actor);
      if (
        !application ||
        !decision ||
        decision.applicationId !== application.id ||
        !["EMAIL_VERIFIED", "IN_REVIEW", "PARTIALLY_APPROVED", "APPROVED"].includes(application.status)
      ) {
        throw new ApplicationMutationError();
      }

      await transaction.applicationModuleDecision.update({
        where: { id: decision.id },
        data: {
          status: input.decision,
          internalReason: input.internalReason || null,
          userVisibleMessage: input.userVisibleMessage || null,
          accessDurationKind: input.accessDurationKind,
          accessExpiresAt: input.decision === "APPROVED" ? input.accessExpiresAt : null,
          reviewedByUserId: input.actor.id,
          decidedAt: new Date()
        }
      });

      const counts = await transaction.applicationModuleDecision.groupBy({
        by: ["status"],
        where: { applicationId: application.id },
        _count: { _all: true }
      });
      const count = (status: string) => counts.find((item) => item.status === status)?._count._all ?? 0;
      const approved = count("APPROVED");
      const pending = count("REQUESTED");
      const rejected = count("REJECTED") + count("BLOCKED");

      const nextStatus =
        approved > 0 && pending > 0
          ? "PARTIALLY_APPROVED"
          : approved > 0
            ? "APPROVED"
            : rejected > 0 && pending === 0
              ? "REJECTED"
              : "IN_REVIEW";
      await transaction.accountApplication.update({
        where: { id: application.id },
        data: { status: nextStatus }
      });

      if (approved > 0 && nextStatus !== "REJECTED" && !application.activation) {
        const existingUser = await transaction.user.findFirst({
          where: { OR: [{ emailNormalized: application.emailNormalized }, { email: application.emailNormalized }] },
          select: { id: true }
        });
        if (existingUser) {
          throw new ApplicationMutationError();
        }
        const issued = await issueActivation(transaction, application.id, application.emailNormalized, application.displayName);
        activationIssued = issued;
      } else if (nextStatus === "REJECTED") {
        rejectionMessage = input.userVisibleMessage || null;
        await enqueueEmailMessageForClient(transaction, {
          idempotencyKey: `application-rejected:${application.id}`,
          kind: "USER_VISIBLE_REJECTION",
          recipientEmail: application.emailNormalized,
          locale: "pt-BR",
          payload: { publicValues: { displayName: application.displayName ?? "", message: rejectionMessage ?? "" } }
        });
      }
    }, { isolationLevel: "Serializable" });
  } catch {
    throw new ApplicationMutationError();
  }

  await writeAuditLog({
    eventType: "ACCOUNT_APPLICATION_REVIEWED",
    result: "SUCCESS",
    actorUserId: input.actor.id,
    resource: "identity.application",
    message: "Account application reviewed.",
    metadata: {
      applicationRef: hashAuditIdentifier(input.applicationId),
      decisionRef: hashAuditIdentifier(input.moduleDecisionId),
      decision: input.decision,
      activationIssued
    }
  });

  return { activationIssued, rejectionMessage };
}

export async function reissueApplicationActivation(
  actor: ApplicationPrincipal,
  sessionId: string,
  applicationId: string
): Promise<void> {
  await requireSecurityElevation(actor.id, sessionId, "ACCOUNT_ACTIVATION_REISSUE");
  if (!isId(applicationId)) {
    throw new ApplicationMutationError();
  }
  try {
    await prisma.$transaction(async (transaction) => {
      await lockApplication(transaction, applicationId);
      const [persistedActor, application] = await Promise.all([
        transaction.user.findUnique({ where: { id: actor.id }, select: { role: true, isActive: true } }),
        transaction.accountApplication.findUnique({
          where: { id: applicationId },
          select: { id: true, emailNormalized: true, displayName: true, status: true }
        })
      ]);
      requireOwner(actor, persistedActor);
      if (!application || !["APPROVED", "PARTIALLY_APPROVED"].includes(application.status)) {
        throw new ApplicationMutationError();
      }
      await issueActivation(transaction, application.id, application.emailNormalized, application.displayName);
    }, { isolationLevel: "Serializable" });
  } catch {
    throw new ApplicationMutationError();
  }

  await writeAuditLog({
    eventType: "ACCOUNT_ACTIVATION_REISSUED",
    result: "SUCCESS",
    actorUserId: actor.id,
    resource: "identity.application",
    message: "Activation link reissued.",
    metadata: { applicationRef: hashAuditIdentifier(applicationId) }
  });
}

async function issueActivation(
  transaction: Prisma.TransactionClient,
  applicationId: string,
  email: string,
  displayName: string | null
): Promise<boolean> {
  const token = randomBytes(32).toString("base64url");
  const now = new Date();
  await transaction.accountActivation.upsert({
    where: { applicationId },
    update: {
      tokenHash: hashToken(token),
      expiresAt: new Date(now.getTime() + ACTIVATION_TTL_MS),
      consumedAt: null,
      updatedAt: now
    },
    create: {
      applicationId,
      tokenHash: hashToken(token),
      expiresAt: new Date(now.getTime() + ACTIVATION_TTL_MS),
      updatedAt: now
    }
  });
  await enqueueEmailMessageForClient(transaction, {
    idempotencyKey: `account-activation:${applicationId}:${hashToken(token)}`,
    kind: "ACCOUNT_ACTIVATION",
    recipientEmail: email,
    locale: "pt-BR",
    now,
    payload: {
      publicValues: { displayName: displayName ?? "" },
      protectedValues: { actionUrl: `https://biel.dev.br/apply/activate?token=${token}` }
    }
  });
  return true;
}

async function requirePersistedOwner(actor: ApplicationPrincipal): Promise<void> {
  const persisted = await prisma.user.findUnique({ where: { id: actor.id }, select: { role: true, isActive: true } });
  requireOwner(actor, persisted);
}

function requireOwner(actor: ApplicationPrincipal, persisted: { role: string; isActive: boolean } | null): void {
  if (actor.role !== "OWNER" || !persisted?.isActive || persisted.role !== "OWNER") {
    throw new ApplicationMutationError();
  }
}

async function lockApplication(transaction: Prisma.TransactionClient, applicationId: string): Promise<void> {
  await transaction.$queryRaw`
    SELECT pg_advisory_xact_lock(hashtextextended(${`bielos-identity-application:${applicationId}`}, 0)) IS NULL AS "locked"
  `;
}

function isId(value: string): boolean {
  return /^[a-zA-Z0-9_-]{8,80}$/.test(value);
}

function hashToken(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}
