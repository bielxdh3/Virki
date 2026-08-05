import { hashAuditIdentifier, writeAuditLog } from "@bielos/auth";
import { invalidateRememberedLoginGrants, revokeLoginChallenges } from "@bielos/auth/security";
import { prisma, type Prisma } from "@bielos/database";

import { canRevokeOtherSession } from "./session-policy";

export const CORE_SESSION_LIST_LIMIT = 100;

type CoreSessionPrincipal = {
  id: string;
};

export type CoreSessionDisplay = {
  id: string;
  createdAt: Date;
  expiresAt: Date;
  isCurrent: boolean;
};

export class CoreSessionMutationError extends Error {
  constructor() {
    super("Core session mutation rejected.");
    this.name = "CoreSessionMutationError";
  }
}

export async function listCoreSessionsForPrincipal(
  principal: CoreSessionPrincipal,
  currentSessionId: string,
  now = new Date()
): Promise<CoreSessionDisplay[]> {
  if (!isValidSessionResourceId(principal.id) || !isValidSessionResourceId(currentSessionId)) {
    return [];
  }

  const persistedUser = await prisma.user.findUnique({
    where: { id: principal.id },
    select: { isActive: true }
  });

  if (!persistedUser?.isActive) {
    return [];
  }

  const currentSession = await prisma.session.findFirst({
    where: {
      id: currentSessionId,
      userId: principal.id,
      revokedAt: null,
      expiresAt: { gt: now }
    },
    select: {
      id: true,
      createdAt: true,
      expiresAt: true
    }
  });

  if (!currentSession) {
    return [];
  }

  const otherSessions = await prisma.session.findMany({
    where: {
      userId: principal.id,
      id: { not: currentSession.id },
      revokedAt: null,
      expiresAt: { gt: now }
    },
    select: {
      id: true,
      createdAt: true,
      expiresAt: true
    },
    orderBy: { createdAt: "desc" },
    take: CORE_SESSION_LIST_LIMIT - 1
  });
  const sessions = [currentSession, ...otherSessions].sort(
    (first, second) => second.createdAt.getTime() - first.createdAt.getTime()
  );

  return sessions.map((session) => ({
    id: session.id,
    createdAt: session.createdAt,
    expiresAt: session.expiresAt,
    isCurrent: session.id === currentSessionId
  }));
}

export async function revokeCoreSessionRecord(
  principal: CoreSessionPrincipal,
  currentSessionId: string,
  targetSessionId: string,
  now = new Date()
) {
  if (
    !isValidSessionResourceId(principal.id) ||
    !canRevokeOtherSession(currentSessionId, targetSessionId)
  ) {
    throw new CoreSessionMutationError();
  }

  try {
    await prisma.$transaction(async (transaction) => {
      await requireActiveSessionPrincipal(
        transaction,
        principal.id,
        currentSessionId,
        now
      );

      const result = await transaction.session.updateMany({
        where: {
          id: targetSessionId,
          userId: principal.id,
          revokedAt: null,
          expiresAt: { gt: now }
        },
        data: { revokedAt: now }
      });

      if (result.count !== 1) {
        throw new CoreSessionMutationError();
      }
    });
  } catch {
    throw new CoreSessionMutationError();
  }

  await writeAuditLog({
    eventType: "AUTH_SESSION_REVOKED",
    result: "SUCCESS",
    actorUserId: principal.id,
      resource: "session",
    message: "Personal session revoked.",
    metadata: {
      scope: "single-other",
      sessionRef: hashAuditIdentifier(targetSessionId)
    }
  });

  return { revokedCount: 1 };
}

export async function revokeAllOtherCoreSessionRecords(
  principal: CoreSessionPrincipal,
  currentSessionId: string,
  confirmed: boolean,
  now = new Date()
) {
  if (
    !confirmed ||
    !isValidSessionResourceId(principal.id) ||
    !isValidSessionResourceId(currentSessionId)
  ) {
    throw new CoreSessionMutationError();
  }

  let revokedCount: number;

  try {
    revokedCount = await prisma.$transaction(async (transaction) => {
      await requireActiveSessionPrincipal(
        transaction,
        principal.id,
        currentSessionId,
        now
      );

      const result = await transaction.session.updateMany({
        where: {
          userId: principal.id,
          id: { not: currentSessionId },
          revokedAt: null,
          expiresAt: { gt: now }
        },
        data: { revokedAt: now }
      });

      await invalidateRememberedLoginGrants(transaction, principal.id);
      await revokeLoginChallenges(transaction, principal.id);

      return result.count;
    });
  } catch {
    throw new CoreSessionMutationError();
  }

  await writeAuditLog({
    eventType: "AUTH_SESSION_REVOKED",
    result: "SUCCESS",
    actorUserId: principal.id,
    resource: "session",
    message: "Other personal sessions revoked.",
    metadata: {
      scope: "all-other",
      revokedCount
    }
  });

  return { revokedCount };
}

async function requireActiveSessionPrincipal(
  transaction: Prisma.TransactionClient,
  userId: string,
  currentSessionId: string,
  now: Date
): Promise<void> {
  const current = await transaction.session.findFirst({
    where: {
      id: currentSessionId,
      userId,
      revokedAt: null,
      expiresAt: { gt: now },
      user: { isActive: true }
    },
    select: { id: true }
  });

  if (!current) {
    throw new CoreSessionMutationError();
  }
}

function isValidSessionResourceId(value: string): boolean {
  return value.length > 0 && value.length <= 128;
}
