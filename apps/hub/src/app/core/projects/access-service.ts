import { hashAuditIdentifier, writeAuditLog, type AuditEventType } from "@bielos/auth";
import type { Prisma } from "@bielos/database";

import { isCoreAdministrator, type CoreProjectPrincipal } from "../authorization";
import {
  canRevokeCoreProjectAccess,
  canSetCoreProjectAccess,
  isCoreProjectAccessLevel,
  requiresActiveOwnerRetentionCheck,
  type CoreProjectAccessLevel
} from "./access-policy";
import { isValidCoreResourceId } from "./validation";
import {
  lockCoreProjectMutation,
  runCoreProjectSerializableTransaction
} from "./transaction";

export class CoreProjectAccessMutationError extends Error {
  constructor() {
    super("Core project access mutation rejected.");
    this.name = "CoreProjectAccessMutationError";
  }
}

export async function setCoreProjectAccessRecord(
  actor: CoreProjectPrincipal,
  projectId: string,
  userId: string,
  accessLevel: string
) {
  if (
    !isValidCoreResourceId(projectId) ||
    !isValidCoreResourceId(userId) ||
    !isCoreProjectAccessLevel(accessLevel)
  ) {
    throw new CoreProjectAccessMutationError();
  }

  let result: {
    kind: "granted" | "changed" | "unchanged";
    accessId: string;
  };

  try {
    result = await runCoreProjectSerializableTransaction(async (transaction) => {
      await lockCoreProjectMutation(transaction, projectId);

      const [persistedActor, project, targetUser, current] = await Promise.all([
        transaction.user.findUnique({
          where: { id: actor.id },
          select: { role: true, isActive: true }
        }),
        transaction.project.findUnique({
          where: { id: projectId },
          select: { id: true, status: true }
        }),
        transaction.user.findUnique({
          where: { id: userId },
          select: { id: true, isActive: true }
        }),
        transaction.projectAccess.findUnique({
          where: { userId_projectId: { userId, projectId } },
          select: { id: true, accessLevel: true }
        })
      ]);

      requirePersistedAdministrator(actor, persistedActor);

      if (!project || project.status === "ARCHIVED" || !targetUser?.isActive) {
        throw new CoreProjectAccessMutationError();
      }

      if (!canSetCoreProjectAccess(actor.role, accessLevel, current?.accessLevel ?? null)) {
        throw new CoreProjectAccessMutationError();
      }

      if (current?.accessLevel === accessLevel) {
        return { kind: "unchanged" as const, accessId: current.id };
      }

      if (
        current &&
        requiresActiveOwnerRetentionCheck(current.accessLevel, targetUser.isActive) &&
        accessLevel !== "OWNER"
      ) {
        await requireMultipleActiveOwners(transaction, projectId);
      }

      if (current) {
        const updated = await transaction.projectAccess.update({
          where: { id: current.id },
          data: { accessLevel },
          select: { id: true }
        });
        return { kind: "changed" as const, accessId: updated.id };
      }

      const created = await transaction.projectAccess.create({
        data: { projectId, userId, accessLevel },
        select: { id: true }
      });
      return { kind: "granted" as const, accessId: created.id };
    });
  } catch {
    throw new CoreProjectAccessMutationError();
  }

  if (result.kind !== "unchanged") {
    await writeProjectAccessAudit({
      eventType:
        result.kind === "granted"
          ? "CORE_PROJECT_ACCESS_GRANTED"
          : "CORE_PROJECT_ACCESS_CHANGED",
      actorUserId: actor.id,
      projectId,
      userId,
      accessId: result.accessId,
      accessLevel,
      message:
        result.kind === "granted"
          ? "Core project access granted."
          : "Core project access changed."
    });
  }

  return result;
}

export async function revokeCoreProjectAccessRecord(
  actor: CoreProjectPrincipal,
  projectId: string,
  userId: string
) {
  if (!isValidCoreResourceId(projectId) || !isValidCoreResourceId(userId)) {
    throw new CoreProjectAccessMutationError();
  }

  let removed: { accessId: string };

  try {
    removed = await runCoreProjectSerializableTransaction(async (transaction) => {
      await lockCoreProjectMutation(transaction, projectId);

      const [persistedActor, current] = await Promise.all([
        transaction.user.findUnique({
          where: { id: actor.id },
          select: { role: true, isActive: true }
        }),
        transaction.projectAccess.findUnique({
          where: { userId_projectId: { userId, projectId } },
          select: {
            id: true,
            accessLevel: true,
            user: { select: { isActive: true } },
            project: { select: { status: true } }
          }
        })
      ]);

      requirePersistedAdministrator(actor, persistedActor);

      if (
        !current ||
        current.project.status === "ARCHIVED" ||
        !canRevokeCoreProjectAccess(actor.role, current.accessLevel)
      ) {
        throw new CoreProjectAccessMutationError();
      }

      if (requiresActiveOwnerRetentionCheck(current.accessLevel, current.user.isActive)) {
        await requireMultipleActiveOwners(transaction, projectId);
      }

      const deletion = await transaction.projectAccess.deleteMany({
        where: { id: current.id, userId, projectId }
      });

      if (deletion.count !== 1) {
        throw new CoreProjectAccessMutationError();
      }

      return { accessId: current.id };
    });
  } catch {
    throw new CoreProjectAccessMutationError();
  }

  await writeProjectAccessAudit({
    eventType: "CORE_PROJECT_ACCESS_REVOKED",
    actorUserId: actor.id,
    projectId,
    userId,
    accessId: removed.accessId,
    message: "Core project access revoked."
  });

  return removed;
}

function requirePersistedAdministrator(
  actor: CoreProjectPrincipal,
  persistedActor: { role: string; isActive: boolean } | null
): void {
  if (
    !isValidCoreResourceId(actor.id) ||
    !isCoreAdministrator(actor.role) ||
    !persistedActor?.isActive ||
    persistedActor.role !== actor.role ||
    !isCoreAdministrator(persistedActor.role)
  ) {
    throw new CoreProjectAccessMutationError();
  }
}

async function requireMultipleActiveOwners(
  transaction: Prisma.TransactionClient,
  projectId: string
): Promise<void> {
  const activeOwnerCount = await transaction.projectAccess.count({
    where: {
      projectId,
      accessLevel: "OWNER",
      user: { isActive: true }
    }
  });

  if (activeOwnerCount <= 1) {
    throw new CoreProjectAccessMutationError();
  }
}

async function writeProjectAccessAudit(input: {
  eventType: AuditEventType;
  actorUserId: string;
  projectId: string;
  userId: string;
  accessId: string;
  accessLevel?: CoreProjectAccessLevel;
  message: string;
}) {
  await writeAuditLog({
    eventType: input.eventType,
    result: "SUCCESS",
    actorUserId: input.actorUserId,
    resource: "core.project-access",
    message: input.message,
    metadata: {
      projectRef: hashAuditIdentifier(input.projectId),
      userRef: hashAuditIdentifier(input.userId),
      accessRef: hashAuditIdentifier(input.accessId),
      ...(input.accessLevel ? { accessLevel: input.accessLevel } : {})
    }
  });
}
