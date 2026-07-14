import { hashAuditIdentifier, writeAuditLog } from "@bielos/auth";
import { prisma } from "@bielos/database";

import { isCoreAdministrator, type CoreProjectPrincipal } from "../authorization";
import {
  isValidCoreResourceId,
  validateCoreProjectInput,
  type CoreProjectFields
} from "./validation";
import {
  lockCoreProjectMutation,
  runCoreProjectSerializableTransaction
} from "./transaction";

export class CoreProjectMutationError extends Error {
  constructor() {
    super("Core project mutation rejected.");
    this.name = "CoreProjectMutationError";
  }
}

export async function createCoreProjectRecord(
  actor: CoreProjectPrincipal,
  fields: CoreProjectFields
) {
  const input = validateCoreProjectInput(fields);

  if (!input) {
    throw new CoreProjectMutationError();
  }

  let project: { id: string; status: string; visibility: string };

  try {
    await requireActiveCoreAdministrator(actor);
    project = await prisma.$transaction(async (transaction) => {
      const createdProject = await transaction.project.create({
        data: input,
        select: { id: true, status: true, visibility: true }
      });

      await transaction.projectAccess.create({
        data: {
          projectId: createdProject.id,
          userId: actor.id,
          accessLevel: "OWNER"
        }
      });

      return createdProject;
    });
  } catch {
    throw new CoreProjectMutationError();
  }

  await writeProjectAudit({
    eventType: "CORE_PROJECT_CREATED",
    actorUserId: actor.id,
    projectId: project.id,
    status: project.status,
    visibility: project.visibility,
    message: "Core project created."
  });

  return project;
}

export async function updateCoreProjectRecord(
  actor: CoreProjectPrincipal,
  projectId: string,
  fields: CoreProjectFields
) {
  const input = validateCoreProjectInput(fields);

  if (!isValidCoreResourceId(projectId) || !input) {
    throw new CoreProjectMutationError();
  }

  try {
    await requireActiveCoreAdministrator(actor);
    const result = await prisma.project.updateMany({
      where: {
        id: projectId,
        status: { not: "ARCHIVED" }
      },
      data: input
    });

    if (result.count !== 1) {
      throw new CoreProjectMutationError();
    }
  } catch {
    throw new CoreProjectMutationError();
  }

  await writeProjectAudit({
    eventType: "CORE_PROJECT_UPDATED",
    actorUserId: actor.id,
    projectId,
    status: input.status,
    visibility: input.visibility,
    message: "Core project updated."
  });

  return { id: projectId, status: input.status, visibility: input.visibility };
}

export async function archiveCoreProjectRecord(
  actor: CoreProjectPrincipal,
  projectId: string,
  confirmed: boolean
) {
  if (!isValidCoreResourceId(projectId) || !confirmed) {
    throw new CoreProjectMutationError();
  }

  try {
    await requireActiveCoreAdministrator(actor);
    await runCoreProjectSerializableTransaction(async (transaction) => {
      await lockCoreProjectMutation(transaction, projectId);

      const result = await transaction.project.updateMany({
        where: {
          id: projectId,
          status: { not: "ARCHIVED" }
        },
        data: { status: "ARCHIVED" }
      });

      if (result.count !== 1) {
        throw new CoreProjectMutationError();
      }
    });
  } catch {
    throw new CoreProjectMutationError();
  }

  await writeProjectAudit({
    eventType: "CORE_PROJECT_ARCHIVED",
    actorUserId: actor.id,
    projectId,
    status: "ARCHIVED",
    message: "Core project archived."
  });

  return { id: projectId, status: "ARCHIVED" as const };
}

async function requireActiveCoreAdministrator(actor: CoreProjectPrincipal): Promise<void> {
  if (!isValidCoreResourceId(actor.id) || !isCoreAdministrator(actor.role)) {
    throw new CoreProjectMutationError();
  }

  const persistedActor = await prisma.user.findUnique({
    where: { id: actor.id },
    select: { role: true, isActive: true }
  });

  if (
    !persistedActor?.isActive ||
    persistedActor.role !== actor.role ||
    !isCoreAdministrator(persistedActor.role)
  ) {
    throw new CoreProjectMutationError();
  }
}

async function writeProjectAudit(input: {
  eventType: "CORE_PROJECT_CREATED" | "CORE_PROJECT_UPDATED" | "CORE_PROJECT_ARCHIVED";
  actorUserId: string;
  projectId: string;
  status: string;
  visibility?: string;
  message: string;
}) {
  await writeAuditLog({
    eventType: input.eventType,
    result: "SUCCESS",
    actorUserId: input.actorUserId,
    resource: "core.project",
    message: input.message,
    metadata: {
      projectRef: hashAuditIdentifier(input.projectId),
      status: input.status,
      ...(input.visibility ? { visibility: input.visibility } : {})
    }
  });
}
