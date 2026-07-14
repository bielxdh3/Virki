"use server";

import { hashAuditIdentifier, writeAuditLog, type AuditEventType } from "@bielos/auth";
import { CSRF_FORM_FIELD_NAME, validateCsrfToken } from "@bielos/auth/csrf";
import { prisma, type Prisma } from "@bielos/database";
import { revalidatePath } from "next/cache";
import { headers } from "next/headers";
import { forbidden, redirect } from "next/navigation";
import { getCurrentSession } from "../../../lib/auth";
import {
  isCloudflareAccessAllowed,
  validateHubCloudflareAccess
} from "../../../lib/cloudflare-access";
import { isCoreAdministrator } from "../authorization";
import {
  canRevokeCoreProjectAccess,
  canSetCoreProjectAccess,
  isCoreProjectAccessLevel,
  requiresActiveOwnerRetentionCheck,
  type CoreProjectAccessLevel
} from "./access-policy";
import {
  isValidCoreResourceId,
  type CoreProjectFields
} from "./validation";
import {
  archiveCoreProjectRecord,
  createCoreProjectRecord,
  updateCoreProjectRecord
} from "./mutation-service";

const CORE_PROJECTS_PATH = "/core/projects";
const SERIALIZABLE_RETRY_LIMIT = 3;

class CoreProjectMutationError extends Error {}

function readFormString(formData: FormData, key: string): string {
  const value = formData.get(key);
  return typeof value === "string" ? value : "";
}

function readProjectFields(formData: FormData): CoreProjectFields {
  return {
    name: readFormString(formData, "name"),
    slug: readFormString(formData, "slug"),
    description: readFormString(formData, "description"),
    visibility: readFormString(formData, "visibility"),
    status: readFormString(formData, "status")
  };
}

function isRetryableTransactionError(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    error.code === "P2034"
  );
}

async function runSerializableTransaction<T>(
  operation: (transaction: Prisma.TransactionClient) => Promise<T>
): Promise<T> {
  for (let attempt = 1; attempt <= SERIALIZABLE_RETRY_LIMIT; attempt += 1) {
    try {
      return await prisma.$transaction(operation, { isolationLevel: "Serializable" });
    } catch (error) {
      if (error instanceof CoreProjectMutationError || !isRetryableTransactionError(error)) {
        throw error;
      }

      if (attempt === SERIALIZABLE_RETRY_LIMIT) {
        throw error;
      }
    }
  }

  throw new CoreProjectMutationError("serializable transaction retry exhausted");
}

async function requireCoreAdministrator(formData: FormData, source: string) {
  const accessResult = await validateHubCloudflareAccess(await headers(), source);

  if (!isCloudflareAccessAllowed(accessResult)) {
    forbidden();
  }

  const csrfResult = validateCsrfToken(readFormString(formData, CSRF_FORM_FIELD_NAME));

  if (!csrfResult.valid) {
    forbidden();
  }

  const session = await getCurrentSession();

  if (!session) {
    redirect("/login");
  }

  if (!isCoreAdministrator(session.user.role)) {
    forbidden();
  }

  return session;
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

function revalidateCoreProjects() {
  revalidatePath(CORE_PROJECTS_PATH);
  revalidatePath("/");
}

export async function createCoreProject(formData: FormData) {
  const session = await requireCoreAdministrator(formData, "core-project-create");

  try {
    await createCoreProjectRecord(session.user, readProjectFields(formData));
  } catch {
    redirect(`${CORE_PROJECTS_PATH}?error=project-create`);
  }

  revalidateCoreProjects();
  redirect(`${CORE_PROJECTS_PATH}?status=created`);
}

export async function updateCoreProject(formData: FormData) {
  const session = await requireCoreAdministrator(formData, "core-project-update");
  const projectId = readFormString(formData, "projectId").trim();

  try {
    await updateCoreProjectRecord(session.user, projectId, readProjectFields(formData));
  } catch {
    redirect(`${CORE_PROJECTS_PATH}?error=project-update`);
  }

  revalidateCoreProjects();
  redirect(`${CORE_PROJECTS_PATH}?status=updated`);
}

export async function archiveCoreProject(formData: FormData) {
  const session = await requireCoreAdministrator(formData, "core-project-archive");
  const projectId = readFormString(formData, "projectId").trim();
  const confirmed = readFormString(formData, "confirmArchive") === "yes";

  try {
    await archiveCoreProjectRecord(session.user, projectId, confirmed);
  } catch {
    redirect(`${CORE_PROJECTS_PATH}?error=project-archive`);
  }

  revalidateCoreProjects();
  redirect(`${CORE_PROJECTS_PATH}?status=archived`);
}

export async function setCoreProjectAccess(formData: FormData) {
  const session = await requireCoreAdministrator(formData, "core-project-access-set");
  const projectId = readFormString(formData, "projectId").trim();
  const userId = readFormString(formData, "userId").trim();
  const accessLevel = readFormString(formData, "accessLevel");

  if (
    !isValidCoreResourceId(projectId) ||
    !isValidCoreResourceId(userId) ||
    !isCoreProjectAccessLevel(accessLevel)
  ) {
    redirect(`${CORE_PROJECTS_PATH}?error=project-access`);
  }

  let result: {
    kind: "granted" | "changed" | "unchanged";
    accessId: string;
  };

  try {
    result = await runSerializableTransaction(async (transaction) => {
      const [project, targetUser, current] = await Promise.all([
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

      if (!project || project.status === "ARCHIVED" || !targetUser?.isActive) {
        throw new CoreProjectMutationError("project access target unavailable");
      }

      if (!canSetCoreProjectAccess(session.user.role, accessLevel, current?.accessLevel ?? null)) {
        throw new CoreProjectMutationError("project access level forbidden");
      }

      if (current?.accessLevel === accessLevel) {
        return { kind: "unchanged" as const, accessId: current.id };
      }

      if (
        current &&
        requiresActiveOwnerRetentionCheck(current.accessLevel, targetUser.isActive) &&
        accessLevel !== "OWNER"
      ) {
        const activeOwnerCount = await transaction.projectAccess.count({
          where: {
            projectId,
            accessLevel: "OWNER",
            user: { isActive: true }
          }
        });

        if (activeOwnerCount <= 1) {
          throw new CoreProjectMutationError("last active project owner cannot be demoted");
        }
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
    redirect(`${CORE_PROJECTS_PATH}?error=project-access`);
  }

  if (result.kind !== "unchanged") {
    await writeProjectAccessAudit({
      eventType:
        result.kind === "granted"
          ? "CORE_PROJECT_ACCESS_GRANTED"
          : "CORE_PROJECT_ACCESS_CHANGED",
      actorUserId: session.user.id,
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

  revalidateCoreProjects();
  redirect(`${CORE_PROJECTS_PATH}?status=access-${result.kind}`);
}

export async function revokeCoreProjectAccess(formData: FormData) {
  const session = await requireCoreAdministrator(formData, "core-project-access-revoke");
  const projectId = readFormString(formData, "projectId").trim();
  const userId = readFormString(formData, "userId").trim();

  if (!isValidCoreResourceId(projectId) || !isValidCoreResourceId(userId)) {
    redirect(`${CORE_PROJECTS_PATH}?error=project-access`);
  }

  let removed: { accessId: string };

  try {
    removed = await runSerializableTransaction(async (transaction) => {
      const current = await transaction.projectAccess.findUnique({
        where: { userId_projectId: { userId, projectId } },
        select: {
          id: true,
          accessLevel: true,
          user: { select: { isActive: true } },
          project: { select: { status: true } }
        }
      });

      if (
        !current ||
        current.project.status === "ARCHIVED" ||
        !canRevokeCoreProjectAccess(session.user.role, current.accessLevel)
      ) {
        throw new CoreProjectMutationError("project access cannot be revoked");
      }

      if (requiresActiveOwnerRetentionCheck(current.accessLevel, current.user.isActive)) {
        const activeOwnerCount = await transaction.projectAccess.count({
          where: {
            projectId,
            accessLevel: "OWNER",
            user: { isActive: true }
          }
        });

        if (activeOwnerCount <= 1) {
          throw new CoreProjectMutationError("last active project owner cannot be revoked");
        }
      }

      const deletion = await transaction.projectAccess.deleteMany({
        where: { id: current.id, userId, projectId }
      });

      if (deletion.count !== 1) {
        throw new CoreProjectMutationError("project access revocation lost race");
      }

      return { accessId: current.id };
    });
  } catch {
    redirect(`${CORE_PROJECTS_PATH}?error=project-access`);
  }

  await writeProjectAccessAudit({
    eventType: "CORE_PROJECT_ACCESS_REVOKED",
    actorUserId: session.user.id,
    projectId,
    userId,
    accessId: removed.accessId,
    message: "Core project access revoked."
  });

  revalidateCoreProjects();
  redirect(`${CORE_PROJECTS_PATH}?status=access-revoked`);
}
