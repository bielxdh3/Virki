"use server";

import { hashAuditIdentifier, writeAuditLog, type AuditEventType } from "@bielos/auth";
import { CSRF_FORM_FIELD_NAME, validateCsrfToken } from "@bielos/auth/csrf";
import { prisma } from "@bielos/database";
import { revalidatePath } from "next/cache";
import { headers } from "next/headers";
import { forbidden, redirect } from "next/navigation";
import { getCurrentSession } from "../../../lib/auth";
import {
  isCloudflareAccessAllowed,
  validateHubCloudflareAccess
} from "../../../lib/cloudflare-access";
import { isCoreAdministrator } from "../authorization";
import { validateCoreProjectInput, type CoreProjectFields } from "./validation";

const CORE_PROJECTS_PATH = "/core/projects";

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

async function writeProjectAudit(input: {
  eventType: AuditEventType;
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

function revalidateCoreProjects() {
  revalidatePath(CORE_PROJECTS_PATH);
  revalidatePath("/");
}

export async function createCoreProject(formData: FormData) {
  const session = await requireCoreAdministrator(formData, "core-project-create");
  const input = validateCoreProjectInput(readProjectFields(formData));

  if (!input) {
    redirect(`${CORE_PROJECTS_PATH}?error=project-create`);
  }

  let project: { id: string; status: string; visibility: string };

  try {
    project = await prisma.$transaction(async (transaction) => {
      const createdProject = await transaction.project.create({
        data: input,
        select: {
          id: true,
          status: true,
          visibility: true
        }
      });

      await transaction.projectAccess.create({
        data: {
          projectId: createdProject.id,
          userId: session.user.id,
          accessLevel: "OWNER"
        }
      });

      return createdProject;
    });
  } catch {
    redirect(`${CORE_PROJECTS_PATH}?error=project-create`);
  }

  await writeProjectAudit({
    eventType: "CORE_PROJECT_CREATED",
    actorUserId: session.user.id,
    projectId: project.id,
    status: project.status,
    visibility: project.visibility,
    message: "Core project created."
  });

  revalidateCoreProjects();
  redirect(`${CORE_PROJECTS_PATH}?status=created`);
}

export async function updateCoreProject(formData: FormData) {
  const session = await requireCoreAdministrator(formData, "core-project-update");
  const projectId = readFormString(formData, "projectId").trim();
  const input = validateCoreProjectInput(readProjectFields(formData));

  if (!projectId || !input) {
    redirect(`${CORE_PROJECTS_PATH}?error=project-update`);
  }

  let updatedCount = 0;

  try {
    const result = await prisma.project.updateMany({
      where: {
        id: projectId,
        status: { not: "ARCHIVED" }
      },
      data: input
    });
    updatedCount = result.count;
  } catch {
    redirect(`${CORE_PROJECTS_PATH}?error=project-update`);
  }

  if (updatedCount !== 1) {
    redirect(`${CORE_PROJECTS_PATH}?error=project-update`);
  }

  await writeProjectAudit({
    eventType: "CORE_PROJECT_UPDATED",
    actorUserId: session.user.id,
    projectId,
    status: input.status,
    visibility: input.visibility,
    message: "Core project updated."
  });

  revalidateCoreProjects();
  redirect(`${CORE_PROJECTS_PATH}?status=updated`);
}

export async function archiveCoreProject(formData: FormData) {
  const session = await requireCoreAdministrator(formData, "core-project-archive");
  const projectId = readFormString(formData, "projectId").trim();
  const confirmed = readFormString(formData, "confirmArchive") === "yes";

  if (!projectId || !confirmed) {
    redirect(`${CORE_PROJECTS_PATH}?error=project-archive`);
  }

  let archivedCount = 0;

  try {
    const result = await prisma.project.updateMany({
      where: {
        id: projectId,
        status: { not: "ARCHIVED" }
      },
      data: {
        status: "ARCHIVED"
      }
    });
    archivedCount = result.count;
  } catch {
    redirect(`${CORE_PROJECTS_PATH}?error=project-archive`);
  }

  if (archivedCount !== 1) {
    redirect(`${CORE_PROJECTS_PATH}?error=project-archive`);
  }

  await writeProjectAudit({
    eventType: "CORE_PROJECT_ARCHIVED",
    actorUserId: session.user.id,
    projectId,
    status: "ARCHIVED",
    message: "Core project archived."
  });

  revalidateCoreProjects();
  redirect(`${CORE_PROJECTS_PATH}?status=archived`);
}
