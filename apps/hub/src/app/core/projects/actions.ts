"use server";

import { CSRF_FORM_FIELD_NAME, validateCsrfToken } from "@bielos/auth/csrf";
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
  type CoreProjectFields
} from "./validation";
import { getCoreProjectDetailPath } from "./detail-policy";
import {
  archiveCoreProjectRecord,
  createCoreProjectRecord,
  updateCoreProjectRecord
} from "./mutation-service";
import { requireSecurityElevation } from "@bielos/auth/administration";
import {
  revokeCoreProjectAccessRecord,
  setCoreProjectAccessRecord
} from "./access-service";

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

function getProjectResultPath(formData: FormData, projectId: string): string {
  if (readFormString(formData, "returnTo") === "detail") {
    return getCoreProjectDetailPath(projectId) ?? CORE_PROJECTS_PATH;
  }

  return CORE_PROJECTS_PATH;
}

function revalidateCoreProjects(projectId?: string) {
  revalidatePath(CORE_PROJECTS_PATH);
  const detailPath = projectId ? getCoreProjectDetailPath(projectId) : null;
  if (detailPath) revalidatePath(detailPath);
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
  const resultPath = getProjectResultPath(formData, projectId);

  try {
    await updateCoreProjectRecord(session.user, projectId, readProjectFields(formData));
  } catch {
    redirect(`${resultPath}?error=project-update`);
  }

  revalidateCoreProjects(projectId);
  redirect(`${resultPath}?status=updated`);
}

export async function archiveCoreProject(formData: FormData) {
  const session = await requireCoreAdministrator(formData, "core-project-archive");
  try { await requireSecurityElevation(session.user.id, session.id, "CORE_PROJECT_ARCHIVE"); } catch { redirect("/core/projects?error=elevation"); }
  const projectId = readFormString(formData, "projectId").trim();
  const confirmed = readFormString(formData, "confirmArchive") === "yes";
  const resultPath = getProjectResultPath(formData, projectId);

  try {
    await archiveCoreProjectRecord(session.user, projectId, confirmed);
  } catch {
    redirect(`${resultPath}?error=project-archive`);
  }

  revalidateCoreProjects(projectId);
  redirect(`${resultPath}?status=archived`);
}

export async function setCoreProjectAccess(formData: FormData) {
  const session = await requireCoreAdministrator(formData, "core-project-access-set");
  try { await requireSecurityElevation(session.user.id, session.id, "PROJECT_OWNER_ACCESS_CHANGE"); } catch { redirect("/core/projects?error=elevation"); }
  const projectId = readFormString(formData, "projectId").trim();
  const userId = readFormString(formData, "userId").trim();
  const accessLevel = readFormString(formData, "accessLevel");
  const resultPath = getProjectResultPath(formData, projectId);

  let result: Awaited<ReturnType<typeof setCoreProjectAccessRecord>>;
  try {
    result = await setCoreProjectAccessRecord(
      session.user,
      projectId,
      userId,
      accessLevel
    );
  } catch {
    redirect(`${resultPath}?error=project-access`);
  }

  revalidateCoreProjects(projectId);
  redirect(`${resultPath}?status=access-${result.kind}`);
}

export async function revokeCoreProjectAccess(formData: FormData) {
  const session = await requireCoreAdministrator(formData, "core-project-access-revoke");
  try { await requireSecurityElevation(session.user.id, session.id, "PROJECT_OWNER_ACCESS_CHANGE"); } catch { redirect("/core/projects?error=elevation"); }
  const projectId = readFormString(formData, "projectId").trim();
  const userId = readFormString(formData, "userId").trim();
  const resultPath = getProjectResultPath(formData, projectId);

  try {
    await revokeCoreProjectAccessRecord(session.user, projectId, userId);
  } catch {
    redirect(`${resultPath}?error=project-access`);
  }

  revalidateCoreProjects(projectId);
  redirect(`${resultPath}?status=access-revoked`);
}
