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
import {
  archiveCoreProjectRecord,
  createCoreProjectRecord,
  updateCoreProjectRecord
} from "./mutation-service";
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

  let result: Awaited<ReturnType<typeof setCoreProjectAccessRecord>>;
  try {
    result = await setCoreProjectAccessRecord(
      session.user,
      projectId,
      userId,
      accessLevel
    );
  } catch {
    redirect(`${CORE_PROJECTS_PATH}?error=project-access`);
  }

  revalidateCoreProjects();
  redirect(`${CORE_PROJECTS_PATH}?status=access-${result.kind}`);
}

export async function revokeCoreProjectAccess(formData: FormData) {
  const session = await requireCoreAdministrator(formData, "core-project-access-revoke");
  const projectId = readFormString(formData, "projectId").trim();
  const userId = readFormString(formData, "userId").trim();

  try {
    await revokeCoreProjectAccessRecord(session.user, projectId, userId);
  } catch {
    redirect(`${CORE_PROJECTS_PATH}?error=project-access`);
  }

  revalidateCoreProjects();
  redirect(`${CORE_PROJECTS_PATH}?status=access-revoked`);
}
