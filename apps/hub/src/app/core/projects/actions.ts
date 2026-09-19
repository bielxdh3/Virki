"use server";

import { CSRF_FORM_FIELD_NAME, validateCsrfToken } from "@bielos/auth/csrf";
import { redirect } from "next/navigation";
import { isCoreAdministrator } from "../authorization";
import { requireSecurityElevation } from "@bielos/auth/administration";
import {
  type CoreProjectFields
} from "./validation";
import { getCoreProjectDetailPath } from "./detail-policy";
import {
  archiveCoreProjectRecord,
  createCoreProjectRecord,
  updateCoreProjectRecord
} from "./mutation-service";
import {
  revokeCoreProjectAccessRecord,
  setCoreProjectAccessRecord
} from "./access-service";
import {
  CORE_PROJECT_ACCESS_ELEVATION_SCOPE,
  CoreProjectAccessActionError,
  executeCoreProjectAccessAction
} from "./project-access-action";
import type { ElevationScope } from "@bielos/auth/elevation-scopes";
import { actionRuntime } from "./action-runtime";

const CORE_PROJECTS_PATH = "/core/projects";
const CORE_PROJECT_ELEVATION_SCOPES = {
  archive: "CORE_PROJECT_ARCHIVE",
  access: CORE_PROJECT_ACCESS_ELEVATION_SCOPE
} as const satisfies Record<"archive" | "access", ElevationScope>;

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
  const accessResult = await actionRuntime.validateAccess(await actionRuntime.getRequestHeaders(), source);

  if (!actionRuntime.accessAllowed(accessResult)) {
    actionRuntime.deny();
    throw new Error("action denied");
  }

  const csrfResult = validateCsrfToken(readFormString(formData, CSRF_FORM_FIELD_NAME));

  if (!csrfResult.valid) {
    actionRuntime.deny();
    throw new Error("action denied");
  }

  const session = await actionRuntime.getSession();

  if (!session) {
    actionRuntime.go("/login");
    throw new Error("action redirect did not terminate");
  }

  if (!isCoreAdministrator(session.user.role)) {
    actionRuntime.deny();
    throw new Error("action denied");
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
  actionRuntime.revalidate(CORE_PROJECTS_PATH);
  const detailPath = projectId ? getCoreProjectDetailPath(projectId) : null;
  if (detailPath) actionRuntime.revalidate(detailPath);
  actionRuntime.revalidate("/");
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
  const projectId = readFormString(formData, "projectId").trim();
  const resultPath = getProjectResultPath(formData, projectId);
  try { await requireSecurityElevation(session.user.id, session.id, CORE_PROJECT_ELEVATION_SCOPES.archive); } catch { redirect(`${resultPath}?error=elevation`); }
  const confirmed = readFormString(formData, "confirmArchive") === "yes";

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
  const projectId = readFormString(formData, "projectId").trim();
  const resultPath = getProjectResultPath(formData, projectId);

  let result: Awaited<ReturnType<typeof setCoreProjectAccessRecord>>;
  try {
    result = (await executeCoreProjectAccessAction(
      formData,
      session.user,
      session.id
    )).result;
  } catch (error) {
    if (error instanceof CoreProjectAccessActionError && error.stage === "elevation") {
      actionRuntime.go(`${resultPath}?error=elevation`);
      throw new Error("action redirect did not terminate", { cause: error });
    }

    actionRuntime.go(`${resultPath}?error=project-access`);
    throw new Error("action redirect did not terminate", { cause: error });
  }

  revalidateCoreProjects(projectId);
  actionRuntime.go(`${resultPath}?status=access-${result.kind}`);
}

export async function revokeCoreProjectAccess(formData: FormData) {
  const session = await requireCoreAdministrator(formData, "core-project-access-revoke");
  const projectId = readFormString(formData, "projectId").trim();
  const userId = readFormString(formData, "userId").trim();
  const resultPath = getProjectResultPath(formData, projectId);
  if (session.user.role !== "OWNER") {
    try { await requireSecurityElevation(session.user.id, session.id, CORE_PROJECT_ELEVATION_SCOPES.access); } catch { redirect(`${resultPath}?error=elevation`); }
  }

  try {
    await revokeCoreProjectAccessRecord(session.user, projectId, userId);
  } catch {
    redirect(`${resultPath}?error=project-access`);
  }

  revalidateCoreProjects(projectId);
  redirect(`${resultPath}?status=access-revoked`);
}
