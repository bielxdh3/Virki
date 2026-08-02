"use server";

import { CSRF_FORM_FIELD_NAME, validateCsrfToken } from "@bielos/auth/csrf";
import { revalidatePath } from "next/cache";
import { headers } from "next/headers";
import { forbidden, redirect } from "next/navigation";
import { getCurrentSession } from "../../../lib/auth";
import { isCloudflareAccessAllowed, validateHubCloudflareAccess } from "../../../lib/cloudflare-access";
import { createFeaturePermissionRequest, createModuleAccessRequest, reviewFeaturePermissionRequest, reviewModuleAccessRequest } from "./service";

const MODULES_PATH = "/core/modules";

export async function requestCoreModule(formData: FormData) {
  const session = await requireMutation(formData, "core-module-request");
  try { await createModuleAccessRequest(session.user, read(formData, "moduleKey"), read(formData, "reason")); } catch { redirect(`${MODULES_PATH}?error=request`); }
  revalidatePath(MODULES_PATH); redirect(`${MODULES_PATH}?status=requested`);
}

export async function requestCoreFeaturePermission(formData: FormData) {
  const session = await requireMutation(formData, "core-feature-request");
  try { await createFeaturePermissionRequest(session.user, read(formData, "moduleKey"), read(formData, "permissionKey"), read(formData, "reason")); } catch { redirect(`${MODULES_PATH}?error=request`); }
  revalidatePath(MODULES_PATH); redirect(`${MODULES_PATH}?status=requested`);
}

export async function reviewCoreModuleRequest(formData: FormData) {
  const session = await requireMutation(formData, "core-module-review");
  if (session.user.role !== "OWNER") forbidden();
  const duration = read(formData, "accessDurationKind");
  const expires = read(formData, "expiresAt");
  try { await reviewModuleAccessRequest({ actor: session.user, sessionId: session.id, requestKey: read(formData, "requestKey"), approve: read(formData, "decision") === "APPROVED", accessDurationKind: duration === "TEMPORARY" ? "TEMPORARY" : "PERMANENT", expiresAt: duration === "TEMPORARY" && expires ? new Date(expires) : null }); } catch { redirect(`${MODULES_PATH}?error=review`); }
  revalidatePath(MODULES_PATH); redirect(`${MODULES_PATH}?status=reviewed`);
}

export async function reviewCoreFeaturePermissionRequest(formData: FormData) {
  const session = await requireMutation(formData, "core-feature-review");
  if (session.user.role !== "OWNER") forbidden();
  const expires = read(formData, "expiresAt");
  try { await reviewFeaturePermissionRequest({ actor: session.user, sessionId: session.id, requestKey: read(formData, "requestKey"), approve: read(formData, "decision") === "APPROVED", expiresAt: expires ? new Date(expires) : null }); } catch { redirect(`${MODULES_PATH}?error=review`); }
  revalidatePath(MODULES_PATH); redirect(`${MODULES_PATH}?status=reviewed`);
}

async function requireMutation(formData: FormData, source: string) {
  if (!isCloudflareAccessAllowed(await validateHubCloudflareAccess(await headers(), source))) forbidden();
  if (!validateCsrfToken(read(formData, CSRF_FORM_FIELD_NAME)).valid) forbidden();
  const session = await getCurrentSession();
  if (!session) redirect("/login");
  return session;
}
function read(formData: FormData, key: string): string { const value = formData.get(key); return typeof value === "string" ? value.trim() : ""; }
