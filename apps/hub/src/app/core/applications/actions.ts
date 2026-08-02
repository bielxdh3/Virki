"use server";

import { CSRF_FORM_FIELD_NAME, validateCsrfToken } from "@bielos/auth/csrf";
import { revalidatePath } from "next/cache";
import { headers } from "next/headers";
import { forbidden, redirect } from "next/navigation";
import { getCurrentSession } from "../../../lib/auth";
import { isCloudflareAccessAllowed, validateHubCloudflareAccess } from "../../../lib/cloudflare-access";
import { reissueApplicationActivation, reviewApplicationModule } from "./service";

const APPLICATIONS_PATH = "/core/applications";

export async function reviewCoreApplication(formData: FormData) {
  const session = await requireOwner(formData, "core-application-review");
  const applicationId = read(formData, "applicationId");
  const moduleDecisionId = read(formData, "moduleDecisionId");
  const decision = read(formData, "decision");
  const duration = read(formData, "accessDurationKind");
  const expiresRaw = read(formData, "accessExpiresAt");

  try {
    await reviewApplicationModule({
      actor: session.user,
      sessionId: session.id,
      applicationId,
      moduleDecisionId,
      decision: decision === "APPROVED" ? "APPROVED" : "REJECTED",
      internalReason: read(formData, "internalReason"),
      userVisibleMessage: read(formData, "userVisibleMessage"),
      accessDurationKind: duration === "TEMPORARY" ? "TEMPORARY" : "PERMANENT",
      accessExpiresAt: duration === "TEMPORARY" && expiresRaw ? new Date(expiresRaw) : null
    });
  } catch {
    redirect(`${APPLICATIONS_PATH}?error=review`);
  }

  revalidatePath(APPLICATIONS_PATH);
  revalidatePath("/");
  redirect(`${APPLICATIONS_PATH}?status=reviewed`);
}

export async function reissueCoreApplicationActivation(formData: FormData) {
  const session = await requireOwner(formData, "core-application-activation-reissue");
  try {
    await reissueApplicationActivation(session.user, session.id, read(formData, "applicationId"));
  } catch {
    redirect(`${APPLICATIONS_PATH}?error=reissue`);
  }
  revalidatePath(APPLICATIONS_PATH);
  redirect(`${APPLICATIONS_PATH}?status=reissued`);
}

async function requireOwner(formData: FormData, source: string) {
  const access = await validateHubCloudflareAccess(await headers(), source);
  if (!isCloudflareAccessAllowed(access)) {
    forbidden();
  }
  if (!validateCsrfToken(read(formData, CSRF_FORM_FIELD_NAME)).valid) {
    forbidden();
  }
  const session = await getCurrentSession();
  if (!session) {
    redirect("/login");
  }
  if (session.user.role !== "OWNER") {
    forbidden();
  }
  return session;
}

function read(formData: FormData, key: string): string {
  const value = formData.get(key);
  return typeof value === "string" ? value.trim() : "";
}
