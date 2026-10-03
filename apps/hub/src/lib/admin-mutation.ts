import { CSRF_FORM_FIELD_NAME, validateCsrfToken } from "@bielos/auth/csrf";
import { forbidden } from "next/navigation";
import { headers } from "next/headers";
import { getCurrentSession } from "./auth";
import { isCloudflareAccessAllowed, validateHubCloudflareAccess } from "./cloudflare-access";
import { getSurface, hasSameOrigin } from "./surface";
import { isAdminRequestAllowed, isAdminRole, isHubAdminMutationSurface } from "./admin-policy";

type AdminSession = NonNullable<Awaited<ReturnType<typeof getCurrentSession>>>;

export async function requireAdminMutation(formData: FormData, source: string): Promise<AdminSession> {
  const requestHeaders = await headers();
  const surface = getSurface(requestHeaders);
  if (!isHubAdminMutationSurface(surface)) forbidden();
  const accessValid = isCloudflareAccessAllowed(await validateHubCloudflareAccess(requestHeaders, source));
  if (!isAdminRequestAllowed(surface, accessValid)) forbidden();
  if (!hasSameOrigin(requestHeaders)) forbidden();
  const csrf = formData.get(CSRF_FORM_FIELD_NAME);
  if (typeof csrf !== "string" || !validateCsrfToken(csrf).valid) forbidden();
  const session = await getCurrentSession();
  if (!session || !isAdminRole(session.user.role)) forbidden();
  return session as AdminSession;
}

export function readFormString(formData: FormData, key: string): string {
  const value = formData.get(key);
  return typeof value === "string" ? value.trim() : "";
}

export function readFormRawString(formData: FormData, key: string): string {
  const value = formData.get(key);
  return typeof value === "string" ? value : "";
}
