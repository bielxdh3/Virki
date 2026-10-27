import { SESSION_COOKIE_NAME } from "@virki/auth";
import { CSRF_FORM_FIELD_NAME } from "@virki/auth/csrf";
import { validateSessionCsrfTokenFor } from "./session-csrf";
import { forbidden } from "next/navigation";
import { cookies, headers } from "next/headers";
import { getCurrentSession } from "./auth";
import { isCloudflareAccessAllowed, validateHubCloudflareAccess } from "./cloudflare-access";
import { getSurface, hasSameOrigin } from "./surface";
import { isAdminRequestAllowed, isAdminRole, isHubAdminMutationSurface } from "./admin-policy";
import { recordSecurityDenial, recordSessionCsrfDenial } from "./audit-denial";

type AdminSession = NonNullable<Awaited<ReturnType<typeof getCurrentSession>>>;

export async function requireAdminMutation(formData: FormData, source: string): Promise<AdminSession> {
  const requestHeaders = await headers();
  const surface = getSurface(requestHeaders);
  if (!isHubAdminMutationSurface(surface)) { await recordSecurityDenial(requestHeaders, source, "role"); forbidden(); }
  const accessValid = isCloudflareAccessAllowed(await validateHubCloudflareAccess(requestHeaders, source));
  if (!isAdminRequestAllowed(surface, accessValid)) forbidden();
  if (!hasSameOrigin(requestHeaders)) { await recordSecurityDenial(requestHeaders, source, "csrf"); forbidden(); }
  const csrf = formData.get(CSRF_FORM_FIELD_NAME);
  const sessionToken = (await cookies()).get(SESSION_COOKIE_NAME)?.value;
  if (typeof csrf !== "string" || !validateSessionCsrfTokenFor(sessionToken, csrf, getAdminCsrfScope(source))) { await recordSessionCsrfDenial(requestHeaders, source, sessionToken); forbidden(); }
  const session = await getCurrentSession();
  if (!session || !isAdminRole(session.user.role)) { await recordSecurityDenial(requestHeaders, source, "role", session); forbidden(); }
  return session as AdminSession;
}

function getAdminCsrfScope(source: string): string {
  if (source.startsWith("admin-account-")) return "admin-accounts";
  if (source.startsWith("admin-project-access-")) return "admin-access";
  if (source.startsWith("admin-project-connection-")) return "admin-connections";
  return "admin-security";
}

export function readFormString(formData: FormData, key: string): string {
  const value = formData.get(key);
  return typeof value === "string" ? value.trim() : "";
}

export function readFormRawString(formData: FormData, key: string): string {
  const value = formData.get(key);
  return typeof value === "string" ? value : "";
}
