import { CSRF_FORM_FIELD_NAME, validateCsrfToken } from "@virki/auth/csrf";
import { getSurface, hasSameOrigin } from "../../lib/surface";

export function resolveRecoveryExpectedRole(
  requestHeaders: Pick<Headers, "get">,
  requiredSurface?: "hub" | "portal",
  env: NodeJS.ProcessEnv = process.env
): "ADMIN" | "USER" | null {
  const surface = getSurface(requestHeaders, env);
  const expectedSurface = surface === "portal" || surface === "hub"
    ? surface
    : surface === "local" && env.NODE_ENV !== "production"
      ? "portal"
      : "unknown";
  if (expectedSurface === "unknown" || (requiredSurface && expectedSurface !== requiredSurface)) return null;
  return expectedSurface === "hub" ? "ADMIN" : "USER";
}

export function hasValidRecoveryActionCsrf(
  requestHeaders: Pick<Headers, "get">,
  formData: Pick<FormData, "get">,
  scope: string,
  env: NodeJS.ProcessEnv = process.env
): boolean {
  if (!hasSameOrigin(requestHeaders)) return false;
  const value = formData.get(CSRF_FORM_FIELD_NAME);
  return validateCsrfToken(typeof value === "string" ? value : null, { scope, env }).valid;
}
