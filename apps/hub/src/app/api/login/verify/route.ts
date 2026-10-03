import { NextResponse } from "next/server";
import { CSRF_FORM_FIELD_NAME, validateCsrfToken } from "@bielos/auth/csrf";
import { createAuditRequestMetadata, hashAuditIdentifier, writeAuditLog, writeAuditLogRequired } from "@bielos/auth";
import { DEVICE_COOKIE_NAME, verifyLoginEmailCode, verifyLoginRecoveryCode, verifyLoginTotpCode } from "@bielos/auth/security";
import { isCloudflareAccessAllowed, validateHubCloudflareAccess } from "../../../../lib/cloudflare-access";
import { getSurface, getSurfaceBaseUrl, hasSameOrigin, safeReturnTo } from "../../../../lib/surface";
import { createLoginResponseAfterRequiredAudit, createVerifiedLoginAudit, type LoginSurface, type LoginVerificationFactor } from "../../../../lib/login-audit";
import { SESSION_COOKIE_NAME, getSessionCookieOptions } from "@bielos/auth";
import { readBoundedFormData } from "../../../../lib/request-form";

export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  const surface = getSurface(request.headers);
  if (surface === "unknown") return new NextResponse("Not found", { status: 404 });
  if (surface === "hub" && !isCloudflareAccessAllowed(await validateHubCloudflareAccess(request.headers, "admin-login-verification-api"))) return new NextResponse("Forbidden", { status: 403 });
  if (!hasSameOrigin(request.headers)) return new NextResponse("Forbidden", { status: 403 });
  const formData = await readBoundedFormData(request);
  if (!formData) return new NextResponse("Bad Request", { status: 400 });
  if (!validateCsrfToken(read(formData, CSRF_FORM_FIELD_NAME)).valid) return new NextResponse("Forbidden", { status: 403 });
  const ceremony = read(formData, "ceremony");
  const factor = read(formData, "factor").toLowerCase();
  const code = read(formData, "code");
  const returnTo = safeReturnTo(read(formData, "returnTo"), surface);
  const deviceToken = readCookie(request.headers.get("cookie"), DEVICE_COOKIE_NAME);
  if (!deviceToken) return new NextResponse("Forbidden", { status: 403 });
  const baseUrl = getSurfaceBaseUrl(request.headers, request.url);
  if (!baseUrl) return new NextResponse("Service Unavailable", { status: 503, headers: { "cache-control": "no-store" } });
  const auditMetadata = createAuditRequestMetadata(request.headers, `${surface}-login-verification`);
  const errorUrl = new URL("/login/verify", baseUrl);
  errorUrl.searchParams.set("ceremony", ceremony);
  errorUrl.searchParams.set("factor", factor);
  if (read(formData, "flow") === "recovery") errorUrl.searchParams.set("flow", "recovery");
  if (returnTo) errorUrl.searchParams.set("returnTo", returnTo);
  errorUrl.searchParams.set("error", "1");
  try {
    if (factor === "email") {
      const result = await verifyLoginEmailCode(ceremony, code, deviceToken);
      if (result.requiresTotp) {
        const totpUrl = new URL("/login/verify", baseUrl);
        totpUrl.searchParams.set("ceremony", ceremony);
        const nextFactor = read(formData, "flow") === "recovery" ? "recovery" : "totp";
        totpUrl.searchParams.set("factor", nextFactor);
        if (nextFactor === "recovery") totpUrl.searchParams.set("flow", "recovery");
        if (returnTo) totpUrl.searchParams.set("returnTo", returnTo);
        return NextResponse.redirect(totpUrl, { status: 303 });
      }
      if (!result.session) throw new Error("missing-session");
      return sessionResponse(result.session, baseUrl, returnTo, surface, "email", auditMetadata);
    }
    if (factor === "totp") {
      return sessionResponse(await verifyLoginTotpCode(ceremony, code, deviceToken), baseUrl, returnTo, surface, "totp", auditMetadata);
    }
    if (factor === "recovery") {
      const result = await verifyLoginRecoveryCode(ceremony, code, deviceToken);
      if (result.kind === "EMAIL_REQUIRED") {
        const emailUrl = new URL("/login/verify", baseUrl);
        emailUrl.searchParams.set("ceremony", ceremony);
        emailUrl.searchParams.set("factor", "email");
        emailUrl.searchParams.set("flow", "recovery");
        if (returnTo) emailUrl.searchParams.set("returnTo", returnTo);
        return NextResponse.redirect(emailUrl, { status: 303 });
      }
      return sessionResponse(result.session, baseUrl, returnTo, surface, "recovery", auditMetadata, "/account/security?recovered=totp");
    }
  } catch {
    await writeAuditLog({ eventType: "AUTH_LOGIN_FAILURE", result: "FAILURE", resource: surface, message: "Security verification failed.", metadata: { ceremonyRef: hashAuditIdentifier(ceremony) } });
  }
  return NextResponse.redirect(errorUrl, { status: 303 });
}

async function sessionResponse(
  session: { userId: string; token: string; expiresAt: Date },
  baseUrl: URL,
  returnTo: string | null,
  surface: LoginSurface,
  factor: LoginVerificationFactor,
  requestMetadata: ReturnType<typeof createAuditRequestMetadata>,
  recoveredFallback?: string
) {
  return createLoginResponseAfterRequiredAudit(
    () => writeAuditLogRequired(createVerifiedLoginAudit(session.userId, surface, factor, requestMetadata)),
    () => {
      const response = NextResponse.redirect(new URL(returnTo ?? recoveredFallback ?? (surface === "hub" ? "/admin/accounts" : "/"), baseUrl), { status: 303 });
      response.cookies.set(SESSION_COOKIE_NAME, session.token, getSessionCookieOptions(session.expiresAt));
      return response;
    },
    auditUnavailableResponse
  );
}

function auditUnavailableResponse() {
  return new NextResponse("Service Unavailable", { status: 503, headers: { "cache-control": "no-store" } });
}

function read(formData: FormData, key: string): string {
  const value = formData.get(key);
  return typeof value === "string" ? value.trim() : "";
}

function readCookie(header: string | null, name: string): string | undefined {
  if (!header) return undefined;
  for (const pair of header.split(";")) {
    const separator = pair.indexOf("=");
    if (separator >= 0 && pair.slice(0, separator).trim() === name) return pair.slice(separator + 1).trim();
  }
  return undefined;
}
