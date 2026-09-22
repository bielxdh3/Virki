import { NextResponse } from "next/server";
import { CSRF_FORM_FIELD_NAME, validateCsrfToken } from "@bielos/auth/csrf";
import { hashAuditIdentifier, writeAuditLog } from "@bielos/auth";
import { verifyLoginEmailCode, verifyLoginTotpCode } from "@bielos/auth/security";
import { isCloudflareAccessAllowed, validateHubCloudflareAccess } from "../../../../lib/cloudflare-access";
import { getSurface, getSurfaceBaseUrl, safeReturnTo } from "../../../../lib/surface";
import { SESSION_COOKIE_NAME, getSessionCookieOptions } from "@bielos/auth";

export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  const surface = getSurface(request.headers);
  if (surface === "unknown") return new NextResponse("Not found", { status: 404 });
  if (surface === "hub" && !isCloudflareAccessAllowed(await validateHubCloudflareAccess(request.headers, "admin-login-verification-api"))) return new NextResponse("Forbidden", { status: 403 });
  const formData = await request.formData();
  if (!validateCsrfToken(read(formData, CSRF_FORM_FIELD_NAME)).valid) return new NextResponse("Forbidden", { status: 403 });
  const ceremony = read(formData, "ceremony");
  const factor = read(formData, "factor").toLowerCase();
  const code = read(formData, "code");
  const returnTo = safeReturnTo(read(formData, "returnTo"));
  const baseUrl = getSurfaceBaseUrl(request.headers, request.url);
  const errorUrl = new URL("/login/verify", baseUrl);
  errorUrl.searchParams.set("ceremony", ceremony);
  errorUrl.searchParams.set("factor", factor);
  if (returnTo) errorUrl.searchParams.set("returnTo", returnTo);
  errorUrl.searchParams.set("error", "1");
  try {
    if (factor === "email") {
      const result = await verifyLoginEmailCode(ceremony, code);
      if (result.requiresTotp) {
        const totpUrl = new URL("/login/verify", baseUrl);
        totpUrl.searchParams.set("ceremony", ceremony);
        totpUrl.searchParams.set("factor", "totp");
        if (returnTo) totpUrl.searchParams.set("returnTo", returnTo);
        return NextResponse.redirect(totpUrl, { status: 303 });
      }
      if (!result.session) throw new Error("missing-session");
      return sessionResponse(result.session, baseUrl, returnTo, surface);
    }
    if (factor === "totp") {
      return sessionResponse(await verifyLoginTotpCode(ceremony, code), baseUrl, returnTo, surface);
    }
  } catch {
    await writeAuditLog({ eventType: "AUTH_LOGIN_FAILURE", result: "FAILURE", resource: "hub", message: "Security verification failed.", metadata: { ceremonyRef: hashAuditIdentifier(ceremony) } });
  }
  return NextResponse.redirect(errorUrl, { status: 303 });
}

function sessionResponse(session: { token: string; expiresAt: Date }, baseUrl: URL, returnTo: string | null, surface: string) {
  const response = NextResponse.redirect(new URL(returnTo ?? (surface === "hub" ? "/admin/accounts" : "/"), baseUrl), { status: 303 });
  response.cookies.set(SESSION_COOKIE_NAME, session.token, getSessionCookieOptions(session.expiresAt));
  return response;
}

function read(formData: FormData, key: string): string {
  const value = formData.get(key);
  return typeof value === "string" ? value.trim() : "";
}
