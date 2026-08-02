import { NextResponse } from "next/server";
import { CSRF_FORM_FIELD_NAME, validateCsrfToken } from "@bielos/auth/csrf";
import { hashAuditIdentifier, writeAuditLog } from "@bielos/auth";
import { verifyLoginEmailCode, verifyLoginTotpCode } from "@bielos/auth/security";
import { isCloudflareAccessAllowed, validateHubCloudflareAccess } from "../../../../lib/cloudflare-access";
import { createHubRedirectUrl } from "../../../../lib/hub-redirect";
import { SESSION_COOKIE_NAME, getSessionCookieOptions } from "@bielos/auth";

export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  const access = await validateHubCloudflareAccess(request.headers, "hub-login-verification-api");
  if (!isCloudflareAccessAllowed(access)) return new NextResponse("Forbidden", { status: 403 });
  const formData = await request.formData();
  if (!validateCsrfToken(read(formData, CSRF_FORM_FIELD_NAME)).valid) return new NextResponse("Forbidden", { status: 403 });
  const ceremony = read(formData, "ceremony");
  const factor = read(formData, "factor").toLowerCase();
  const code = read(formData, "code");
  const errorUrl = createHubRedirectUrl("/login/verify", request.url);
  errorUrl.searchParams.set("ceremony", ceremony);
  errorUrl.searchParams.set("factor", factor);
  errorUrl.searchParams.set("error", "1");
  try {
    if (factor === "email") {
      const result = await verifyLoginEmailCode(ceremony, code);
      if (result.requiresTotp) {
        const totpUrl = createHubRedirectUrl("/login/verify", request.url);
        totpUrl.searchParams.set("ceremony", ceremony);
        totpUrl.searchParams.set("factor", "totp");
        return NextResponse.redirect(totpUrl, { status: 303 });
      }
      if (!result.session) throw new Error("missing-session");
      return sessionResponse(result.session, request.url);
    }
    if (factor === "totp") {
      return sessionResponse(await verifyLoginTotpCode(ceremony, code), request.url);
    }
  } catch {
    await writeAuditLog({ eventType: "AUTH_LOGIN_FAILURE", result: "FAILURE", resource: "hub", message: "Security verification failed.", metadata: { ceremonyRef: hashAuditIdentifier(ceremony) } });
  }
  return NextResponse.redirect(errorUrl, { status: 303 });
}

function sessionResponse(session: { token: string; expiresAt: Date }, requestUrl: string) {
  const response = NextResponse.redirect(createHubRedirectUrl("/", requestUrl), { status: 303 });
  response.cookies.set(SESSION_COOKIE_NAME, session.token, getSessionCookieOptions(session.expiresAt));
  return response;
}

function read(formData: FormData, key: string): string {
  const value = formData.get(key);
  return typeof value === "string" ? value.trim() : "";
}
