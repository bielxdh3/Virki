import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";
import {
  getExpiredSessionCookieOptions,
  getSessionByToken,
  revokeSessionToken,
  SESSION_COOKIE_NAME,
  createAuditRequestMetadata,
  hashAuditEmail,
  writeAuditLog
} from "@bielos/auth";
import { CSRF_FORM_FIELD_NAME, validateCsrfToken } from "@bielos/auth/csrf";
import { isCloudflareAccessAllowed, validateHubCloudflareAccess } from "../../../lib/cloudflare-access";
import { createHubRedirectUrl } from "../../../lib/hub-redirect";

export const dynamic = "force-dynamic";

export async function POST(request: NextRequest) {
  const accessResult = await validateHubCloudflareAccess(request.headers, "hub-logout-api");

  if (!isCloudflareAccessAllowed(accessResult)) {
    return new NextResponse("Forbidden", { status: 403 });
  }

  const formData = await request.formData();
  const csrfResult = validateCsrfToken(getFormString(formData, CSRF_FORM_FIELD_NAME));

  if (!csrfResult.valid) {
    return new NextResponse("Forbidden", { status: 403 });
  }

  let redirectUrl: URL | undefined;

  try {
    redirectUrl = createHubRedirectUrl("/login", request.url);
  } catch {
    redirectUrl = undefined;
  }

  const sessionToken = request.cookies.get(SESSION_COOKIE_NAME)?.value;
  const currentSession = sessionToken ? await getSessionByToken(sessionToken) : null;

  if (sessionToken && currentSession) {
    const revokedCount = await revokeSessionToken(sessionToken);
    const metadata = {
      ...createAuditRequestMetadata(request.headers, "logout-route"),
      revokedCount
    };

    await writeAuditLog({
      eventType: "AUTH_LOGOUT",
      result: "SUCCESS",
      actorUserId: currentSession.user.id,
      actorEmailHash: hashAuditEmail(currentSession.user.email),
      resource: "hub",
      message: "User logged out.",
      metadata
    });

    if (revokedCount > 0) {
      await writeAuditLog({
        eventType: "AUTH_SESSION_REVOKED",
        result: "SUCCESS",
        actorUserId: currentSession.user.id,
        actorEmailHash: hashAuditEmail(currentSession.user.email),
        resource: "session",
        message: "Session revoked.",
        metadata
      });
    }
  }

  const response = redirectUrl
    ? NextResponse.redirect(redirectUrl, { status: 303 })
    : new NextResponse("Service unavailable", { status: 503 });
  response.cookies.set(SESSION_COOKIE_NAME, "", getExpiredSessionCookieOptions());

  return response;
}

function getFormString(formData: FormData, key: string): string {
  const value = formData.get(key);
  return typeof value === "string" ? value : "";
}
