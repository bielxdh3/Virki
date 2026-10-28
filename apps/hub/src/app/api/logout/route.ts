import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";
import {
  getExpiredSessionCookieOptions,
  hashSessionToken,
  hashAuditSessionReference,
  getSessionByToken,
  revokeSessionToken,
  SESSION_COOKIE_NAME,
  createAuditRequestMetadata,
  hashAuditEmail,
  writeAuditLog
} from "@virki/auth";
import { CSRF_FORM_FIELD_NAME, validateCsrfToken } from "@virki/auth/csrf";

import { isCloudflareAccessAllowed, validateHubCloudflareAccess } from "../../../lib/cloudflare-access";
import { getSurface, getSurfaceBaseUrl, hasSameOrigin, requestHost } from "../../../lib/surface";
import { readBoundedFormData } from "../../../lib/request-form";
import { recordSecurityDenial, recordSessionCsrfDenial } from "../../../lib/audit-denial";

export const dynamic = "force-dynamic";

export async function POST(request: NextRequest) {
  const surface = getSurface(request.headers);
  if (surface === "unknown") return new NextResponse("Not found", { status: 404 });
  if (surface === "hub" && !isCloudflareAccessAllowed(await validateHubCloudflareAccess(request.headers, "admin-logout-api"))) {
    return new NextResponse("Forbidden", { status: 403 });
  }
  if (!hasSameOrigin(request.headers)) { await recordSecurityDenial(request.headers, "logout-origin", "csrf"); return new NextResponse("Forbidden", { status: 403 }); }

  const formData = await readBoundedFormData(request, 8 * 1024);
  if (!formData) return new NextResponse("Bad Request", { status: 400 });
  const sessionToken = request.cookies.get(SESSION_COOKIE_NAME)?.value;
  // With a session cookie the token must be bound to that session. Without one (e.g. the session already
  // expired) an unbound "logout" token is accepted so the user can still clear stale cookies; nothing to revoke.
  const csrfResult = validateCsrfToken(getFormString(formData, CSRF_FORM_FIELD_NAME), {
    scope: "logout",
    ...(sessionToken ? { binding: hashSessionToken(sessionToken) } : {})
  });

  if (!csrfResult.valid) {
    await recordSessionCsrfDenial(request.headers, "logout-csrf", sessionToken);
    return new NextResponse("Forbidden", { status: 403 });
  }

  const currentSession = sessionToken ? await getSessionByToken(sessionToken) : null;

  if (sessionToken && currentSession) {
    const revokedCount = await revokeSessionToken(sessionToken);
    const metadata = {
      ...createAuditRequestMetadata(request.headers, `${surface}-logout-route`),
      revokedCount
    };

    await writeAuditLog({
      eventType: "AUTH_LOGOUT",
      result: "SUCCESS",
      actorUserId: currentSession.user.id,
      actorRole: currentSession.user.role === "ADMIN" ? "ADMIN" : currentSession.user.role === "USER" ? "USER" : undefined,
      sessionRef: hashAuditSessionReference(currentSession.id),
      actorEmailHash: hashAuditEmail(currentSession.user.email),
      resource: surface,
      message: "User logged out.",
      metadata
    });

    if (revokedCount > 0) {
      await writeAuditLog({
        eventType: "AUTH_SESSION_REVOKED",
        result: "SUCCESS",
        actorUserId: currentSession.user.id,
        actorRole: currentSession.user.role === "ADMIN" ? "ADMIN" : currentSession.user.role === "USER" ? "USER" : undefined,
        sessionRef: hashAuditSessionReference(currentSession.id),
        actorEmailHash: hashAuditEmail(currentSession.user.email),
        resource: "session",
        message: "Session revoked.",
        metadata
      });
    }
  }

  let redirectUrl: URL;
  try {
    const configuredBaseUrl = surface === "hub"
      ? process.env.VIRKI_HUB_URL
      : surface === "portal"
        ? process.env.VIRKI_PORTAL_URL
        : undefined;
    const redirectBase = getSurfaceBaseUrl(request.headers, request.url);
    if (!redirectBase) throw new Error("Logout redirect origin is unavailable.");
    const fallbackHost = requestHost(request.headers);
    const redirectHost = redirectBase.hostname.toLowerCase().replace(/\.$/u, "");
    if (process.env.NODE_ENV === "production" && (
      surface === "local" ||
      redirectBase.protocol !== "https:" ||
      (!configuredBaseUrl && redirectHost !== fallbackHost)
    )) throw new Error("Logout redirect origin is unavailable.");
    redirectUrl = new URL("/login", redirectBase);
  } catch {
    const response = new NextResponse("Logout completed; redirect unavailable.", {
      status: 503,
      headers: { "Cache-Control": "no-store" }
    });
    response.cookies.set(SESSION_COOKIE_NAME, "", getExpiredSessionCookieOptions());
    return response;
  }

  const response = NextResponse.redirect(redirectUrl, { status: 303 });
  response.headers.set("Cache-Control", "no-store");
  response.cookies.set(SESSION_COOKIE_NAME, "", getExpiredSessionCookieOptions());

  return response;
}

function getFormString(formData: FormData, key: string): string {
  const value = formData.get(key);
  return typeof value === "string" ? value : "";
}
