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
import { isCloudflareAccessAllowed, validateHubCloudflareAccess } from "../../../lib/cloudflare-access";

export const dynamic = "force-dynamic";

export async function POST(request: NextRequest) {
  const accessResult = await validateHubCloudflareAccess(request.headers, "hub-logout-api");

  if (!isCloudflareAccessAllowed(accessResult)) {
    return new NextResponse("Forbidden", { status: 403 });
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

  const response = NextResponse.redirect(new URL("/login", request.url), { status: 303 });
  response.cookies.set(SESSION_COOKIE_NAME, "", getExpiredSessionCookieOptions());

  return response;
}
