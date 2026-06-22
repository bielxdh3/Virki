import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";
import {
  getExpiredSessionCookieOptions,
  getSessionByToken,
  revokeSessionToken,
  SESSION_COOKIE_NAME
} from "@bielos/auth";

export const dynamic = "force-dynamic";

export async function POST(request: NextRequest) {
  const sessionToken = request.cookies.get(SESSION_COOKIE_NAME)?.value;
  const currentSession = sessionToken ? await getSessionByToken(sessionToken) : null;

  if (sessionToken && currentSession) {
    await revokeSessionToken(sessionToken);
  }

  const response = NextResponse.redirect(new URL("/login", request.url), { status: 303 });
  response.cookies.set(SESSION_COOKIE_NAME, "", getExpiredSessionCookieOptions());

  return response;
}
