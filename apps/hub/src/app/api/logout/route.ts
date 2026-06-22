import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";
import {
  getExpiredSessionCookieOptions,
  revokeSessionToken,
  SESSION_COOKIE_NAME
} from "@bielos/auth";

export const dynamic = "force-dynamic";

export async function POST(request: NextRequest) {
  const sessionToken = request.cookies.get(SESSION_COOKIE_NAME)?.value;

  if (sessionToken) {
    await revokeSessionToken(sessionToken);
  }

  const response = NextResponse.redirect(new URL("/login", request.url), { status: 303 });
  response.cookies.set(SESSION_COOKIE_NAME, "", getExpiredSessionCookieOptions());

  return response;
}
