import { NextResponse } from "next/server";
import {
  authenticateUser,
  createSession,
  getSessionCookieOptions,
  SESSION_COOKIE_NAME
} from "@bielos/auth";

export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  const formData = await request.formData();
  const email = String(formData.get("email") ?? "");
  const password = String(formData.get("password") ?? "");

  if (!email || !password) {
    return redirectToLogin(request, true);
  }

  const user = await authenticateUser(email, password);

  if (!user) {
    return redirectToLogin(request, true);
  }

  const session = await createSession(user.id);
  const response = NextResponse.redirect(new URL("/", request.url), { status: 303 });
  response.cookies.set(
    SESSION_COOKIE_NAME,
    session.token,
    getSessionCookieOptions(session.expiresAt)
  );

  return response;
}

function redirectToLogin(request: Request, failed: boolean) {
  const url = new URL("/login", request.url);

  if (failed) {
    url.searchParams.set("error", "1");
  }

  return NextResponse.redirect(url, { status: 303 });
}
