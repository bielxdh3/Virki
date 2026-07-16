import { NextResponse, type NextRequest } from "next/server";
import { SESSION_COOKIE_NAME } from "@bielos/auth/constants";
import { createHubRedirectUrl } from "./lib/hub-redirect";

const PUBLIC_ROUTES = new Set(["/login", "/api/login", "/api/logout", "/api/health"]);
const PUBLIC_FILE_PATTERN = /\.(?:ico|png|jpg|jpeg|gif|svg|webp|css|js|map|txt|xml)$/i;

export function proxy(
  request: NextRequest,
  env: Readonly<Record<string, string | undefined>> = process.env
) {
  const { pathname } = request.nextUrl;

  if (isPublicPath(pathname)) {
    return NextResponse.next();
  }

  const hasSessionCookie = Boolean(request.cookies.get(SESSION_COOKIE_NAME)?.value);

  if (!hasSessionCookie) {
    try {
      return NextResponse.redirect(createHubRedirectUrl("/login", request.url, env));
    } catch {
      return new NextResponse("Service unavailable", { status: 503 });
    }
  }

  return NextResponse.next();
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"]
};

function isPublicPath(pathname: string): boolean {
  const normalizedPathname =
    pathname.length > 1 && pathname.endsWith("/") ? pathname.slice(0, -1) : pathname;

  return (
    PUBLIC_ROUTES.has(normalizedPathname) ||
    normalizedPathname.startsWith("/_next/") ||
    PUBLIC_FILE_PATTERN.test(normalizedPathname)
  );
}
