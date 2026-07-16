import { NextResponse, type NextRequest } from "next/server";
import { SESSION_COOKIE_NAME } from "@bielos/auth/constants";
import { createHubRedirectUrl } from "./lib/hub-redirect";

const PUBLIC_ROUTES = new Set(["/login", "/api/login", "/api/logout", "/api/health"]);
const PUBLIC_FILE_PATTERN = /\.(?:ico|png|jpg|jpeg|gif|svg|webp|css|js|map|txt|xml)$/i;
const CLOUDFLARE_ACCESS_JWT_HEADER = "cf-access-jwt-assertion";

export function proxy(request: NextRequest) {
  return evaluateProxyRequest(request, process.env);
}

export function evaluateProxyRequest(
  request: NextRequest,
  env: Readonly<Record<string, string | undefined>>
) {
  const { pathname } = request.nextUrl;

  if (isPublicPath(pathname)) {
    return NextResponse.next();
  }

  if (
    env.CLOUDFLARE_ACCESS_JWT_REQUIRED === "true" &&
    !request.headers.get(CLOUDFLARE_ACCESS_JWT_HEADER)
  ) {
    return new NextResponse("Forbidden", { status: 403 });
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
