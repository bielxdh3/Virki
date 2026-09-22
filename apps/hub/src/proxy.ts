import { NextResponse, type NextRequest } from "next/server";
import { SESSION_COOKIE_NAME } from "@bielos/auth/constants";
import { validateCloudflareAccessJwt } from "@bielos/auth/cloudflare-access";
import { getSurface } from "./lib/surface";

const PROTECTED_CACHE_CONTROL = "private, no-store, max-age=0, must-revalidate";
const PUBLIC_ROUTES = new Set([
  "/login",
  "/api/login",
  "/login/verify",
  "/api/login/verify",
  "/api/logout",
  "/api/health",
  "/recover",
  "/api/recover"
]);
const OIDC_ROOT_ROUTES = new Set([
  "/auth",
  "/token",
  "/jwks",
  "/session/end",
  "/me",
  "/token/revocation",
]);
const PUBLIC_FILE_PATTERN = /\.(?:ico|png|jpg|jpeg|gif|svg|webp|css|js|map|txt|xml|woff2?)$/iu;

export async function proxy(request: NextRequest) {
  return evaluateProxyRequest(request, process.env);
}

export async function evaluateProxyRequest(request: NextRequest, env: Readonly<Record<string, string | undefined>>) {
  const surface = getSurface(request.headers, env as NodeJS.ProcessEnv);
  const pathname = normalizePath(request.nextUrl.pathname);

  if (surface === "unknown") return new NextResponse("Not found", { status: 404, headers: { "Cache-Control": "no-store" } });

  if (surface === "hub" && pathname !== "/api/health" && env.CLOUDFLARE_ACCESS_JWT_REQUIRED === "true") {
    const access = await validateCloudflareAccessJwt(request.headers, env as NodeJS.ProcessEnv);
    if (!access.allowed) return new NextResponse("Forbidden", { status: 403, headers: { "Cache-Control": "no-store" } });
  }

  if (isPublicPath(pathname, surface)) return NextResponse.next();

  if (!request.cookies.get(SESSION_COOKIE_NAME)?.value) {
    const response = NextResponse.redirect(loginUrl(request, surface, env));
    response.headers.set("Cache-Control", "no-store");
    return response;
  }

  const response = NextResponse.next();
  response.headers.set("Cache-Control", PROTECTED_CACHE_CONTROL);
  return response;
}

function loginUrl(request: NextRequest, surface: "hub" | "portal" | "local", env: Readonly<Record<string, string | undefined>>) {
  const configured = surface === "hub" ? env.NEXT_PUBLIC_HUB_URL : env.NEXT_PUBLIC_PORTAL_URL;
  const base = configured ? new URL(configured) : new URL(request.url);
  base.pathname = "/login";
  base.search = "";
  base.hash = "";
  return base;
}

function isPublicPath(pathname: string, surface: "hub" | "portal" | "local"): boolean {
  if (
    PUBLIC_ROUTES.has(pathname) ||
    pathname.startsWith("/_next/") ||
    PUBLIC_FILE_PATTERN.test(pathname)
  ) return true;
  if (surface !== "hub" && (pathname.startsWith("/.well-known/") || pathname.startsWith("/interaction/"))) return true;
  if (surface !== "hub" && pathname.startsWith("/resume/")) return true;
  return surface !== "hub" && OIDC_ROOT_ROUTES.has(pathname);
}

function normalizePath(pathname: string): string {
  return pathname.length > 1 && pathname.endsWith("/") ? pathname.slice(0, -1) : pathname;
}

export const config = { matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"] };
