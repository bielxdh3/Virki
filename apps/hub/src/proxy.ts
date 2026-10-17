import { NextResponse, type NextRequest } from "next/server";
import { SESSION_COOKIE_NAME } from "@virki/auth/constants";
import { validateCloudflareAccessJwt } from "@virki/auth/cloudflare-access";
import { getSurface, getSurfaceBaseUrl, safeReturnTo, TRUSTED_REQUEST_PATH_HEADER } from "./lib/surface";

const PROTECTED_CACHE_CONTROL = "private, no-store, max-age=0, must-revalidate";
const PUBLIC_ROUTES = new Set([
  "/login",
  "/api/login",
  "/login/verify",
  "/api/login/verify",
  "/api/logout",
  "/api/health",
  "/recover",
  "/recover/open"
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

/**
 * Per-request nonce CSP (https://nextjs.org/docs/app/guides/content-security-policy).
 * `form-action` is omitted for the portal login/verify pages: those forms post to same-origin routes that 303 to
 * `/auth/<uid>`, which the issuer 303s to the external relying-party redirect URI, and Chromium enforces
 * `form-action` on every redirect hop of a form submission.
 */
export function buildContentSecurityPolicy(nonce: string, env: Readonly<Record<string, string | undefined>>, options: { allowExternalFormRedirect?: boolean } = {}): string {
  const directives = [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${env.NODE_ENV === "development" ? " 'unsafe-eval'" : ""}`,
    `style-src 'self' 'nonce-${nonce}'`,
    "img-src 'self' data:",
    "font-src 'self'",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'none'"
  ];
  if (!options.allowExternalFormRedirect) directives.push("form-action 'self'");
  directives.push("frame-ancestors 'none'");
  if (env.NODE_ENV === "production") directives.push("upgrade-insecure-requests");
  return directives.join("; ");
}

function createNonce(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

export async function proxy(request: NextRequest) {
  return evaluateProxyRequest(request, process.env);
}

export async function evaluateProxyRequest(request: NextRequest, env: Readonly<Record<string, string | undefined>>) {
  const nonce = createNonce();
  const surface = getSurface(request.headers, env as NodeJS.ProcessEnv);
  const pathname = normalizePath(request.nextUrl.pathname);
  const csp = buildContentSecurityPolicy(nonce, env, { allowExternalFormRedirect: surface === "portal" && (pathname === "/login" || pathname === "/login/verify") });
  const withCsp = <T extends NextResponse>(response: T): T => {
    response.headers.set("Content-Security-Policy", csp);
    return response;
  };
  // Never trust client-supplied internal headers; only values set below reach the app.
  const forwardedHeaders = new Headers(request.headers);
  forwardedHeaders.delete(TRUSTED_REQUEST_PATH_HEADER);
  forwardedHeaders.delete("x-nonce");
  forwardedHeaders.set("x-nonce", nonce);
  forwardedHeaders.set("Content-Security-Policy", csp);

  if (surface === "unknown") return withCsp(new NextResponse("Not found", { status: 404, headers: { "Cache-Control": "no-store" } }));
  // Loopback/Compose host names never pass through Cloudflare Access; in production they only serve the health probe.
  if (surface === "local" && env.NODE_ENV === "production" && pathname !== "/api/health") return withCsp(new NextResponse("Not found", { status: 404, headers: { "Cache-Control": "no-store" } }));

  if (surface === "hub" && pathname !== "/api/health") {
    const access = await validateCloudflareAccessJwt(request.headers, env as NodeJS.ProcessEnv);
    if (!access.allowed) {
      const headers = new Headers({ "Cache-Control": "no-store" });
      if (env.NODE_ENV === "development" && env.VIRKI_E2E_ACCESS_DIAGNOSTICS === "true" && access.reason) {
        headers.set("x-virki-e2e-access-reason", access.reason);
        const kid = readE2eAccessKeyId(request.headers.get("cf-access-jwt-assertion"));
        if (kid) headers.set("x-virki-e2e-access-kid", kid);
      }
      return withCsp(new NextResponse("Forbidden", { status: 403, headers }));
    }
  }

  if (isPublicPath(pathname, surface)) {
    const response = NextResponse.next({ request: { headers: forwardedHeaders } });
    // Issuer-proxied OIDC paths are answered by the issuer, which sets its own (single) Content-Security-Policy.
    if (!isIssuerProxiedPath(pathname, surface)) response.headers.set("Content-Security-Policy", csp);
    return response;
  }

  if (!request.cookies.get(SESSION_COOKIE_NAME)?.value) {
    const requestedPath = safeReturnTo(`${pathname}${request.nextUrl.search}`, surface);
    const destination = loginUrl(request, surface, env, requestedPath);
    if (!destination) return withCsp(new NextResponse("Service Unavailable", { status: 503, headers: { "Cache-Control": "no-store" } }));
    const response = withCsp(NextResponse.redirect(destination));
    response.headers.set("Cache-Control", "no-store");
    return response;
  }

  forwardedHeaders.set(TRUSTED_REQUEST_PATH_HEADER, `${pathname}${request.nextUrl.search}`.slice(0, 2048));
  const response = withCsp(NextResponse.next({ request: { headers: forwardedHeaders } }));
  response.headers.set("Cache-Control", PROTECTED_CACHE_CONTROL);
  return response;
}

function readE2eAccessKeyId(token: string | null): string | undefined {
  const encodedHeader = token?.split(".", 1)[0];
  if (!encodedHeader) return undefined;
  try {
    const base64 = encodedHeader.replace(/-/gu, "+").replace(/_/gu, "/").padEnd(Math.ceil(encodedHeader.length / 4) * 4, "=");
    const header: unknown = JSON.parse(atob(base64));
    if (!header || typeof header !== "object" || !("kid" in header) || typeof header.kid !== "string" || !/^[A-Za-z0-9._-]{1,64}$/u.test(header.kid)) return undefined;
    return header.kid;
  } catch {
    return undefined;
  }
}

function loginUrl(request: NextRequest, surface: "hub" | "portal" | "local", env: Readonly<Record<string, string | undefined>>, returnTo: string | null) {
  const base = getSurfaceBaseUrl(request.headers, request.url, env as NodeJS.ProcessEnv);
  if (!base) return null;
  base.pathname = "/login";
  base.search = "";
  base.hash = "";
  if (returnTo) base.searchParams.set("returnTo", returnTo);
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
  if (surface !== "hub" && /^\/auth\/[A-Za-z0-9_-]{8,160}$/u.test(pathname)) return true;
  return surface !== "hub" && OIDC_ROOT_ROUTES.has(pathname);
}

function isIssuerProxiedPath(pathname: string, surface: "hub" | "portal" | "local"): boolean {
  if (surface !== "portal") return false;
  return pathname.startsWith("/.well-known/") || pathname.startsWith("/interaction/") || pathname.startsWith("/resume/") || pathname.startsWith("/auth/") || OIDC_ROOT_ROUTES.has(pathname);
}

function normalizePath(pathname: string): string {
  return pathname.length > 1 && pathname.endsWith("/") ? pathname.slice(0, -1) : pathname;
}

export const config = { matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"] };
