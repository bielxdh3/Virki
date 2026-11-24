import type { ServerResponse } from "node:http";

const PUBLIC_CORS_ROUTES = new Set(["discovery", "jwks", "openid_credential_issuer"]);
const CLIENT_CORS_ROUTES = new Set([
  "userinfo", "token", "revocation", "introspection", "device_authorization",
  "pushed_authorization_request", "credential", "challenge"
]);

type IssuerCorsContext = {
  method: string;
  oidc?: { route?: string; client?: unknown };
  response: {
    headerSent: boolean;
    remove(name: string): unknown;
  };
  res: {
    setHeader(name: string, value: string): unknown;
    removeHeader(name: string): unknown;
  };
};

/**
 * oidc-provider intentionally enables CORS for public discovery/JWKS resources.
 * Use a wildcard there (without credentials), and never reflect an Origin on
 * client-bound error responses when no client was authenticated/assigned.
 */
export async function issuerCorsResponsePolicyMiddleware(
  context: IssuerCorsContext,
  next: () => Promise<unknown>
): Promise<void> {
  // Clear credentials before any provider route can end the response directly.
  context.response.remove("Access-Control-Allow-Credentials");
  try {
    await next();
  } finally {
    // Koa's response.remove() is guarded once headers have been sent. Some
    // interaction paths call res.end() directly instead of returning a body.
    if (!context.response.headerSent) {
      const route = context.oidc?.route?.replace(/^cors\./u, "") ?? "";
      if (PUBLIC_CORS_ROUTES.has(route)) {
        context.res.setHeader("Access-Control-Allow-Origin", "*");
      } else if (context.method !== "OPTIONS" && CLIENT_CORS_ROUTES.has(route) && !context.oidc?.client) {
        context.response.remove("Access-Control-Allow-Origin");
      }
      context.response.remove("Access-Control-Allow-Credentials");
    }
  }
}

/**
 * Issuer responses are JSON, redirects and the oidc-provider default HTML pages (error, logout confirmation,
 * post-logout success). Those pages carry one inline <style> block and no scripts, so style-src needs
 * 'unsafe-inline' and script-src stays closed (default-src 'none').
 * oidc-provider always supports response_mode=form_post: on /auth* it renders an auto-submitting form to the
 * relying party's registered redirect URI. The provider adds that inline script's hash to an existing script-src,
 * so /auth* starts with script-src 'none' (leaving only the appended hash permitted) and omits form-action (the post
 * targets the external redirect URI).
 * The logout confirmation form posts to /session/end/confirm and the provider answers with a 303 to the relying
 * party's post_logout_redirect_uri. Chromium enforces form-action on that redirect, so form-action is omitted for
 * /session/end*; everywhere else it is 'self'.
 */
export function issuerContentSecurityPolicy(pathname: string): string {
  const authorization = isAuthorizationPath(pathname);
  // oidc-provider appends the exact form_post inline-script hash to an existing
  // script-src directive. Start from 'none' so that hash is the only permitted
  // script source; 'self' would unnecessarily allow every same-origin script.
  const directives = ["default-src 'none'", ...(authorization ? ["script-src 'none'"] : []), "style-src 'unsafe-inline'", "base-uri 'none'"];
  if (!isLogoutPath(pathname) && !authorization) directives.push("form-action 'self'");
  directives.push("frame-ancestors 'none'");
  return directives.join("; ");
}

function isAuthorizationPath(pathname: string): boolean {
  return pathname === "/auth" || pathname.startsWith("/auth/");
}

function isLogoutPath(pathname: string): boolean {
  return pathname === "/session/end" || pathname.startsWith("/session/end/");
}

function requestPathname(response: ServerResponse): string {
  try {
    return new URL(response.req?.url ?? "/", "http://issuer.invalid").pathname;
  } catch {
    return "/";
  }
}

export function setIssuerSecurityHeaders(response: ServerResponse, production = process.env.NODE_ENV === "production"): void {
  response.setHeader("Content-Security-Policy", issuerContentSecurityPolicy(requestPathname(response)));
  response.setHeader("Permissions-Policy", "camera=(), geolocation=(), microphone=()");
  response.setHeader("Referrer-Policy", "no-referrer");
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("X-Frame-Options", "DENY");
  if (production) response.setHeader("Strict-Transport-Security", "max-age=31536000");
}

export function setIssuerSensitiveResponseCachePolicy(
  response: Pick<ServerResponse, "setHeader">,
  pathname: string
): void {
  if (
    // OIDC authorization, resume and logout have subpaths that may carry a
    // provider interaction or its redirect. Protect the entire reviewed
    // route family, not only the bare endpoint; otherwise sensitive responses
    // depend on oidc-provider supplying its own cache policy on every branch.
    isAuthorizationPath(pathname) ||
    isLogoutPath(pathname) ||
    /^\/resume\/[A-Za-z0-9_-]{8,160}$/u.test(pathname) ||
    pathname === "/token" ||
    pathname === "/token/revocation" ||
    pathname === "/me" ||
    /^\/interaction\/[A-Za-z0-9_-]{8,160}$/u.test(pathname)
  ) {
    response.setHeader("Cache-Control", "no-store");
  }
  // RFC 6749 §5.1 requires both headers on token responses. oidc-provider
  // supplies Cache-Control: no-store, but does not add the legacy Pragma field.
  if (pathname === "/token") response.setHeader("Pragma", "no-cache");
}

export async function issuerSensitiveResponseCachePolicyMiddleware(
  context: { path: string; res: ServerResponse },
  next: () => Promise<unknown>
): Promise<void> {
  setIssuerSensitiveResponseCachePolicy(context.res, context.path);
  await next();
}
