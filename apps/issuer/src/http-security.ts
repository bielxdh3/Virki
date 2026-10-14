import type { ServerResponse } from "node:http";

/**
 * Issuer responses are JSON, redirects and the oidc-provider default HTML pages (error, logout confirmation,
 * post-logout success). Those pages carry one inline <style> block and no scripts, so style-src needs
 * 'unsafe-inline' and script-src stays closed (default-src 'none').
 * oidc-provider always supports response_mode=form_post: on /auth* it renders an auto-submitting form to the
 * relying party's registered redirect URI. The provider adds that inline script's hash to an existing script-src,
 * so /auth* declares script-src 'self' and omits form-action (the post targets the external redirect URI).
 * The logout confirmation form posts to /session/end/confirm and the provider answers with a 303 to the relying
 * party's post_logout_redirect_uri. Chromium enforces form-action on that redirect, so form-action is omitted for
 * /session/end*; everywhere else it is 'self'.
 */
export function issuerContentSecurityPolicy(pathname: string): string {
  const authorization = isAuthorizationPath(pathname);
  const directives = ["default-src 'none'", ...(authorization ? ["script-src 'self'"] : []), "style-src 'unsafe-inline'", "base-uri 'none'"];
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
  if (pathname === "/auth" || /^\/interaction\/[A-Za-z0-9_-]{8,80}$/u.test(pathname)) {
    response.setHeader("Cache-Control", "no-store");
  }
}
