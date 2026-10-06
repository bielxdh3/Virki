import type { ServerResponse } from "node:http";

export function setIssuerSecurityHeaders(response: ServerResponse, production = process.env.NODE_ENV === "production"): void {
  response.setHeader("Content-Security-Policy", "frame-ancestors 'none'");
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
