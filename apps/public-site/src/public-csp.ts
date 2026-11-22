export function buildPublicContentSecurityPolicy(nodeEnv: string | undefined, nonce: string): string {
  return [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}'${nodeEnv === "development" ? " 'unsafe-eval'" : ""}`,
    // Custom not-found page uses the same external stylesheet as the landing
    // page. No framework fallback inline styles need an unsafe-inline escape.
    "style-src 'self'",
    "img-src 'self' data:",
    "font-src 'self'",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'",
    ...(nodeEnv === "production" ? ["upgrade-insecure-requests"] : [])
  ].join("; ");
}
