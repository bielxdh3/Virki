export function buildPublicContentSecurityPolicy(nodeEnv: string | undefined, nonce: string): string {
  return [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}'${nodeEnv === "development" ? " 'unsafe-eval'" : ""}`,
    // The production 404 uses the external stylesheet and never needs inline
    // styles. Next's *development-only* overlay injects unnonced style tags;
    // keep its exception strictly outside production and unknown environments.
    `style-src 'self'${nodeEnv === "development" ? " 'unsafe-inline'" : ""}`,
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
