export function buildPublicContentSecurityPolicy(nodeEnv: string | undefined, nonce: string): string {
  return [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}'${nodeEnv === "development" ? " 'unsafe-eval'" : ""}`,
    // The framework's default not-found document still uses inline styles.
    "style-src 'self' 'unsafe-inline'",
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
