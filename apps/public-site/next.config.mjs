// The landing page is a single static-content route. Next.js emits inline bootstrap and flight-data <script>
// tags whose content changes per request, so without a per-request nonce (no proxy on this surface) hashes are
// impossible and script-src needs 'unsafe-inline'. Mitigations: nothing user-controlled is rendered, there are no
// forms, and every other directive is locked down. Inline styles are only emitted by the built-in 404 page.
export function buildPublicContentSecurityPolicy(nodeEnv = process.env.NODE_ENV) {
  return [
    "default-src 'self'",
    `script-src 'self' 'unsafe-inline'${nodeEnv === "development" ? " 'unsafe-eval'" : ""}`,
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

/** @type {import('next').NextConfig} */
const nextConfig = {
  transpilePackages: [],
  async headers() {
    const headers = [
      { key: "Content-Security-Policy", value: buildPublicContentSecurityPolicy() },
      { key: "Permissions-Policy", value: "camera=(), geolocation=(), microphone=()" },
      { key: "Referrer-Policy", value: "no-referrer" },
      { key: "X-Content-Type-Options", value: "nosniff" },
      { key: "X-Frame-Options", value: "DENY" }
    ];
    if (process.env.NODE_ENV === "production") headers.push({ key: "Strict-Transport-Security", value: "max-age=31536000" });
    return [{ source: "/:path*", headers }];
  }
};

export default nextConfig;
