import path from "node:path";
import { fileURLToPath } from "node:url";

const appDir = path.dirname(fileURLToPath(import.meta.url));
const workspaceRoot = path.resolve(appDir, "../..");

/** @type {import('next').NextConfig} */
const nextConfig = {
  experimental: {
    authInterrupts: true
  },
  outputFileTracingRoot: workspaceRoot,
  serverExternalPackages: ["@node-rs/argon2", "@prisma/client"],
  transpilePackages: ["@bielos/auth", "@bielos/database"],
  async headers() {
    const headers = [
      { key: "Content-Security-Policy", value: "frame-ancestors 'none'" },
      { key: "Permissions-Policy", value: "camera=(), geolocation=(), microphone=()" },
      { key: "Referrer-Policy", value: "no-referrer" },
      { key: "X-Content-Type-Options", value: "nosniff" },
      { key: "X-Frame-Options", value: "DENY" }
    ];
    if (process.env.NODE_ENV === "production") headers.push({ key: "Strict-Transport-Security", value: "max-age=31536000" });
    return [{ source: "/:path*", headers }];
  },
  async rewrites() {
    const issuer = process.env.BIELOS_OIDC_PROXY_URL ?? "http://oidc-issuer:3003";
    const portalHost = process.env.BIELOS_PORTAL_HOSTNAME ?? "portal.biel.dev.br";
    const paths = ["/.well-known/:path*", "/auth", "/auth/:uid", "/token", "/token/revocation", "/jwks", "/me", "/session/end", "/interaction/:path*", "/resume/:path*"];
    return paths.map((source) => ({ source, has: [{ type: "host", value: portalHost }], destination: `${issuer}${source}` }));
  },
  webpack: (config, { isServer }) => {
    if (isServer) {
      config.externals = [
        ...(Array.isArray(config.externals) ? config.externals : [config.externals].filter(Boolean)),
        {
          "@node-rs/argon2": "commonjs @node-rs/argon2"
        }
      ];
    }

    return config;
  }
};

export default nextConfig;
