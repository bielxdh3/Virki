import path from "node:path";
import { fileURLToPath } from "node:url";

const appDir = path.dirname(fileURLToPath(import.meta.url));
const workspaceRoot = path.resolve(appDir, "../..");

/** @type {import('next').NextConfig} */
const nextConfig = {
  experimental: {
    authInterrupts: true,
    // Keep the framework's existing raw Server Action body cap explicit.
    serverActions: { bodySizeLimit: "1mb" }
  },
  outputFileTracingRoot: workspaceRoot,
  serverExternalPackages: ["@node-rs/argon2", "@prisma/client"],
  transpilePackages: ["@virki/auth", "@virki/database"],
  // Content-Security-Policy is set per request (with a nonce) by src/proxy.ts; do not add a second one here.
  async headers() {
    const headers = [
      { key: "Permissions-Policy", value: "camera=(), geolocation=(), microphone=()" },
      { key: "Referrer-Policy", value: "strict-origin" },
      { key: "X-Content-Type-Options", value: "nosniff" },
      { key: "X-Frame-Options", value: "DENY" }
    ];
    if (process.env.NODE_ENV === "production") headers.push({ key: "Strict-Transport-Security", value: "max-age=31536000" });
    return [{ source: "/:path*", headers }];
  },
  async rewrites() {
    const issuer = process.env.VIRKI_OIDC_PROXY_URL ?? "http://oidc-issuer:3003";
    const portalHost = process.env.VIRKI_PORTAL_HOSTNAME ?? "portal.biel.dev.br";
    const paths = ["/.well-known/:path*", "/auth", "/auth/:uid", "/token", "/token/revocation", "/jwks", "/me", "/session/end", "/session/end/:path*", "/interaction/:path*", "/resume/:path*"];
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
