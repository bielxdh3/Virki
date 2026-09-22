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
  async rewrites() {
    const issuer = process.env.BIELOS_OIDC_PROXY_URL ?? "http://oidc-issuer:3003";
    const portalHost = process.env.BIELOS_PORTAL_HOSTNAME ?? "portal.biel.dev.br";
    const paths = ["/.well-known/:path*", "/auth", "/token", "/token/revocation", "/jwks", "/me", "/session/end", "/interaction/:path*", "/resume/:path*"];
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
