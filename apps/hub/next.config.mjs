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
  transpilePackages: ["@bielos/ui", "@bielos/types", "@bielos/auth", "@bielos/database"],
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
