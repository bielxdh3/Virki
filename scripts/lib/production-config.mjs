import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = path.resolve(fileURLToPath(new URL("../..", import.meta.url)));
const privateConfigPath = path.join(repositoryRoot, ".production.operator.json");

export function readProductionConfig({ env = process.env, configPath = privateConfigPath } = {}) {
  let fileConfig = {};
  if (existsSync(configPath)) {
    try {
      fileConfig = JSON.parse(readFileSync(configPath, "utf8"));
    } catch {
      return {};
    }
  }

  return {
    sshAlias: env.BIELOS_PRODUCTION_SSH_ALIAS ?? fileConfig.sshAlias ?? "",
    host: env.BIELOS_PRODUCTION_HOST ?? fileConfig.host ?? "",
    port: env.BIELOS_PRODUCTION_PORT ?? fileConfig.port ?? "",
    root: env.BIELOS_PRODUCTION_ROOT ?? fileConfig.root ?? "",
  };
}

export function isValidProductionConfig(config) {
  if (!config || typeof config !== "object") return false;
  const port = Number(config.port);
  return (
    typeof config.sshAlias === "string" && /^(?!-)[A-Za-z0-9_.-]{1,128}$/u.test(config.sshAlias) &&
    typeof config.host === "string" && /^[A-Za-z0-9.-]{1,253}$/u.test(config.host) &&
    Number.isInteger(port) && port >= 1 && port <= 65535 &&
    typeof config.root === "string" &&
    /^\/(?:[A-Za-z0-9_.-]+\/)*[A-Za-z0-9_.-]+$/u.test(config.root) &&
    !config.root.split("/").some((segment) => segment === "." || segment === "..")
  );
}
