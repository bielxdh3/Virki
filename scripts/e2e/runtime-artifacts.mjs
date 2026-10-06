import { existsSync } from "node:fs";
import { basename, isAbsolute, join, relative, resolve, sep } from "node:path";
import { tmpdir } from "node:os";

const artifactPaths = [
  ["BIELOS_E2E_TLS_KEY_PATH", "server-key.pem"],
  ["BIELOS_E2E_TLS_CERTIFICATE_PATH", "server-cert.pem"],
  ["BIELOS_E2E_TLS_CA_CERTIFICATE_PATH", "test-ca-cert.pem"],
  ["BIELOS_E2E_ACCESS_SIGNING_KEY_FILE", "access-signing-key.json"],
  ["BIELOS_E2E_OIDC_PRIVATE_CONFIG_FILE", "issuer-config.json"]
];

export function reuseE2eRuntimeDirectory(env = process.env) {
  if (env.BIELOS_E2E_RUNTIME_READY !== "true") return undefined;

  const directory = env.BIELOS_E2E_RUNTIME_DIRECTORY;
  if (!directory || !isAbsolute(directory)) return undefined;

  const resolvedDirectory = resolve(directory);
  if (resolvedDirectory !== directory || !basename(directory).startsWith("bielos-e2e-tls-")) return undefined;

  const relativeDirectory = relative(resolve(tmpdir()), resolvedDirectory);
  if (relativeDirectory === ".." || relativeDirectory.startsWith(`..${sep}`) || isAbsolute(relativeDirectory)) return undefined;

  if (artifactPaths.some(([variable, name]) => env[variable] !== join(directory, name))) return undefined;
  if (["server-key.pem", "server-cert.pem", "test-ca-cert.pem", "access-signing-key.json"].some((name) => !existsSync(join(directory, name)))) return undefined;

  return directory;
}

export function reuseE2eEmailOutboxKey(env = process.env) {
  return env.BIELOS_E2E_RUNTIME_READY === "true" ? env.BIELOS_EMAIL_OUTBOX_KEY : undefined;
}
