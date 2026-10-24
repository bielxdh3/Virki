import { createECDH, timingSafeEqual } from "node:crypto";

export const DEFAULT_DEVELOPMENT_ISSUER = "https://portal.biel.dev.br";

export function readIssuer(env: NodeJS.ProcessEnv): string {
  const configured = env.VIRKI_OIDC_ISSUER?.trim();
  if (env.NODE_ENV === "production" && !configured) throw new Error("OIDC issuer URL is required in production.");
  const issuerUrl = new URL(configured || DEFAULT_DEVELOPMENT_ISSUER);
  if (issuerUrl.username || issuerUrl.password || issuerUrl.search || issuerUrl.hash || issuerUrl.pathname !== "/") throw new Error("OIDC issuer URL is invalid.");
  if (env.NODE_ENV === "production" && issuerUrl.protocol !== "https:") throw new Error("OIDC issuer requires HTTPS in production.");
  return issuerUrl.origin;
}

export function readSigningJwks(value: string | undefined): { keys: Array<Record<string, string>> } {
  if (!value) throw new Error("OIDC signing keys are unavailable.");
  let parsed: unknown;
  try { parsed = JSON.parse(value); }
  catch { throw new Error("OIDC signing keys are invalid."); }
  if (!parsed || typeof parsed !== "object" || !Array.isArray((parsed as { keys?: unknown }).keys)) throw new Error("OIDC signing keys are invalid.");
  const keys = (parsed as { keys: unknown[] }).keys;
  if (!keys.length || keys.some((key) => !isPrivateSigningKey(key))) throw new Error("OIDC requires private ES256 signing keys with unique key IDs.");
  const ids = keys.map((key) => (key as Record<string, string>).kid);
  if (new Set(ids).size !== ids.length) throw new Error("OIDC requires private ES256 signing keys with unique key IDs.");
  return { keys: keys as Array<Record<string, string>> };
}

function isPrivateSigningKey(value: unknown): boolean {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const key = value as Record<string, unknown>;
  if (key.kty !== "EC" || key.crv !== "P-256" || key.alg !== "ES256" || key.use !== "sig" ||
      typeof key.kid !== "string" || !/^[A-Za-z0-9._-]{1,128}$/u.test(key.kid) ||
      !isCanonicalP256Coordinate(key.d) || !isCanonicalP256Coordinate(key.x) || !isCanonicalP256Coordinate(key.y)) return false;
  try {
    const privateKey = createECDH("prime256v1");
    privateKey.setPrivateKey(Buffer.from(key.d, "base64url"));
    const publicPoint = privateKey.getPublicKey(undefined, "uncompressed");
    const configuredPoint = Buffer.concat([Buffer.from([4]), Buffer.from(key.x, "base64url"), Buffer.from(key.y, "base64url")]);
    return timingSafeEqual(publicPoint, configuredPoint);
  } catch { return false; }
}

function isCanonicalP256Coordinate(value: unknown): value is string {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{43}$/u.test(value)) return false;
  const decoded = Buffer.from(value, "base64url");
  return decoded.length === 32 && decoded.toString("base64url") === value;
}
