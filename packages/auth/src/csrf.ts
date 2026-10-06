import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";

export const CSRF_FORM_FIELD_NAME = "csrfToken";
export const CSRF_TOKEN_TTL_MS = 2 * 60 * 60 * 1000;

const CSRF_TOKEN_VERSION = "v2";
const CSRF_NONCE_BYTES = 24;
const CSRF_SECRET_BYTES = 32;
const CSRF_CLOCK_SKEW_MS = 30_000;

const globalForCsrf = globalThis as unknown as {
  bielosCsrfSecret?: Buffer;
};

export type CsrfValidationResult =
  | { valid: true }
  | { valid: false; reason: "missing" | "malformed" | "expired" | "invalid" | "wrong-scope" | "misconfigured" };

export type CsrfTokenOptions = {
  now?: number;
  scope?: string;
  env?: NodeJS.ProcessEnv;
};

export function createCsrfToken(options: CsrfTokenOptions = {}): string {
  const now = options.now ?? Date.now();
  const scope = options.scope ?? "global";
  if (!Number.isSafeInteger(now) || !isValidScope(scope)) throw new Error("Invalid CSRF token input.");

  const keys = getCsrfKeys(options.env ?? process.env);
  if (!keys) throw new Error("CSRF signing key is unavailable.");
  const expiresAt = now + CSRF_TOKEN_TTL_MS;
  const nonce = randomBytes(CSRF_NONCE_BYTES).toString("base64url");
  const encodedScope = Buffer.from(scope, "utf8").toString("base64url");
  const keyId = getKeyId(keys.current);
  const payload = `${CSRF_TOKEN_VERSION}.${keyId}.${expiresAt}.${nonce}.${encodedScope}`;

  return `${payload}.${signCsrfPayload(payload, keys.current)}`;
}

export function validateCsrfToken(
  token: string | null | undefined,
  options: CsrfTokenOptions = {}
): CsrfValidationResult {
  if (!token) return { valid: false, reason: "missing" };
  if (token.length > 512) return { valid: false, reason: "malformed" };
  const scope = options.scope ?? "global";
  if (!isValidScope(scope)) return { valid: false, reason: "malformed" };

  const parts = token.split(".");
  if (parts.length !== 6 || parts[0] !== CSRF_TOKEN_VERSION) return { valid: false, reason: "malformed" };

  const [, keyId, expiresText, nonce, encodedScope, signature] = parts;
  if (!/^[a-f0-9]{64}$/u.test(keyId) || !/^[A-Za-z0-9_-]{32}$/u.test(nonce) || !/^[A-Za-z0-9_-]+$/u.test(encodedScope) || !/^[A-Za-z0-9_-]{43}$/u.test(signature)) {
    return { valid: false, reason: "malformed" };
  }
  const expiresAt = Number(expiresText);
  const now = options.now ?? Date.now();
  if (!Number.isSafeInteger(expiresAt) || !Number.isSafeInteger(now)) return { valid: false, reason: "malformed" };
  if (expiresAt <= now) return { valid: false, reason: "expired" };
  if (expiresAt - now > CSRF_TOKEN_TTL_MS + CSRF_CLOCK_SKEW_MS) return { valid: false, reason: "invalid" };

  let decodedScope: string;
  try {
    decodedScope = Buffer.from(encodedScope, "base64url").toString("utf8");
  } catch {
    return { valid: false, reason: "malformed" };
  }
  if (!isValidScope(decodedScope)) return { valid: false, reason: "malformed" };
  if (decodedScope !== scope) return { valid: false, reason: "wrong-scope" };

  const keys = getCsrfKeys(options.env ?? process.env);
  if (!keys) return { valid: false, reason: "misconfigured" };
  const key = [keys.current, ...(keys.previous ? [keys.previous] : [])].find((candidate) => getKeyId(candidate) === keyId);
  if (!key) return { valid: false, reason: "invalid" };

  const payload = parts.slice(0, 5).join(".");
  if (!safeEqual(signature, signCsrfPayload(payload, key))) return { valid: false, reason: "invalid" };
  return { valid: true };
}

function getCsrfKeys(env: NodeJS.ProcessEnv): { current: Buffer; previous?: Buffer } | null {
  const currentText = env.BIELOS_CSRF_SIGNING_KEY;
  const previousText = env.BIELOS_CSRF_SIGNING_KEY_PREVIOUS;
  const production = env.NODE_ENV === "production";
  if (currentText !== undefined || previousText !== undefined) {
    const current = parseSecret(currentText);
    const previous = previousText === undefined || previousText === "" ? undefined : parseSecret(previousText);
    if (!current || (previousText !== undefined && previousText !== "" && !previous)) return null;
    return { current, ...(previous ? { previous } : {}) };
  }
  if (production) return null;
  globalForCsrf.bielosCsrfSecret ??= randomBytes(CSRF_SECRET_BYTES);
  return { current: globalForCsrf.bielosCsrfSecret };
}

function parseSecret(value: string | undefined): Buffer | null {
  if (!value || !/^[a-f0-9]{64}$/iu.test(value)) return null;
  return Buffer.from(value, "hex");
}

function getKeyId(key: Buffer): string {
  return createHash("sha256").update("bielos-csrf-key-id\0").update(key).digest("hex");
}

function signCsrfPayload(payload: string, key: Buffer): string {
  return createHmac("sha256", key).update("bielos-csrf-token\0").update(payload, "utf8").digest("base64url");
}

function isValidScope(scope: string): boolean {
  return /^[a-z0-9][a-z0-9:._-]{0,63}$/u.test(scope);
}

function safeEqual(value: string, expectedValue: string): boolean {
  const valueBuffer = Buffer.from(value, "utf8");
  const expectedBuffer = Buffer.from(expectedValue, "utf8");
  return valueBuffer.length === expectedBuffer.length && timingSafeEqual(valueBuffer, expectedBuffer);
}
