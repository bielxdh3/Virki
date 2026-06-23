import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

export const CSRF_FORM_FIELD_NAME = "csrfToken";

const CSRF_TOKEN_VERSION = "v1";
const CSRF_TOKEN_TTL_MS = 2 * 60 * 60 * 1000;
const CSRF_NONCE_BYTES = 24;
const CSRF_SECRET_BYTES = 32;

const globalForCsrf = globalThis as unknown as {
  bielosCsrfSecret?: Buffer;
};

export type CsrfValidationResult =
  | { valid: true }
  | { valid: false; reason: "missing" | "malformed" | "expired" | "invalid" };

export function createCsrfToken(now = Date.now()): string {
  const expiresAt = now + CSRF_TOKEN_TTL_MS;
  const nonce = randomBytes(CSRF_NONCE_BYTES).toString("base64url");
  const payload = `${CSRF_TOKEN_VERSION}.${expiresAt}.${nonce}`;

  return `${payload}.${signCsrfPayload(payload)}`;
}

export function validateCsrfToken(
  token: string | null | undefined,
  now = Date.now()
): CsrfValidationResult {
  if (!token) {
    return { valid: false, reason: "missing" };
  }

  const parts = token.split(".");

  if (parts.length !== 4 || parts[0] !== CSRF_TOKEN_VERSION) {
    return { valid: false, reason: "malformed" };
  }

  const expiresAt = Number(parts[1]);

  if (!Number.isSafeInteger(expiresAt)) {
    return { valid: false, reason: "malformed" };
  }

  if (expiresAt <= now) {
    return { valid: false, reason: "expired" };
  }

  const payload = parts.slice(0, 3).join(".");
  const signature = parts[3];
  const expectedSignature = signCsrfPayload(payload);

  if (!safeEqual(signature, expectedSignature)) {
    return { valid: false, reason: "invalid" };
  }

  return { valid: true };
}

function signCsrfPayload(payload: string): string {
  return createHmac("sha256", getCsrfSecret()).update(payload, "utf8").digest("base64url");
}

function getCsrfSecret(): Buffer {
  globalForCsrf.bielosCsrfSecret ??= randomBytes(CSRF_SECRET_BYTES);
  return globalForCsrf.bielosCsrfSecret;
}

function safeEqual(value: string, expectedValue: string): boolean {
  const valueBuffer = Buffer.from(value, "utf8");
  const expectedBuffer = Buffer.from(expectedValue, "utf8");

  if (valueBuffer.length !== expectedBuffer.length) {
    return false;
  }

  return timingSafeEqual(valueBuffer, expectedBuffer);
}
