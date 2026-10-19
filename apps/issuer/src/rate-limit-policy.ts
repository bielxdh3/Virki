import { createHash } from "node:crypto";

export const OIDC_RATE_LIMIT_RETRY_AFTER_SECONDS = 900;
export const OIDC_AUTH_SOURCE_CEILING = 300;
export const OIDC_AUTH_BUCKET_LIMIT = 30;
export const OIDC_TOKEN_LIMIT = 600;

export type RateLimitCheck = { identifier: string; maxAttempts: number };

/** Ceiling first, then the bucket. The cookie only selects a bucket; it is never trusted for authentication. */
export function selectAuthRateLimits(clientAddress: string, sessionCookieValue: string | null): RateLimitCheck[] {
  const bucket = sessionCookieValue
    ? `oidc-auth-browser:${createHash("sha256").update(sessionCookieValue).digest("hex")}`
    : `oidc-source:${clientAddress}`;
  return [
    { identifier: `oidc-auth-source:${clientAddress}`, maxAttempts: OIDC_AUTH_SOURCE_CEILING },
    { identifier: bucket, maxAttempts: OIDC_AUTH_BUCKET_LIMIT }
  ];
}

export function isInteractionPath(path: string): boolean {
  return /^\/interaction\/[A-Za-z0-9_-]{8,80}$/u.test(path);
}

export function selectInteractionRateLimits(clientAddress: string, sessionCookieValue: string | null): RateLimitCheck[] {
  const bucket = sessionCookieValue
    ? `oidc-interaction-browser:${createHash("sha256").update(sessionCookieValue).digest("hex")}`
    : `oidc-interaction-anonymous:${clientAddress}`;
  return [
    { identifier: `oidc-interaction-source:${clientAddress}`, maxAttempts: OIDC_AUTH_SOURCE_CEILING },
    { identifier: bucket, maxAttempts: OIDC_AUTH_BUCKET_LIMIT }
  ];
}

export function selectRateLimitAudit(clientAddress: string): RateLimitCheck {
  return { identifier: `oidc-rate-limit-audit:${clientAddress}`, maxAttempts: 1 };
}

const MAX_BASIC_HEADER_LENGTH = 2048;
const MAX_CLIENT_ID_LENGTH = 256;

export function parseBasicClientId(authorization: string | undefined): string {
  if (!authorization || authorization.length > MAX_BASIC_HEADER_LENGTH) return "invalid";
  const match = /^Basic ([A-Za-z0-9+/_-]+={0,2})$/iu.exec(authorization);
  if (!match) return "invalid";
  try {
    const decoded = Buffer.from(match[1], "base64").toString("utf8");
    const separator = decoded.indexOf(":");
    if (separator < 1) return "invalid";
    // RFC 6749 2.3.1: credentials are form-urlencoded before base64.
    const clientId = decodeURIComponent(decoded.slice(0, separator).replace(/\+/gu, " "));
    return clientId && clientId.length <= MAX_CLIENT_ID_LENGTH ? clientId : "invalid";
  } catch {
    return "invalid";
  }
}

// The per-source ceiling bounds an address that rotates client_id values to obtain fresh per-client buckets.
export const OIDC_TOKEN_SOURCE_CEILING = 2000;

export function selectTokenRateLimits(clientAddress: string, authorization: string | undefined): RateLimitCheck[] {
  const clientRef = createHash("sha256").update(parseBasicClientId(authorization)).digest("hex").slice(0, 32);
  return [
    { identifier: `oidc-token-source:${clientAddress}`, maxAttempts: OIDC_TOKEN_SOURCE_CEILING },
    { identifier: `oidc-token:${clientAddress}:${clientRef}`, maxAttempts: OIDC_TOKEN_LIMIT }
  ];
}

export function isTokenEndpoint(method: string, path: string): boolean {
  const normalizedPath = path.length > 1 && path.endsWith("/") ? path.slice(0, -1) : path;
  return method === "POST" && ["/token", "/token/revocation"].includes(normalizedPath.toLowerCase());
}
