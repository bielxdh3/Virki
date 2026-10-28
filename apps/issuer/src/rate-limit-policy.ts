import { createHash } from "node:crypto";

export const OIDC_RATE_LIMIT_RETRY_AFTER_SECONDS = 900;
export const OIDC_AUTH_SOURCE_CEILING = 300;
export const OIDC_AUTH_BUCKET_LIMIT = 30;
export const OIDC_TOKEN_LIMIT = 600;

export type RateLimitCheck = { identifier: string; maxAttempts: number };
export type PublicOidcRateLimitEndpoint = "userinfo" | "session-end" | "auth-action";

/** The caller passes a session ID only after validating the server-side session cookie. */
export function selectAuthRateLimits(clientAddress: string, authenticatedSessionId: string | null): RateLimitCheck[] {
  const bucket = authenticatedSessionId
    ? `oidc-auth-browser:${createHash("sha256").update(authenticatedSessionId).digest("hex")}`
    : `oidc-source:${clientAddress}`;
  return [
    { identifier: `oidc-auth-source:${clientAddress}`, maxAttempts: OIDC_AUTH_SOURCE_CEILING },
    { identifier: bucket, maxAttempts: OIDC_AUTH_BUCKET_LIMIT }
  ];
}

export function isInteractionPath(path: string): boolean {
  return /^\/interaction\/[A-Za-z0-9_-]{8,80}$/u.test(path);
}

export function selectInteractionRateLimits(clientAddress: string, authenticatedSessionId: string | null): RateLimitCheck[] {
  const bucket = authenticatedSessionId
    ? `oidc-interaction-browser:${createHash("sha256").update(authenticatedSessionId).digest("hex")}`
    : `oidc-interaction-anonymous:${clientAddress}`;
  return [
    { identifier: `oidc-interaction-source:${clientAddress}`, maxAttempts: OIDC_AUTH_SOURCE_CEILING },
    { identifier: bucket, maxAttempts: OIDC_AUTH_BUCKET_LIMIT }
  ];
}

export function getPublicOidcRateLimitEndpoint(method: string, path: string): PublicOidcRateLimitEndpoint | null {
  // oidc-provider serves UserInfo for HEAD as well as GET/POST. HEAD must not
  // escape the database-backed quota simply because it returns no body.
  if (method !== "GET" && method !== "POST" && method !== "HEAD") return null;
  if (path === "/me") return "userinfo";
  if (path === "/session/end") return "session-end";
  if (method === "POST" && path === "/session/end/confirm") return "session-end";
  if ((method === "GET" || method === "HEAD") && path === "/session/end/success") return "session-end";
  if (/^\/auth\/[A-Za-z0-9_-]{8,80}$/u.test(path)) return "auth-action";
  return null;
}

export function selectPublicOidcRateLimits(
  clientAddress: string,
  authenticatedSessionId: string | null,
  endpoint: PublicOidcRateLimitEndpoint,
  validatedBearerToken?: string
): RateLimitCheck[] {
  // Only server-validated sessions and access tokens select persistent identity buckets.
  const bearer = endpoint === "userinfo" && typeof validatedBearerToken === "string" &&
    /^[A-Za-z0-9._~+/-]{8,4096}={0,2}$/u.test(validatedBearerToken)
    ? validatedBearerToken : null;
  const bucket = bearer
    ? `oidc-public-userinfo-bearer:${createHash("sha256").update(bearer).digest("hex")}`
    : authenticatedSessionId
    ? `oidc-public-${endpoint}-browser:${createHash("sha256").update(authenticatedSessionId).digest("hex")}`
    : `oidc-public-${endpoint}-anonymous:${clientAddress}`;
  return [
    { identifier: `oidc-public-source:${endpoint}:${clientAddress}`, maxAttempts: OIDC_AUTH_SOURCE_CEILING },
    { identifier: bucket, maxAttempts: OIDC_AUTH_BUCKET_LIMIT }
  ];
}

export function isNonCanonicalOidcEndpointPath(path: string): boolean {
  const canonicalPaths = ["/auth", "/token", "/token/revocation", "/me", "/session/end", "/session/end/confirm", "/session/end/success", "/jwks", "/.well-known/openid-configuration", "/.well-known/oauth-authorization-server"];
  const lowerWithoutTrailingSlashes = path.toLowerCase().replace(/\/+$/u, "");
  if (canonicalPaths.includes(lowerWithoutTrailingSlashes) && path !== lowerWithoutTrailingSlashes) return true;
  // The portal proxy admits up to 160 UID chars. Reject anything the issuer
  // does not intentionally meter instead of passing it to provider routing.
  if (/^\/auth\/[A-Za-z0-9_-]{1,160}\/?$/iu.test(path) && !/^\/auth\/[A-Za-z0-9_-]{8,80}$/u.test(path)) return true;
  if (/^\/interaction\/[A-Za-z0-9_-]{8,80}\/?$/iu.test(path) && !isInteractionPath(path)) return true;
  return false;
}

export function selectRateLimitAudit(clientAddress: string): RateLimitCheck {
  return { identifier: `oidc-rate-limit-audit:${clientAddress}`, maxAttempts: 1 };
}

export function parseBearerToken(authorization: string | undefined): string | null {
  if (!authorization) return null;
  const match = /^Bearer ([A-Za-z0-9._~+/-]{8,4096}={0,2})$/iu.exec(authorization);
  return match?.[1] ?? null;
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

export function selectTokenRateLimits(clientAddress: string, registeredClientId: string | null): RateLimitCheck[] {
  const clientRef = createHash("sha256").update(registeredClientId ?? "invalid").digest("hex").slice(0, 32);
  return [
    { identifier: `oidc-token-source:${clientAddress}`, maxAttempts: OIDC_TOKEN_SOURCE_CEILING },
    { identifier: `oidc-token:${clientAddress}:${clientRef}`, maxAttempts: OIDC_TOKEN_LIMIT }
  ];
}

export function isTokenEndpoint(method: string, path: string): boolean {
  const normalizedPath = path.length > 1 && path.endsWith("/") ? path.slice(0, -1) : path;
  return method === "POST" && ["/token", "/token/revocation"].includes(normalizedPath.toLowerCase());
}
