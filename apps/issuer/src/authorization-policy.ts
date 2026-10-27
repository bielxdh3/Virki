import { createHmac, timingSafeEqual } from "node:crypto";

const MULTI_FACTOR_ACR = "urn:virki:loa:2";
const PASSWORD_ACR = "urn:virki:loa:1";
const AUTH_REQUEST_MARKER_TTL_MS = 15 * 60 * 1_000;

export const OIDC_SUPPORTED_ACR_VALUES = [PASSWORD_ACR, MULTI_FACTOR_ACR] as const;
export const OIDC_PROVIDER_CLAIMS = {
  amr: null,
  openid: ["sub"],
  profile: ["name"],
  email: ["email", "email_verified"]
};
export const OIDC_DISCOVERY_CONFIGURATION = {
  acrValues: [...OIDC_SUPPORTED_ACR_VALUES],
  features: { claimsParameter: { enabled: true } }
};

export function requiresProjectAccessInteraction(
  accountId: string | undefined,
  clientId: string | undefined,
  hasActiveGrant: boolean
): boolean {
  return Boolean(accountId && clientId && !hasActiveGrant);
}

export function isOidcAccountEligible(account: { role: string; isActive: boolean; accountStatus: string } | null | undefined): boolean {
  return Boolean(account && account.role === "USER" && account.isActive && account.accountStatus === "ACTIVE");
}

export type ProjectGrantAuthorizationState = {
  revokedAt: Date | null;
  user: {
    role: string;
    isActive: boolean;
    accountStatus: string;
  };
  connection: {
    enabled: boolean;
  };
};

export function isCurrentActiveUserProjectGrant(
  grant: ProjectGrantAuthorizationState | null | undefined
): boolean {
  return Boolean(
    grant &&
    grant.user.role === "USER" &&
    grant.user.isActive &&
    grant.user.accountStatus === "ACTIVE" &&
    grant.connection.enabled &&
    grant.revokedAt === null
  );
}

export function isOidcInteractionPathBound(routeUid: string, activeInteractionUid: string): boolean {
  return routeUid === activeInteractionUid;
}

export function isOidcGrantBoundToInteraction(
  grant: { accountId?: string; clientId?: string } | null | undefined,
  accountId: string,
  clientId: string
): boolean {
  return Boolean(grant && grant.accountId === accountId && grant.clientId === clientId);
}

export function getOidcAuthenticationContext(
  authenticationMethods: readonly string[],
  requiredAcrValues: readonly string[] = []
): { acr: string; amr: string[] } {
  const methods = [...new Set(authenticationMethods.filter((method) => /^[a-z][a-z0-9_-]{0,31}$/u.test(method)))];
  const multiFactor = methods.includes("mfa");
  const acr = multiFactor
    ? requiredAcrValues.includes(PASSWORD_ACR) && !requiredAcrValues.includes(MULTI_FACTOR_ACR) ? PASSWORD_ACR : MULTI_FACTOR_ACR
    : PASSWORD_ACR;
  return { acr, amr: methods };
}

export function isCurrentOidcAuthenticationContext(input: {
  currentAcr: string | undefined;
  currentAmr: unknown;
  currentLoginTs: number | undefined;
  authenticationMethods: readonly string[];
  authenticatedAt: Date;
}): boolean {
  if (!Array.isArray(input.currentAmr) || !input.currentAmr.every((method) => typeof method === "string")) return false;
  const currentMethods = [...new Set(input.currentAmr as string[])].sort();
  const expectedMethods = [...new Set(input.authenticationMethods.filter((method) => /^[a-z][a-z0-9_-]{0,31}$/u.test(method)))].sort();
  return typeof input.currentAcr === "string" &&
    satisfiesEssentialOidcAcrValues([input.currentAcr], input.authenticationMethods) &&
    input.currentLoginTs === Math.floor(input.authenticatedAt.getTime() / 1_000) &&
    currentMethods.length === expectedMethods.length &&
    currentMethods.every((method, index) => method === expectedMethods[index]);
}

export function supportsEssentialOidcAcrValues(requiredAcrValues: readonly string[]): boolean {
  return requiredAcrValues.includes(PASSWORD_ACR) || requiredAcrValues.includes(MULTI_FACTOR_ACR);
}

export function satisfiesEssentialOidcAcrValues(
  requiredAcrValues: readonly string[],
  authenticationMethods: readonly string[]
): boolean {
  if (!supportsEssentialOidcAcrValues(requiredAcrValues)) return false;
  const achievedAcr = getOidcAuthenticationContext(authenticationMethods).acr;
  return requiredAcrValues.includes(achievedAcr) || (achievedAcr === MULTI_FACTOR_ACR && requiredAcrValues.includes(PASSWORD_ACR));
}

export function requiresOidcAssuranceInteraction(input: {
  requestedAcrValues: string | undefined;
  currentAcr: string | undefined;
  authenticationMethods: readonly string[];
}): boolean {
  const requestedAcrValues = splitAcrValues(input.requestedAcrValues);
  const requestsMultiFactor = requestedAcrValues.includes(MULTI_FACTOR_ACR) &&
    (!requestedAcrValues.includes(PASSWORD_ACR) || input.authenticationMethods.includes("mfa"));
  return requestsMultiFactor && (
    !input.authenticationMethods.includes("mfa") || input.currentAcr !== MULTI_FACTOR_ACR
  );
}

export function createOidcAuthRequestMarker(uid: string, startedAtMs: number, key: Uint8Array): string {
  if (!/^[A-Za-z0-9_-]{8,80}$/u.test(uid) || !Number.isSafeInteger(startedAtMs) || startedAtMs <= 0 || key.byteLength < 32) {
    throw new Error("Invalid OIDC authentication request marker input.");
  }
  const payload = Buffer.from(JSON.stringify({ uid, startedAtMs }), "utf8").toString("base64url");
  const signature = createHmac("sha256", key).update("virki-oidc-auth-request\0").update(payload).digest("base64url");
  return `${payload}.${signature}`;
}

export function readOidcAuthRequestMarker(
  value: string | undefined,
  expectedUid: string,
  key: Uint8Array,
  nowMs = Date.now()
): number | null {
  if (!value || value.length > 512 || key.byteLength < 32 || !/^[A-Za-z0-9_-]{8,80}$/u.test(expectedUid)) return null;
  const separator = value.indexOf(".");
  if (separator <= 0 || separator !== value.lastIndexOf(".")) return null;
  const payload = value.slice(0, separator);
  const signatureText = value.slice(separator + 1);
  if (!/^[A-Za-z0-9_-]+$/u.test(payload) || !/^[A-Za-z0-9_-]{43}$/u.test(signatureText)) return null;

  const expectedSignature = createHmac("sha256", key).update("virki-oidc-auth-request\0").update(payload).digest();
  const suppliedSignature = Buffer.from(signatureText, "base64url");
  if (suppliedSignature.length !== expectedSignature.length || !timingSafeEqual(suppliedSignature, expectedSignature)) return null;

  let decoded: unknown;
  try {
    decoded = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
  } catch {
    return null;
  }
  if (!decoded || typeof decoded !== "object") return null;
  const marker = decoded as { uid?: unknown; startedAtMs?: unknown };
  if (marker.uid !== expectedUid || typeof marker.startedAtMs !== "number" || !Number.isSafeInteger(marker.startedAtMs)) return null;
  if (marker.startedAtMs <= 0 || marker.startedAtMs > nowMs || nowMs - marker.startedAtMs > AUTH_REQUEST_MARKER_TTL_MS) return null;
  return marker.startedAtMs;
}

export function requiresFreshOidcAuthentication(input: {
  prompt: string | undefined;
  maxAge: string | number | undefined;
  requestedAcrValues?: string;
  requiredAcrValues?: readonly string[];
  authenticationMethods: readonly string[];
  requestStartedAtMs?: number;
  authenticatedAt: Date;
  now?: Date;
}): boolean {
  const promptRequestsLogin = input.prompt?.split(/\s+/u).includes("login") ?? false;
  if (promptRequestsLogin && (
    input.requestStartedAtMs === undefined || input.authenticatedAt.getTime() <= input.requestStartedAtMs
  )) return true;

  const requestedAcrValues = splitAcrValues(input.requestedAcrValues);
  const requestsMultiFactor = (
    requestedAcrValues.includes(MULTI_FACTOR_ACR) &&
    (!requestedAcrValues.includes(PASSWORD_ACR) || input.authenticationMethods.includes("mfa"))
  ) || (
    input.requiredAcrValues?.includes(MULTI_FACTOR_ACR) &&
    !input.requiredAcrValues.includes(PASSWORD_ACR)
  );
  if (requestsMultiFactor && !input.authenticationMethods.includes("mfa") && (
    input.requestStartedAtMs === undefined || input.authenticatedAt.getTime() <= input.requestStartedAtMs
  )) return true;

  if (input.maxAge === undefined) return false;
  const maxAge = typeof input.maxAge === "number" ? input.maxAge : Number(input.maxAge);
  if (!Number.isSafeInteger(maxAge) || maxAge < 0) return true;
  if (maxAge === 0 && (
    input.requestStartedAtMs === undefined || input.authenticatedAt.getTime() <= input.requestStartedAtMs
  )) return true;
  if (input.requestStartedAtMs !== undefined && input.authenticatedAt.getTime() > input.requestStartedAtMs) return false;
  const now = Math.floor((input.requestStartedAtMs ?? (input.now ?? new Date()).getTime()) / 1_000);
  const authenticatedAt = Math.floor(input.authenticatedAt.getTime() / 1_000);
  return now - authenticatedAt > maxAge;
}

function splitAcrValues(value: string | undefined): string[] {
  return value?.split(/\s+/u).filter(Boolean) ?? [];
}

export function hasValidOidcStateAndNonce(state: string, nonce: string, requiresNonce: boolean): boolean {
  return isValidOpaqueValue(state) && (!requiresNonce || isValidOpaqueValue(nonce));
}

export function hasValidOidcAuthorizationQuery(query: URLSearchParams): boolean {
  // The issuer and oidc-provider must interpret each authorization parameter identically.
  // Ambiguous duplicates could make the pre-validation miss an OpenID nonce requirement.
  const seen = new Set<string>();
  for (const key of query.keys()) {
    if (seen.has(key)) return false;
    seen.add(key);
  }
  const scope = query.get("scope") ?? "";
  return hasValidOidcStateAndNonce(
    query.get("state") ?? "",
    query.get("nonce") ?? "",
    scope.split(/\s+/u).includes("openid")
  );
}

function isValidOpaqueValue(value: string): boolean {
  if (value.length < 16 || value.length > 512) return false;
  return !Array.from(value).some((character) => {
    const code = character.charCodeAt(0);
    return code <= 0x1f || code === 0x7f;
  });
}
