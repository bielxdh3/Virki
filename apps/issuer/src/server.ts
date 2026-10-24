import { createServer } from "node:http";
import { randomUUID } from "node:crypto";
import { runWithAuditContext, writeAuditLog } from "@virki/auth/audit";
import { SESSION_COOKIE_NAME, cleanupExpiredLoginRateLimits, consumeRateLimitAttemptInTransaction, getSessionByToken, hashAuditIdentifier, hashAuditSessionReference, isTrustedClientAddress, writeAuditLogRequired } from "@virki/auth";
import { prisma } from "@virki/database";
import Provider, { interactionPolicy, type Account, type KoaContextWithOIDC } from "oidc-provider";
import { installAuditResponseGate, requireAuditBeforeResponse, useNativeOidcResponse } from "./audit-gate";
import { readInteractionDetailsOrRespond } from "./interaction-error";
import { createProviderEventAudit } from "./provider-audit";
import { setIssuerSecurityHeaders, setIssuerSensitiveResponseCachePolicy } from "./http-security";
import { readIssuer, readSigningJwks } from "./issuer-config";
import { OIDC_RATE_LIMIT_RETRY_AFTER_SECONDS, getPublicOidcRateLimitEndpoint, isInteractionPath, isNonCanonicalOidcEndpointPath, isTokenEndpoint, selectAuthRateLimits, selectInteractionRateLimits, selectPublicOidcRateLimits, selectRateLimitAudit, selectTokenRateLimits, type RateLimitCheck } from "./rate-limit-policy";
import { deleteExpiredOidcArtifacts, PrismaOidcAdapter } from "./adapter";
import { createOidcAuthRequestMarker, getOidcAuthenticationContext, hasValidOidcAuthorizationQuery, isCurrentActiveUserProjectGrant, isCurrentOidcAuthenticationContext, isOidcAccountEligible, isOidcGrantBoundToInteraction, isOidcInteractionPathBound, OIDC_DISCOVERY_CONFIGURATION, OIDC_PROVIDER_CLAIMS, readOidcAuthRequestMarker, requiresFreshOidcAuthentication, requiresOidcAssuranceInteraction, requiresProjectAccessInteraction, satisfiesEssentialOidcAcrValues, supportsEssentialOidcAcrValues } from "./authorization-policy";

const issuer = readIssuer(process.env);
const signingJwks = readSigningJwks(process.env.VIRKI_OIDC_SIGNING_JWKS);
const cookieKey = readCookieKey(process.env.VIRKI_OIDC_COOKIE_KEY);
const policy = interactionPolicy.base();
const consentPrompt = policy.get("consent");
if (!consentPrompt) throw new Error("OIDC consent policy is unavailable.");

policy.add(new interactionPolicy.Prompt({ name: "virki_session" }, new interactionPolicy.Check(
  "central_session_required",
  "A current Virki portal session is required.",
  async (rawContext) => {
    const context = rawContext as KoaContextWithOIDC;
    const accountId = context.oidc.session?.accountId;
    if (!accountId) return false;
    const token = getCookie(context.req.headers.cookie, SESSION_COOKIE_NAME);
    const session = token ? await getSessionByToken(token) : null;
    if (!session || session.user.id !== accountId) return true;
    return !isCurrentOidcAuthenticationContext({
      currentAcr: getString(context.oidc.acr) ?? undefined,
      currentAmr: context.oidc.amr,
      currentLoginTs: context.oidc.session?.loginTs,
      authenticationMethods: session.authenticationMethods,
      authenticatedAt: session.createdAt
    });
  }
)), 0);

policy.add(new interactionPolicy.Prompt({ name: "virki_project_access" }, new interactionPolicy.Check(
  "active_project_grant",
  "Project access is not enabled.",
  "access_denied",
  async (rawContext) => {
    const context = rawContext as KoaContextWithOIDC;
    const accountId = context.oidc.session?.accountId;
    const clientId = context.oidc.client?.clientId;
    if (!accountId || !clientId) return false;
    const hasActiveGrant = await hasActiveProjectGrant(accountId, clientId);
    return requiresProjectAccessInteraction(accountId, clientId, hasActiveGrant);
  }
)), 1);

policy.add(new interactionPolicy.Prompt({ name: "virki_assurance" }, new interactionPolicy.Check(
  "multi_factor_assurance_required",
  "Multi-factor authentication is required.",
  async (rawContext) => {
    const context = rawContext as KoaContextWithOIDC;
    const accountId = context.oidc.session?.accountId;
    if (!accountId) return false;
    const token = getCookie(context.req.headers.cookie, SESSION_COOKIE_NAME);
    const session = token ? await getSessionByToken(token) : null;
    if (!session || session.user.id !== accountId) return false;
    return requiresOidcAssuranceInteraction({
      requestedAcrValues: getString(context.oidc.params?.acr_values) ?? undefined,
      currentAcr: getString(context.oidc.acr) ?? undefined,
      authenticationMethods: session.authenticationMethods
    });
  }
)), 2);

consentPrompt.checks.add(new interactionPolicy.Check(
  "virki_project_grant",
  "Project access is not enabled.",
  "access_denied",
  async (rawContext) => {
    const context = rawContext as KoaContextWithOIDC;
    const accountId = context.oidc.session?.accountId;
    if (!accountId) return false;
    const clientId = context.oidc.client?.clientId;
    return !clientId || !(await hasActiveProjectGrant(accountId, clientId));
  }
));

const provider = new Provider(issuer, {
  ...OIDC_DISCOVERY_CONFIGURATION,
  adapter: (model) => new PrismaOidcAdapter(model),
  clients: [],
  clientDefaults: {
    grant_types: ["authorization_code"],
    response_types: ["code"],
    token_endpoint_auth_method: "client_secret_basic",
    id_token_signed_response_alg: "ES256"
  },
  scopes: ["openid", "profile", "email"],
  claims: OIDC_PROVIDER_CLAIMS,
  features: {
    devInteractions: { enabled: false },
    clientCredentials: { enabled: false },
    registration: { enabled: false },
    registrationManagement: { enabled: false },
    requestObjects: { request: false, requestUri: false },
    ...OIDC_DISCOVERY_CONFIGURATION.features,
    deviceFlow: { enabled: false },
    introspection: { enabled: false },
    revocation: { enabled: true }
  },
  pkce: {
    methods: ["S256"],
    required: () => true
  },
  ttl: {
    AuthorizationCode: 90,
    AccessToken: 300
  },
  cookies: {
    keys: [cookieKey],
    long: { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production" },
    short: { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production" }
  },
  jwks: signingJwks,
  interactions: {
    policy,
    url: (rawContext, interaction) => {
      const context = rawContext as KoaContextWithOIDC;
      const startedAtMs = authorizationRequestStartedAt.get(context);
      if (startedAtMs === undefined) return `/interaction/${interaction.uid}`;
      const marker = createOidcAuthRequestMarker(interaction.uid, startedAtMs, Buffer.from(cookieKey, "base64url"));
      return `/interaction/${interaction.uid}?virki_auth_request=${encodeURIComponent(marker)}`;
    }
  },
  findAccount: async (_context, id): Promise<Account | undefined> => {
    const user = await prisma.user.findUnique({ where: { id }, select: { id: true, email: true, displayName: true, emailVerifiedAt: true, role: true, isActive: true, accountStatus: true } });
    if (!user || !isOidcAccountEligible(user)) return undefined;
    return {
      accountId: user.id,
      async claims() {
        return {
          sub: user.id,
          email: user.email,
          email_verified: Boolean(user.emailVerifiedAt),
          ...(user.displayName ? { name: user.displayName } : {})
        };
      }
    };
  }
});

let securityDataCleanupRunning = false;
async function cleanupExpiredSecurityData(): Promise<void> {
  if (securityDataCleanupRunning) return;
  securityDataCleanupRunning = true;
  try {
    const now = new Date();
    await Promise.all([deleteExpiredOidcArtifacts(prisma, now), cleanupExpiredLoginRateLimits(now)]);
  } catch {
    console.error("Expired security data cleanup failed.");
  } finally {
    securityDataCleanupRunning = false;
  }
}

void cleanupExpiredSecurityData();
const securityDataCleanupTimer = setInterval(() => void cleanupExpiredSecurityData(), 15 * 60 * 1_000);
securityDataCleanupTimer.unref();

provider.proxy = true;
const authorizationRequestStartedAt = new WeakMap<object, number>();
let lastRateLimitStorageOutageLogMs = 0;
provider.use(async (rawContext, next) => {
  const context = rawContext as KoaContextWithOIDC;
  setIssuerSensitiveResponseCachePolicy(context.res, context.path);
  if (isNonCanonicalOidcEndpointPath(context.path)) {
    context.status = 404;
    context.body = { error: "invalid_request" };
    return;
  }
  if (context.path === "/auth") {
    if (context.method !== "GET") {
      context.status = 405;
      context.set("Allow", "GET");
      context.body = { error: "invalid_request" };
      return;
    }
    authorizationRequestStartedAt.set(context, Date.now());
    if (!hasValidOidcAuthorizationQuery(new URL(context.req.url ?? "/auth", issuer).searchParams)) {
      context.status = 400;
      context.body = { error: "invalid_request", error_description: "Invalid or ambiguous authorization parameters." };
      return;
    }
    const sessionCookie = getCookie(context.req.headers.cookie, SESSION_COOKIE_NAME);
    if (await rateLimitRequest(context, (address) => selectAuthRateLimits(address, sessionCookie))) return;
  } else if (isTokenEndpoint(context.method, context.path)) {
    const authorization = getString(context.req.headers.authorization) ?? undefined;
    if (await rateLimitRequest(context, (address) => selectTokenRateLimits(address, authorization))) return;
  } else {
    const endpoint = getPublicOidcRateLimitEndpoint(context.method, context.path);
    if (endpoint) {
      const sessionCookie = getCookie(context.req.headers.cookie, SESSION_COOKIE_NAME);
      const bearerAuthorization = getString(context.req.headers.authorization) ?? undefined;
      if (await rateLimitRequest(context, (address) => selectPublicOidcRateLimits(address, sessionCookie, endpoint, bearerAuthorization))) return;
    }
  }

  const match = isInteractionPath(context.path) ? context.path.match(/^\/interaction\/([A-Za-z0-9_-]{8,80})$/u) : null;
  if (match) {
    const sessionCookie = getCookie(context.req.headers.cookie, SESSION_COOKIE_NAME);
    if (await rateLimitRequest(context, (address) => selectInteractionRateLimits(address, sessionCookie))) return;
    await handleInteraction(context, match[1]);
    return;
  }
  await next();
});

provider.on("authorization.success", (context) => {
  const oidc = (context as KoaContextWithOIDC).oidc;
  requireAuditBeforeResponse((context as KoaContextWithOIDC).res, writeAuditLogRequired({
    eventType: "SSO_AUTHORIZATION_ISSUED",
    result: "SUCCESS",
    actorUserId: oidc.session?.accountId,
    resource: "sso.authorization",
    message: "Project authorization code issued.",
    metadata: oidc.client ? { clientRef: hashAuditIdentifier(oidc.client.clientId) } : undefined
  }));
});

provider.on("authorization.error", (rawContext, error) => {
  const context = rawContext as KoaContextWithOIDC;
  const clientId = context.oidc.client?.clientId;
  requireAuditBeforeResponse(context.res, writeAuditLogRequired({
    eventType: "SSO_AUTHORIZATION_DENIED",
    result: "FAILURE",
    actorUserId: context.oidc.session?.accountId,
    resource: "sso.authorization",
    message: "OIDC authorization request rejected.",
    metadata: { ...(clientId ? { clientRef: hashAuditIdentifier(clientId) } : {}), error: safeOidcError(error) }
  }));
});

provider.on("grant.success", (rawContext) => {
  const context = rawContext as KoaContextWithOIDC;
  const clientId = context.oidc.client?.clientId;
  requireAuditBeforeResponse(context.res, writeAuditLogRequired({
    eventType: "SSO_TOKEN_ISSUED",
    result: "SUCCESS",
    actorUserId: context.oidc.entities.Grant?.accountId ?? context.oidc.entities.Account?.accountId,
    resource: "sso.token",
    message: "OIDC token response issued.",
    metadata: clientId ? { clientRef: hashAuditIdentifier(clientId) } : undefined
  }));
});

provider.on("grant.error", (rawContext) => {
  const context = rawContext as KoaContextWithOIDC;
  const clientId = context.oidc.client?.clientId;
  requireAuditBeforeResponse(context.res, writeAuditLogRequired({
    eventType: "SSO_TOKEN_REJECTED",
    result: "FAILURE",
    actorUserId: context.oidc.entities.Grant?.accountId ?? context.oidc.entities.Account?.accountId,
    resource: "sso.token",
    message: "OIDC token request rejected.",
    metadata: clientId ? { clientRef: hashAuditIdentifier(clientId) } : undefined
  }));
});

provider.on("userinfo.error", (rawContext, error) => auditProviderEvent("userinfo.error", rawContext, error));
provider.on("revocation.error", (rawContext, error) => auditProviderEvent("revocation.error", rawContext, error));
provider.on("end_session.success", (rawContext) => auditProviderEvent("end_session.success", rawContext));
provider.on("end_session.error", (rawContext, error) => auditProviderEvent("end_session.error", rawContext, error));
provider.on("end_session_confirm.error", (rawContext, error) => auditProviderEvent("end_session_confirm.error", rawContext, error));
provider.on("end_session_success.error", (rawContext, error) => auditProviderEvent("end_session_success.error", rawContext, error));
provider.on("server_error", (rawContext, error) => auditProviderEvent("server_error", rawContext, error));

const port = Number(process.env.OIDC_ISSUER_PORT ?? "3003");
if (!Number.isSafeInteger(port) || port < 1024 || port > 65535) throw new Error("OIDC issuer port is invalid.");
const bindAddress = process.env.VIRKI_OIDC_BIND_ADDRESS ?? "0.0.0.0";
if (bindAddress !== "0.0.0.0" && bindAddress !== "127.0.0.1") throw new Error("OIDC issuer bind address is invalid.");
const providerCallback = provider.callback();
const server = createServer((request, response) => {
  setIssuerSecurityHeaders(response);
  installAuditResponseGate(response);
  const requestId = randomUUID();
  response.setHeader("x-virki-request-id", requestId);
  let path: string;
  try {
    path = new URL(request.url ?? "/", issuer).pathname;
  } catch {
    response.statusCode = 400;
    response.setHeader("Cache-Control", "no-store");
    response.setHeader("Content-Type", "text/plain; charset=utf-8");
    response.end("Bad Request");
    return;
  }
  const route = /^\/(?:token(?:\/revocation)?|auth|jwks|me|session\/end)$/u.test(path) ? path : /^\/(?:interaction|auth)\/[A-Za-z0-9_-]{8,80}$/u.test(path) ? `/${path.split("/")[1]}/:id` : undefined;
  runWithAuditContext({ requestId, service: "issuer", route, method: request.method }, () => providerCallback(request, response));
});
server.listen(port, bindAddress, () => {
  console.log("Virki OIDC issuer ready.");
});

async function handleInteraction(context: KoaContextWithOIDC, uid: string): Promise<void> {
  const interactionResult = await readInteractionDetailsOrRespond(context, () => provider.interactionDetails(context.req, context.res));
  if (!interactionResult.ok) return;
  const interaction = interactionResult.value;
  if (!isOidcInteractionPathBound(uid, interaction.uid)) {
    context.status = 400;
    context.body = { error: "invalid_request" };
    return;
  }
  await writeAuditLog({ eventType: "SSO_INTERACTION_STARTED", result: "INFO", resource: "sso.interaction", metadata: { requestRef: hashAuditIdentifier(uid) } });
  const essentialAcr = getEssentialAcrRequest(interaction.prompt.details.acr);
  if (essentialAcr.required && !supportsEssentialOidcAcrValues(essentialAcr.values)) {
    await denyInteraction(context);
    return;
  }
  const authRequestStartedAtMs = readOidcAuthRequestMarker(
    getString(context.query.virki_auth_request) ?? undefined,
    uid,
    Buffer.from(cookieKey, "base64url")
  );
  const sessionToken = getCookie(context.req.headers.cookie, SESSION_COOKIE_NAME);
  const session = sessionToken ? await getSessionByToken(sessionToken) : null;

  const interactionReturnTo = new URL(`/interaction/${uid}`, issuer);
  if (authRequestStartedAtMs !== null) {
    interactionReturnTo.searchParams.set("virki_auth_request", getString(context.query.virki_auth_request) ?? "");
  }

  if (!session) {
    const login = new URL("/login", issuer);
    login.searchParams.set("returnTo", `${interactionReturnTo.pathname}${interactionReturnTo.search}`);
    context.status = 303;
    context.redirect(login.href);
    return;
  }

  if (["login", "virki_session", "virki_assurance"].includes(interaction.prompt.name) && requiresFreshOidcAuthentication({
    prompt: getString(interaction.params.prompt) ?? undefined,
    maxAge: getStringOrNumber(interaction.params.max_age),
    requestedAcrValues: getString(interaction.params.acr_values) ?? undefined,
    requiredAcrValues: essentialAcr.values,
    authenticationMethods: session.authenticationMethods,
    requestStartedAtMs: authRequestStartedAtMs ?? undefined,
    authenticatedAt: session.createdAt
  })) {
    if (authRequestStartedAtMs === null) {
      await denyInteraction(context);
      return;
    }
    const login = new URL("/login", issuer);
    login.searchParams.set("returnTo", `${interactionReturnTo.pathname}${interactionReturnTo.search}`);
    login.searchParams.set("reauth", "1");
    context.status = 303;
    context.redirect(login.href);
    return;
  }

  if (essentialAcr.required && !satisfiesEssentialOidcAcrValues(essentialAcr.values, session.authenticationMethods)) {
    await denyInteraction(context);
    return;
  }

  if (["login", "virki_session", "virki_assurance"].includes(interaction.prompt.name) || interaction.session?.accountId !== session.user.id) {
    const authentication = getOidcAuthenticationContext(session.authenticationMethods, essentialAcr.values);
    requireAuditBeforeResponse(context.res, writeAuditLogRequired({ eventType: "SSO_INTERACTION_COMPLETED", result: "SUCCESS", actorUserId: session.user.id, actorRole: session.user.role === "USER" ? "USER" : undefined, sessionRef: hashAuditSessionReference(session.id), resource: "sso.interaction", metadata: { requestRef: hashAuditIdentifier(uid) } }));
    useNativeOidcResponse(context);
    await provider.interactionFinished(context.req, context.res, {
      login: { accountId: session.user.id, ts: Math.floor(session.createdAt.getTime() / 1_000), ...authentication }
    }, { mergeWithLastSubmission: false });
    return;
  }

  if (interaction.prompt.name !== "consent") {
    await denyInteraction(context);
    return;
  }

  const clientId = getString(interaction.params.client_id);
  if (!clientId || !(await hasActiveProjectGrant(session.user.id, clientId))) {
    requireAuditBeforeResponse(context.res, writeAuditLogRequired({
      eventType: "SSO_AUTHORIZATION_DENIED",
      result: "FAILURE",
      actorUserId: session.user.id,
      resource: "sso.authorization",
      message: "Project access was not granted.",
      metadata: { clientRef: clientId ? hashAuditIdentifier(clientId) : null }
    }));
    await denyInteraction(context);
    return;
  }

  const grant = interaction.grantId
    ? await provider.Grant.find(interaction.grantId)
    : new provider.Grant({ accountId: session.user.id, clientId });
  if (!grant || !isOidcGrantBoundToInteraction(grant, session.user.id, clientId)) {
    await denyInteraction(context);
    return;
  }
  grant.addOIDCScope("openid profile email");
  const missingClaims = interaction.prompt.details.missingOIDCClaims;
  if (Array.isArray(missingClaims) && missingClaims.every((claim) => typeof claim === "string")) grant.addOIDCClaims(missingClaims);
  const grantId = await grant.save();
  requireAuditBeforeResponse(context.res, writeAuditLogRequired({ eventType: "SSO_INTERACTION_COMPLETED", result: "SUCCESS", actorUserId: session.user.id, actorRole: "USER", sessionRef: hashAuditSessionReference(session.id), resource: "sso.interaction", metadata: { requestRef: hashAuditIdentifier(uid) } }));
  useNativeOidcResponse(context);
  await provider.interactionFinished(context.req, context.res, { consent: { grantId } }, { mergeWithLastSubmission: true });
}

function auditProviderEvent(eventName: string, rawContext: unknown, error?: unknown): void {
  if (!rawContext || typeof rawContext !== "object") return;
  const context = rawContext as KoaContextWithOIDC;
  const record = createProviderEventAudit(eventName, context, error);
  if (!record) return;
  requireAuditBeforeResponse(context.res, writeAuditLogRequired(record));
}

async function denyInteraction(context: KoaContextWithOIDC): Promise<void> {
  await writeAuditLog({ eventType: "SSO_INTERACTION_DENIED", result: "DENIED", resource: "sso.interaction" });
  useNativeOidcResponse(context);
  await provider.interactionFinished(context.req, context.res, {
    error: "access_denied",
    error_description: "Access denied."
  }, { mergeWithLastSubmission: false });
}

async function hasActiveProjectGrant(userId: string, clientId: string): Promise<boolean> {
  const grant = await prisma.userProjectGrant.findFirst({
    where: { userId, connection: { clientId } },
    select: {
      revokedAt: true,
      user: { select: { role: true, isActive: true, accountStatus: true } },
      connection: { select: { enabled: true } }
    }
  });
  return isCurrentActiveUserProjectGrant(grant);
}

/** Returns true when the request was answered (503 or 429). Public traffic always arrives via Cloudflare. */
async function rateLimitRequest(context: KoaContextWithOIDC, select: (address: string) => RateLimitCheck[]): Promise<boolean> {
  const clientAddress = getString(context.req.headers["cf-connecting-ip"]) ?? undefined;
  if (process.env.NODE_ENV === "production" && !isTrustedClientAddress(clientAddress)) {
    await writeRateLimitAuditOnce(context.req.socket.remoteAddress ?? "unknown", new Date(), "unavailable");
    context.status = 503;
    context.body = { error: "temporarily_unavailable" };
    return true;
  }
  if (!isTrustedClientAddress(clientAddress)) return false;
  const now = new Date();
  let allowed: boolean;
  try {
    allowed = await prisma.$transaction(async (transaction) => {
      for (const check of select(clientAddress)) {
        const attempt = await consumeRateLimitAttemptInTransaction(transaction, check.identifier, now, check.maxAttempts);
        if (!attempt.allowed) return false;
      }
      return true;
    });
  } catch {
    // Rate-limit storage failure must be observable, but never expose a DB
    // exception, Authorization header, CF address or a session identifier.
    // Throttle diagnostics while the database is down to avoid log flooding.
    const timestamp = Date.now();
    if (timestamp - lastRateLimitStorageOutageLogMs >= 60_000) {
      lastRateLimitStorageOutageLogMs = timestamp;
      console.error("OIDC rate limiter storage unavailable; refusing request with 503.");
    }
    context.status = 503;
    context.set("Retry-After", String(OIDC_RATE_LIMIT_RETRY_AFTER_SECONDS));
    context.body = { error: "temporarily_unavailable" };
    return true;
  }
  if (allowed) return false;
  await writeRateLimitAuditOnce(clientAddress, now, "rate-limited");
  context.status = 429;
  context.set("Retry-After", String(OIDC_RATE_LIMIT_RETRY_AFTER_SECONDS));
  context.body = { error: "temporarily_unavailable" };
  return true;
}

async function writeRateLimitAuditOnce(clientAddress: string, now: Date, reason: "rate-limited" | "unavailable"): Promise<void> {
  const auditCheck = selectRateLimitAudit(clientAddress);
  try {
    const attempt = await prisma.$transaction((transaction) =>
      consumeRateLimitAttemptInTransaction(transaction, auditCheck.identifier, now, auditCheck.maxAttempts)
    );
    if (!attempt.allowed) return;
  } catch {
    return;
  }
  try {
    await writeAuditLog({ eventType: "RATE_LIMIT_REACHED", result: "DENIED", reason, resource: "sso.rate-limit" });
  } catch {
    // Keep throttling effective if this optional denial audit cannot be stored.
  }
}

function readCookieKey(value: string | undefined): string {
  if (!value || !/^[A-Za-z0-9_-]{43}$/u.test(value) || Buffer.from(value, "base64url").length !== 32) throw new Error("OIDC cookie key is unavailable.");
  return value;
}

function getCookie(header: string | undefined, name: string): string | null {
  for (const part of (header ?? "").split(";")) {
    const separator = part.indexOf("=");
    if (separator > 0 && part.slice(0, separator).trim() === name) return part.slice(separator + 1).trim();
  }
  return null;
}

function getString(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

function getStringOrNumber(value: unknown): string | number | undefined {
  return typeof value === "string" || typeof value === "number" ? value : undefined;
}

function getEssentialAcrRequest(value: unknown): { required: boolean; values: string[] } {
  if (!value || typeof value !== "object") return { required: false, values: [] };
  const request = value as { essential?: unknown; value?: unknown; values?: unknown };
  if (request.essential !== true) return { required: false, values: [] };
  if (typeof request.value === "string") return { required: true, values: [request.value] };
  return { required: true, values: Array.isArray(request.values) ? request.values.filter((item): item is string => typeof item === "string") : [] };
}

function safeOidcError(value: unknown): string {
  if (!value || typeof value !== "object") return "invalid_request";
  const code = (value as { error?: unknown }).error;
  return typeof code === "string" && /^[a-z_]{3,40}$/u.test(code) ? code : "invalid_request";
}
