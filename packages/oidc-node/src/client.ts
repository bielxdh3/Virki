import { randomBytes, timingSafeEqual } from "node:crypto";
import * as oidc from "openid-client";
import { hashFlowState, type TransactionStore, type AuthorizationTransaction } from "./store.js";

export type VirkiClientOptions = {
  /** Pinned trusted issuer, normally https://portal.biel.dev.br. Never user-supplied. */
  issuer: string;
  clientId: string;
  /** Confidential RP server secret. Never pass to the browser or serialize into a session. */
  clientSecret: string;
  /** Exact callback URI registered in Hub > Connections. */
  redirectUri: string;
  store: TransactionStore;
  transactionTtlMs?: number;
  /** Optional Cloudflare Access service-token pair for server-to-server OIDC requests only. */
  cloudflareAccess?: { clientId: string; clientSecret: string };
};

export type ValidatedClientOptions = Required<Omit<VirkiClientOptions, "transactionTtlMs" | "cloudflareAccess">> & { transactionTtlMs: number };

export type IdentityClaims = {
  sub: string;
  amr?: string[];
  acr?: string;
  auth_time?: number;
  email?: string;
  email_verified?: boolean;
  name?: string;
};

export type VerifiedLogin = {
  identity: Readonly<IdentityClaims>;
  /** Keep exclusively in the RP backend; never put this into a browser session or URL. */
  serverOnly: { accessToken: string };
};

type TokenChecks = { expectedState: string; expectedNonce: string; pkceCodeVerifier: string };

/** Internal protocol seam, not exported from the published package. */
export type OidcProtocol = {
  authorizationUrl(parameters: URLSearchParams): URL;
  redeem(callbackUrl: URL, checks: TokenChecks): Promise<{ claims: unknown; accessToken: string }>;
  revokeToken(token: string): Promise<void>;
  getUserInfo?(token: string, expectedSubject: string): Promise<unknown>;
};

export function validateClientOptions(input: VirkiClientOptions): ValidatedClientOptions {
  if (!input || !input.store || typeof input.store.put !== "function" || typeof input.store.take !== "function") throw new Error("Invalid confidential OIDC client configuration.");
  if (typeof input.clientId !== "string" || !/^[A-Za-z0-9_-]{5,160}$/u.test(input.clientId) || typeof input.clientSecret !== "string" || input.clientSecret.length < 16) {
    throw new Error("Invalid confidential OIDC client configuration.");
  }
  const issuer = requireExactHttpsUrl(input.issuer, true);
  const redirectUri = requireExactHttpsUrl(input.redirectUri, false);
  if (input.cloudflareAccess !== undefined && !isValidAccessPair(input.cloudflareAccess)) {
    throw new Error("Invalid confidential OIDC Access configuration.");
  }
  const transactionTtlMs = input.transactionTtlMs ?? 10 * 60_000;
  if (!Number.isSafeInteger(transactionTtlMs) || transactionTtlMs < 1000 || transactionTtlMs > 15 * 60_000) throw new Error("Invalid OIDC transaction lifetime.");
  return { issuer, redirectUri, clientId: input.clientId, clientSecret: input.clientSecret, store: input.store, transactionTtlMs };
}

function isValidAccessPair(value: unknown): value is NonNullable<VirkiClientOptions["cloudflareAccess"]> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const credentials = value as Record<string, unknown>;
  const keys = Object.keys(credentials);
  return keys.length === 2 && keys.includes("clientId") && keys.includes("clientSecret")
    && typeof credentials.clientId === "string" && /^[\x21-\x7e]{1,256}$/u.test(credentials.clientId)
    && typeof credentials.clientSecret === "string" && /^[\x21-\x7e]{1,1024}$/u.test(credentials.clientSecret);
}

function requireExactHttpsUrl(input: string, originOnly: boolean): string {
  if (typeof input !== "string" || input.trim() !== input || input.length > 2048 || input.includes("*")) throw new Error("Invalid HTTPS OIDC endpoint.");
  let url: URL;
  try { url = new URL(input); } catch { throw new Error("Invalid HTTPS OIDC endpoint."); }
  if (url.protocol !== "https:" || url.username || url.password || url.hash || url.search || (originOnly ? url.origin !== input : url.href !== input) || (originOnly && (url.pathname !== "/" || url.port !== ""))) {
    throw new Error("Invalid HTTPS OIDC endpoint.");
  }
  return input;
}

/** Disallow discovery pointing an otherwise pinned client at a different authority (including SSRF). */
export function validateIssuerEndpoints(metadata: Record<string, unknown>, pinnedIssuer: string): void {
  if (metadata.issuer !== pinnedIssuer) throw new Error("Untrusted OIDC issuer metadata.");
  for (const field of ["authorization_endpoint", "token_endpoint", "jwks_uri", "userinfo_endpoint", "revocation_endpoint"] as const) {
    const endpoint = metadata[field];
    if (endpoint === undefined && ["userinfo_endpoint", "revocation_endpoint"].includes(field)) continue;
    if (typeof endpoint !== "string") throw new Error("Untrusted OIDC issuer metadata.");
    try {
      const url = new URL(endpoint);
      if (url.origin !== pinnedIssuer || url.protocol !== "https:" || url.username || url.password || url.hash || url.search) throw new Error();
    } catch { throw new Error("Untrusted OIDC issuer metadata."); }
  }
}

/** Run only on a Node server, with a RP-owned transaction store. */
export async function createVirkiOidcClient(options: VirkiClientOptions): Promise<VirkiOidcNodeClient> {
  const validated = validateClientOptions(options);
  const discoveryOptions: oidc.DiscoveryRequestOptions = { timeout: 10, execute: [oidc.enableNonRepudiationChecks] };
  if (options.cloudflareAccess) {
    discoveryOptions[oidc.customFetch] = accessBackchannelFetch(validated.issuer, options.cloudflareAccess);
  }
  const client = await oidc.discovery(
    new URL(validated.issuer),
    validated.clientId,
    { id_token_signed_response_alg: "ES256", token_endpoint_auth_method: "client_secret_basic" },
    oidc.ClientSecretBasic(validated.clientSecret),
    discoveryOptions
  );
  validateIssuerEndpoints(client.serverMetadata() as unknown as Record<string, unknown>, validated.issuer);
  return new VirkiOidcNodeClient(validated, createOidcProtocol(client));
}

/** This fetch is retained by openid-client for discovery, token, JWKS, userinfo and revocation. */
function accessBackchannelFetch(issuer: string, credentials: NonNullable<VirkiClientOptions["cloudflareAccess"]>): oidc.CustomFetch {
  return async (url, options) => {
    let endpoint: URL;
    try { endpoint = new URL(url); } catch { throw new Error("OIDC Access backchannel destination refused."); }
    if (endpoint.protocol !== "https:" || endpoint.origin !== issuer || endpoint.username || endpoint.password || endpoint.hash) {
      throw new Error("OIDC Access backchannel destination refused.");
    }
    const headers = new Headers(options.headers);
    headers.set("CF-Access-Client-Id", credentials.clientId);
    headers.set("CF-Access-Client-Secret", credentials.clientSecret);
    try {
      // Never follow a Cloudflare challenge or an upstream 3xx with the Access identity.
      // openid-client's FetchBody includes binary views that Node fetch accepts;
      // its declaration is broader than TypeScript's DOM RequestInit body union.
      const response = await fetch(endpoint.href, { ...options, body: options.body as RequestInit["body"],
        headers, redirect: "manual", cache: "no-store" });
      if (response.status >= 300 && response.status < 400) throw new Error("OIDC Access backchannel redirect refused.");
      return response;
    } catch {
      // The fetcher may include request headers in an error. Never pass its details to callers.
      throw new Error("OIDC Access backchannel request failed.");
    }
  };
}

/** Internal adapter runs the real openid-client validation and signing-key checks. */
export function createOidcProtocol(client: oidc.Configuration): OidcProtocol {
  return {
    authorizationUrl: (params) => oidc.buildAuthorizationUrl(client, params),
    redeem: async (callbackUrl, checks) => {
      const tokens = await oidc.authorizationCodeGrant(client, callbackUrl, { ...checks, idTokenExpected: true });
      const claims = tokens.claims();
      if (!claims || !tokens.access_token) throw new Error("OIDC token validation failed.");
      return { claims, accessToken: tokens.access_token };
    },
    revokeToken: async (token) => { await oidc.tokenRevocation(client, token, { token_type_hint: "access_token" }); },
    getUserInfo: async (token, subject) => oidc.fetchUserInfo(client, token, subject)
  };
}

/** Constructor is intentionally not exposed by package exports; tests can inject a protocol. */
export class VirkiOidcNodeClient {
  private readonly settings: ValidatedClientOptions;

  constructor(options: VirkiClientOptions, private readonly protocol: OidcProtocol) {
    this.settings = validateClientOptions(options);
  }

  async beginLogin(browserBinding: string): Promise<{ url: URL; expiresAt: Date }> {
    checkBrowserBinding(browserBinding);
    const state = oidc.randomState();
    const nonce = oidc.randomNonce();
    const codeVerifier = oidc.randomPKCECodeVerifier();
    const challenge = await oidc.calculatePKCECodeChallenge(codeVerifier);
    const expiresAt = Date.now() + this.settings.transactionTtlMs;
    const record: AuthorizationTransaction = {
      stateHash: hashFlowState(state), browserHash: hashFlowState(browserBinding),
      codeVerifier, nonce, issuer: this.settings.issuer, clientId: this.settings.clientId,
      redirectUri: this.settings.redirectUri, expiresAt
    };
    await this.settings.store.put(record);
    const url = this.protocol.authorizationUrl(new URLSearchParams({
      client_id: this.settings.clientId,
      response_type: "code",
      redirect_uri: this.settings.redirectUri,
      scope: "openid profile email",
      code_challenge: challenge,
      code_challenge_method: "S256",
      state, nonce
    }));
    if (url.origin !== this.settings.issuer || url.protocol !== "https:" || url.pathname !== "/auth") throw new Error("Untrusted OIDC authorization endpoint.");
    return { url, expiresAt: new Date(expiresAt) };
  }

  async completeCallback(callbackUrl: string | URL, browserBinding: string): Promise<VerifiedLogin> {
    checkBrowserBinding(browserBinding);
    const url = new URL(String(callbackUrl));
    const expected = new URL(this.settings.redirectUri);
    if (url.protocol !== "https:" || url.origin !== expected.origin || url.pathname !== expected.pathname || url.hash || url.username || url.password || expected.search) throw new Error("OIDC callback rejected.");
    const state = uniqueParameter(url.searchParams, "state");
    if (!state || !/^[A-Za-z0-9_-]{32,128}$/u.test(state) || url.searchParams.getAll("code").length > 1 || url.searchParams.getAll("error").length > 1) throw new Error("OIDC callback rejected.");

    // Spend the transaction BEFORE verifying browser / error / exchanging tokens.
    // A stolen state, wrong browser, OAuth denial or network failure cannot be replayed.
    const transaction = await this.settings.store.take(hashFlowState(state));
    if (!transaction || transaction.expiresAt <= Date.now() || !safeHashEquals(transaction.browserHash, hashFlowState(browserBinding))
      || transaction.clientId !== this.settings.clientId || transaction.issuer !== this.settings.issuer || transaction.redirectUri !== this.settings.redirectUri) {
      throw new Error("OIDC callback rejected.");
    }
    if (url.searchParams.has("error") || !uniqueParameter(url.searchParams, "code")) throw new Error("OIDC callback rejected.");
    try {
      const result = await this.protocol.redeem(url, { expectedState: state, expectedNonce: transaction.nonce, pkceCodeVerifier: transaction.codeVerifier });
      const claims = validateIdentity(result.claims, this.settings.issuer, this.settings.clientId, transaction.nonce);
      if (typeof result.accessToken !== "string" || !result.accessToken) throw new Error();
      return { identity: Object.freeze(claims), serverOnly: { accessToken: result.accessToken } };
    } catch {
      // Never expose upstream error messages, tokens or credentials to callers/logs.
      throw new Error("OIDC callback rejected.");
    }
  }

  /** Caller must maintain its OWN RP session. This does not revoke Virki's central session. */
  async revokeAccessToken(serverOnlyToken: string): Promise<void> {
    if (typeof serverOnlyToken !== "string" || !serverOnlyToken || serverOnlyToken.length > 8192) throw new Error("Invalid token.");
    await this.protocol.revokeToken(serverOnlyToken);
  }

  async userInfo(serverOnlyToken: string, expectedSubject: string): Promise<unknown> {
    if (typeof serverOnlyToken !== "string" || !serverOnlyToken || !expectedSubject || !this.protocol.getUserInfo) throw new Error("OIDC userinfo unavailable.");
    return this.protocol.getUserInfo(serverOnlyToken, expectedSubject);
  }
}

function validateIdentity(input: unknown, issuer: string, clientId: string, nonce: string): IdentityClaims {
  if (!input || typeof input !== "object") throw new Error("Invalid ID Token.");
  const value = input as Record<string, unknown>;
  const aud = value.aud;
  const now = Math.floor(Date.now() / 1000);
  if (value.iss !== issuer || typeof value.sub !== "string" || !value.sub || value.nonce !== nonce
    || !(aud === clientId || (Array.isArray(aud) && aud.includes(clientId)))
    || (Array.isArray(aud) && aud.length > 1 && value.azp !== clientId)
    || typeof value.exp !== "number" || !Number.isSafeInteger(value.exp) || value.exp <= now
    || typeof value.iat !== "number" || !Number.isSafeInteger(value.iat) || value.iat > now + 30
    || value.exp <= value.iat
    || (value.auth_time !== undefined && (typeof value.auth_time !== "number" || !Number.isSafeInteger(value.auth_time) || value.auth_time > now + 30))
    || (value.amr !== undefined && (!Array.isArray(value.amr) || !value.amr.every((method: unknown) => typeof method === "string")))
    || (value.acr !== undefined && typeof value.acr !== "string")) throw new Error("Invalid ID Token.");
  // The RP gets only mapped, useful identity attributes. Protocol proof fields
  // (notably the nonce) stay internal, even after successful verification.
  return { sub: value.sub,
    ...(Array.isArray(value.amr) ? { amr: value.amr as string[] } : {}),
    ...(typeof value.acr === "string" ? { acr: value.acr } : {}),
    ...(typeof value.auth_time === "number" ? { auth_time: value.auth_time } : {}),
    ...(typeof value.email === "string" ? { email: value.email } : {}),
    ...(typeof value.email_verified === "boolean" ? { email_verified: value.email_verified } : {}),
    ...(typeof value.name === "string" ? { name: value.name } : {}) };
}

function safeHashEquals(first: string, second: string): boolean {
  return /^[a-f0-9]{64}$/u.test(first) && /^[a-f0-9]{64}$/u.test(second)
    && timingSafeEqual(Buffer.from(first, "hex"), Buffer.from(second, "hex"));
}

function checkBrowserBinding(value: string): void {
  // A random opaque server-issued pre-login cookie; reject weak client-chosen identifiers.
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{43,128}$/u.test(value)) throw new Error("OIDC browser binding unavailable.");
}

function uniqueParameter(params: URLSearchParams, name: string): string | null {
  const values = params.getAll(name);
  return values.length === 1 && values[0] ? values[0] : null;
}

/** Generate new RP-bound browser/session cookies on the server, never in the browser. */
export function randomRpSessionId(): string { return randomBytes(32).toString("base64url"); }
