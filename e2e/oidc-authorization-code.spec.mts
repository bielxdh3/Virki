import { createHash, createPublicKey, randomBytes, verify as verifySignature, X509Certificate, type JsonWebKey as NodeJsonWebKey } from "node:crypto";
import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { request as httpsRequest, createServer as createHttpsServer } from "node:https";
import { DEVICE_COOKIE_NAME } from "@bielos/auth/constants";
import { PrismaClient } from "@bielos/database";
import { expect, test, type BrowserContext } from "@playwright/test";

// @ts-expect-error This existing JavaScript safety helper has no declaration file.
import { assertDisposableCoreTestDatabase } from "../scripts/core-test-database-safety.mjs";

const portalUrl = "https://portal.localhost:3001";
const fixturePath = process.env.BIELOS_E2E_AUTH_FIXTURE_FILE;
const hasFixture = Boolean(fixturePath && existsSync(fixturePath));

test.skip(!process.env.BIELOS_E2E_DATABASE_URL?.trim() || !hasFixture, "OIDC E2E requires the explicit disposable database fixture.");

type OidcFixture = {
  user: { id: string; email: string; password: string; deviceToken: string };
  projectConnectionId: string;
  oidc: { clientId: string; clientSecret: string };
};

type HubResponse = { status: number; body: string };

let fixture: OidcFixture;

test.beforeAll(async () => {
  if (!fixturePath) throw new Error("OIDC E2E fixture path is unavailable.");
  const value: unknown = JSON.parse(await readFile(fixturePath, "utf8"));
  if (!isOidcFixture(value)) throw new Error("OIDC E2E fixture is invalid.");
  fixture = value;
});

test("USER completes Authorization Code + PKCE at a real HTTPS RP callback and cannot replay the code", async ({ browser }) => {
  const keyPath = process.env.BIELOS_E2E_TLS_KEY_PATH;
  const certificatePath = process.env.BIELOS_E2E_TLS_CERTIFICATE_PATH;
  if (!keyPath || !certificatePath) throw new Error("OIDC E2E loopback TLS material is unavailable.");
  const [key, certificate] = await Promise.all([readFile(keyPath), readFile(certificatePath)]);
  if (!new X509Certificate(certificate).ca) throw new Error("OIDC E2E server certificate is not a certificate authority.");
  const callbacks: URL[] = [];
  const callbackWaiters: Array<(url: URL) => void> = [];
  const receiveCallback = (url: URL) => {
    const waiter = callbackWaiters.shift();
    if (waiter) waiter(url);
    else callbacks.push(url);
  };
  const nextCallback = () => {
    const queued = callbacks.shift();
    if (queued) return Promise.resolve(queued);
    return new Promise<URL>((resolve) => callbackWaiters.push(resolve));
  };
  let redirectUri: string | undefined;
  const callbackServer = createHttpsServer({ key, cert: certificate }, (request, response) => {
    if (!redirectUri) {
      response.writeHead(503, { "cache-control": "no-store" }).end();
      return;
    }
    const callback = new URL(request.url ?? "/", redirectUri);
    if (request.method !== "GET" || callback.pathname !== "/callback") {
      response.writeHead(404, { "cache-control": "no-store" }).end();
      return;
    }
    receiveCallback(callback);
    response.writeHead(200, { "cache-control": "no-store", "content-type": "text/plain; charset=utf-8" });
    response.end("OIDC response received.");
  });

  let context: BrowserContext | undefined;
  try {
    await new Promise<void>((resolve, reject) => {
      callbackServer.once("error", reject);
      callbackServer.listen(0, "127.0.0.1", () => resolve());
    });
    const callbackAddress = callbackServer.address();
    if (!callbackAddress || typeof callbackAddress === "string" || callbackAddress.port < 1) {
      throw new Error("OIDC E2E callback server did not bind a loopback port.");
    }
    redirectUri = `https://127.0.0.1:${callbackAddress.port}/callback`;
    const callbackUri = redirectUri;
    await registerRedirectUri(callbackUri);

    const codeVerifier = randomOpaqueValue();
    const codeChallenge = createHash("sha256").update(codeVerifier, "ascii").digest("base64url");
    const state = randomOpaqueValue();
    const nonce = randomOpaqueValue();
    const discoveryResponse = await requestHub("/.well-known/openid-configuration", { ca: certificate });
    expect(discoveryResponse.status).toBe(200);
    const discovery = parseJsonObject(discoveryResponse.body, "OIDC discovery response is invalid.");
    expect(discovery.issuer === portalUrl).toBe(true);

    const authorizationPath = issuerEndpointPath(discovery.authorization_endpoint, "/auth");
    const tokenPath = issuerEndpointPath(discovery.token_endpoint, "/token");
    const jwksPath = issuerEndpointPath(discovery.jwks_uri, "/jwks");
    const makeAuthorizationUrl = (challenge: string, requestState: string, requestNonce: string) => {
      const url = new URL(authorizationPath, portalUrl);
      url.search = new URLSearchParams({
        client_id: fixture.oidc.clientId,
        redirect_uri: callbackUri,
        response_type: "code",
        scope: "openid profile email",
        state: requestState,
        nonce: requestNonce,
        code_challenge: challenge,
        code_challenge_method: "S256"
      }).toString();
      return url;
    };

    context = await browser.newContext({ ignoreHTTPSErrors: true });
    await context.addCookies([{
      name: DEVICE_COOKIE_NAME,
      value: fixture.user.deviceToken,
      url: portalUrl,
      httpOnly: true,
      secure: true,
      sameSite: "Lax"
    }]);
    const page = await context.newPage();
    await page.goto(makeAuthorizationUrl(codeChallenge, state, nonce).href);
    await completePortalLoginIfNeeded(page);

    const callback = await nextCallback();
    expect(callback.origin === new URL(callbackUri).origin).toBe(true);
    expect(callback.pathname === "/callback").toBe(true);
    expect(callback.searchParams.getAll("state")).toHaveLength(1);
    expect(callback.searchParams.get("state") === state).toBe(true);
    expect(callback.searchParams.has("error")).toBe(false);
    const authorizationCode = callback.searchParams.get("code");
    if (!authorizationCode || callback.searchParams.getAll("code").length !== 1) {
      throw new Error("OIDC callback did not contain exactly one authorization code.");
    }

    const tokenForm = new URLSearchParams({
      grant_type: "authorization_code",
      code: authorizationCode,
      redirect_uri: callbackUri,
      code_verifier: codeVerifier
    }).toString();
    const clientAuthorization = `Basic ${Buffer.from(`${fixture.oidc.clientId}:${fixture.oidc.clientSecret}`, "utf8").toString("base64")}`;
    const tokenResponse = await requestHub(tokenPath, {
      ca: certificate,
      method: "POST",
      headers: {
        authorization: clientAuthorization,
        "content-type": "application/x-www-form-urlencoded",
        "content-length": String(Buffer.byteLength(tokenForm))
      },
      body: tokenForm
    });
    expect(tokenResponse.status).toBe(200);
    const tokenSet = parseJsonObject(tokenResponse.body, "OIDC token response is invalid.");
    const idToken = readString(tokenSet.id_token);
    if (!idToken) throw new Error("OIDC token response did not contain an ID token.");
    const [headerPart, claimsPart, signaturePart, extraPart] = idToken.split(".");
    if (!headerPart || !claimsPart || !signaturePart || extraPart !== undefined) throw new Error("OIDC ID token is malformed.");
    const header = parseJwtSegment(headerPart);
    const claims = parseJwtSegment(claimsPart);
    expect(header.alg === "ES256").toBe(true);
    const jwksResponse = await requestHub(jwksPath, { ca: certificate });
    expect(jwksResponse.status).toBe(200);
    const jwks = parseJsonObject(jwksResponse.body, "OIDC JWKS response is invalid.");
    if (!Array.isArray(jwks.keys)) throw new Error("OIDC JWKS did not contain signing keys.");
    const signingKey = jwks.keys.find((item) => isRecord(item) && item.kid === header.kid);
    if (!isRecord(signingKey)) throw new Error("OIDC ID token signing key was not published in JWKS.");
    expect(signingKey.kty === "EC" && signingKey.crv === "P-256" && signingKey.use === "sig" && signingKey.alg === "ES256").toBe(true);
    expect(Object.hasOwn(signingKey, "d")).toBe(false);
    const signatureValid = verifySignature(
      "sha256",
      Buffer.from(`${headerPart}.${claimsPart}`, "ascii"),
      { key: createPublicKey({ key: signingKey as unknown as NodeJsonWebKey, format: "jwk" }), dsaEncoding: "ieee-p1363" },
      Buffer.from(signaturePart, "base64url")
    );
    expect(signatureValid).toBe(true);

    const audience = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    expect(claims.iss === portalUrl).toBe(true);
    expect(claims.sub === fixture.user.id).toBe(true);
    expect(audience.includes(fixture.oidc.clientId)).toBe(true);
    expect(claims.nonce === nonce).toBe(true);
    expect(claims.email === fixture.user.email).toBe(true);
    expect(claims.email_verified === true).toBe(true);
    expect(typeof claims.exp === "number" && claims.exp > Math.floor(Date.now() / 1_000)).toBe(true);

    const replayResponse = await requestHub(tokenPath, {
      ca: certificate,
      method: "POST",
      headers: {
        authorization: clientAuthorization,
        "content-type": "application/x-www-form-urlencoded",
        "content-length": String(Buffer.byteLength(tokenForm))
      },
      body: tokenForm
    });
    expect(replayResponse.status).toBe(400);
    const replayBody = parseJsonObject(replayResponse.body, "OIDC replay response is invalid.");
    expect(replayBody.error === "invalid_grant").toBe(true);

    const expectedVerifier = randomOpaqueValue();
    const expectedChallenge = createHash("sha256").update(expectedVerifier, "ascii").digest("base64url");
    const rejectedState = randomOpaqueValue();
    const rejectedNonce = randomOpaqueValue();
    await page.goto(makeAuthorizationUrl(expectedChallenge, rejectedState, rejectedNonce).href);
    await completePortalLoginIfNeeded(page);
    const rejectedCallback = await nextCallback();
    expect(rejectedCallback.searchParams.get("state") === rejectedState).toBe(true);
    const rejectedCode = rejectedCallback.searchParams.get("code");
    if (!rejectedCode) throw new Error("OIDC callback did not contain an authorization code for PKCE rejection.");

    const wrongVerifier = randomOpaqueValue();
    expect(wrongVerifier).not.toBe(expectedVerifier);
    const wrongVerifierForm = new URLSearchParams({
      grant_type: "authorization_code",
      code: rejectedCode,
      redirect_uri: callbackUri,
      code_verifier: wrongVerifier
    }).toString();
    const wrongVerifierResponse = await requestHub(tokenPath, {
      ca: certificate,
      method: "POST",
      headers: {
        authorization: clientAuthorization,
        "content-type": "application/x-www-form-urlencoded",
        "content-length": String(Buffer.byteLength(wrongVerifierForm))
      },
      body: wrongVerifierForm
    });
    expect(wrongVerifierResponse.status).toBe(400);
    const wrongVerifierBody = parseJsonObject(wrongVerifierResponse.body, "OIDC PKCE rejection response is invalid.");
    expect(wrongVerifierBody.error === "invalid_grant").toBe(true);
  } finally {
    try {
      await context?.close();
    } finally {
      if (callbackServer.listening) {
        await new Promise<void>((resolve) => callbackServer.close(() => resolve()));
      }
    }
  }
});

function requestHub(path: string, options: {
  ca: Buffer;
  method?: "GET" | "POST";
  headers?: Record<string, string>;
  body?: string;
}): Promise<HubResponse> {
  if (!path.startsWith("/") || path.startsWith("//")) throw new Error("OIDC issuer endpoint path is invalid.");
  return new Promise((resolve, reject) => {
    const request = httpsRequest({
      hostname: "127.0.0.1",
      port: 3001,
      path,
      method: options.method ?? "GET",
      headers: { ...options.headers, Host: "portal.localhost:3001" },
      servername: "portal.localhost",
      ca: options.ca
    }, (response) => {
      const chunks: Buffer[] = [];
      response.on("data", (chunk: Buffer | string) => chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
      response.on("end", () => resolve({ status: response.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") }));
    });
    request.once("error", (error: unknown) => {
      const code = error && typeof error === "object" && "code" in error && typeof error.code === "string"
        ? error.code
        : "NETWORK_ERROR";
      reject(new Error("OIDC HTTPS request for " + path + " to portal.localhost failed (" + code + ")."));
    });
    request.end(options.body);
  });
}

async function completePortalLoginIfNeeded(page: import("@playwright/test").Page): Promise<void> {
  const emailInput = page.getByLabel("E-mail", { exact: true });
  if (!(await emailInput.isVisible())) return;
  await emailInput.fill(fixture.user.email);
  await page.getByLabel("Senha", { exact: true }).fill(fixture.user.password);
  await page.getByRole("button", { name: "Entrar", exact: true }).click();
}

async function registerRedirectUri(redirectUri: string): Promise<void> {
  const databaseUrl = process.env.BIELOS_E2E_DATABASE_URL?.trim();
  if (!databaseUrl) throw new Error("OIDC E2E requires the explicit disposable database fixture.");
  assertDisposableCoreTestDatabase(databaseUrl, process.env);
  const prisma = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
  try {
    const result = await prisma.projectConnection.updateMany({
      where: { id: fixture.projectConnectionId, clientId: fixture.oidc.clientId, enabled: true },
      data: { redirectUris: [redirectUri] }
    });
    if (result.count !== 1) throw new Error("OIDC E2E could not configure the run-scoped callback URI.");
  } finally {
    await prisma.$disconnect();
  }
}

function issuerEndpointPath(value: unknown, expectedPath: string): string {
  const endpointText = readString(value);
  if (!endpointText) throw new Error("OIDC discovery is missing a required endpoint.");
  const endpoint = new URL(endpointText);
  if (endpoint.origin !== portalUrl || endpoint.pathname !== expectedPath || endpoint.search || endpoint.hash) {
    throw new Error("OIDC discovery returned an unexpected issuer endpoint.");
  }
  return `${endpoint.pathname}${endpoint.search}`;
}

function parseJsonObject(value: string, errorMessage: string): Record<string, unknown> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new Error(errorMessage);
  }
  if (!isRecord(parsed)) throw new Error(errorMessage);
  return parsed;
}

function parseJwtSegment(value: string): Record<string, unknown> {
  try {
    return parseJsonObject(Buffer.from(value, "base64url").toString("utf8"), "OIDC ID token is malformed.");
  } catch {
    throw new Error("OIDC ID token is malformed.");
  }
}

function randomOpaqueValue(): string {
  return randomBytes(32).toString("base64url");
}

function isOidcFixture(value: unknown): value is OidcFixture {
  if (!isRecord(value) || !isRecord(value.user) || !isRecord(value.oidc)) return false;
  return typeof value.user.id === "string" && typeof value.user.email === "string" &&
    typeof value.user.password === "string" && typeof value.user.deviceToken === "string" &&
    typeof value.projectConnectionId === "string" && typeof value.oidc.clientId === "string" &&
    typeof value.oidc.clientSecret === "string";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function readString(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}
