import { createHash, createPublicKey, randomBytes, verify as verifySignature, X509Certificate, type JsonWebKey as NodeJsonWebKey } from "node:crypto";
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { request as httpsRequest, createServer as createHttpsServer } from "node:https";
import { TLSSocket } from "node:tls";
import { DEVICE_COOKIE_NAME } from "@virki/auth/constants";
import { PrismaClient } from "@virki/database";
import { expect, test, type BrowserContext } from "@playwright/test";

// @ts-expect-error This existing JavaScript safety helper has no declaration file.
import { assertDisposableCoreTestDatabase } from "../scripts/core-test-database-safety.mjs";

const portalUrl = "https://portal.localhost:3001";
const fixturePath = process.env.VIRKI_E2E_AUTH_FIXTURE_FILE;
const hasFixture = Boolean(fixturePath && existsSync(fixturePath));

test.skip(!process.env.VIRKI_E2E_DATABASE_URL?.trim() || !hasFixture, "OIDC E2E requires the explicit disposable database fixture.");

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
  const keyPath = process.env.VIRKI_E2E_TLS_KEY_PATH;
  const certificatePath = process.env.VIRKI_E2E_TLS_CERTIFICATE_PATH;
  const caCertificatePath = process.env.VIRKI_E2E_TLS_CA_CERTIFICATE_PATH;
  if (!keyPath || !certificatePath || !caCertificatePath) throw new Error("OIDC E2E loopback TLS material is unavailable.");
  const [key, certificate, caCertificate] = await Promise.all([readFile(keyPath), readFile(certificatePath), readFile(caCertificatePath)]);
  const serverCertificate = new X509Certificate(certificate);
  const testCaCertificate = new X509Certificate(caCertificate);
  if (serverCertificate.ca || !testCaCertificate.ca || !serverCertificate.verify(testCaCertificate.publicKey) || !serverCertificate.checkHost("portal.localhost")) {
    throw new Error("OIDC E2E server certificate is not a valid leaf signed by the test CA.");
  }
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
    const discoveryResponse = await requestHub("/.well-known/openid-configuration", { ca: caCertificate, expectedCertificate: certificate });
    expect(discoveryResponse.status).toBe(200);
    const discovery = parseJsonObject(discoveryResponse.body, "OIDC discovery response is invalid.");
    expect(discovery.issuer === portalUrl).toBe(true);

    const authorizationPath = issuerEndpointPath(discovery.authorization_endpoint, "/auth");
    const tokenPath = issuerEndpointPath(discovery.token_endpoint, "/token");
    const jwksPath = issuerEndpointPath(discovery.jwks_uri, "/jwks");
    const userinfoPath = issuerEndpointPath(discovery.userinfo_endpoint, "/me");
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

    context = await browser.newContext();
    await context.addCookies([{
      name: DEVICE_COOKIE_NAME,
      value: fixture.user.deviceToken,
      url: portalUrl,
      httpOnly: true,
      secure: true,
      sameSite: "Lax"
    }]);
    const page = await context.newPage();
    const flowResponses: string[] = [];
    page.on("response", (response) => {
      const responseUrl = new URL(response.url());
      if (responseUrl.origin !== portalUrl || !["document", "fetch", "xhr"].includes(response.request().resourceType())) return;
      const path = safeOidcPagePath(responseUrl.pathname);
      const redirect = response.status() >= 300 && response.status() < 400
        ? safeOidcRedirect(response.headers()["location"], responseUrl, callbackUri)
        : "";
      const loginDenial = responseUrl.pathname === "/api/login" && response.status() === 403
        ? ` (${loginDenialDiagnostic(response.headers())}; request-origin=${safeOriginKind(response.request().headers().origin, portalUrl)})`
        : "";
      flowResponses.push(`${response.request().method()} ${path} ${response.status()}${redirect}${loginDenial}`);
      if (flowResponses.length > 16) flowResponses.shift();
    });
    await page.goto(makeAuthorizationUrl(codeChallenge, state, nonce).href);
    await completePortalLoginIfNeeded(page, true);

    const callback = await waitForAuthorizationCallback(page, callbackUri, nextCallback, flowResponses);
    expect(flowResponses).toContain("GET /auth/[route] 303 -> callback/callback");
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
      ca: caCertificate,
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
    const accessToken = readString(tokenSet.access_token);
    if (!accessToken) throw new Error("OIDC token response did not contain an access token.");
    const [headerPart, claimsPart, signaturePart, extraPart] = idToken.split(".");
    if (!headerPart || !claimsPart || !signaturePart || extraPart !== undefined) throw new Error("OIDC ID token is malformed.");
    const header = parseJwtSegment(headerPart);
    const claims = parseJwtSegment(claimsPart);
    expect(header.alg === "ES256").toBe(true);
    const jwksResponse = await requestHub(jwksPath, { ca: caCertificate });
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
    expect(typeof claims.exp === "number" && claims.exp > Math.floor(Date.now() / 1_000)).toBe(true);

    const userinfoResponse = await requestHub(userinfoPath, {
      ca: caCertificate,
      headers: { authorization: `Bearer ${accessToken}` }
    });
    expect(userinfoResponse.status).toBe(200);
    const userinfo = parseJsonObject(userinfoResponse.body, "OIDC UserInfo response is invalid.");
    expect(userinfo.sub === fixture.user.id).toBe(true);
    expect(userinfo.email === fixture.user.email).toBe(true);
    expect(userinfo.email_verified === true).toBe(true);

    const replayResponse = await requestHub(tokenPath, {
      ca: caCertificate,
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
    flowResponses.length = 0;
    await page.goto(makeAuthorizationUrl(expectedChallenge, rejectedState, rejectedNonce).href);
    await completePortalLoginIfNeeded(page);
    const rejectedCallback = await waitForAuthorizationCallback(page, callbackUri, nextCallback, flowResponses);
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
      ca: caCertificate,
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
  expectedCertificate?: Buffer;
  method?: "GET" | "POST";
  headers?: Record<string, string>;
  body?: string;
}): Promise<HubResponse> {
  if (!path.startsWith("/") || path.startsWith("//")) throw new Error("OIDC issuer endpoint path is invalid.");
  return new Promise((resolve, reject) => {
    let tlsSocket: TLSSocket | undefined;
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
    request.once("socket", (socket) => {
      if (socket instanceof TLSSocket) tlsSocket = socket;
    });
    request.once("error", (error: unknown) => {
      const code = error && typeof error === "object" && "code" in error && typeof error.code === "string"
        ? error.code
        : "NETWORK_ERROR";
      const socket = tlsSocket ?? (request.socket instanceof TLSSocket ? request.socket : undefined);
      const peer = socket?.getPeerCertificate(true);
      const peerFingerprint = typeof peer?.fingerprint256 === "string" ? peer.fingerprint256 : "unavailable";
      const peerSubject = safeCommonName(peer?.subject);
      const peerIssuer = safeCommonName(peer?.issuer);
      const peerChain = safeCertificateChain(peer);
      const opensslPeerChain = safeOpenSslPeerChain(process.env.VIRKI_E2E_TLS_CA_CERTIFICATE_PATH);
      const expectedFingerprint = options.expectedCertificate ? new X509Certificate(options.expectedCertificate).fingerprint256 : "unavailable";
      const caFingerprint = new X509Certificate(options.ca).fingerprint256;
      const authorizationError = socket?.authorizationError ? String(socket.authorizationError).replace(/[^A-Z0-9_-]/giu, "").slice(0, 80) : "none";
      reject(new Error(`OIDC HTTPS request for ${path} to portal.localhost failed (${code}; peer=${peerFingerprint}; peerSubject=${peerSubject}; peerIssuer=${peerIssuer}; peerChain=${peerChain}; opensslPeerChain=${opensslPeerChain}; expectedLeaf=${expectedFingerprint}; trustedCA=${caFingerprint}; authorization=${authorizationError}).`));
    });
    request.end(options.body);
  });
}

function loginDenialDiagnostic(headers: Record<string, string>): string {
  const ceremonyStages = new Set([
    "transaction-start",
    "account-lookup",
    "account-state",
    "account-lock-query",
    "account-lock-no-match",
    "trusted-device-lookup",
    "remembered-challenges-revoke",
    "remembered-session-create",
    "challenge-revoke",
    "ceremony-rate-limited",
    "challenge-code-hash",
    "challenge-create",
    "outbox-enqueue",
    "transaction-commit"
  ]);
  const allowedReasons = new Set([
    "cloudflare-access",
    "csrf-expired",
    "csrf-invalid",
    "csrf-malformed",
    "csrf-misconfigured",
    "csrf-missing",
    "csrf-wrong-scope",
    "expired-cloudflare-access-jwt",
    "inactive-cloudflare-access-jwt",
    "invalid-cloudflare-access-audience",
    "invalid-cloudflare-access-config",
    "invalid-cloudflare-access-issuer",
    "invalid-cloudflare-access-jwt",
    "invalid-cloudflare-access-signature",
    "missing-cloudflare-access-config",
    "missing-cloudflare-access-jwt",
    "missing-cloudflare-access-signing-key",
    "same-origin",
    "same-origin-missing-origin",
    "same-origin-missing-host",
    "same-origin-invalid-host",
    "same-origin-malformed-origin",
    "same-origin-null-origin",
    "same-origin-comma-in-origin",
    "same-origin-disallowed-protocol",
    "same-origin-authority-mismatch",
    "same-origin-hostname-mismatch",
    "same-origin-port-mismatch",
    "same-origin-invalid-origin-components",
    "input-too-long",
    "authentication-invalid-credentials",
    "authentication-rate-limited",
    "authentication-limiter-unavailable",
    "role-mismatch",
    "security-ceremony-unavailable"
  ]);
  const routeReason = headers["x-virki-e2e-login-reason"];
  if (routeReason) {
    const stage = routeReason.startsWith("security-ceremony-unavailable-")
      ? routeReason.slice("security-ceremony-unavailable-".length)
      : "";
    const recognized = allowedReasons.has(routeReason) || ceremonyStages.has(stage);
    return `login-route:${recognized ? routeReason : "unrecognized"}`;
  }
  const proxyReason = headers["x-virki-e2e-access-reason"];
  if (proxyReason) {
    const stage = proxyReason.startsWith("security-ceremony-unavailable-")
      ? proxyReason.slice("security-ceremony-unavailable-".length)
      : "";
    const recognized = allowedReasons.has(proxyReason) || ceremonyStages.has(stage);
    return `hub-proxy:${recognized ? proxyReason : "unrecognized"}`;
  }
  return "not-reported";
}

function safeOriginKind(value: string | undefined, expectedOrigin: string): string {
  if (!value) return "missing";
  if (value === "null") return "null-origin";
  return value === expectedOrigin ? "same-origin" : "other-origin";
}

function safeCertificateChain(value: unknown): string {
  const fingerprints: string[] = [];
  const visited = new Set<object>();
  let current = value;
  while (current && typeof current === "object" && !visited.has(current)) {
    visited.add(current);
    if ("fingerprint256" in current && typeof current.fingerprint256 === "string") fingerprints.push(current.fingerprint256);
    current = "issuerCertificate" in current ? current.issuerCertificate : undefined;
  }
  return fingerprints.length ? fingerprints.join(",") : "unavailable";
}

function safeOpenSslPeerChain(caPath: string | undefined): string {
  if (!caPath) return "unavailable";
  let output: string;
  try {
    output = execFileSync("openssl", [
      "s_client", "-connect", "127.0.0.1:3001", "-servername", "portal.localhost",
      "-verify_hostname", "portal.localhost", "-verify_return_error", "-verify", "5",
      "-CAfile", caPath, "-no-CApath", "-showcerts"
    ], { encoding: "utf8", input: "", timeout: 5_000, maxBuffer: 64 * 1024 });
  } catch (error) {
    if (!error || typeof error !== "object") return "unavailable";
    const stdout = "stdout" in error ? String(error.stdout ?? "") : "";
    const stderr = "stderr" in error ? String(error.stderr ?? "") : "";
    output = `${stdout}\n${stderr}`;
  }
  const certificates = [...output.matchAll(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/gu)]
    .slice(0, 3)
    .map(([pem]) => {
      try { return new X509Certificate(pem).fingerprint256; } catch { return undefined; }
    })
    .filter((fingerprint): fingerprint is string => Boolean(fingerprint));
  return certificates.length ? certificates.join(",") : "unavailable";
}

function safeCommonName(value: unknown): string {
  if (!value || typeof value !== "object" || !("CN" in value)) return "unavailable";
  const commonName = value.CN;
  const text = Array.isArray(commonName) ? commonName[0] : commonName;
  if (typeof text !== "string") return "unavailable";
  return text.replace(/[^\p{L}\p{N} ._-]/gu, "").slice(0, 80) || "unavailable";
}

async function completePortalLoginIfNeeded(page: import("@playwright/test").Page, required = false): Promise<void> {
  const emailInput = page.getByLabel("E-mail", { exact: true });
  if (!required && !(await emailInput.isVisible())) return;
  await expect(emailInput).toBeVisible({ timeout: 10_000 });
  const documentOrigin = await page.evaluate(() => window.origin);
  await emailInput.fill(fixture.user.email);
  await page.getByLabel("Senha", { exact: true }).fill(fixture.user.password);
  const loginResponsePromise = page.waitForResponse((response) =>
    new URL(response.url()).pathname === "/api/login" && response.request().method() === "POST"
  );
  await page.getByRole("button", { name: "Entrar", exact: true }).click();
  const loginResponse = await loginResponsePromise;
  const requestOrigin = loginResponse.request().headers().origin;
  if (loginResponse.status() === 403) {
    throw new Error(`OIDC login POST was denied (${loginDenialDiagnostic(loginResponse.headers())}; document-origin=${safeOriginKind(documentOrigin, portalUrl)}; request-origin=${safeOriginKind(requestOrigin, portalUrl)}).`);
  }
  expect(documentOrigin).toBe(portalUrl);
  expect(requestOrigin).toBe(portalUrl);
  const location = loginResponse.headers().location;
  if (loginResponse.status() === 303 && location) {
    const redirect = new URL(location, portalUrl);
    if (redirect.pathname === "/login" && redirect.searchParams.get("error") === "1") {
      throw new Error(`OIDC login was rejected (${loginDenialDiagnostic(loginResponse.headers())}).`);
    }
  }
  await expect(emailInput).toBeHidden({ timeout: 10_000 });
}

async function waitForAuthorizationCallback(
  page: import("@playwright/test").Page,
  callbackUri: string,
  nextCallback: () => Promise<URL>,
  flowResponses: string[]
): Promise<URL> {
  const callbackOrigin = new URL(callbackUri).origin;
  const callback = nextCallback();
  try {
    await page.waitForURL((url) => url.origin === callbackOrigin && url.pathname === "/callback", { timeout: 15_000 });
  } catch {
    const currentUrl = new URL(page.url());
    const pathname = currentUrl.pathname;
    const origin = currentUrl.origin === callbackOrigin ? "callback" : currentUrl.origin === portalUrl ? "portal" : "other";
    const pageState = pathname === "/login" ? "login"
      : pathname === "/login/verify" ? "login-verification"
        : pathname === "/" ? "portal-home"
          : pathname === "/account/security" ? "account-security"
            : pathname.startsWith("/interaction/") ? "interaction"
              : pathname === "/auth" ? "auth" : "other";
    const pagePath = safeOidcPagePath(pathname);
    const loginFormVisible = await page.getByLabel("E-mail", { exact: true }).isVisible().catch(() => false);
    const alerts = await page.getByRole("alert").allTextContents().catch(() => []);
    const safeAlert = alerts.map(sanitizeDiagnosticText).filter(Boolean).slice(0, 2).join(" | ") || "none";
    const bodyText = await page.locator("body").innerText().catch(() => "");
    const bodyState = classifyOidcPageContent(bodyText);
    throw new Error(`OIDC browser did not reach its callback (origin=${origin}; pageState=${pageState}; pagePath=${pagePath}; bodyState=${bodyState}; loginFormVisible=${loginFormVisible}; alert=${safeAlert}; responses=${flowResponses.join(",") || "none"}).`);
  }
  return callback;
}

function safeOidcPagePath(pathname: string): string {
  if (["/", "/login", "/login/verify", "/account/security", "/auth", "/callback", "/api/login", "/api/login/verify", "/token", "/jwks", "/me", "/session/end"].includes(pathname)) return pathname;
  if (pathname.startsWith("/.well-known/")) return "/.well-known/[route]";
  if (pathname.startsWith("/_next/")) return "/_next/[asset]";
  if (/^\/(?:interaction|resume)\/[^/]+$/u.test(pathname)) return pathname.startsWith("/interaction/") ? "/interaction/[id]" : "/resume/[id]";
  if (/^\/login\/.+$/u.test(pathname)) return "/login/[route]";
  if (pathname.startsWith("/account/")) return "/account/[route]";
  if (pathname.startsWith("/api/")) return "/api/[route]";
  const [first] = pathname.split("/").filter(Boolean);
  if (first && /^[a-z][a-z-]{0,31}$/u.test(first)) return `/${first}/[route]`;
  return "unrecognized";
}

function safeOidcRedirect(location: string | undefined, responseUrl: URL, callbackUri: string): string {
  if (!location) return "";
  try {
    const target = new URL(location, responseUrl);
    const targetOrigin = target.origin === portalUrl ? "portal" : target.origin === new URL(callbackUri).origin ? "callback" : "other";
    return ` -> ${targetOrigin}${safeOidcPagePath(target.pathname)}`;
  } catch {
    return " -> invalid";
  }
}

function classifyOidcPageContent(value: string): string {
  const text = value.toLowerCase();
  if (!text.trim()) return "empty";
  if (/\b404\b|not found|não encontrado/iu.test(text)) return "not-found";
  if (/\b500\b|internal server error|application error|erro interno/iu.test(text)) return "server-error";
  if (/access denied|forbidden|acesso negado/iu.test(text)) return "access-denied";
  if (/consent|consentimento/iu.test(text)) return "consent";
  if (/entrar|sign in|e-mail/iu.test(text)) return "login";
  return "other";
}

function sanitizeDiagnosticText(value: string): string {
  return value
    .replace(/https?:\/\/\S+/giu, "[url]")
    .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/giu, "[email]")
    .replace(/\b\d{6}\b/gu, "[code]")
    .replace(/\b[A-Z0-9_-]{20,}\b/giu, "[opaque]")
    .replace(/\s+/gu, " ")
    .trim()
    .slice(0, 120);
}

async function registerRedirectUri(redirectUri: string): Promise<void> {
  const databaseUrl = process.env.VIRKI_E2E_DATABASE_URL?.trim();
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
