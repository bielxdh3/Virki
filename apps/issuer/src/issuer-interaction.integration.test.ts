// Exercises the actual issuer listener and interaction handler, with synthetic keys and a guarded disposable DB.
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { createHash, createHmac, generateKeyPairSync, randomBytes, randomUUID } from "node:crypto";
import { connect as connectTcp, createServer } from "node:net";
import { after, before, test } from "node:test";
import { createRateLimitIdentifierHash } from "../../../packages/auth/src/rate-limit-config";
import { createSession, getSessionByToken, SESSION_COOKIE_NAME } from "@virki/auth";
import { grantProjectAccess, revokeProjectAccess } from "@virki/auth/administration";
import { decryptOidcPayload, encryptOidcClientSecret, hashOidcIdentifier } from "@virki/auth/oidc-secrets";
import { prisma } from "@virki/database";
import { createTestUser, integrationOptions, queuedEmails, seedAdminSessionWithElevation } from "../../../packages/auth/src/integration-fixtures";
import { selectAuthRateLimits, selectInteractionRateLimits, selectPublicOidcRateLimits, selectTokenRateLimits } from "./rate-limit-policy";
import { createTotpSecret, startLoginCeremony, verifyLoginEmailCode, verifyLoginTotpCode } from "@virki/auth/security";

let child: ChildProcess;
let origin: string;
const redirectUri = "https://project.integration.invalid/callback";
const clientSecret = randomBytes(32).toString("base64url");
const verifier = randomBytes(32).toString("base64url");

before(async () => {
  if (integrationOptions.skip) return;
  const reservation = createServer();
  await new Promise<void>((resolve) => reservation.listen(0, "127.0.0.1", resolve));
  const address = reservation.address();
  assert.ok(address && typeof address !== "string");
  const port = address.port;
  await new Promise<void>((resolve) => reservation.close(() => resolve()));
  origin = `http://127.0.0.1:${port}`;
  const key = generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey.export({ format: "jwk" });
  child = spawn(process.execPath, ["--import", "tsx", "apps/issuer/src/server.ts"], {
    windowsHide: true,
    env: { ...process.env, VIRKI_OIDC_ISSUER: origin, OIDC_ISSUER_PORT: String(port), VIRKI_OIDC_BIND_ADDRESS: "127.0.0.1",
      VIRKI_AUDIT_HASH_SECRET: randomBytes(32).toString("hex"),
      VIRKI_OIDC_COOKIE_KEY: randomBytes(32).toString("base64url"),
      VIRKI_OIDC_SIGNING_JWKS: JSON.stringify({ keys: [{ ...key, kid: "integration", alg: "ES256", use: "sig" }] }) },
    stdio: ["ignore", "pipe", "pipe"]
  });
  await new Promise<void>((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error("Local issuer did not start within 15 seconds.")), 15_000);
    child.once("exit", () => { clearTimeout(timeout); reject(new Error("Local issuer exited before startup.")); });
    child.stdout?.on("data", (chunk) => {
      if (String(chunk).includes("Virki OIDC issuer ready.")) { clearTimeout(timeout); resolve(); }
    });
  });
});

after(async () => {
  if (child && child.exitCode === null) {
    // The Node child owns the listener directly; no shell or production service is involved.
    child.kill();
    await new Promise<void>((resolve) => child.once("exit", () => resolve()));
  }
  await prisma.$disconnect();
});

test("actual issuer returns 400 for an invalid request target and keeps serving", integrationOptions, async () => {
  const reservation = createServer();
  await new Promise<void>((resolve) => reservation.listen(0, "127.0.0.1", resolve));
  const address = reservation.address();
  assert.ok(address && typeof address !== "string");
  const port = address.port;
  await new Promise<void>((resolve) => reservation.close(() => resolve()));
  const isolatedOrigin = `http://127.0.0.1:${port}`;
  const key = generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey.export({ format: "jwk" });
  const isolatedChild = spawn(process.execPath, ["--import", "tsx", "apps/issuer/src/server.ts"], {
    windowsHide: true,
    env: { ...process.env, VIRKI_OIDC_ISSUER: isolatedOrigin, OIDC_ISSUER_PORT: String(port), VIRKI_OIDC_BIND_ADDRESS: "127.0.0.1",
      VIRKI_AUDIT_HASH_SECRET: randomBytes(32).toString("hex"),
      VIRKI_OIDC_COOKIE_KEY: randomBytes(32).toString("base64url"),
      VIRKI_OIDC_SIGNING_JWKS: JSON.stringify({ keys: [{ ...key, kid: "malformed-target-test", alg: "ES256", use: "sig" }] }) },
    stdio: ["ignore", "pipe", "pipe"]
  });
  let stderr = "";
  isolatedChild.stderr?.on("data", (chunk) => { stderr += String(chunk); });

  try {
    await new Promise<void>((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error("Isolated issuer did not start within 15 seconds.")), 15_000);
      isolatedChild.once("exit", (code) => { clearTimeout(timeout); reject(new Error(`Isolated issuer exited before startup (${code}): ${stderr}`)); });
      isolatedChild.stdout?.on("data", (chunk) => {
        if (String(chunk).includes("Virki OIDC issuer ready.")) { clearTimeout(timeout); resolve(); }
      });
    });

    const malformedResponse = await new Promise<string>((resolve, reject) => {
      const socket = connectTcp(port, "127.0.0.1");
      const chunks: Buffer[] = [];
      socket.setTimeout(5_000, () => socket.destroy(new Error("Malformed-target request timed out.")));
      socket.once("connect", () => socket.write("GET //:80 HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"));
      socket.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
      socket.once("end", () => resolve(Buffer.concat(chunks).toString("latin1")));
      socket.once("error", reject);
    }).catch(() => "");
    assert.match(malformedResponse, /^HTTP\/1\.1 400\b/u, `Expected a controlled 400; issuer stderr: ${stderr}`);
    assert.equal(isolatedChild.exitCode, null, "Malformed input must not terminate the issuer process.");

    const validResponse = await fetch(`${isolatedOrigin}/.well-known/openid-configuration`);
    assert.equal(validResponse.status, 200);
    assert.equal((await validResponse.json() as { issuer?: string }).issuer, isolatedOrigin);
  } finally {
    if (isolatedChild.exitCode === null && isolatedChild.signalCode === null) {
      const exited = new Promise<void>((resolve) => isolatedChild.once("exit", () => resolve()));
      isolatedChild.kill();
      await exited;
    }
  }
});

test("actual issuer rejects endpoint aliases and rate-limits the public userinfo route", integrationOptions, async () => {
  for (const path of ["/AUTH", "/auth/", "/AUTH/", "/AUTH/abcdefgh"]) {
    const response = await fetch(`${origin}${path}`, { redirect: "manual" });
    assert.equal(response.status, 404, `${path} must not reach a provider alias route`);
    assert.equal(response.headers.get("location"), null);
  }
  const methodAlias = await fetch(`${origin}/auth`, { method: "POST", redirect: "manual" });
  assert.equal(methodAlias.status, 405);
  assert.equal(methodAlias.headers.get("allow"), "GET");

  const headers = { "cf-connecting-ip": randomClientAddress() };
  let response: Response | undefined;
  for (let attempt = 0; attempt < 31; attempt += 1) response = await fetch(`${origin}/me`, { headers, redirect: "manual" });
  assert.equal(response?.status, 429, "the public userinfo route must stop after its anonymous per-IP quota");
  assert.equal(response?.headers.get("retry-after"), "900");
});

test("rotating invalid session cookies share one anonymous interaction bucket", integrationOptions, async () => {
  const fixture = await seed();
  const client = browser();
  const clientAddress = randomClientAddress();
  const sourceHeaders = { "cf-connecting-ip": clientAddress };
  const started = await client.request(authorization(fixture.clientId), { headers: sourceHeaders });
  assert.equal(started.status, 303);
  const interactionUrl = new URL(started.headers.get("location")!, origin);
  assert.match(interactionUrl.pathname, /^\/interaction\/[A-Za-z0-9_-]{8,80}$/u);

  const rotatedCookies = Array.from({ length: 301 }, () => randomBytes(32).toString("base64url"));
  const trackedHashes = [
    ...selectAuthRateLimits(clientAddress, null),
    ...selectInteractionRateLimits(clientAddress, null)
  ].map(({ identifier }) => createRateLimitIdentifierHash(identifier));
  const startedAt = performance.now();
  const observations = await Promise.all(rotatedCookies.map(async (cookie): Promise<{ status: number } | { transportError: string }> => {
    client.setSession(cookie);
    try {
      const response = await client.request(interactionUrl.href, { headers: sourceHeaders });
      return { status: response.status };
    } catch (error) {
      return { transportError: error instanceof Error ? error.name : "unknown" };
    }
  }));
  const elapsedMs = performance.now() - startedAt;

  const storedBuckets = await prisma.loginRateLimit.count({ where: { identifierHash: { in: trackedHashes } } });
  const httpStatuses = observations.flatMap((observation) => "status" in observation ? [observation.status] : []);
  const transportErrors = observations.flatMap((observation) => "transportError" in observation ? [observation.transportError] : []);
  const statusCounts = Object.fromEntries([...new Set(httpStatuses)].sort((left, right) => left - right)
    .map((status) => [String(status), httpStatuses.filter((observed) => observed === status).length]));
  const blocked = httpStatuses.filter((status) => status === 429).length;
  const storageErrors = httpStatuses.filter((status) => status === 503).length;
  console.log(`rotating invalid cookie load: ${JSON.stringify({ requests: observations.length, statuses: statusCounts, transportErrors: transportErrors.length, transportErrorKinds: [...new Set(transportErrors)].sort(), rows: storedBuckets, denied_429: blocked, storage_503: storageErrors, elapsed_ms: Number(elapsedMs.toFixed(1)) })}`);

  assert.equal(observations.length, 301, "every planned cookie request must produce one observation");
  assert.equal(transportErrors.length, 0, `request transport errors=${JSON.stringify(transportErrors)}`);
  assert.equal(storedBuckets, 4,
    "unknown cookies should share the auth source/anonymous and interaction source/anonymous rows");
  assert.equal(blocked, 271,
    `300 requests must hit the source ceiling and 30-attempt anonymous bucket without identity amplification; statuses=${JSON.stringify(statusCounts)}`);
  assert.equal(storageErrors, 0,
    `the bounded flood must not turn limiter contention into storage errors; statuses=${JSON.stringify(statusCounts)}`);
  assert.deepEqual(statusCounts, { "303": 30, "429": 271 },
    "all non-denied requests should remain normal login redirects, with no unclassified response status");
});

test("unsupported interaction methods return 405 before auditing or consuming limiter rows", integrationOptions, async () => {
  const fixture = await seed();
  const client = browser();
  const clientAddress = randomClientAddress();
  const headers = { "cf-connecting-ip": clientAddress };
  const started = await client.request(authorization(fixture.clientId), { headers });
  assert.equal(started.status, 303);
  const interactionUrl = new URL(started.headers.get("location")!, origin);
  assert.match(interactionUrl.pathname, /^\/interaction\/[A-Za-z0-9_-]{8,80}$/u);
  const trackedHashes = [...selectAuthRateLimits(clientAddress, null), ...selectInteractionRateLimits(clientAddress, null)]
    .map(({ identifier }) => createRateLimitIdentifierHash(identifier));
  const beforeAudit = await prisma.auditLog.count({ where: { eventType: "SSO_INTERACTION_STARTED" } });
  const beforeLimiter = await prisma.loginRateLimit.count({ where: { identifierHash: { in: trackedHashes } } });

  for (const method of ["POST", "PUT", "HEAD", "DELETE"]) {
    const response = await client.request(interactionUrl.href, { method, headers });
    assert.equal(response.status, 405, `${method} must be rejected before interaction handling`);
    assert.equal(response.headers.get("allow"), "GET");
  }
  assert.equal(await prisma.auditLog.count({ where: { eventType: "SSO_INTERACTION_STARTED" } }), beforeAudit);
  assert.equal(await prisma.loginRateLimit.count({ where: { identifierHash: { in: trackedHashes } } }), beforeLimiter);
});

test("rotating invalid bearer tokens share one anonymous UserInfo bucket", integrationOptions, async () => {
  const clientAddress = randomClientAddress();
  const rotatedTokens = Array.from({ length: 301 }, () => randomBytes(32).toString("base64url"));
  const trackedHashes = [
    ...selectPublicOidcRateLimits(clientAddress, null, "userinfo")
  ].map(({ identifier }) => createRateLimitIdentifierHash(identifier));
  let response: Response | undefined;
  let denied = 0;
  const startedAt = performance.now();
  for (const token of rotatedTokens) {
    response = await fetch(`${origin}/me`, {
      headers: { "cf-connecting-ip": clientAddress, authorization: `Bearer ${token}` },
      redirect: "manual"
    });
    if (response.status === 429) denied += 1;
  }
  const elapsedMs = performance.now() - startedAt;

  assert.equal(response?.status, 429, "unknown bearer-token rotation must hit the shared source ceiling");
  assert.equal(denied, 271, "the 300-request source budget and anonymous bucket must both be enforced");
  assert.equal(await prisma.loginRateLimit.count({ where: { identifierHash: { in: trackedHashes } } }), 2,
    "unknown bearer tokens should share only the UserInfo source and anonymous rows");
  console.log(`rotating invalid bearer load: requests=${rotatedTokens.length}, rows=2, denied_429=${denied}, elapsed_ms=${elapsedMs.toFixed(1)}`);
});

test("rotating unregistered Basic client IDs share one bounded invalid-token bucket", integrationOptions, async () => {
  const clientAddress = randomClientAddress();
  const clientIds = Array.from({ length: 301 }, () => `unregistered-${randomUUID()}`);
  const authorizationFor = (clientId: string) => `Basic ${Buffer.from(`${clientId}:not-a-secret`).toString("base64")}`;
  const trackedHashes = selectTokenRateLimits(clientAddress, null).map(({ identifier }) => createRateLimitIdentifierHash(identifier));

  const startedAt = performance.now();
  for (const clientId of clientIds) {
    const response = await fetch(`${origin}/token`, {
      method: "POST",
      headers: {
        "cf-connecting-ip": clientAddress,
        authorization: authorizationFor(clientId),
        "content-type": "application/x-www-form-urlencoded"
      },
      body: new URLSearchParams({ grant_type: "client_credentials" }),
      redirect: "manual"
    });
    assert.notEqual(response.status, 503, "bounded registered-client lookups must fail closed only on storage errors");
  }
  const elapsedMs = performance.now() - startedAt;

  assert.equal(await prisma.loginRateLimit.count({ where: { identifierHash: { in: trackedHashes } } }), 2,
    "unregistered client IDs should share only the token source and invalid-client rows");
  console.log(`rotating unregistered client load: requests=${clientIds.length}, rows=2, lookup_ceiling=2000/15m, elapsed_ms=${elapsedMs.toFixed(1)}`);
});

test("a validated browser session retains its per-session quota and completes a real OIDC flow", integrationOptions, async () => {
  const fixture = await seed();
  const clientAddress = randomClientAddress();
  const client = browser();
  const created = await createSession(fixture.userId);
  const session = await getSessionByToken(created.token);
  assert.ok(session);
  client.setSession(created.token);

  const result = await client.follow(authorization(fixture.clientId), { headers: { "cf-connecting-ip": clientAddress } });
  assert.equal(result.origin, "https://project.integration.invalid");
  assert.ok(result.searchParams.get("code"));

  const sessionBuckets = [...selectAuthRateLimits(clientAddress, session.id), ...selectInteractionRateLimits(clientAddress, session.id)]
    .map(({ identifier }) => createRateLimitIdentifierHash(identifier));
  assert.equal(await prisma.loginRateLimit.count({ where: { identifierHash: { in: sessionBuckets } } }), 4,
    "the validated session must keep separate auth and interaction buckets alongside their source ceilings");
});

test("valid sessions can outpace one expired-row cleanup batch while staying under the source ceiling", integrationOptions, async () => {
  const fixture = await seed();
  const clientAddress = randomClientAddress();
  const sessions = [] as Array<{ token: string; id: string }>;
  for (let index = 0; index < 129; index += 1) {
    const created = await createSession(fixture.userId);
    const session = await getSessionByToken(created.token);
    assert.ok(session, `session ${index + 1} must validate`);
    sessions.push({ token: created.token, id: session.id });
  }

  const startedAt = performance.now();
  for (const { token } of sessions) {
    const client = browser();
    client.setSession(token);
    assert.equal((await client.request(authorization(fixture.clientId), { headers: { "cf-connecting-ip": clientAddress } })).status, 303);
  }
  const elapsedMs = performance.now() - startedAt;
  const trackedHashes = [
    ...selectAuthRateLimits(clientAddress, null).slice(0, 1),
    ...sessions.map(({ id }) => selectAuthRateLimits(clientAddress, id)[1])
  ].map(({ identifier }) => createRateLimitIdentifierHash(identifier));
  const generatedRows = await prisma.loginRateLimit.count({ where: { identifierHash: { in: trackedHashes } } });
  assert.equal(generatedRows, 130, "129 distinct valid sessions create one source row and 129 identity rows");
  console.log(`valid session cardinality: requests=129, rows=${generatedRows}, cleanup_batch_limit=128, elapsed_ms=${elapsedMs.toFixed(1)}`);
});

for (const invalidation of [
  {
    label: "revoked session",
    apply: (sessionId: string, _userId: string) => prisma.session.update({ where: { id: sessionId }, data: { revokedAt: new Date() } })
  },
  {
    label: "blocked account",
    apply: (_sessionId: string, userId: string) => prisma.user.update({ where: { id: userId }, data: { isActive: false, accountStatus: "BLOCKED" } })
  }
]) {
test(`interaction rechecks a ${invalidation.label} after its identity limiter wait`, integrationOptions, async () => {
  const fixture = await seed();
  const clientAddress = randomClientAddress();
  const headers = { "cf-connecting-ip": clientAddress };
  const client = browser();
  const created = await createSession(fixture.userId);
  const session = await getSessionByToken(created.token);
  assert.ok(session);
  client.setSession(created.token);
  const started = await client.request(authorization(fixture.clientId), { headers });
  assert.equal(started.status, 303);
  const interactionUrl = started.headers.get("location");
  assert.ok(interactionUrl);

  const identityHash = createRateLimitIdentifierHash(selectInteractionRateLimits(clientAddress, session.id)[1].identifier);
  let release!: () => void;
  let locked!: () => void;
  let blockerPid = 0;
  const acquired = new Promise<void>((resolve) => { locked = resolve; });
  const gate = new Promise<void>((resolve) => { release = resolve; });
  const holder = prisma.$transaction(async (transaction) => {
    [{ pid: blockerPid }] = await transaction.$queryRaw<Array<{ pid: number }>>`SELECT pg_backend_pid() AS pid`;
    await transaction.$queryRaw`SELECT pg_advisory_xact_lock(hashtextextended(${identityHash}, 0)) IS NULL AS "locked"`;
    locked();
    await gate;
  }, { timeout: 10000 });
  await acquired;

  try {
    const pendingResponse = client.request(interactionUrl, { headers });
    const waiterPid = await waitForBlockedQuery(blockerPid, "pg_advisory_xact_lock");
    assert.ok(waiterPid > 0, "the request must be blocked by this test's per-session limiter lock");
    await invalidation.apply(session.id, fixture.userId);
    release();

    const response = await pendingResponse;
    assert.equal(response.status, 303);
    assert.equal(new URL(response.headers.get("location")!, origin).pathname, "/login",
      "the authorization handler must re-read the session after limiter waiting");
  } finally {
    release();
    await holder;
  }
});
}

test("a registered client and its real access token still use their scoped OIDC quotas", integrationOptions, async () => {
  const fixture = await seed();
  const clientAddress = randomClientAddress();
  const client = browser();
  client.setSession((await createSession(fixture.userId)).token);
  const result = await client.follow(authorization(fixture.clientId), { headers: { "cf-connecting-ip": clientAddress } });
  assert.ok(result.searchParams.get("code"));

  const token = await exchange(fixture.clientId, result.searchParams.get("code")!, clientAddress);
  assert.equal(token.status, 200);
  assert.ok(token.body.access_token);
  const userinfo = await fetch(`${origin}/me`, {
    headers: { "cf-connecting-ip": clientAddress, authorization: `Bearer ${token.body.access_token}` },
    redirect: "manual"
  });
  assert.equal(userinfo.status, 200);

  const tokenBuckets = selectTokenRateLimits(clientAddress, fixture.clientId).map(({ identifier }) => createRateLimitIdentifierHash(identifier));
  const userinfoBuckets = selectPublicOidcRateLimits(clientAddress, null, "userinfo", token.body.access_token).map(({ identifier }) => createRateLimitIdentifierHash(identifier));
  assert.equal(await prisma.loginRateLimit.count({ where: { identifierHash: { in: [...tokenBuckets, ...userinfoBuckets] } } }), 4,
    "registered client and validated access token each retain their own source and identity rows");
});

test("issuer returns 503 when the source limiter cannot acquire its storage lock", integrationOptions, async () => {
  const fixture = await seed();
  const clientAddress = randomClientAddress();
  const hash = createRateLimitIdentifierHash(selectAuthRateLimits(clientAddress, null)[0].identifier);
  let release!: () => void;
  let locked!: () => void;
  const acquired = new Promise<void>((resolve) => { locked = resolve; });
  const gate = new Promise<void>((resolve) => { release = resolve; });
  const holder = prisma.$transaction(async (transaction) => {
    await transaction.$queryRaw`SELECT pg_advisory_xact_lock(hashtextextended(${hash}, 0)) IS NULL AS "locked"`;
    locked();
    await gate;
  }, { timeout: 10000 });
  await acquired;
  try {
    const response = await fetch(authorization(fixture.clientId), {
      headers: { "cf-connecting-ip": clientAddress },
      redirect: "manual"
    });
    assert.equal(response.status, 503);
    assert.equal(response.headers.get("retry-after"), "900");
    assert.equal(await prisma.loginRateLimit.count({ where: { identifierHash: hash } }), 0,
      "failed source storage must not create a partial limiter row or release the request");
  } finally {
    release();
    await holder;
  }
});

async function seed(options: { totpSecret?: string; origin?: string; redirectUris?: string[] } = {}) {
  const user = await createTestUser({ label: "issuer-interaction", totpSecret: options.totpSecret });
  const clientId = `client-${randomUUID()}`;
  const connection = await prisma.projectConnection.create({ data: {
    name: "Issuer interaction", slug: clientId, origin: options.origin ?? "https://project.integration.invalid", clientId,
    clientSecretCiphertext: encryptOidcClientSecret(clientSecret), redirectUris: options.redirectUris ?? [redirectUri]
  } });
  await prisma.userProjectGrant.create({ data: { userId: user.id, connectionId: connection.id } });
  return { userId: user.id, email: user.email, clientId, connectionId: connection.id };
}

async function establishPasswordAcrConsent(fixture: { userId: string; clientId: string }, client: ReturnType<typeof browser>) {
  const passwordOnly = await createSession(fixture.userId);
  const authenticatedMethods = (await getSessionByToken(passwordOnly.token))?.authenticationMethods;
  assert.deepEqual(authenticatedMethods, ["pwd"]);
  client.setSession(passwordOnly.token);

  const request = {
    acr_values: "urn:virki:loa:1 urn:virki:loa:2",
    claims: JSON.stringify({ id_token: {
      acr: { essential: true, values: ["urn:virki:loa:1", "urn:virki:loa:2"] },
      amr: { essential: true }
    } })
  };
  const authorizationResult = await client.follow(authorization(fixture.clientId, request));
  const code = authorizationResult.searchParams.get("code");
  assert.equal(Boolean(code), true, "the password ACR alternative must establish prior consent");
  const token = await exchange(fixture.clientId, code!);
  assert.equal(token.status, 200);
  assert.ok(token.body.id_token);
  const claims = JSON.parse(Buffer.from(token.body.id_token.split(".")[1], "base64url").toString("utf8")) as { acr?: string; amr?: string[] };
  assert.equal(claims.acr, "urn:virki:loa:1");
  assert.ok(claims.amr?.includes("pwd"));
  assert.equal(claims.amr?.includes("mfa"), false);

  const grantCount = await prisma.oidcArtifact.count({ where: {
    model: "Grant",
    accountIdHash: hashOidcIdentifier(fixture.userId),
    clientIdHash: hashOidcIdentifier(fixture.clientId)
  } });
  assert.equal(grantCount, 1, "the provider must retain consent for the same account and client");
  return { passwordOnly, authenticatedMethods, request };
}

async function startConsentWithPreviousGrant(fixture: { userId: string; clientId: string }) {
  const client = browser();
  const created = await createSession(fixture.userId);
  const session = await getSessionByToken(created.token);
  assert.ok(session);
  client.setSession(created.token);
  const initial = await client.follow(authorization(fixture.clientId));
  assert.ok(initial.searchParams.get("code"), "the initial authorization creates a provider Grant");

  const pending = await client.request(authorization(fixture.clientId, { prompt: "consent" }));
  assert.equal(pending.status, 303);
  const interactionUrl = new URL(pending.headers.get("location")!, origin);
  const uid = interactionUrl.pathname.split("/").at(-1)!;
  const interaction = await prisma.oidcArtifact.findUnique({
    where: { model_idHash: { model: "Interaction", idHash: hashOidcIdentifier(uid) } },
    select: { payloadCiphertext: true }
  });
  assert.ok(interaction, "the provider persists the consent Interaction before handling it");
  const payload = JSON.parse(decryptOidcPayload(interaction.payloadCiphertext)) as { grantId?: unknown };
  assert.equal(typeof payload.grantId, "string", "the pending consent Interaction references the prior provider Grant");
  const grantId = payload.grantId as string;
  assert.equal(await prisma.oidcArtifact.count({ where: { model: "Grant", idHash: hashOidcIdentifier(grantId) } }), 1);
  return { client, interactionUrl, grantId, sessionId: session.id };
}

async function completeTotpLogin(fixture: { userId: string; email: string }, secret: string, now = new Date()) {
  const start = await startLoginCeremony(fixture.userId, undefined, "pt-BR", now);
  assert.equal(start.kind, "CEREMONY");
  if (start.kind !== "CEREMONY") assert.fail("A new TOTP login must start a verification ceremony.");
  const code = (await queuedEmails(fixture.email)).filter((message) => message.kind === "EMAIL_TWO_FACTOR" || message.kind === "NEW_DEVICE_VERIFICATION").at(-1)?.code;
  assert.ok(code, "the real login ceremony queues its email verification code");
  assert.deepEqual(await verifyLoginEmailCode(start.ceremonyId, code, start.deviceToken, now), { requiresTotp: true, session: null });
  return verifyLoginTotpCode(start.ceremonyId, totpAt(secret, now), start.deviceToken, now);
}

function base32Decode(value: string): Buffer {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bytes: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (const character of value) {
    buffer = ((buffer << 5) | alphabet.indexOf(character)) & 0xffff;
    bits += 5;
    if (bits >= 8) {
      bytes.push((buffer >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

function totpAt(secret: string, now: Date): string {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(now.getTime() / 1_000 / 30)));
  const digest = createHmac("sha1", base32Decode(secret)).update(counter).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary = ((digest[offset] & 0x7f) << 24) | (digest[offset + 1] << 16) | (digest[offset + 2] << 8) | digest[offset + 3];
  return String(binary % 1_000_000).padStart(6, "0");
}

function browser() {
  const cookies = new Map<string, string>();
  return {
    setSession: (token: string) => cookies.set(SESSION_COOKIE_NAME, token),
    async request(url: string, options: { method?: string; headers?: Record<string, string> } = {}) {
      assert.equal(new URL(url, origin).origin, origin, "All HTTP traffic must stay on the local issuer.");
      const response = await fetch(new URL(url, origin), { method: options.method ?? "GET", redirect: "manual", headers: {
        cookie: [...cookies].map(([name, value]) => `${name}=${value}`).join("; "),
        ...options.headers
      } });
      for (const cookie of response.headers.getSetCookie()) {
        const pair = cookie.split(";", 1)[0];
        const index = pair.indexOf("=");
        cookies.set(pair.slice(0, index), pair.slice(index + 1));
      }
      return response;
    },
    async follow(url: string, options: { method?: string; headers?: Record<string, string> } = {}) {
      for (let hop = 0; hop < 16; hop += 1) {
        const response = await this.request(url, options);
        const location = response.headers.get("location");
        assert.ok(location, `Expected a redirect, received local status ${response.status}.`);
        const next = new URL(location, origin);
        if (next.origin !== origin || next.pathname === "/login") return next;
        url = next.href;
      }
      assert.fail("Issuer interaction did not converge within 16 local redirects.");
    }
  };
}

async function followIssuerRedirects(client: ReturnType<typeof browser>, startUrl: string) {
  let current = new URL(startUrl);
  const redirects: Array<{ from: string; status: number; to: string }> = [];
  for (let hop = 0; hop < 16; hop += 1) {
    const response = await client.request(current.href);
    const location = response.headers.get("location");
    if (!location) return { destination: current, status: response.status, redirects };
    const next = new URL(location, origin);
    redirects.push({ from: safeIssuerPath(current.pathname), status: response.status, to: safeIssuerPath(next.pathname) });
    if (next.origin !== origin || next.pathname === "/login") {
      return { destination: next, status: response.status, redirects };
    }
    current = next;
  }
  assert.fail("Issuer interaction did not converge within 16 local redirects.");
}

function authorization(clientId: string, extra: Record<string, string> = {}, requestedRedirectUri = redirectUri) {
  return `${origin}/auth?${new URLSearchParams({ client_id: clientId, redirect_uri: requestedRedirectUri, response_type: "code", scope: "openid",
    state: randomBytes(24).toString("base64url"), nonce: randomBytes(24).toString("base64url"),
    code_challenge: createHash("sha256").update(verifier).digest("base64url"), code_challenge_method: "S256", ...extra })}`;
}

function safeIssuerPath(pathname: string): string {
  return pathname.replace(/^\/interaction\/[A-Za-z0-9_-]{8,80}$/u, "/interaction/:id");
}

function randomClientAddress(): string {
  return `2001:db8:${randomBytes(2).toString("hex")}::${randomBytes(2).toString("hex")}`;
}

async function waitForBlockedQuery(blockerPid: number, queryFragment: string): Promise<number> {
  const deadline = Date.now() + 5_000;
  while (Date.now() < deadline) {
    const blocked = await prisma.$queryRaw<Array<{ pid: number }>>`
      SELECT pid
      FROM pg_stat_activity
      WHERE wait_event_type = 'Lock'
        AND pg_blocking_pids(pid) @> ARRAY[${blockerPid}]::integer[]
        AND query LIKE ${`%${queryFragment}%`}
      LIMIT 1
    `;
    if (blocked[0]) return blocked[0].pid;
    await new Promise<void>((resolve) => setImmediate(resolve));
  }
  throw new Error(`Timed out waiting for PostgreSQL lock wait on ${queryFragment}.`);
}

async function exchange(clientId: string, code: string, clientAddress?: string) {
  const response = await fetch(`${origin}/token`, { method: "POST", headers: {
    "content-type": "application/x-www-form-urlencoded", authorization: `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString("base64")}`,
    ...(clientAddress ? { "cf-connecting-ip": clientAddress } : {})
  }, body: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: redirectUri, code_verifier: verifier }) });
  return { status: response.status, body: await response.json() as { access_token?: string; id_token?: string; error?: string } };
}

const reauthenticationRequests: Array<Record<string, string>> = [{ prompt: "login" }, { max_age: "0" }, { max_age: "1" }];
for (const request of reauthenticationRequests) {
  test(`actual issuer preserves completed reauthentication through consent for ${JSON.stringify(request)}`, integrationOptions, async () => {
    const fixture = await seed();
    const oldSession = await createSession(fixture.userId);
    await prisma.session.updateMany({ where: { userId: fixture.userId }, data: { createdAt: new Date(Date.now() - 60_000) } });
    const client = browser();
    client.setSession(oldSession.token);
    const login = await client.follow(authorization(fixture.clientId, request));
    assert.equal(login.pathname, "/login");
    assert.equal(login.searchParams.get("reauth"), "1");
    const fresh = await createSession(fixture.userId);
    client.setSession(fresh.token);
    const result = await client.follow(new URL(login.searchParams.get("returnTo")!, origin).href);
    assert.equal(result.origin, "https://project.integration.invalid");
    assert.ok(result.searchParams.get("code"), `Authorization must finish after reauthentication; got ${result.pathname}.`);
  });
}

test("actual issuer preserves essential ACR2 across mixed acr_values and rejects a fresh password-only account switch", integrationOptions, async () => {
  const original = await seed();
  const switched = await createTestUser({ label: "issuer-account-switch" });
  await prisma.userProjectGrant.create({ data: { userId: switched.id, connectionId: original.connectionId } });

  const oldSession = await createSession(original.userId);
  await prisma.session.updateMany({ where: { userId: original.userId }, data: { createdAt: new Date(Date.now() - 60_000) } });
  const client = browser();
  client.setSession(oldSession.token);

  const login = await client.follow(authorization(original.clientId, {
    prompt: "login",
    max_age: "0",
    acr_values: "urn:virki:loa:1 urn:virki:loa:2",
    claims: JSON.stringify({ id_token: { acr: { essential: true, values: ["urn:virki:loa:2"] } } })
  }));
  assert.equal(login.pathname, "/login");
  assert.equal(login.searchParams.get("reauth"), "1");

  // Model a completed password-only sign-in as a different account during the same interaction.
  const switchedPasswordSession = await createSession(switched.id);
  client.setSession(switchedPasswordSession.token);
  const result = await client.follow(new URL(login.searchParams.get("returnTo")!, origin).href);
  assert.equal(result.pathname, "/callback", "The provider must finish with a protocol error instead of asking the password-only account to repeat login forever.");
  assert.equal(result.searchParams.get("error"), "access_denied");
  assert.equal(result.searchParams.get("code"), null);
});

test("actual provider returns the achieved ACR after prompt-login for voluntary ACR2 without MFA", integrationOptions, async () => {
  const fixture = await seed();
  const client = browser();
  const original = await createSession(fixture.userId);
  client.setSession(original.token);
  assert.ok((await client.follow(authorization(fixture.clientId))).searchParams.get("code"));
  await prisma.session.updateMany({ where: { userId: fixture.userId }, data: { createdAt: new Date(Date.now() - 60_000) } });

  const login = await client.follow(authorization(fixture.clientId, {
    prompt: "login",
    acr_values: "urn:virki:loa:2",
    claims: JSON.stringify({ id_token: { amr: { essential: true } } })
  }));
  assert.equal(login.pathname, "/login");
  assert.equal(login.searchParams.get("reauth"), "1");

  const fresh = await createSession(fixture.userId);
  assert.deepEqual((await getSessionByToken(fresh.token))?.authenticationMethods, ["pwd"]);
  client.setSession(fresh.token);
  const result = await client.follow(new URL(login.searchParams.get("returnTo")!, origin).href);
  assert.ok(result.searchParams.get("code"), `voluntary ACR2 must fall back to the achieved password ACR; got ${result.searchParams.get("error") ?? result.pathname}`);

  const token = await exchange(fixture.clientId, result.searchParams.get("code")!);
  assert.equal(token.status, 200);
  assert.ok(token.body.id_token);
  const claims = JSON.parse(Buffer.from(token.body.id_token.split(".")[1], "base64url").toString("utf8")) as { acr?: string; amr?: string[] };
  assert.equal(claims.acr, "urn:virki:loa:1");
  assert.ok(claims.amr?.includes("pwd"));
  assert.equal(claims.amr?.includes("mfa"), false);
});

test("actual provider enforces essential MFA ACR before reusing a password session and consent", integrationOptions, async () => {
  const fixture = await seed();
  const client = browser();
  const passwordOnly = await createSession(fixture.userId);
  const authenticatedMethods = (await getSessionByToken(passwordOnly.token))?.authenticationMethods;
  assert.deepEqual(authenticatedMethods, ["pwd"]);
  client.setSession(passwordOnly.token);

  const consentedRequest = {
    acr_values: "urn:virki:loa:1 urn:virki:loa:2",
    claims: JSON.stringify({ id_token: { acr: { essential: true, values: ["urn:virki:loa:1", "urn:virki:loa:2"] } } })
  };
  const consented = await client.follow(authorization(fixture.clientId, consentedRequest));
  const consentedCode = consented.searchParams.get("code");
  assert.equal(Boolean(consentedCode), true, "the password ACR alternative must establish prior consent");
  const consentedToken = await exchange(fixture.clientId, consentedCode!);
  assert.equal(consentedToken.status, 200);
  assert.ok(consentedToken.body.id_token);
  const consentedClaims = JSON.parse(Buffer.from(consentedToken.body.id_token.split(".")[1], "base64url").toString("utf8")) as { acr?: string; amr?: string[] };
  assert.equal(consentedClaims.acr, "urn:virki:loa:1");
  assert.equal(consentedClaims.amr?.includes("mfa") ?? false, false);

  const grantCount = await prisma.oidcArtifact.count({ where: {
    model: "Grant",
    accountIdHash: hashOidcIdentifier(fixture.userId),
    clientIdHash: hashOidcIdentifier(fixture.clientId)
  } });
  assert.equal(grantCount, 1, "the provider must retain the consent Grant for the same account and client");

  const beforeOrdinaryRepeat = await prisma.auditLog.count({ where: { eventType: "SSO_INTERACTION_STARTED" } });
  const ordinaryRepeat = await client.follow(authorization(fixture.clientId, consentedRequest));
  assert.equal(Boolean(ordinaryRepeat.searchParams.get("code")), true, "ordinary authorization should reuse the provider session and prior consent");
  assert.equal(await prisma.auditLog.count({ where: { eventType: "SSO_INTERACTION_STARTED" } }), beforeOrdinaryRepeat,
    "ordinary authorization reuse must not start an interaction");

  const beforeAttack = await prisma.auditLog.count({ where: { eventType: "SSO_INTERACTION_STARTED" } });
  let current = new URL(authorization(fixture.clientId, {
    acr_values: "urn:virki:loa:1 urn:virki:loa:2",
    claims: JSON.stringify({ id_token: { acr: { essential: true, values: ["urn:virki:loa:2"] } } })
  }));
  const redirects: Array<{ from: string; status: number; to: string | null }> = [];
  let final = current;
  for (let hop = 0; hop < 16; hop += 1) {
    const response = await client.request(current.href);
    const location = response.headers.get("location");
    const next = location ? new URL(location, origin) : null;
    redirects.push({ from: safeIssuerPath(current.pathname), status: response.status, to: next ? safeIssuerPath(next.pathname) : null });
    if (!next || next.origin !== origin || next.pathname === "/login") {
      final = next ?? current;
      break;
    }
    current = next;
    if (hop === 15) assert.fail("Essential ACR session reuse did not converge within 16 local redirects.");
  }

  const interactionCount = (await prisma.auditLog.count({ where: { eventType: "SSO_INTERACTION_STARTED" } })) - beforeAttack;
  const code = final.searchParams.get("code");
  let tokenEvidence: { status: number; acr: string | null; amr: string[] | null } | undefined;
  if (code) {
    const token = await exchange(fixture.clientId, code);
    const claims = token.body.id_token
      ? JSON.parse(Buffer.from(token.body.id_token.split(".")[1], "base64url").toString("utf8")) as { acr?: string; amr?: string[] }
      : null;
    tokenEvidence = { status: token.status, acr: claims?.acr ?? null, amr: claims?.amr ?? null };
  }
  console.log(`essential ACR session reuse evidence: ${JSON.stringify({
    redirects,
    finalPath: final.pathname,
    protocolError: final.searchParams.get("error"),
    reauth: final.searchParams.get("reauth") === "1",
    interactionCount,
    authenticatedMethods,
    codeIssued: Boolean(code),
    token: tokenEvidence
  })}`);

  assert.equal(Boolean(code), false, "essential MFA-only ACR must not issue a code from a password-only session");
  assert.ok(final.pathname === "/login" || final.searchParams.has("error"),
    "unmet essential MFA must start stronger authentication or return an OIDC denial");
  if (final.pathname === "/login") assert.equal(final.searchParams.get("reauth"), "1");
});

test("actual provider accepts essential MFA ACR after a real TOTP session without forced login", integrationOptions, async () => {
  const secret = createTotpSecret();
  const fixture = await seed({ totpSecret: secret });
  const client = browser();
  const freshMfa = await completeTotpLogin(fixture, secret);
  const session = await getSessionByToken(freshMfa.token);
  assert.ok(session?.authenticationMethods.includes("mfa"), "the central login must verify TOTP before authorization");
  client.setSession(freshMfa.token);

  const request = {
    acr_values: "urn:virki:loa:1 urn:virki:loa:2",
    claims: JSON.stringify({ id_token: {
      acr: { essential: true, values: ["urn:virki:loa:2"] },
      amr: { essential: true }
    } })
  };
  const first = await client.follow(authorization(fixture.clientId, request));
  const firstCode = first.searchParams.get("code");
  assert.equal(Boolean(firstCode), true, "a genuinely verified MFA session must satisfy essential ACR2");
  const beforeRepeat = await prisma.auditLog.count({ where: { eventType: "SSO_INTERACTION_STARTED" } });
  const repeat = await client.follow(authorization(fixture.clientId, request));
  const code = repeat.searchParams.get("code");
  assert.equal(Boolean(code), true, "the existing MFA provider session and consent must be reusable");
  assert.equal(await prisma.auditLog.count({ where: { eventType: "SSO_INTERACTION_STARTED" } }), beforeRepeat,
    "a satisfied essential ACR must not force another interaction");

  const token = await exchange(fixture.clientId, code!);
  assert.equal(token.status, 200);
  assert.ok(token.body.id_token);
  const claims = JSON.parse(Buffer.from(token.body.id_token.split(".")[1], "base64url").toString("utf8")) as { acr?: string; amr?: string[] };
  assert.equal(claims.acr, "urn:virki:loa:2");
  assert.ok(claims.amr?.includes("mfa"), "the issued MFA ACR must match the verified TOTP methods");
});

test("actual provider preserves password fallback for mixed voluntary ACR after consent reuse", integrationOptions, async () => {
  const fixture = await seed();
  const client = browser();
  const setup = await establishPasswordAcrConsent(fixture, client);
  const before = await prisma.auditLog.count({ where: { eventType: "SSO_INTERACTION_STARTED" } });
  const result = await client.follow(authorization(fixture.clientId, {
    acr_values: "urn:virki:loa:1 urn:virki:loa:2",
    claims: JSON.stringify({ id_token: { amr: { essential: true } } })
  }));
  const code = result.searchParams.get("code");
  assert.equal(Boolean(code), true, "a voluntary ACR preference must not require MFA from a password-only session");
  assert.equal(await prisma.auditLog.count({ where: { eventType: "SSO_INTERACTION_STARTED" } }), before,
    "prior consent and the provider session should be reused without another interaction");

  const token = await exchange(fixture.clientId, code!);
  assert.equal(token.status, 200);
  assert.ok(token.body.id_token);
  const claims = JSON.parse(Buffer.from(token.body.id_token.split(".")[1], "base64url").toString("utf8")) as { acr?: string; amr?: string[] };
  assert.equal(claims.acr, "urn:virki:loa:1");
  assert.ok(claims.amr?.includes("pwd"));
  assert.equal(claims.amr?.includes("mfa"), false);
  assert.deepEqual(setup.authenticatedMethods, ["pwd"]);
});

test("actual provider accepts a null voluntary ACR claim after password-only consent reuse", integrationOptions, async () => {
  const fixture = await seed();
  const client = browser();
  await establishPasswordAcrConsent(fixture, client);
  const before = await prisma.auditLog.count({ where: { eventType: "SSO_INTERACTION_STARTED" } });
  const result = await client.follow(authorization(fixture.clientId, {
    claims: JSON.stringify({ id_token: { acr: null } })
  }));
  const code = result.searchParams.get("code");
  assert.equal(Boolean(code), true, "null voluntary ACR must not deny a valid password-only session");
  assert.equal(await prisma.auditLog.count({ where: { eventType: "SSO_INTERACTION_STARTED" } }), before,
    "voluntary claim request must reuse existing consent");
  const token = await exchange(fixture.clientId, code!);
  assert.equal(token.status, 200);
  assert.ok(token.body.id_token);
  const claims = JSON.parse(Buffer.from(token.body.id_token.split(".")[1], "base64url").toString("utf8")) as { acr?: string };
  assert.equal(claims.acr, "urn:virki:loa:1", "report the achieved assurance, without claiming MFA");
});

test("actual provider accepts an essential ACR claim without a value restriction using the achieved password ACR", integrationOptions, async () => {
  const fixture = await seed();
  const client = browser();
  await establishPasswordAcrConsent(fixture, client);
  const before = await prisma.auditLog.count({ where: { eventType: "SSO_INTERACTION_STARTED" } });

  const result = await client.follow(authorization(fixture.clientId, {
    claims: JSON.stringify({ id_token: { acr: { essential: true }, amr: { essential: true } } })
  }));
  const code = result.searchParams.get("code");
  assert.equal(Boolean(code), true, "an essential ACR claim without a value qualifier must allow any achieved supported ACR");
  assert.equal(await prisma.auditLog.count({ where: { eventType: "SSO_INTERACTION_STARTED" } }), before,
    "a password session already supplies a supported ACR and prior consent covers the claim");

  const token = await exchange(fixture.clientId, code!);
  assert.equal(token.status, 200);
  assert.ok(token.body.id_token);
  const claims = JSON.parse(Buffer.from(token.body.id_token.split(".")[1], "base64url").toString("utf8")) as { acr?: string; amr?: string[] };
  assert.equal(claims.acr, "urn:virki:loa:1");
  assert.ok(claims.amr?.includes("pwd"));
  assert.equal(claims.amr?.includes("mfa"), false);
});

test("actual issuer denies unsupported and malformed essential ACR without a login loop", integrationOptions, async () => {
  const fixture = await seed();
  const client = browser();
  await establishPasswordAcrConsent(fixture, client);

  for (const [label, acr] of [
    ["unsupported", { essential: true, value: "urn:virki:loa:3" }],
    ["malformed", { essential: true, values: ["urn:virki:loa:2", 1] }]
  ] as const) {
    const before = await prisma.auditLog.count({ where: { eventType: "SSO_INTERACTION_STARTED" } });
    const result = await followIssuerRedirects(client, authorization(fixture.clientId, {
      acr_values: "urn:virki:loa:1 urn:virki:loa:2",
      claims: JSON.stringify({ id_token: { acr } })
    }));
    assert.equal(Boolean(result.destination.searchParams.get("code")), false, `${label} essential ACR must not issue a code`);
    assert.notEqual(result.destination.pathname, "/login", `${label} essential ACR must deny instead of looping through login`);
    if (result.destination.origin !== origin) {
      assert.equal(result.destination.searchParams.get("error"), "access_denied", `${label} essential ACR must return a protocol denial`);
    } else {
      assert.ok(result.status >= 400 && result.status < 500, `${label} essential ACR must be rejected at the provider boundary`);
    }
    const interactions = (await prisma.auditLog.count({ where: { eventType: "SSO_INTERACTION_STARTED" } })) - before;
    assert.ok(interactions <= 1, `${label} essential ACR must not create repeated interactions`);
  }
});

test("actual provider returns a noninteractive OIDC error for prompt-none with unmet essential MFA", integrationOptions, async () => {
  const fixture = await seed();
  const client = browser();
  await establishPasswordAcrConsent(fixture, client);
  const before = await prisma.auditLog.count({ where: { eventType: "SSO_INTERACTION_STARTED" } });

  const result = await followIssuerRedirects(client, authorization(fixture.clientId, {
    prompt: "none",
    acr_values: "urn:virki:loa:1 urn:virki:loa:2",
    claims: JSON.stringify({ id_token: { acr: { essential: true, values: ["urn:virki:loa:2"] } } })
  }));

  assert.equal(Boolean(result.destination.searchParams.get("code")), false, "prompt=none cannot issue a code without essential MFA");
  assert.equal(result.destination.origin, new URL(redirectUri).origin);
  assert.ok(["login_required", "interaction_required"].includes(result.destination.searchParams.get("error") ?? ""),
    "prompt=none must return an OIDC noninteractive error");
  assert.ok(result.redirects.every(({ to }) => !to.startsWith("/interaction/") && to !== "/login"),
    "prompt=none cannot redirect through an interactive authentication loop");
  assert.equal(await prisma.auditLog.count({ where: { eventType: "SSO_INTERACTION_STARTED" } }), before,
    "a noninteractive denial must not start an interaction handler");
});

test("actual provider does not downgrade an essential ACR2 request on an existing password session", integrationOptions, async () => {
  const fixture = await seed();
  const client = browser();
  client.setSession((await createSession(fixture.userId)).token);
  const initial = await client.follow(authorization(fixture.clientId));
  assert.ok(initial.searchParams.get("code"));

  const login = await client.follow(authorization(fixture.clientId, {
    claims: JSON.stringify({ id_token: { acr: { essential: true, value: "urn:virki:loa:2" } } })
  }));
  assert.equal(login.pathname, "/login", "an unsatisfied essential ACR may request a stronger authentication ceremony");
  assert.equal(login.searchParams.get("reauth"), "1");

  const passwordOnly = await createSession(fixture.userId);
  assert.deepEqual((await getSessionByToken(passwordOnly.token))?.authenticationMethods, ["pwd"]);
  client.setSession(passwordOnly.token);
  const result = await client.follow(new URL(login.searchParams.get("returnTo")!, origin).href);
  assert.equal(result.pathname, "/callback");
  assert.equal(result.searchParams.get("error"), "access_denied", "a fresh password-only session still cannot satisfy essential ACR2");
  assert.equal(result.searchParams.get("code"), null);
});

test("actual provider accepts the lower essential ACR alternative after prompt-login password reauthentication", integrationOptions, async () => {
  const fixture = await seed();
  const client = browser();
  client.setSession((await createSession(fixture.userId)).token);
  assert.ok((await client.follow(authorization(fixture.clientId))).searchParams.get("code"));
  await prisma.session.updateMany({ where: { userId: fixture.userId }, data: { createdAt: new Date(Date.now() - 60_000) } });

  const login = await client.follow(authorization(fixture.clientId, {
    prompt: "login",
    acr_values: "urn:virki:loa:2 urn:virki:loa:1",
    claims: JSON.stringify({ id_token: { acr: { essential: true, values: ["urn:virki:loa:2", "urn:virki:loa:1"] }, amr: { essential: true } } })
  }));
  assert.equal(login.pathname, "/login");
  const fresh = await createSession(fixture.userId);
  assert.deepEqual((await getSessionByToken(fresh.token))?.authenticationMethods, ["pwd"]);
  client.setSession(fresh.token);
  const result = await client.follow(new URL(login.searchParams.get("returnTo")!, origin).href);
  assert.ok(result.searchParams.get("code"), `one requested essential ACR is achievable; got ${result.searchParams.get("error") ?? result.pathname}`);

  const token = await exchange(fixture.clientId, result.searchParams.get("code")!);
  assert.equal(token.status, 200);
  assert.ok(token.body.id_token);
  const claims = JSON.parse(Buffer.from(token.body.id_token.split(".")[1], "base64url").toString("utf8")) as { acr?: string; amr?: string[] };
  assert.equal(claims.acr, "urn:virki:loa:1");
  assert.ok(claims.amr?.includes("pwd"), "the requested AMR claim must report the password method");
  assert.equal(claims.amr?.includes("mfa"), false, "the password-only session must never be labeled as MFA");
});

test("actual provider prefers ACR2 when a real TOTP login satisfies mixed essential ACR values", integrationOptions, async () => {
  const secret = createTotpSecret();
  const fixture = await seed({ totpSecret: secret });
  const client = browser();
  client.setSession((await completeTotpLogin(fixture, secret, new Date(Date.now() - 60_000))).token);
  assert.ok((await client.follow(authorization(fixture.clientId))).searchParams.get("code"));
  await prisma.session.updateMany({ where: { userId: fixture.userId }, data: { createdAt: new Date(Date.now() - 60_000) } });

  const login = await client.follow(authorization(fixture.clientId, {
    prompt: "login",
    acr_values: "urn:virki:loa:2 urn:virki:loa:1",
    claims: JSON.stringify({ id_token: { acr: { essential: true, values: ["urn:virki:loa:2", "urn:virki:loa:1"] }, amr: { essential: true } } })
  }));
  assert.equal(login.pathname, "/login");
  const fresh = await completeTotpLogin(fixture, secret);
  assert.ok((await getSessionByToken(fresh.token))?.authenticationMethods.includes("mfa"));
  client.setSession(fresh.token);
  const result = await client.follow(new URL(login.searchParams.get("returnTo")!, origin).href);
  assert.ok(result.searchParams.get("code"), `a verified MFA session satisfies the preferred ACR; got ${result.searchParams.get("error") ?? result.pathname}`);

  const token = await exchange(fixture.clientId, result.searchParams.get("code")!);
  assert.equal(token.status, 200);
  assert.ok(token.body.id_token);
  const claims = JSON.parse(Buffer.from(token.body.id_token.split(".")[1], "base64url").toString("utf8")) as { acr?: string; amr?: string[] };
  assert.equal(claims.acr, "urn:virki:loa:2");
  assert.ok(claims.amr?.includes("mfa"), "the returned MFA ACR must be backed by the TOTP session");
});

test("actual issuer denies an unsupported essential ACR without downgrading it", integrationOptions, async () => {
  const fixture = await seed();
  const client = browser();
  client.setSession((await createSession(fixture.userId)).token);
  const result = await client.follow(authorization(fixture.clientId, {
    claims: JSON.stringify({ id_token: { acr: { essential: true, value: "urn:virki:loa:3" } } })
  }));
  assert.equal(result.searchParams.get("error"), "access_denied");
  assert.equal(result.searchParams.get("code"), null);
});

test("actual issuer rejects an unregistered client_id without redirecting to its supplied callback", integrationOptions, async () => {
  const response = await fetch(authorization(`unregistered-${randomUUID()}`), { redirect: "manual" });
  assert.ok(response.status >= 400 && response.status < 500, `unknown client_id must be a protocol client error, got ${response.status}`);
  assert.equal(response.headers.get("location"), null, "an untrusted client_id cannot select a redirect destination");
});

test("actual issuer allows explicitly registered third-party callbacks per client and rejects mixed-client or malicious URIs", integrationOptions, async () => {
  const callbackA = "https://login.alpha.integration.invalid/oidc/callback";
  const callbackB = "https://login.beta.integration.invalid/oidc/callback";
  const maliciousCallback = "https://attacker.integration.invalid/oidc/callback";
  const fixture = await seed({ origin: "https://project.alpha.integration.invalid", redirectUris: [callbackA] });
  const clientIdB = `client-${randomUUID()}`;
  const connectionB = await prisma.projectConnection.create({ data: {
    name: "Issuer interaction second client", slug: clientIdB, origin: "https://project.beta.integration.invalid", clientId: clientIdB,
    clientSecretCiphertext: encryptOidcClientSecret(clientSecret), redirectUris: [callbackB]
  } });
  await prisma.userProjectGrant.create({ data: { userId: fixture.userId, connectionId: connectionB.id } });

  const client = browser();
  client.setSession((await createSession(fixture.userId)).token);
  for (const [clientId, callbackUri, callbackHost] of [
    [fixture.clientId, callbackA, "https://login.alpha.integration.invalid"],
    [clientIdB, callbackB, "https://login.beta.integration.invalid"]
  ]) {
    const result = await client.follow(authorization(clientId, {}, callbackUri));
    assert.equal(result.origin, callbackHost, "an explicitly registered cross-origin callback is valid for its own client");
    assert.equal(result.pathname, "/oidc/callback");
    assert.ok(result.searchParams.get("code"), "the authorization code is returned to the exact registered callback");
  }

  for (const [clientId, callbackUri] of [
    [fixture.clientId, callbackB],
    [fixture.clientId, maliciousCallback],
    [clientIdB, callbackA]
  ]) {
    const response = await client.request(authorization(clientId, {}, callbackUri));
    assert.ok(response.status >= 400 && response.status < 500,
      `unregistered URI ${callbackUri} for ${clientId} must be rejected by the actual OIDC provider`);
    assert.equal(response.headers.get("location"), null, "invalid or another client's callback is never used as a redirect destination");
  }
});

test("actual issuer completes a new OIDC grant after sequential project-access revocation and regrant", integrationOptions, async () => {
  const fixture = await seed();
  const client = browser();
  client.setSession((await createSession(fixture.userId)).token);
  const initial = await client.follow(authorization(fixture.clientId));
  assert.ok(initial.searchParams.get("code"));

  const appGrant = await prisma.userProjectGrant.findUniqueOrThrow({
    where: { userId_connectionId: { userId: fixture.userId, connectionId: fixture.connectionId } },
    select: { id: true }
  });
  const artifactScope = { accountIdHash: hashOidcIdentifier(fixture.userId), clientIdHash: hashOidcIdentifier(fixture.clientId) };
  const admin = await createTestUser({ role: "ADMIN", label: "issuer-regrant-admin" });
  const elevation = await seedAdminSessionWithElevation(admin.id, "PROJECT_ACCESS_CHANGE");
  const actor = { id: admin.id, role: "ADMIN" };
  await revokeProjectAccess(actor, elevation.sessionId, appGrant.id);
  assert.equal(await prisma.oidcArtifact.count({ where: { model: "Grant", ...artifactScope } }), 0,
    "revocation clears the prior provider Grant before access is re-granted");
  await grantProjectAccess(actor, elevation.sessionId, fixture.userId, fixture.connectionId);

  const reauthorized = await client.follow(authorization(fixture.clientId));
  assert.ok(reauthorized.searchParams.get("code"), `freshly re-granted access should authorize; got ${reauthorized.searchParams.get("error") ?? reauthorized.pathname}`);
  assert.equal(await prisma.oidcArtifact.count({ where: { model: "Grant", ...artifactScope } }), 1);
});

test("actual issuer recovers when its Interaction write commits after the access-revocation artifact-delete snapshot", integrationOptions, async () => {
  const fixture = await seed();
  const client = browser();
  client.setSession((await createSession(fixture.userId)).token);
  const initial = await client.follow(authorization(fixture.clientId));
  assert.ok(initial.searchParams.get("code"));

  const appGrant = await prisma.userProjectGrant.findUniqueOrThrow({
    where: { userId_connectionId: { userId: fixture.userId, connectionId: fixture.connectionId } },
    select: { id: true }
  });
  const artifactScope = { accountIdHash: hashOidcIdentifier(fixture.userId), clientIdHash: hashOidcIdentifier(fixture.clientId) };
  const priorGrants = await prisma.oidcArtifact.findMany({ where: { model: "Grant", ...artifactScope }, select: { idHash: true } });
  assert.equal(priorGrants.length, 1);

  let deleted!: () => void;
  let release!: () => void;
  const deletionComplete = new Promise<void>((resolve) => { deleted = resolve; });
  const commitGate = new Promise<void>((resolve) => { release = resolve; });
  const revocation = prisma.$transaction(async (transaction) => {
    assert.equal((await transaction.userProjectGrant.updateMany({
      where: { id: appGrant.id, revokedAt: null }, data: { revokedAt: new Date() }
    })).count, 1);
    await transaction.oidcArtifact.deleteMany({ where: artifactScope });
    // Match revokeProjectAccess ordering, then hold its DELETE snapshot open while the real provider writes.
    deleted();
    await commitGate;
  }, { isolationLevel: "ReadCommitted", timeout: 10_000 });
  await deletionComplete;

  try {
    const pending = await client.request(authorization(fixture.clientId, { prompt: "consent" }));
    assert.equal(pending.status, 303);
    const interactionUrl = new URL(pending.headers.get("location")!, origin);
    const uid = interactionUrl.pathname.split("/").at(-1)!;
    const interaction = await prisma.oidcArtifact.findUnique({
      where: { model_idHash: { model: "Interaction", idHash: hashOidcIdentifier(uid) } },
      select: { payloadCiphertext: true }
    });
    assert.ok(interaction, "the real provider persists its pending Interaction during the revoke transaction");
    const payload = JSON.parse(decryptOidcPayload(interaction.payloadCiphertext)) as { grantId?: unknown };
    assert.equal(typeof payload.grantId, "string");
    assert.equal(hashOidcIdentifier(payload.grantId as string), priorGrants[0]!.idHash,
      "the Interaction created before revoke commits still references the old provider Grant");

    release();
    await revocation;
    assert.equal(await prisma.oidcArtifact.count({ where: { model: "Grant", ...artifactScope } }), 0);
    assert.equal(await prisma.oidcArtifact.count({ where: { model: "Interaction", idHash: hashOidcIdentifier(uid) } }), 1,
      "the INSERT committed after the revocation DELETE snapshot remains pending");

    const admin = await createTestUser({ role: "ADMIN", label: "issuer-regrant-race-admin" });
    const elevation = await seedAdminSessionWithElevation(admin.id, "PROJECT_ACCESS_CHANGE");
    await grantProjectAccess({ id: admin.id, role: "ADMIN" }, elevation.sessionId, fixture.userId, fixture.connectionId);
    const result = await client.follow(interactionUrl.href);
    assert.ok(result.searchParams.get("code"), `active regrant should recover the pending Interaction; got ${result.searchParams.get("error") ?? result.pathname}`);

    const replay = await client.request(interactionUrl.href);
    assert.ok(replay.status >= 400, `a completed provider Interaction must reject replay, got HTTP ${replay.status}`);
    assert.equal(replay.headers.get("location"), null, "replay cannot issue a second authorization redirect");
    assert.equal(await prisma.oidcArtifact.count({ where: { model: "Grant", ...artifactScope } }), 1,
      "replaying the completed Interaction cannot create a second provider Grant");
  } finally {
    release();
    await revocation;
  }
});

test("actual issuer creates a replacement for an absent provider Grant only with active project access", integrationOptions, async () => {
  const fixture = await seed();
  const { client, interactionUrl, grantId } = await startConsentWithPreviousGrant(fixture);
  assert.equal((await prisma.oidcArtifact.deleteMany({ where: { model: "Grant", idHash: hashOidcIdentifier(grantId) } })).count, 1);

  // Handler-state coverage: production access revocation also removes matching Interactions.
  // This keeps the pending Interaction to exercise the safe missing-Grant branch; it does not
  // claim to reproduce the concurrent revoke/upsert interleaving.
  const result = await client.follow(interactionUrl.href);
  assert.ok(result.searchParams.get("code"), `an absent prior provider Grant may be replaced after current access is verified; got ${result.searchParams.get("error")}`);
  assert.equal(await prisma.oidcArtifact.count({ where: { model: "Grant", accountIdHash: hashOidcIdentifier(fixture.userId), clientIdHash: hashOidcIdentifier(fixture.clientId) } }), 1);
});

for (const denial of [
  {
    label: "revoked project grant",
    denialResponse: "callback" as const,
    apply: (fixture: Awaited<ReturnType<typeof seed>>) => prisma.userProjectGrant.updateMany({ where: { userId: fixture.userId, connectionId: fixture.connectionId, revokedAt: null }, data: { revokedAt: new Date() } })
  },
  {
    label: "blocked account",
    denialResponse: "login" as const,
    apply: (fixture: Awaited<ReturnType<typeof seed>>) => prisma.user.update({ where: { id: fixture.userId }, data: { isActive: false, accountStatus: "BLOCKED" } })
  },
  {
    label: "disabled connection",
    denialResponse: "protocol-error" as const,
    apply: (fixture: Awaited<ReturnType<typeof seed>>) => prisma.projectConnection.update({ where: { id: fixture.connectionId }, data: { enabled: false } })
  },
  {
    label: "revoked portal session",
    denialResponse: "login" as const,
    apply: (_fixture: Awaited<ReturnType<typeof seed>>, sessionId: string) => prisma.session.update({ where: { id: sessionId }, data: { revokedAt: new Date() } })
  }
]) {
  test(`actual issuer does not renew an absent provider Grant after a ${denial.label}`, integrationOptions, async () => {
    const fixture = await seed();
    const pending = await startConsentWithPreviousGrant(fixture);
    assert.equal((await prisma.oidcArtifact.deleteMany({ where: { model: "Grant", idHash: hashOidcIdentifier(pending.grantId) } })).count, 1);
    await denial.apply(fixture, pending.sessionId);

    if (denial.denialResponse === "callback") {
      // interactionFinished first redirects back through the provider's /auth/{uid}
      // action, which then returns the protocol error to the registered callback.
      const destination = await pending.client.follow(pending.interactionUrl.href);
      assert.equal(destination.origin, new URL(redirectUri).origin, `revoked project access must return to the registered callback; received ${destination.href}`);
      assert.equal(destination.pathname, new URL(redirectUri).pathname);
      assert.equal(destination.searchParams.get("error"), "access_denied");
      assert.equal(destination.searchParams.get("code"), null);
    } else {
      const result = await pending.client.request(pending.interactionUrl.href);
      const location = result.headers.get("location");
      if (denial.denialResponse === "login") {
      assert.equal(result.status, 303, "a blocked or revoked session must return to local login without issuing a code");
      assert.ok(location);
      const destination = new URL(location, origin);
      assert.equal(destination.origin, origin);
      assert.equal(destination.pathname, "/login");
      assert.equal(destination.searchParams.get("code"), null);
      } else {
      assert.ok(result.status >= 400, `a disabled connection must be rejected by the provider, got HTTP ${result.status}`);
      assert.equal(location, null, "a disabled connection cannot redirect to a registered callback");
      }
    }
    assert.equal(await prisma.oidcArtifact.count({ where: { model: "Grant", accountIdHash: hashOidcIdentifier(fixture.userId), clientIdHash: hashOidcIdentifier(fixture.clientId) } }), 0,
      "an absent provider Grant cannot be recreated after the server-side authorization check fails");
  });
}

test("real client explicit claims consent finishes and includes the requested ID token claim", integrationOptions, async () => {
  const fixture = await seed();
  const client = browser();
  client.setSession((await createSession(fixture.userId)).token);
  const result = await client.follow(authorization(fixture.clientId, { claims: JSON.stringify({ id_token: { email: { essential: true } } }) }));
  assert.equal(result.origin, "https://project.integration.invalid");
  assert.ok(result.searchParams.get("code"));
  const token = await exchange(fixture.clientId, result.searchParams.get("code")!);
  assert.equal(token.status, 200);
  assert.ok(token.body.id_token);
  const claims = JSON.parse(Buffer.from(token.body.id_token.split(".")[1], "base64url").toString("utf8"));
  const user = await prisma.user.findUniqueOrThrow({ where: { id: fixture.userId } });
  assert.equal(claims.email, user.email);
});

test("token audit actor comes from verified models on success and remains absent for unknown failed codes", integrationOptions, async () => {
  const fixture = await seed();
  const client = browser();
  client.setSession((await createSession(fixture.userId)).token);
  const result = await client.follow(authorization(fixture.clientId));
  assert.ok(result.searchParams.get("code"));
  assert.equal((await exchange(fixture.clientId, result.searchParams.get("code")!)).status, 200);
  const success = await prisma.auditLog.findFirst({ where: { eventType: "SSO_TOKEN_ISSUED", actorUserId: fixture.userId } });
  assert.ok(success, "Verified token exchange must retain its account actor without relying on issuer browser session.");
  const failed = await exchange(fixture.clientId, randomBytes(24).toString("base64url"));
  assert.equal(failed.status, 400);
  const failure = await prisma.auditLog.findFirst({ where: { eventType: "SSO_TOKEN_REJECTED", actorUserId: null }, orderBy: { createdAt: "desc" } });
  assert.ok(failure, "An unknown code cannot invent an account actor.");
});

test("failed exchange after verified grant loading retains the model actor", integrationOptions, async () => {
  const fixture = await seed();
  const client = browser();
  client.setSession((await createSession(fixture.userId)).token);
  const result = await client.follow(authorization(fixture.clientId));
  assert.ok(result.searchParams.get("code"));
  await prisma.user.update({ where: { id: fixture.userId }, data: { isActive: false } });
  assert.equal((await exchange(fixture.clientId, result.searchParams.get("code")!)).status, 400);
  const failure = await prisma.auditLog.findFirst({ where: { eventType: "SSO_TOKEN_REJECTED", actorUserId: fixture.userId } });
  assert.ok(failure, "Account lookup failure after model verification still has a known grant actor.");
});

test("pre-login Interaction is indexed by client and purged without a fabricated account", integrationOptions, async () => {
  const fixture = await seed();
  const client = browser();
  const response = await client.request(authorization(fixture.clientId));
  assert.equal(response.status, 303);
  const where = { model: "Interaction", clientIdHash: hashOidcIdentifier(fixture.clientId) };
  const pending = await prisma.oidcArtifact.findMany({ where });
  assert.equal(pending.length, 1);
  assert.equal(pending[0].accountIdHash, null);
  await prisma.projectConnection.update({ where: { id: fixture.connectionId }, data: { enabled: false } });
  assert.equal((await prisma.oidcArtifact.deleteMany({ where: { clientIdHash: hashOidcIdentifier(fixture.clientId) } })).count, 1);
  assert.equal(await prisma.oidcArtifact.count({ where }), 0);
  const resumed = await client.request(response.headers.get("location")!);
  assert.notEqual(resumed.status, 303, "Purged interaction cannot complete an authorization.");
});

test("unknown interaction IDs do not create persistent interaction-start audit rows", integrationOptions, async () => {
  const client = browser();
  const before = await prisma.auditLog.count({ where: { eventType: "SSO_INTERACTION_STARTED" } });
  const response = await client.request(`${origin}/interaction/${randomBytes(12).toString("base64url")}`);
  assert.ok(response.status >= 400, "An unknown interaction ID must fail closed.");
  const after = await prisma.auditLog.count({ where: { eventType: "SSO_INTERACTION_STARTED" } });
  assert.equal(after, before, "Unvalidated interaction IDs must not create durable audit writes.");
});
