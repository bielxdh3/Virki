// Exercises the actual issuer listener and interaction handler, with synthetic keys and a guarded disposable DB.
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { createHash, generateKeyPairSync, randomBytes, randomUUID } from "node:crypto";
import { createServer } from "node:net";
import { after, before, test } from "node:test";
import { createSession, SESSION_COOKIE_NAME } from "@virki/auth";
import { encryptOidcClientSecret, hashOidcIdentifier } from "@virki/auth/oidc-secrets";
import { prisma } from "@virki/database";
import { createTestUser, integrationOptions } from "../../../packages/auth/src/integration-fixtures";

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

async function seed() {
  const user = await createTestUser({ label: "issuer-interaction" });
  const clientId = `client-${randomUUID()}`;
  const connection = await prisma.projectConnection.create({ data: {
    name: "Issuer interaction", slug: clientId, origin: "https://project.integration.invalid", clientId,
    clientSecretCiphertext: encryptOidcClientSecret(clientSecret), redirectUris: [redirectUri]
  } });
  await prisma.userProjectGrant.create({ data: { userId: user.id, connectionId: connection.id } });
  return { userId: user.id, clientId, connectionId: connection.id };
}

function browser() {
  const cookies = new Map<string, string>();
  return {
    setSession: (token: string) => cookies.set(SESSION_COOKIE_NAME, token),
    async request(url: string) {
      assert.equal(new URL(url, origin).origin, origin, "All HTTP traffic must stay on the local issuer.");
      const response = await fetch(new URL(url, origin), { redirect: "manual", headers: { cookie: [...cookies].map(([name, value]) => `${name}=${value}`).join("; ") } });
      for (const cookie of response.headers.getSetCookie()) {
        const pair = cookie.split(";", 1)[0];
        const index = pair.indexOf("=");
        cookies.set(pair.slice(0, index), pair.slice(index + 1));
      }
      return response;
    },
    async follow(url: string) {
      for (let hop = 0; hop < 16; hop += 1) {
        const response = await this.request(url);
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

function authorization(clientId: string, extra: Record<string, string> = {}) {
  return `${origin}/auth?${new URLSearchParams({ client_id: clientId, redirect_uri: redirectUri, response_type: "code", scope: "openid",
    state: randomBytes(24).toString("base64url"), nonce: randomBytes(24).toString("base64url"),
    code_challenge: createHash("sha256").update(verifier).digest("base64url"), code_challenge_method: "S256", ...extra })}`;
}

async function exchange(clientId: string, code: string) {
  const response = await fetch(`${origin}/token`, { method: "POST", headers: {
    "content-type": "application/x-www-form-urlencoded", authorization: `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString("base64")}`
  }, body: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: redirectUri, code_verifier: verifier }) });
  return { status: response.status, body: await response.json() as { id_token?: string; error?: string } };
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
