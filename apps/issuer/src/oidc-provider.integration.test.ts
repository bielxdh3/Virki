// Drives a real in-process oidc-provider (configured like server.ts) through the real PrismaOidcAdapter
// against the disposable PostgreSQL. It must not import server.ts, which starts a listener at import.
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, randomBytes, randomUUID } from "node:crypto";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { after, before, test } from "node:test";
import { createTestUser, integrationOptions } from "../../../packages/auth/src/integration-fixtures";
import { encryptOidcClientSecret, hashOidcIdentifier } from "@virki/auth/oidc-secrets";
import { revokeUserOidcArtifactsInTransaction } from "@virki/auth/security";
import { prisma } from "@virki/database";
import Provider from "oidc-provider";
import { deleteExpiredOidcArtifacts, PrismaOidcAdapter } from "./adapter";

let server: Server;
let provider: Provider;
let origin: string;
const redirectUri = "https://project.integration.invalid/callback";
const clientSecret = randomBytes(24).toString("base64url");
const verifier = randomBytes(32).toString("base64url");
const challenge = createHash("sha256").update(verifier).digest("base64url");

before(async () => {
  if (integrationOptions.skip) return;
  server = createServer((request, response) => void provider.callback()(request, response));
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const jwk = generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey.export({ format: "jwk" });
  provider = new Provider(origin, {
    adapter: (model) => new PrismaOidcAdapter(model),
    clients: [],
    clientDefaults: { grant_types: ["authorization_code"], response_types: ["code"], token_endpoint_auth_method: "client_secret_basic", id_token_signed_response_alg: "ES256" },
    scopes: ["openid", "profile", "email"],
    claims: { openid: ["sub"], profile: ["name"], email: ["email", "email_verified"] },
    features: { devInteractions: { enabled: false }, clientCredentials: { enabled: false }, registration: { enabled: false }, deviceFlow: { enabled: false }, introspection: { enabled: false }, revocation: { enabled: true } },
    pkce: { methods: ["S256"], required: () => true },
    ttl: { AuthorizationCode: 90, AccessToken: 300 },
    cookies: { keys: [randomBytes(32).toString("base64url")] },
    jwks: { keys: [{ ...jwk, kid: "test", use: "sig", alg: "ES256" }] },
    findAccount: async (_context, id) => ({ accountId: id, claims: async () => ({ sub: id }) })
  });
  provider.on("server_error", () => undefined);
});

after(async () => {
  if (server) await new Promise((resolve) => server.close(resolve));
  await prisma.$disconnect();
});

async function seed() {
  const user = await createTestUser({ label: "oidc-provider" });
  const clientId = `client-${randomUUID()}`;
  const connection = await prisma.projectConnection.create({
    data: { name: "Integration", slug: clientId, origin: "https://project.integration.invalid", clientId, clientSecretCiphertext: encryptOidcClientSecret(clientSecret), redirectUris: [redirectUri] }
  });
  await prisma.userProjectGrant.create({ data: { userId: user.id, connectionId: connection.id } });
  return { userId: user.id, clientId };
}

async function issueCode({ userId, clientId }: { userId: string; clientId: string }) {
  const client = await provider.Client.find(clientId);
  assert.ok(client, "client loads through the adapter");
  const grant = new provider.Grant({ accountId: userId, clientId });
  grant.addOIDCScope("openid");
  const grantId = await grant.save();
  const code = await new provider.AuthorizationCode({ accountId: userId, client, grantId, gty: "authorization_code", redirectUri, scope: "openid", codeChallenge: challenge, codeChallengeMethod: "S256" }).save();
  return { code, grantId };
}

async function exchange(clientId: string, code: string, codeVerifier: string | null = verifier) {
  const body = new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: redirectUri });
  if (codeVerifier !== null) body.set("code_verifier", codeVerifier);
  const response = await fetch(`${origin}/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", authorization: `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString("base64")}` },
    body
  });
  const json = (await response.json()) as { access_token?: string; error?: string };
  return { status: response.status, json };
}

const userinfo = (accessToken: string) => fetch(`${origin}/me`, { headers: { authorization: `Bearer ${accessToken}` } });
const purge = (userId: string) => prisma.$transaction((transaction) => revokeUserOidcArtifactsInTransaction(transaction, userId));

test("artifact storage removes nonpositive TTL rewrites and cleanup includes the exact expiry boundary", integrationOptions, async () => {
  const fixture = await seed();
  const adapter = new PrismaOidcAdapter("Interaction");
  const interactionPayload = { params: { client_id: fixture.clientId } } as never;
  const expiredId = randomUUID();
  await adapter.upsert(expiredId, interactionPayload, 300);
  await adapter.upsert(expiredId, interactionPayload, 0);
  assert.equal(await adapter.find(expiredId), undefined);
  assert.equal(await prisma.oidcArtifact.count({ where: { idHash: hashOidcIdentifier(expiredId) } }), 0);

  const cutoff = new Date(Date.now() + 3_000);
  const identifiers = [randomUUID(), randomUUID(), randomUUID()];
  for (const [index, id] of identifiers.entries()) {
    await adapter.upsert(id, interactionPayload, 300);
    await prisma.oidcArtifact.update({ where: { model_idHash: { model: "Interaction", idHash: hashOidcIdentifier(id) } }, data: { expiresAt: new Date(cutoff.getTime() + index - 1) } });
  }
  await deleteExpiredOidcArtifacts(prisma, cutoff);
  const remaining = await prisma.oidcArtifact.findMany({ where: { idHash: { in: identifiers.map(hashOidcIdentifier) } }, select: { idHash: true } });
  assert.deepEqual(remaining, [{ idHash: hashOidcIdentifier(identifiers[2]) }]);
  await adapter.destroy(identifiers[2]);
});

test("positive control: a valid exchange succeeds and the opaque access token reaches /me", integrationOptions, async () => {
  const seeded = await seed();
  const { code } = await issueCode(seeded);
  const result = await exchange(seeded.clientId, code);
  assert.equal(result.status, 200);
  assert.ok(result.json.access_token);
  const me = await userinfo(result.json.access_token);
  assert.equal(me.status, 200);
  assert.equal(((await me.json()) as { sub: string }).sub, seeded.userId);
});

test("a redirect removed after authorization-code issuance cannot redeem the older code", integrationOptions, async () => {
  const seeded = await seed();
  const { code } = await issueCode(seeded);
  await prisma.projectConnection.update({
    where: { clientId: seeded.clientId },
    data: { redirectUris: ["https://project.integration.invalid/new-callback"] }
  });
  const result = await exchange(seeded.clientId, code);
  assert.equal(result.status, 400);
  assert.equal(result.json.error, "invalid_grant");
  assert.equal(result.json.access_token, undefined);
});

test("missing or wrong code_verifier is rejected and the code stays usable", integrationOptions, async () => {
  const seeded = await seed();
  const { code } = await issueCode(seeded);
  const missing = await exchange(seeded.clientId, code, null);
  const wrong = await exchange(seeded.clientId, code, randomBytes(32).toString("base64url"));
  assert.equal(missing.status, 400);
  assert.equal(wrong.status, 400);
  assert.equal((await exchange(seeded.clientId, code)).status, 200);
});

test("concurrent exchanges issue at most one token, and every replay is rejected", integrationOptions, async () => {
  for (let round = 0; round < 36; round += 1) {
    const seeded = await seed();
    const { code, grantId } = await issueCode(seeded);
    const results = await Promise.all([exchange(seeded.clientId, code), exchange(seeded.clientId, code), exchange(seeded.clientId, code)]);
    const winners = results.filter((result) => result.status === 200);
    assert.ok(winners.length <= 1, `round ${round}: at most one exchange succeeds: ${JSON.stringify(results.map(result => [result.status, result.json.error]))}`);
    assert.ok(results.every((result) => result.status === 200 || (result.status === 400 && result.json.error === "invalid_grant")), `losers get invalid_grant, never a 500: ${JSON.stringify(results.map((result) => [result.status, result.json.error]))}`);
    if (winners.length === 0) {
      assert.equal(
        await prisma.oidcArtifact.count({ where: { model: "AccessToken", grantHash: hashOidcIdentifier(grantId) } }),
        0,
        "a fully denied race must not leave a bearer token persisted"
      );
    }
    const third = await exchange(seeded.clientId, code);
    assert.equal(third.status, 400);
    assert.equal(third.json.error, "invalid_grant");
  }
});

test("a purge before the exchange rejects it, and a late token upsert cannot persist", integrationOptions, async () => {
  const seeded = await seed();
  const { code, grantId } = await issueCode(seeded);
  await purge(seeded.userId);
  const result = await exchange(seeded.clientId, code);
  assert.notEqual(result.status, 200);
  assert.equal(result.json.access_token, undefined);
  await assert.rejects(() => new PrismaOidcAdapter("AccessToken").upsert(randomUUID(), { accountId: seeded.userId, clientId: seeded.clientId, grantId } as never, 300), /invalid_grant/u);
  await assert.rejects(() => new PrismaOidcAdapter("AuthorizationCode").upsert(randomUUID(), { accountId: seeded.userId, clientId: seeded.clientId, grantId, redirectUri } as never, 90), /invalid_grant/u);
});

test("a purge after issuance makes the opaque access token unusable at /me", integrationOptions, async () => {
  const seeded = await seed();
  const { code } = await issueCode(seeded);
  const result = await exchange(seeded.clientId, code);
  assert.equal(result.status, 200);
  const issued = result.json.access_token as string;
  assert.equal((await userinfo(issued)).status, 200);
  await purge(seeded.userId);
  const after = await userinfo(issued);
  assert.equal(after.status, 401);
});
