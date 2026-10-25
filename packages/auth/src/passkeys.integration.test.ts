import { after, test } from "node:test";
import assert from "node:assert/strict";
import { createHash, createHmac, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { isoCBOR } from "@simplewebauthn/server/helpers";
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from "@simplewebauthn/server";
import { prisma } from "@virki/database";
import { createTestUser, integrationOptions } from "./integration-fixtures";
import { confirmTotpEnrollment, startTotpEnrollment } from "./security";
import { getOidcAuthenticationContext } from "../../../apps/issuer/src/authorization-policy";
import {
  createPasskeyBrowserToken,
  finishPasskeyAuthentication,
  finishPasskeyRegistration,
  hashPasskeyChallenge,
  listUserPasskeys,
  mutatePasskey,
  startPasskeyAuthentication,
  startPasskeyRegistration
} from "./passkeys";

after(() => prisma.$disconnect());

const rpID = "portal.biel.dev.br";
const origin = "https://portal.biel.dev.br";
const sha = (value: Buffer | string) => createHash("sha256").update(value).digest();

function totpCodeForFixture(secret: string, now: Date) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bytes: number[] = [];
  let bits = 0;
  let buffer = 0;
  for (const character of secret) {
    buffer = (buffer << 5) | alphabet.indexOf(character);
    bits += 5;
    if (bits >= 8) { bytes.push((buffer >>> (bits - 8)) & 255); bits -= 8; }
  }
  const step = Math.floor(now.getTime() / 30_000);
  const digest = createHmac("sha1", Buffer.from(bytes)).update(Buffer.from(step.toString(16).padStart(16, "0"), "hex")).digest();
  return String((digest.readUInt32BE(digest[digest.length - 1]! & 15) & 0x7fffffff) % 1_000_000).padStart(6, "0");
}

test("registration challenge cannot survive second-factor enrollment/confirmation", integrationOptions, async () => {
  for (const change of ["pending", "active"] as const) {
    const user = await createTestUser({ label: `passkey-factor-switch-${change}` });
    const session = await prisma.session.create({ data: { userId: user.id, tokenHash: randomBytes(32).toString("hex"), expiresAt: new Date(Date.now() + 60_000) } });
    const nonce = createPasskeyBrowserToken();
    const registration = await startPasskeyRegistration(user.id, session.id, user.password, nonce);
    const factor = await startTotpEnrollment(user.id, user.email);
    if (change === "active") {
      const now = new Date();
      await confirmTotpEnrollment(user.id, totpCodeForFixture(factor.secret, now), now);
      assert.equal((await prisma.user.findUniqueOrThrow({ where: { id: user.id } })).secondFactorMethod, "TOTP");
    } else {
      assert.equal((await prisma.totpFactor.findUniqueOrThrow({ where: { userId: user.id } })).status, "PENDING");
    }
    await assert.rejects(finishPasskeyRegistration(user.id, session.id, nonce, registerResponse(authenticator(), registration.challenge), "Should not exist"));
    assert.equal(await prisma.passkeyCredential.count({ where: { userId: user.id } }), 0, "factor transition must not install a credential");
    assert.equal(await prisma.auditLog.count({ where: { actorUserId: user.id, eventType: "PASSKEY_REGISTERED" } }), 0, "factor transition must not emit successful registration audit");
  }
});

test("ACTIVE TOTP registration succeeds with fresh proof; revoking the factor invalidates another pending challenge", integrationOptions, async () => {
  const user = await createTestUser({ label: "passkey-totp-fresh" });
  const session = await prisma.session.create({ data: { userId: user.id, tokenHash: randomBytes(32).toString("hex"), expiresAt: new Date(Date.now() + 60_000) } });
  const { secret } = await startTotpEnrollment(user.id, user.email);
  const previousWindow = new Date(Date.now() - 30_000);
  await confirmTotpEnrollment(user.id, totpCodeForFixture(secret, previousWindow), previousWindow);

  const firstNonce = createPasskeyBrowserToken();
  const first = await startPasskeyRegistration(user.id, session.id, user.password, firstNonce, rpID, totpCodeForFixture(secret, new Date()));
  await finishPasskeyRegistration(user.id, session.id, firstNonce, registerResponse(authenticator(), first.challenge), "Allowed with active TOTP");
  assert.equal(await prisma.passkeyCredential.count({ where: { userId: user.id } }), 1);

  const secondNonce = createPasskeyBrowserToken();
  const nextWindow = new Date(Date.now() + 30_000);
  const pending = await startPasskeyRegistration(user.id, session.id, user.password, secondNonce, rpID, totpCodeForFixture(secret, nextWindow));
  // The ordinary disableTotp flow also revokes sessions. Change just this
  // factor state under the canonical User lock to prove factor fencing itself.
  await prisma.$transaction(async tx => {
    await tx.$queryRaw`SELECT "id" FROM "User" WHERE "id" = ${user.id} FOR UPDATE`;
    await tx.totpFactor.update({ where: { userId: user.id }, data: { status: "REVOKED" } });
  });
  await assert.rejects(finishPasskeyRegistration(user.id, session.id, secondNonce, registerResponse(authenticator(), pending.challenge), "Should not exist"));
  assert.equal(await prisma.passkeyCredential.count({ where: { userId: user.id } }), 1);
  assert.equal(await prisma.auditLog.count({ where: { actorUserId: user.id, eventType: "PASSKEY_REGISTERED" } }), 1);
});

async function awaitBlockedOn(blockingPid: number) {
  const until = Date.now() + 6_000;
  while (Date.now() < until) {
    const rows = await prisma.$queryRaw<Array<{ blocked: number }>>`
      SELECT COUNT(*)::int AS blocked FROM pg_stat_activity
      WHERE wait_event_type = 'Lock' AND ${blockingPid} = ANY(pg_blocking_pids(pid))
    `;
    if ((rows[0]?.blocked ?? 0) > 0) return;
    await new Promise(resolve => setTimeout(resolve, 15));
  }
  throw new Error("Expected physical PostgreSQL lock contention did not occur");
}

function authenticator() {
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const jwk = publicKey.export({ format: "jwk" });
  const key = isoCBOR.encode(new Map<number, number | Uint8Array>([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x!, "base64url")], [-3, Buffer.from(jwk.y!, "base64url")]]));
  return { credentialId: randomBytes(32).toString("base64url"), key, privateKey };
}

function clientData(type: "webauthn.create" | "webauthn.get", challenge: string, targetOrigin = origin) {
  return Buffer.from(JSON.stringify({ type, challenge, origin: targetOrigin, crossOrigin: false })).toString("base64url");
}

function registerResponse(key: ReturnType<typeof authenticator>, challenge: string): RegistrationResponseJSON {
  const identifier = Buffer.from(key.credentialId, "base64url");
  const data = Buffer.concat([
    sha(rpID), Buffer.from([0x45, 0, 0, 0, 0]), Buffer.alloc(16),
    Buffer.from([identifier.length >> 8, identifier.length & 255]), identifier, Buffer.from(key.key)
  ]);
  const attestation = isoCBOR.encode(new Map<string, string | Map<string, never> | Uint8Array>([["fmt", "none"], ["attStmt", new Map<string, never>()], ["authData", data]]));
  return {
    id: key.credentialId, rawId: key.credentialId, type: "public-key",
    response: { clientDataJSON: clientData("webauthn.create", challenge), attestationObject: Buffer.from(attestation).toString("base64url"), transports: ["internal"] },
    clientExtensionResults: {}, authenticatorAttachment: "platform"
  };
}

function assertion(key: ReturnType<typeof authenticator>, userId: string, challenge: string, overrides: { targetOrigin?: string; targetRpId?: string; uv?: boolean; counter?: number; userHandle?: string } = {}): AuthenticationResponseJSON {
  const data = Buffer.concat([sha(overrides.targetRpId ?? rpID), Buffer.from([overrides.uv === false ? 0x01 : 0x05]), Buffer.from([0, 0, 0, overrides.counter ?? 1])]);
  const encodedClient = clientData("webauthn.get", challenge, overrides.targetOrigin);
  const signed = Buffer.concat([data, sha(Buffer.from(encodedClient, "base64url"))]);
  return {
    id: key.credentialId, rawId: key.credentialId, type: "public-key",
    response: {
      authenticatorData: data.toString("base64url"),
      clientDataJSON: encodedClient,
      signature: sign("sha256", signed, key.privateKey).toString("base64url"),
      userHandle: overrides.userHandle ?? Buffer.from(userId, "utf8").toString("base64url")
    },
    clientExtensionResults: {}, authenticatorAttachment: "platform"
  };
}

test("passkey cryptography, account binding, replay, UV, RP, origin, revocation and OIDC assurance on disposable PostgreSQL", integrationOptions, async () => {
  const user = await createTestUser({ label: "passkeys" });
  const session = await prisma.session.create({ data: { userId: user.id, tokenHash: randomBytes(32).toString("hex"), expiresAt: new Date(Date.now() + 60 * 60_000) } });
  const other = await createTestUser({ label: "passkeys-other" });
  const key = authenticator();
  const nonce = createPasskeyBrowserToken();

  const registration = await startPasskeyRegistration(user.id, session.id, user.password, nonce);
  await assert.rejects(finishPasskeyRegistration(other.id, session.id, nonce, registerResponse(key, registration.challenge), "intrusa"));
  assert.equal((await prisma.passkeyChallenge.findUniqueOrThrow({ where: { challengeHash: hashPasskeyChallenge(registration.challenge) } })).consumedAt !== null, true);
  await assert.rejects(finishPasskeyRegistration(user.id, session.id, nonce, registerResponse(key, registration.challenge), "replay"));

  const expiredToken = createPasskeyBrowserToken();
  const registration2 = await startPasskeyRegistration(user.id, session.id, user.password, expiredToken);
  const challenge2 = await prisma.passkeyChallenge.findUniqueOrThrow({ where: { challengeHash: hashPasskeyChallenge(registration2.challenge) } });
  await prisma.passkeyChallenge.update({ where: { id: challenge2.id }, data: { expiresAt: new Date(Date.now() - 1_000) } });
  await assert.rejects(finishPasskeyRegistration(user.id, session.id, expiredToken, registerResponse(key, registration2.challenge), "expired"));

  const regToken = createPasskeyBrowserToken();
  const options = await startPasskeyRegistration(user.id, session.id, user.password, regToken);
  await finishPasskeyRegistration(user.id, session.id, regToken, registerResponse(key, options.challenge), "Chave A");
  assert.equal((await listUserPasskeys(user.id))[0]?.name, "Chave A");
  assert.equal((await listUserPasskeys(other.id)).length, 0);

  const loginToken = createPasskeyBrowserToken();
  const login = await startPasskeyAuthentication(loginToken, "203.0.113.12");
  assert.equal(login.allowCredentials, undefined, "discoverable login does not expose stable IDs");
  const valid = assertion(key, user.id, login.challenge);
  const created = await finishPasskeyAuthentication(loginToken, valid);
  const issued = await prisma.session.findUniqueOrThrow({ where: { tokenHash: hashPasskeyChallenge(created.token) } });
  assert.deepEqual(issued.authenticationMethods, ["webauthn"]);
  assert.deepEqual(getOidcAuthenticationContext(issued.authenticationMethods), { amr: ["webauthn"], acr: "urn:virki:loa:1" });
  await assert.rejects(finishPasskeyAuthentication(loginToken, valid), "challenge replay blocked");

  for (const malformed of [
    { targetOrigin: "https://hub.biel.dev.br" },
    { targetRpId: "hub.biel.dev.br" },
    { uv: false },
    { userHandle: Buffer.from(other.id).toString("base64url") }
  ]) {
    const browserToken = createPasskeyBrowserToken();
    const options = await startPasskeyAuthentication(browserToken, "203.0.113.13");
    await assert.rejects(finishPasskeyAuthentication(browserToken, assertion(key, user.id, options.challenge, { ...malformed, counter: 2 })));
    await assert.rejects(finishPasskeyAuthentication(browserToken, assertion(key, user.id, options.challenge, { counter: 2 })), "invalid ceremony burns challenge");
  }

  await assert.rejects(startPasskeyAuthentication(createPasskeyBrowserToken(), "203.0.113.15", user.email, "portal.biel.dev.br", "wrong password"));
  const nonDiscoverableToken = createPasskeyBrowserToken();
  const namedOptions = await startPasskeyAuthentication(nonDiscoverableToken, "203.0.113.15", user.email, "portal.biel.dev.br", user.password);
  assert.equal(namedOptions.allowCredentials?.[0]?.id, key.credentialId);
  await finishPasskeyAuthentication(nonDiscoverableToken, assertion(key, user.id, namedOptions.challenge, { counter: 2 }));

  const concurrentToken = createPasskeyBrowserToken();
  const concurrent = await startPasskeyAuthentication(concurrentToken, "203.0.113.16");
  const simultaneous = await Promise.allSettled([finishPasskeyAuthentication(concurrentToken, assertion(key, user.id, concurrent.challenge, { counter: 3 })), finishPasskeyAuthentication(concurrentToken, assertion(key, user.id, concurrent.challenge, { counter: 3 }))]);
  assert.equal(simultaneous.filter(result => result.status === "fulfilled").length, 1, "only one same-challenge request succeeds");

  const rows = await listUserPasskeys(user.id);
  await assert.rejects(mutatePasskey(other.id, session.id, rows[0]!.id, other.password, "revoke"), "other account cannot revoke credential");
  await assert.rejects(mutatePasskey(user.id, session.id, rows[0]!.id, "bad password", "revoke"), "strong proof mandatory");
  await mutatePasskey(user.id, session.id, rows[0]!.id, user.password, "rename", "Renomeada");
  assert.equal((await listUserPasskeys(user.id))[0]?.name, "Renomeada");
  await assert.rejects(mutatePasskey(user.id, session.id, rows[0]!.id, user.password, "revoke"), "sixth strong-proof operation hits rate limiter");
  // Test fixture only: advance to a new proof window without changing production limits.
  await prisma.loginRateLimit.deleteMany({});
  await mutatePasskey(user.id, session.id, rows[0]!.id, user.password, "revoke");
  assert.equal((await listUserPasskeys(user.id)).length, 0);
  const revokedToken = createPasskeyBrowserToken();
  const revokedChallenge = await startPasskeyAuthentication(revokedToken, "203.0.113.17");
  await assert.rejects(finishPasskeyAuthentication(revokedToken, assertion(key, user.id, revokedChallenge.challenge, { counter: 4 })));
});

test("challenge expiry while blocked by a physical PostgreSQL row lock cannot consume stale challenge", integrationOptions, async () => {
  await assert.rejects(startPasskeyAuthentication(createPasskeyBrowserToken(), "::bad,forged"), "forwarded source must be a valid single IP address");
  const browserNonce = createPasskeyBrowserToken();
  const options = await startPasskeyAuthentication(browserNonce, "203.0.113.21");
  const row = await prisma.passkeyChallenge.findUniqueOrThrow({ where: { challengeHash: hashPasskeyChallenge(options.challenge) } });
  await prisma.passkeyChallenge.update({ where: { id: row.id }, data: { expiresAt: new Date(Date.now() + 1200) } });
  let pending!: Promise<unknown>;
  await prisma.$transaction(async tx => {
    const [blocker] = await tx.$queryRaw<Array<{ pid: number }>>`SELECT pg_backend_pid()::int AS pid`;
    await tx.$queryRaw`SELECT "id" FROM "PasskeyChallenge" WHERE "id" = ${row.id} FOR UPDATE`;
    // No valid authenticator needed here: a stale challenge must be denied BEFORE
    // signature processing and must not be marked consumed after lock expiry.
    pending = finishPasskeyAuthentication(browserNonce, {
      id: randomBytes(32).toString("base64url"), rawId: randomBytes(32).toString("base64url"), type: "public-key",
      response: { clientDataJSON: clientData("webauthn.get", options.challenge), authenticatorData: "AA", signature: "AA" },
      clientExtensionResults: {}
    });
    await awaitBlockedOn(blocker!.pid);
    await new Promise(resolve => setTimeout(resolve, 1400));
  });
  await assert.rejects(pending);
  const after = await prisma.passkeyChallenge.findUniqueOrThrow({ where: { id: row.id } });
  assert.equal(after.consumedAt, null, "stale challenge must remain unclaimed when physical lock releases");
});

test("account lock delay cannot convert an expired or revoked acting session into a successful passkey mutation", integrationOptions, async () => {
  const timezone = await prisma.$queryRaw<Array<{ zone: string }>>`SELECT current_setting('TimeZone') AS zone`;
  assert.equal(timezone[0]?.zone, "America/Porto_Velho", "exercise time-zone shifted PostgreSQL connection, not only UTC");
  const user = await createTestUser({ label: "passkey-lock-expiry" });
  const session = await prisma.session.create({ data: { userId: user.id, tokenHash: randomBytes(32).toString("hex"), expiresAt: new Date(Date.now() + 60_000) } });
  const row = await prisma.passkeyCredential.create({ data: {
    userId: user.id, credentialId: randomBytes(32).toString("base64url"), publicKey: randomBytes(32), counter: 0n,
    transports: ["internal"], backupEligible: false, backupState: false, name: "Original"
  } });
  let pending!: Promise<unknown>;
  await prisma.$transaction(async tx => {
    const [blocker] = await tx.$queryRaw<Array<{ pid: number }>>`SELECT pg_backend_pid()::int AS pid`;
    await tx.$queryRaw`SELECT "id" FROM "User" WHERE "id" = ${user.id} FOR UPDATE`;
    pending = mutatePasskey(user.id, session.id, row.id, user.password, "rename", "Should never commit");
    await awaitBlockedOn(blocker!.pid);
    await tx.session.update({ where: { id: session.id }, data: { expiresAt: new Date(Date.now() - 1000), revokedAt: new Date() } });
  });
  await assert.rejects(pending);
  assert.equal((await prisma.passkeyCredential.findUniqueOrThrow({ where: { id: row.id } })).name, "Original");
});
