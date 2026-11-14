import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { prisma } from "@virki/database";
import { hashPassword } from "./index";
import {
  createPasskeyBrowserToken,
  passkeysEnabledForRequest,
  expectedPasskeyRP,
  hashPasskeyChallenge,
  readClientChallenge,
  startPasskeyRegistration,
  finishPasskeyRegistration,
  startPasskeyAuthentication,
  validatePasskeyName
} from "./passkeys";

test("WebAuthn cannot expand the USER origin to the ADMIN subdomain", () => {
  const env = { NODE_ENV: "production", VIRKI_PASSKEYS_ENABLED: "true" };
  assert.deepEqual(expectedPasskeyRP(env), { rpID: "portal.biel.dev.br", origin: "https://portal.biel.dev.br" });
  assert.equal(passkeysEnabledForRequest("portal", "portal.biel.dev.br", env), true);
  for (const [surface, host] of [["hub", "hub.biel.dev.br"], ["local", "localhost"], ["portal", "evil.portal.biel.dev.br"]]) {
    assert.equal(passkeysEnabledForRequest(surface, host, env), false);
  }
  assert.equal(passkeysEnabledForRequest("portal", "portal.biel.dev.br", { ...env, VIRKI_PASSKEYS_ENABLED: "false" }), false);
  assert.deepEqual(expectedPasskeyRP({ NODE_ENV: "test", VIRKI_PASSKEYS_LOCAL_TESTING: "true" }, "portal.localhost"), { rpID: "portal.localhost", origin: "https://portal.localhost:3001" });
  assert.equal(passkeysEnabledForRequest("portal", "portal.localhost", { ...env, NODE_ENV: "test", VIRKI_PASSKEYS_LOCAL_TESTING: "true" }), true);
  assert.equal(passkeysEnabledForRequest("portal", "portal.localhost", { ...env, NODE_ENV: "production", VIRKI_PASSKEYS_LOCAL_TESTING: "true" }), false);
});

test("ADMIN WebAuthn requires a separate hub RP, separate rollout flag and role", async (context) => {
  const env = { NODE_ENV: "production", VIRKI_PASSKEYS_ENABLED: "true", VIRKI_ADMIN_PASSKEYS_ENABLED: "true" };
  assert.deepEqual(expectedPasskeyRP(env, "hub.biel.dev.br", "ADMIN"), { rpID: "hub.biel.dev.br", origin: "https://hub.biel.dev.br" });
  assert.equal(passkeysEnabledForRequest("hub", "hub.biel.dev.br", env, "ADMIN"), true);
  assert.equal(passkeysEnabledForRequest("hub", "hub.biel.dev.br", env, "USER"), false);
  assert.equal(passkeysEnabledForRequest("portal", "portal.biel.dev.br", env, "ADMIN"), false);
  assert.equal(passkeysEnabledForRequest("hub", "evil.hub.biel.dev.br", env, "ADMIN"), false);
  assert.equal(passkeysEnabledForRequest("hub", "hub.biel.dev.br", { ...env, VIRKI_ADMIN_PASSKEYS_ENABLED: "false" }, "ADMIN"), false);
  assert.throws(() => expectedPasskeyRP(env, "portal.biel.dev.br", "ADMIN"), /Passkey ceremony rejected/u);
  assert.throws(() => expectedPasskeyRP(env, "hub.biel.dev.br", "USER"), /Passkey ceremony rejected/u);
  assert.throws(() => expectedPasskeyRP(env, "attacker.invalid", "ADMIN"), /Passkey ceremony rejected/u);
  assert.deepEqual(expectedPasskeyRP({ ...env, NODE_ENV: "test", VIRKI_PASSKEYS_LOCAL_TESTING: "true" }, "localhost", "ADMIN"), { rpID: "localhost", origin: "http://localhost:3001" });
  assert.throws(() => expectedPasskeyRP({ ...env, VIRKI_PASSKEYS_LOCAL_TESTING: "true" }, "localhost", "ADMIN"));

  const oldFlag = process.env.VIRKI_ADMIN_PASSKEYS_ENABLED;
  process.env.VIRKI_ADMIN_PASSKEYS_ENABLED = "false";
  context.after(() => { if (oldFlag === undefined) delete process.env.VIRKI_ADMIN_PASSKEYS_ENABLED; else process.env.VIRKI_ADMIN_PASSKEYS_ENABLED = oldFlag; });
  // Feature-disabled direct callers must not mint or consume a database challenge.
  await assert.rejects(startPasskeyRegistration("user-id", "session-id", "password", createPasskeyBrowserToken(), "hub.biel.dev.br", "", "ADMIN"));
  await assert.rejects(finishPasskeyRegistration("user-id", "session-id", createPasskeyBrowserToken(), {} as never, "key", "hub.biel.dev.br", "ADMIN"));
});

test("clientData only supplies an exact, bounded challenge; stored digest matches original", () => {
  const challenge = "f".repeat(43);
  const data = Buffer.from(JSON.stringify({ type: "webauthn.get", challenge, origin: "https://portal.biel.dev.br" })).toString("base64url");
  assert.equal(readClientChallenge(data, "webauthn.get"), challenge);
  assert.equal(readClientChallenge(data, "webauthn.create"), null);
  assert.equal(readClientChallenge("!", "webauthn.get"), null);
  assert.equal(readClientChallenge(Buffer.from(JSON.stringify({ type: "webauthn.get", challenge: "x" })).toString("base64url"), "webauthn.get"), null);
  assert.equal(hashPasskeyChallenge(challenge), createHash("sha256").update(challenge).digest("hex"));
});

test("passkey labels are bounded and cannot carry control characters", () => {
  assert.equal(validatePasskeyName("  Meu celular  "), "Meu celular");
  assert.equal(validatePasskeyName("\nmalicioso"), null);
  assert.equal(validatePasskeyName("x".repeat(81)), null);
});

test("password-assisted passkey start rejects a verifier rotated after the password was checked", async (t) => {
  const email = "rotated-verifier@integration.invalid";
  const oldPassword = "previous-password-verified-by-argon2";
  const newPassword = "unrelated-replacement-password";
  const originalHash = await hashPassword(oldPassword);
  const rotatedHash = await hashPassword(newPassword);
  const actor = { id: "rotating-user", email, displayName: "Rotation", role: "USER" as const, isActive: true, accountStatus: "ACTIVE" as const };
  let userReads = 0;
  let credentialReads = 0;
  let savedChallenges = 0;
  let persistedProofHash: string | undefined;
  function replaceMethod(target: object, name: string, method: unknown) {
    // Prisma delegates are proxies whose descriptors do not work with t.mock.method.
    const original = Reflect.get(target, name);
    Object.defineProperty(target, name, { value: method, configurable: true, writable: true });
    t.after(() => Object.defineProperty(target, name, { value: original, configurable: true, writable: true }));
  }

  // Deterministically rotate the stored verifier at the exact second read:
  // authenticateUser has already verified oldPassword using originalHash.
  replaceMethod(prisma.user, "findUnique", async () => {
    userReads++;
    return { ...actor, passwordHash: userReads === 1 ? originalHash : rotatedHash };
  });
  replaceMethod(prisma, "$transaction", async (callback: (tx: unknown) => Promise<unknown>) => callback({
    $queryRaw: async () => [],
    loginRateLimit: { findUnique: async () => null, create: async () => ({}) }
  }));
  replaceMethod(prisma, "passkeyCredential", { findMany: async () => {
    credentialReads++;
    return [{ credentialId: "leaked-credential-id", transports: ["internal"] }];
  } });
  replaceMethod(prisma, "passkeyChallenge", {
    create: async (request: { data: { proofHash?: string } }) => {
      savedChallenges++;
      persistedProofHash = request.data.proofHash;
      return {};
    },
    findMany: async () => []
  });

  await assert.rejects(
    startPasskeyAuthentication(createPasskeyBrowserToken(), "203.0.113.125", email, "portal.biel.dev.br", oldPassword),
    /Passkey ceremony rejected/
  );
  assert.equal(userReads, 2, "rotation occurred after the first password verifier lookup");
  assert.equal(credentialReads, 0, "rotated credentials must not be enumerated");
  assert.equal(savedChallenges, 0, "rotated proof must not mint an authentication challenge");

  const current = await startPasskeyAuthentication(createPasskeyBrowserToken(), "203.0.113.126", email, "portal.biel.dev.br", newPassword);
  assert.equal(current.allowCredentials?.[0]?.id, "leaked-credential-id", "the replacement password still works");
  assert.equal(credentialReads, 1);
  assert.equal(savedChallenges, 1);
  assert.equal(persistedProofHash, hashPasskeyChallenge(rotatedHash), "successful proof is pinned to the actually verified hash");

  await assert.rejects(startPasskeyAuthentication(createPasskeyBrowserToken(), "203.0.113.127", email, "portal.biel.dev.br", "wrong-password"), /Passkey ceremony rejected/);
  assert.equal(credentialReads, 1, "bad password still cannot enumerate credentials");
  assert.equal(savedChallenges, 1, "bad password still cannot create a challenge");
});
