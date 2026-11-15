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

const stagingPasskeyEnv = {
  NODE_ENV: "production",
  VIRKI_HUB_PERIMETER_MODE: "native",
  VIRKI_STAGING_PASSKEY_RP_ENABLED: "true",
  VIRKI_PORTAL_HOSTNAME: "staging-portal.biel.dev.br",
  VIRKI_HUB_HOSTNAME: "staging-hub.biel.dev.br",
  VIRKI_PASSKEYS_ENABLED: "true",
  VIRKI_ADMIN_PASSKEYS_ENABLED: "true",
  VIRKI_PASSKEYS_LOCAL_TESTING: "true"
};

test("opted-in native staging uses distinct exact HTTPS USER and ADMIN relying parties", () => {
  const env = stagingPasskeyEnv;
  assert.deepEqual(expectedPasskeyRP(env, env.VIRKI_PORTAL_HOSTNAME, "USER"), {
    rpID: env.VIRKI_PORTAL_HOSTNAME, origin: "https://staging-portal.biel.dev.br"
  });
  assert.deepEqual(expectedPasskeyRP(env, env.VIRKI_HUB_HOSTNAME, "ADMIN"), {
    rpID: env.VIRKI_HUB_HOSTNAME, origin: "https://staging-hub.biel.dev.br"
  });
  assert.equal(passkeysEnabledForRequest("portal", env.VIRKI_PORTAL_HOSTNAME, env, "USER"), true);
  assert.equal(passkeysEnabledForRequest("hub", env.VIRKI_HUB_HOSTNAME, env, "ADMIN"), true);

  for (const [surface, host, role] of [
    ["hub", env.VIRKI_PORTAL_HOSTNAME, "USER"],
    ["portal", env.VIRKI_HUB_HOSTNAME, "ADMIN"],
    ["portal", env.VIRKI_HUB_HOSTNAME, "USER"],
    ["hub", env.VIRKI_PORTAL_HOSTNAME, "ADMIN"],
    ["portal", "portal.biel.dev.br", "USER"],
    ["hub", "hub.biel.dev.br", "ADMIN"],
    ["portal", `evil.${env.VIRKI_PORTAL_HOSTNAME}`, "USER"],
    ["hub", `evil.${env.VIRKI_HUB_HOSTNAME}`, "ADMIN"],
    ["hub", env.VIRKI_HUB_HOSTNAME, "USER"],
    ["portal", env.VIRKI_PORTAL_HOSTNAME, "ADMIN"],
    ["local", "localhost", "USER"],
    ["local", "localhost", "ADMIN"]
  ] as const) {
    assert.equal(passkeysEnabledForRequest(surface, host, env, role), false, `${role} ${surface}/${host}`);
  }
  assert.throws(() => expectedPasskeyRP(env, env.VIRKI_HUB_HOSTNAME, "USER"), /Passkey ceremony rejected/u);
  assert.throws(() => expectedPasskeyRP(env, env.VIRKI_PORTAL_HOSTNAME, "ADMIN"), /Passkey ceremony rejected/u);
  assert.throws(() => expectedPasskeyRP(env, "portal.biel.dev.br", "USER"), /Passkey ceremony rejected/u);
  assert.throws(() => expectedPasskeyRP(env, "hub.biel.dev.br", "ADMIN"), /Passkey ceremony rejected/u);
  assert.throws(() => expectedPasskeyRP(env, "localhost", "ADMIN"), /Passkey ceremony rejected/u);
  assert.equal(passkeysEnabledForRequest("portal", env.VIRKI_PORTAL_HOSTNAME, {
    ...env, VIRKI_PASSKEYS_ENABLED: "false"
  }), false);
  assert.equal(passkeysEnabledForRequest("hub", env.VIRKI_HUB_HOSTNAME, {
    ...env, VIRKI_ADMIN_PASSKEYS_ENABLED: "false"
  }, "ADMIN"), false);
  assert.equal(passkeysEnabledForRequest("hub", env.VIRKI_HUB_HOSTNAME, {
    ...env, VIRKI_PASSKEYS_ENABLED: "false"
  }, "ADMIN"), false);
});

test("native staging RP opt-in fails closed for incomplete, reused or malformed names and contexts", () => {
  const defaults = {
    ...stagingPasskeyEnv,
    VIRKI_STAGING_PASSKEY_RP_ENABLED: "false",
    VIRKI_PORTAL_HOSTNAME: "staging-portal.biel.dev.br",
    VIRKI_HUB_HOSTNAME: "staging-hub.biel.dev.br"
  };
  // Custom surface hostnames alone never alter production's RP default.
  assert.deepEqual(expectedPasskeyRP(defaults, "portal.biel.dev.br"), {
    rpID: "portal.biel.dev.br", origin: "https://portal.biel.dev.br"
  });
  assert.deepEqual(expectedPasskeyRP(defaults, "hub.biel.dev.br", "ADMIN"), {
    rpID: "hub.biel.dev.br", origin: "https://hub.biel.dev.br"
  });
  assert.equal(passkeysEnabledForRequest("portal", "staging-portal.biel.dev.br", defaults), false);
  assert.equal(passkeysEnabledForRequest("hub", "staging-hub.biel.dev.br", defaults, "ADMIN"), false);

  const invalid: Array<[string, Record<string, string | undefined>]> = [
    ["missing portal", { VIRKI_PORTAL_HOSTNAME: undefined }],
    ["missing hub", { VIRKI_HUB_HOSTNAME: undefined }],
    ["empty portal", { VIRKI_PORTAL_HOSTNAME: "" }],
    ["same host", { VIRKI_HUB_HOSTNAME: stagingPasskeyEnv.VIRKI_PORTAL_HOSTNAME }],
    ["prod USER host", { VIRKI_PORTAL_HOSTNAME: "portal.biel.dev.br" }],
    ["prod ADMIN host", { VIRKI_HUB_HOSTNAME: "hub.biel.dev.br" }],
    ["cross-role prod USER host", { VIRKI_HUB_HOSTNAME: "portal.biel.dev.br" }],
    ["cross-role prod ADMIN host", { VIRKI_PORTAL_HOSTNAME: "hub.biel.dev.br" }],
    ["shared parent", { VIRKI_PORTAL_HOSTNAME: "biel.dev.br" }],
    ["nested under prod", { VIRKI_HUB_HOSTNAME: "staging.hub.biel.dev.br" }],
    ["upper case", { VIRKI_PORTAL_HOSTNAME: "Staging-Portal.biel.dev.br" }],
    ["trailing dot", { VIRKI_PORTAL_HOSTNAME: "staging-portal.biel.dev.br." }],
    ["leading dot", { VIRKI_PORTAL_HOSTNAME: ".staging.biel.dev.br" }],
    ["extra port", { VIRKI_PORTAL_HOSTNAME: "staging-portal.biel.dev.br:443" }],
    ["scheme", { VIRKI_HUB_HOSTNAME: "https://staging-hub.biel.dev.br" }],
    ["wildcard", { VIRKI_PORTAL_HOSTNAME: "*.biel.dev.br" }],
    ["IP", { VIRKI_PORTAL_HOSTNAME: "192.0.2.12" }],
    ["bracketed IPv6", { VIRKI_HUB_HOSTNAME: "[2001:db8::1]" }],
    ["localhost", { VIRKI_PORTAL_HOSTNAME: "localhost" }],
    ["localhost suffix", { VIRKI_PORTAL_HOSTNAME: "portal.localhost" }],
    ["unicode", { VIRKI_PORTAL_HOSTNAME: "portál.staging.example" }],
    ["punycode IDN", { VIRKI_PORTAL_HOSTNAME: "xn--portl-4sa.example" }],
    ["control", { VIRKI_PORTAL_HOSTNAME: "staging\nhost.example" }],
    ["space", { VIRKI_PORTAL_HOSTNAME: "staging host.example" }],
    ["invalid label", { VIRKI_PORTAL_HOSTNAME: "-staging.example" }],
    ["single label", { VIRKI_PORTAL_HOSTNAME: "staging" }],
    ["staging flag empty", { VIRKI_STAGING_PASSKEY_RP_ENABLED: "" }],
    ["staging flag wrong case", { VIRKI_STAGING_PASSKEY_RP_ENABLED: "TRUE" }],
    ["non-native", { VIRKI_HUB_PERIMETER_MODE: "access" }],
    ["missing perimeter mode", { VIRKI_HUB_PERIMETER_MODE: undefined }],
    ["test NODE_ENV", { NODE_ENV: "test" }],
    ["missing NODE_ENV", { NODE_ENV: undefined }]
  ];
  for (const [reason, overrides] of invalid) {
    const env = { ...stagingPasskeyEnv, ...overrides };
    for (const [role, host, surface] of [
      ["USER", "staging-portal.biel.dev.br", "portal"],
      ["ADMIN", "staging-hub.biel.dev.br", "hub"]
    ] as const) {
      assert.throws(() => expectedPasskeyRP(env, host, role), /Passkey ceremony rejected/u, `${reason}, ${role}`);
      assert.equal(passkeysEnabledForRequest(surface, host, env, role), false, `${reason}, ${role}`);
    }
    assert.throws(() => expectedPasskeyRP(env, "portal.biel.dev.br", "USER"),
      /Passkey ceremony rejected/u, `${reason}: no production fallback`);
    assert.throws(() => expectedPasskeyRP(env, "hub.biel.dev.br", "ADMIN"),
      /Passkey ceremony rejected/u, `${reason}: no production ADMIN fallback`);
    assert.equal(passkeysEnabledForRequest("local", "localhost", env, "USER"), false,
      `${reason}: no localhost bypass`);
  }
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
