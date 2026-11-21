import assert from "node:assert/strict";
import { randomBytes, randomInt } from "node:crypto";
import { after, test } from "node:test";
import { prisma } from "@virki/database";
import { CSRF_FORM_FIELD_NAME, createCsrfToken } from "@virki/auth/csrf";
import { getSessionByToken, SESSION_COOKIE_NAME } from "@virki/auth";
import { createTotpSecret, DEVICE_COOKIE_NAME, hashDeviceToken, LOGIN_EMAIL_CEREMONY_ACCOUNT_LIMIT, LOGIN_EMAIL_CEREMONY_SOURCE_LIMIT, startLoginCeremony, type LoginCeremonyStart } from "@virki/auth/security";
import { createTestUser, integrationOptions, queuedEmails } from "../../../../../../../packages/auth/src/integration-fixtures";
import { POST } from "./route";
import { POST as loginPost } from "../route";

after(() => prisma.$disconnect());

type Ceremony = Extract<LoginCeremonyStart, { kind: "CEREMONY" }>;

async function createTrustedTotpDevice(label: string) {
  const user = await createTestUser({ label, totpSecret: createTotpSecret() });
  const deviceToken = randomBytes(32).toString("base64url");
  await prisma.trustedDevice.create({ data: { userId: user.id, deviceIdHash: hashDeviceToken(deviceToken) } });
  return { user, deviceToken };
}

async function startTotpRecoveryChallenge(userId: string, deviceToken: string, now: Date): Promise<Ceremony> {
  const start = await startLoginCeremony(userId, deviceToken, "pt-BR", now, true, "USER");
  assert.equal(start.kind, "CEREMONY");
  assert.equal(start.factor, "TOTP");
  return start as Ceremony;
}

async function postRecovery(ceremonyId: string, deviceToken: string, address: string): Promise<URL> {
  const formData = new FormData();
  formData.set(CSRF_FORM_FIELD_NAME, createCsrfToken({ scope: "login-verification" }));
  formData.set("ceremony", ceremonyId);
  formData.set("factor", "recovery");
  formData.set("code", "000000000000000000");
  formData.set("flow", "recovery");
  const response = await POST(new Request("https://portal.biel.dev.br/api/login/verify", {
    method: "POST",
    headers: {
      host: "portal.biel.dev.br",
      origin: "https://portal.biel.dev.br",
      cookie: `${DEVICE_COOKIE_NAME}=${deviceToken}`,
      "cf-connecting-ip": address
    },
    body: formData
  }));
  assert.equal(response.status, 303);
  const location = response.headers.get("location");
  assert.ok(location);
  return new URL(location);
}

function testSourceAddress() {
  return `2001:db8::${randomInt(1, 0xffff).toString(16)}`;
}

test("trusted TOTP recovery email reopenings keep the per-device quota", integrationOptions, async () => {
  const previousPortalUrl = process.env.VIRKI_PORTAL_URL;
  process.env.VIRKI_PORTAL_URL = "https://portal.biel.dev.br";
  try {
    const { user, deviceToken } = await createTrustedTotpDevice("recovery-device-quota");
    const baselineMails = (await queuedEmails(user.email)).length;
    const address = testSourceAddress();
    const base = new Date();
    const locations: URL[] = [];

    for (let attempt = 0; attempt < LOGIN_EMAIL_CEREMONY_ACCOUNT_LIMIT + 1; attempt += 1) {
      const ceremony = await startTotpRecoveryChallenge(user.id, deviceToken, new Date(base.getTime() + attempt * 1_000));
      locations.push(await postRecovery(ceremony.ceremonyId, deviceToken, address));
    }

    assert.equal(locations.filter((location) => location.searchParams.get("factor") === "email").length, LOGIN_EMAIL_CEREMONY_ACCOUNT_LIMIT);
    assert.equal(locations.filter((location) => location.searchParams.get("error") === "1").length, 1);
    assert.equal((await queuedEmails(user.email)).length - baselineMails, LOGIN_EMAIL_CEREMONY_ACCOUNT_LIMIT);
  } finally {
    if (previousPortalUrl === undefined) delete process.env.VIRKI_PORTAL_URL;
    else process.env.VIRKI_PORTAL_URL = previousPortalUrl;
  }
});

test("trusted TOTP recovery email reopenings share the account quota across devices", integrationOptions, async () => {
  const previousPortalUrl = process.env.VIRKI_PORTAL_URL;
  process.env.VIRKI_PORTAL_URL = "https://portal.biel.dev.br";
  try {
    // The fixture helper appends "-" and a UUID (37 bytes); keep the local part at most 64 octets.
    const { user, deviceToken: firstDeviceToken } = await createTrustedTotpDevice("recovery-account-quota");
    assert.ok(Buffer.byteLength(user.email.split("@")[0], "utf8") <= 64, "recovery fixture must have a valid SMTP local part");
    const secondDeviceToken = randomBytes(32).toString("base64url");
    await prisma.trustedDevice.create({ data: { userId: user.id, deviceIdHash: hashDeviceToken(secondDeviceToken) } });
    const baselineMails = (await queuedEmails(user.email)).length;
    const address = testSourceAddress();
    const base = new Date();
    const devices = [firstDeviceToken, secondDeviceToken];
    const locations: URL[] = [];

    for (let attempt = 0; attempt < LOGIN_EMAIL_CEREMONY_ACCOUNT_LIMIT + 1; attempt += 1) {
      const deviceToken = devices[attempt % devices.length];
      const ceremony = await startTotpRecoveryChallenge(user.id, deviceToken, new Date(base.getTime() + attempt * 1_000));
      locations.push(await postRecovery(ceremony.ceremonyId, deviceToken, address));
    }

    assert.equal(locations.filter((location) => location.searchParams.get("factor") === "email").length, LOGIN_EMAIL_CEREMONY_ACCOUNT_LIMIT);
    assert.equal(locations.filter((location) => location.searchParams.get("error") === "1").length, 1);
    assert.equal((await queuedEmails(user.email)).length - baselineMails, LOGIN_EMAIL_CEREMONY_ACCOUNT_LIMIT);
  } finally {
    if (previousPortalUrl === undefined) delete process.env.VIRKI_PORTAL_URL;
    else process.env.VIRKI_PORTAL_URL = previousPortalUrl;
  }
});

test("trusted TOTP recovery email reopenings share the per-source quota across accounts", integrationOptions, async () => {
  const previousPortalUrl = process.env.VIRKI_PORTAL_URL;
  process.env.VIRKI_PORTAL_URL = "https://portal.biel.dev.br";
  try {
    const devices = await Promise.all(Array.from({ length: Math.ceil((LOGIN_EMAIL_CEREMONY_SOURCE_LIMIT + 1) / LOGIN_EMAIL_CEREMONY_ACCOUNT_LIMIT) }, (_, index) => createTrustedTotpDevice(`recovery-source-quota-${index}`)));
    const baselineMails = (await Promise.all(devices.map(({ user }) => queuedEmails(user.email)))).flat().length;
    const address = testSourceAddress();
    const base = new Date();
    const locations: URL[] = [];

    for (let attempt = 0; attempt < LOGIN_EMAIL_CEREMONY_ACCOUNT_LIMIT; attempt += 1) {
      for (const [accountIndex, { user, deviceToken }] of devices.entries()) {
        const ceremony = await startTotpRecoveryChallenge(user.id, deviceToken, new Date(base.getTime() + (attempt * devices.length + accountIndex) * 1_000));
        locations.push(await postRecovery(ceremony.ceremonyId, deviceToken, address));
      }
    }

    assert.equal(locations.length, devices.length * LOGIN_EMAIL_CEREMONY_ACCOUNT_LIMIT);
    assert.equal(locations.filter((location) => location.searchParams.get("factor") === "email").length, LOGIN_EMAIL_CEREMONY_SOURCE_LIMIT);
    assert.equal(locations.filter((location) => location.searchParams.get("error") === "1").length, locations.length - LOGIN_EMAIL_CEREMONY_SOURCE_LIMIT);
    const finalMails = (await Promise.all(devices.map(({ user }) => queuedEmails(user.email)))).flat().length;
    assert.equal(finalMails - baselineMails, LOGIN_EMAIL_CEREMONY_SOURCE_LIMIT);
  } finally {
    if (previousPortalUrl === undefined) delete process.env.VIRKI_PORTAL_URL;
    else process.env.VIRKI_PORTAL_URL = previousPortalUrl;
  }
});

test("authenticated login rotates an attacker-supplied pre-auth session cookie after email proof", integrationOptions, async () => {
  const previousHostname = process.env.VIRKI_PORTAL_HOSTNAME;
  const previousUrl = process.env.VIRKI_PORTAL_URL;
  process.env.VIRKI_PORTAL_HOSTNAME = "portal.session-fixation.invalid";
  process.env.VIRKI_PORTAL_URL = "http://portal.session-fixation.invalid";

  try {
    const user = await createTestUser({ label: "session-fixation" });
    const attackerSuppliedSessionToken = randomBytes(32).toString("base64url");
    const loginForm = new FormData();
    loginForm.set(CSRF_FORM_FIELD_NAME, createCsrfToken({ scope: "login" }));
    loginForm.set("email", user.email);
    loginForm.set("password", user.password);

    const loginResponse = await loginPost(new Request("http://portal.session-fixation.invalid/api/login", {
      method: "POST",
      headers: {
        host: "portal.session-fixation.invalid",
        origin: "http://portal.session-fixation.invalid",
        "cf-connecting-ip": "2001:db8::1234",
        cookie: `${SESSION_COOKIE_NAME}=${attackerSuppliedSessionToken}`
      },
      body: loginForm
    }));

    assert.equal(loginResponse.status, 303);
    const loginLocation = loginResponse.headers.get("location");
    assert.ok(loginLocation);
    const ceremonyId = new URL(loginLocation).searchParams.get("ceremony");
    assert.ok(ceremonyId);
    const deviceToken = loginResponse.cookies.get(DEVICE_COOKIE_NAME)?.value;
    assert.ok(deviceToken, "the login ceremony must issue its own device token");
    assert.equal(loginResponse.cookies.get(SESSION_COOKIE_NAME), undefined,
      "a password-only response must not issue an authenticated session before the second factor");

    const code = (await queuedEmails(user.email))
      .filter((message) => message.kind === "NEW_DEVICE_VERIFICATION" || message.kind === "EMAIL_TWO_FACTOR")
      .at(-1)?.code;
    assert.ok(code, "the new-device email proof must be available in the disposable outbox");

    const verificationForm = new FormData();
    verificationForm.set(CSRF_FORM_FIELD_NAME, createCsrfToken({ scope: "login-verification" }));
    verificationForm.set("ceremony", ceremonyId);
    verificationForm.set("factor", "email");
    verificationForm.set("code", code);
    const verificationResponse = await POST(new Request("http://portal.session-fixation.invalid/api/login/verify", {
      method: "POST",
      headers: {
        host: "portal.session-fixation.invalid",
        origin: "http://portal.session-fixation.invalid",
        "cf-connecting-ip": "2001:db8::1234",
        cookie: `${DEVICE_COOKIE_NAME}=${deviceToken}; ${SESSION_COOKIE_NAME}=${attackerSuppliedSessionToken}`
      },
      body: verificationForm
    }));

    assert.equal(verificationResponse.status, 303);
    const authenticatedSessionToken = verificationResponse.cookies.get(SESSION_COOKIE_NAME)?.value;
    assert.ok(authenticatedSessionToken, "successful second-factor verification must issue a new session cookie");
    assert.notEqual(authenticatedSessionToken, attackerSuppliedSessionToken,
      "the server must never promote or reuse a caller-supplied pre-auth session identifier");
    assert.equal((await getSessionByToken(attackerSuppliedSessionToken)), null,
      "the attacker-supplied identifier must not resolve to an authenticated session");
    assert.equal((await getSessionByToken(authenticatedSessionToken))?.user.id, user.id,
      "the newly issued session must resolve to the authenticated account");
  } finally {
    if (previousHostname === undefined) delete process.env.VIRKI_PORTAL_HOSTNAME;
    else process.env.VIRKI_PORTAL_HOSTNAME = previousHostname;
    if (previousUrl === undefined) delete process.env.VIRKI_PORTAL_URL;
    else process.env.VIRKI_PORTAL_URL = previousUrl;
  }
});
