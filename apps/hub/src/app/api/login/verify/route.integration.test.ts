import assert from "node:assert/strict";
import { randomBytes, randomInt } from "node:crypto";
import { after, test } from "node:test";
import { prisma } from "@virki/database";
import { CSRF_FORM_FIELD_NAME, createCsrfToken } from "@virki/auth/csrf";
import { createTotpSecret, DEVICE_COOKIE_NAME, hashDeviceToken, LOGIN_EMAIL_CEREMONY_ACCOUNT_LIMIT, LOGIN_EMAIL_CEREMONY_SOURCE_LIMIT, startLoginCeremony, type LoginCeremonyStart } from "@virki/auth/security";
import { createTestUser, integrationOptions, queuedEmails } from "../../../../../../../packages/auth/src/integration-fixtures";
import { POST } from "./route";

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
    const { user, deviceToken: firstDeviceToken } = await createTrustedTotpDevice("recovery-account-device-quota");
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
