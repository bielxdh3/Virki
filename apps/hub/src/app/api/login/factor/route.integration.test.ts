import assert from "node:assert/strict";
import { after, test } from "node:test";
import { prisma } from "@virki/database";
import { createCsrfToken, CSRF_FORM_FIELD_NAME } from "@virki/auth/csrf";
import { DEVICE_COOKIE_NAME, createTotpSecret, generateRecoveryCode, hashRecoveryCode, startLoginCeremony } from "@virki/auth/security";
import { createTestUser, integrationOptions } from "../../../../../../../packages/auth/src/integration-fixtures";
import { POST as selectFactor } from "./route";
import { POST as verifyCode } from "../verify/route";

after(() => prisma.$disconnect());

function request(path: string, form: FormData, deviceToken: string, origin = "https://portal.biel.dev.br") {
  return new Request(`https://portal.biel.dev.br${path}`, {
    method: "POST", headers: {
      host: "portal.biel.dev.br", origin, cookie: `${DEVICE_COOKIE_NAME}=${deviceToken}`,
      "cf-connecting-ip": "203.0.113.221"
    }, body: form
  });
}

test("PostgreSQL HTTP: CSRF, role/device and factor choice gate the one-time backup login", integrationOptions, async () => {
  const previousPortalUrl = process.env.VIRKI_PORTAL_URL;
  process.env.VIRKI_PORTAL_URL = "https://portal.biel.dev.br";
  try {
  const owner = await createTestUser({ label: "http-login-backup", totpSecret: createTotpSecret() });
  const code = generateRecoveryCode();
  await prisma.recoveryCode.create({ data: { userId: owner.id, codeHash: hashRecoveryCode(code) } });
  const started = await startLoginCeremony(owner.id, undefined, "pt-BR", new Date(), false, "USER", "203.0.113.221", "REGISTERED");
  assert.equal(started.kind, "CEREMONY");
  assert.equal(started.factor, "TOTP");

  const select = (csrf: string) => {
    const form = new FormData();
    form.set(CSRF_FORM_FIELD_NAME, csrf);
    form.set("ceremony", started.ceremonyId);
    return form;
  };
  assert.equal((await selectFactor(request("/api/login/factor", select(""), started.deviceToken))).status, 403);
  assert.equal((await selectFactor(request("/api/login/factor", select(createCsrfToken({ scope: "login-verification" })), started.deviceToken))).status, 403);
  assert.equal((await selectFactor(request("/api/login/factor", select(createCsrfToken({ scope: "login-factor-selection" })), started.deviceToken, "https://evil.invalid"))).status, 403);
  assert.equal((await selectFactor(request("/api/login/factor", select(createCsrfToken({ scope: "login-factor-selection" })), "not-this-device"))).status, 303);
  assert.equal((await prisma.recoveryCode.findFirstOrThrow({ where: { userId: owner.id } })).usedAt, null);

  const selected = await selectFactor(request("/api/login/factor", select(createCsrfToken({ scope: "login-factor-selection" })), started.deviceToken));
  assert.equal(selected.status, 303);
  assert.equal(new URL(selected.headers.get("location")!).searchParams.get("factor"), "backup");
  const submit = (factor: string, csrf: string) => {
    const form = new FormData();
    form.set(CSRF_FORM_FIELD_NAME, csrf);
    form.set("ceremony", started.ceremonyId);
    form.set("factor", factor);
    form.set("code", code);
    return form;
  };
  const csrf = createCsrfToken({ scope: "login-verification" });
  const tampered = await verifyCode(request("/api/login/verify", submit("totp", csrf), started.deviceToken));
  assert.equal(tampered.status, 303);
  assert.equal(new URL(tampered.headers.get("location")!).searchParams.get("error"), "1");
  assert.equal((await prisma.recoveryCode.findFirstOrThrow({ where: { userId: owner.id } })).usedAt, null);
  const accepted = await verifyCode(request("/api/login/verify", submit("backup", csrf), started.deviceToken));
  assert.equal(accepted.status, 303);
  assert.equal(new URL(accepted.headers.get("location")!).pathname, "/");
  assert.match(accepted.headers.get("set-cookie") ?? "", /virki_session=/u);
  assert.doesNotMatch(accepted.headers.get("set-cookie") ?? "", /;\s*Domain=/iu);
  assert.equal((await prisma.recoveryCode.findFirstOrThrow({ where: { userId: owner.id } })).usedAt instanceof Date, true);
  const repeated = await verifyCode(request("/api/login/verify", submit("backup", csrf), started.deviceToken));
  assert.equal(new URL(repeated.headers.get("location")!).searchParams.get("error"), "1");
  } finally {
    if (previousPortalUrl === undefined) delete process.env.VIRKI_PORTAL_URL;
    else process.env.VIRKI_PORTAL_URL = previousPortalUrl;
  }
});
