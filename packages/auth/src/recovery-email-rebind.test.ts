import assert from "node:assert/strict";
import test from "node:test";
import { isRecoveryEmailRebindSession, normalizeNewRecoveryEmail, RECOVERY_EMAIL_REBIND_WINDOW_MS } from "./recovery-email-rebind";
import { renderEmailMessage, protectEmailPayload, decryptEmailPayload } from "./email";

function actor(now = new Date()) {
  return {
    id: "synthetic-session",
    createdAt: new Date(now.getTime() - 2_000),
    expiresAt: new Date(now.getTime() + 60_000),
    authenticationMethods: ["recovery", "passkey", "totp"],
    user: { id: "synthetic-user", email: "lost@example.invalid", role: "USER" }
  };
}

test("only a live and newly created recovery session can rebind a mailbox", () => {
  const now = new Date("2026-11-09T12:00:00.000Z");
  const valid = actor(now);
  assert.equal(isRecoveryEmailRebindSession(valid, now), true);
  assert.equal(isRecoveryEmailRebindSession({ ...valid, authenticationMethods: ["pwd", "email"] }, now), false);
  assert.equal(isRecoveryEmailRebindSession({ ...valid, authenticationMethods: ["recovery"], user: { ...valid.user, role: "GUEST" } }, now), false);
  assert.equal(isRecoveryEmailRebindSession({ ...valid, createdAt: new Date(now.getTime() + 1) }, now), false);
  assert.equal(isRecoveryEmailRebindSession({ ...valid, createdAt: new Date(now.getTime() - RECOVERY_EMAIL_REBIND_WINDOW_MS) }, now), false);
  assert.equal(isRecoveryEmailRebindSession({ ...valid, expiresAt: now }, now), false);
  assert.equal(isRecoveryEmailRebindSession({ ...valid, createdAt: new Date(NaN) }, now), false);
});

test("new mailbox accepts a single normalized address, never an address list or header", () => {
  assert.equal(normalizeNewRecoveryEmail(" New+Alias@Exemplo.COM "), "new+alias@exemplo.com");
  for (const value of ["", "a@b", "a@b.invalid, b@c.invalid", "Name <a@b.invalid>", "a@b.invalid\r\nBcc:c@d.invalid", "a..b@example.invalid"]) {
    assert.equal(normalizeNewRecoveryEmail(value), null, value);
  }
});

test("new-mail OTP uses the encrypted outbox and the old-mail notice contains no code", () => {
  const fixtureEnv = { NODE_ENV: "test" };
  const stored = protectEmailPayload({ publicValues: { displayName: "Account" }, protectedValues: { code: "123456" } }, fixtureEnv);
  assert.equal(JSON.stringify(stored).includes("123456"), false);
  const decoded = decryptEmailPayload(stored, fixtureEnv);
  assert.equal(decoded.code, "123456");
  const newMail = renderEmailMessage("RECOVERY_EMAIL_REBIND", "pt-BR", { ...decoded, recipientEmail: "new@example.invalid" });
  assert.equal(newMail.to, "new@example.invalid");
  assert.match(newMail.text, /123456/u);
  assert.equal(Object.hasOwn(newMail, "html"), false);
  const notice = renderEmailMessage("RECOVERY_EMAIL_REBIND_NOTICE", "pt-BR", { recipientEmail: "old@example.invalid" });
  assert.equal(notice.to, "old@example.invalid");
  assert.doesNotMatch(notice.text, /123456|new@example.invalid/u);
});
