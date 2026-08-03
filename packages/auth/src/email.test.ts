import assert from "node:assert/strict";
import test from "node:test";
import {
  createDeterministicTestTransport,
  decryptEmailPayload,
  getEmailTransportStatus,
  isSmtpEmailTransportConfigured,
  protectEmailPayload,
  renderEmailMessage
} from "./email";

test("production email is unavailable without a real transport or outbox key", () => {
  assert.deepEqual(getEmailTransportStatus({ NODE_ENV: "production" }), {
    state: "unavailable",
    reason: "transport-missing"
  });
  assert.deepEqual(
    getEmailTransportStatus({ NODE_ENV: "production", BIELOS_EMAIL_TRANSPORT: "smtp" }),
    { state: "unavailable", reason: "outbox-key-missing" }
  );
  assert.deepEqual(
    getEmailTransportStatus({
      NODE_ENV: "production",
      BIELOS_EMAIL_TRANSPORT: "smtp",
      BIELOS_EMAIL_OUTBOX_KEY: "0000000000000000000000000000000000000000000000000000000000000000",
      BIELOS_EMAIL_SMTP_HOST: "smtp-relay.brevo.com",
      BIELOS_EMAIL_SMTP_USER: "smtp-user@example.invalid",
      BIELOS_EMAIL_SMTP_PASSWORD: "smtp-password-placeholder",
      BIELOS_EMAIL_FROM: "no-reply@biel.dev.br"
    }),
    { state: "configured" }
  );
});

test("SMTP configuration is fail-closed without contacting the provider", () => {
  const configured = {
    NODE_ENV: "production",
    BIELOS_EMAIL_SMTP_HOST: "smtp-relay.brevo.com",
    BIELOS_EMAIL_SMTP_PORT: "587",
    BIELOS_EMAIL_SMTP_SECURE: "false",
    BIELOS_EMAIL_SMTP_USER: "smtp-user@example.invalid",
    BIELOS_EMAIL_SMTP_PASSWORD: "smtp-password-placeholder",
    BIELOS_EMAIL_FROM: "no-reply@biel.dev.br"
  };

  assert.equal(isSmtpEmailTransportConfigured(configured), true);
  assert.equal(
    isSmtpEmailTransportConfigured({ ...configured, BIELOS_EMAIL_FROM: "invalid" }),
    false
  );
  assert.equal(
    isSmtpEmailTransportConfigured({ ...configured, BIELOS_EMAIL_SMTP_PORT: "70000" }),
    false
  );
  assert.equal(
    isSmtpEmailTransportConfigured({ ...configured, BIELOS_EMAIL_SMTP_SECURE: "sometimes" }),
    false
  );
});

test("protected email values are encrypted at rest and reconstruct only in memory", () => {
  const payload = protectEmailPayload(
    {
      publicValues: { displayName: "Owner" },
      protectedValues: { code: "123456", actionUrl: "https://biel.dev.br/activate?token=raw" }
    },
    { NODE_ENV: "test" }
  );
  const serialized = JSON.stringify(payload);
  assert.equal(serialized.includes("123456"), false);
  assert.equal(serialized.includes("raw"), false);
  assert.deepEqual(decryptEmailPayload(payload, { NODE_ENV: "test" }), {
    displayName: "Owner",
    code: "123456",
    actionUrl: "https://biel.dev.br/activate?token=raw"
  });
});

test("deterministic transport and localized templates stay provider-neutral", async () => {
  const testTransport = createDeterministicTestTransport();
  await testTransport.transport.send(
    renderEmailMessage("EMAIL_TWO_FACTOR", "pt-BR", {
      recipientEmail: "owner@example.invalid",
      code: "654321"
    })
  );
  assert.equal(testTransport.sent.length, 1);
  assert.match(testTransport.sent[0].subject, /código/i);
  assert.match(testTransport.sent[0].text, /654321/);
});
