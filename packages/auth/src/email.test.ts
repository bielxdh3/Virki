import assert from "node:assert/strict";
import { once } from "node:events";
import { createServer } from "node:net";
import test from "node:test";
import nodemailer from "nodemailer";
import { isSingleMailboxAddress } from "./email-address";
import {
  claimNextEmailMessage,
  createDeterministicTestTransport,
  createSmtpEmailTransport,
  decryptEmailPayload,
  getEmailTransportStatus,
  isSmtpEmailTransportConfigured,
  getEmailProcessingLeaseExpiresAt,
  processNextEmailMessage,
  protectEmailPayload,
  renderEmailMessage
} from "./email";

test("invitation display names are rendered only in a plain-text body", () => {
  const displayName = "<img src=x onerror=alert(1)>";
  const message = renderEmailMessage("ACCOUNT_INVITATION", "pt-BR", {
    displayName,
    recipientEmail: "recipient@example.invalid",
    actionUrl: "https://portal.example.invalid/recover/open?request=synthetic"
  });

  assert.equal(message.text.startsWith(`${displayName},\n`), true);
  assert.equal(Object.hasOwn(message, "html"), false);
});

test("production email is unavailable without a real transport or outbox key", () => {
  assert.deepEqual(getEmailTransportStatus({ NODE_ENV: "production" }), {
    state: "unavailable",
    reason: "transport-missing"
  });
  assert.deepEqual(
    getEmailTransportStatus({ NODE_ENV: "production", VIRKI_EMAIL_TRANSPORT: "smtp" }),
    { state: "unavailable", reason: "outbox-key-missing" }
  );
  assert.deepEqual(
    getEmailTransportStatus({
      NODE_ENV: "production",
      VIRKI_EMAIL_TRANSPORT: "smtp",
      VIRKI_EMAIL_OUTBOX_KEY: "0000000000000000000000000000000000000000000000000000000000000000",
      VIRKI_EMAIL_SMTP_HOST: "smtp-relay.brevo.com",
      VIRKI_EMAIL_SMTP_USER: "smtp-user@example.invalid",
      VIRKI_EMAIL_SMTP_PASSWORD: "smtp-password-placeholder",
      VIRKI_EMAIL_FROM: "no-reply@biel.dev.br"
    }),
    { state: "configured" }
  );
});

test("SMTP configuration is fail-closed without contacting the provider", () => {
  const configured = {
    NODE_ENV: "production",
    VIRKI_EMAIL_SMTP_HOST: "smtp-relay.brevo.com",
    VIRKI_EMAIL_SMTP_PORT: "587",
    VIRKI_EMAIL_SMTP_SECURE: "false",
    VIRKI_EMAIL_SMTP_USER: "smtp-user@example.invalid",
    VIRKI_EMAIL_SMTP_PASSWORD: "smtp-password-placeholder",
    VIRKI_EMAIL_FROM: "no-reply@biel.dev.br"
  };

  assert.equal(isSmtpEmailTransportConfigured(configured), true);
  assert.equal(isSmtpEmailTransportConfigured({ ...configured, VIRKI_EMAIL_SMTP_SECURE: "" }), true);
  assert.equal(isSmtpEmailTransportConfigured({ ...configured, VIRKI_EMAIL_SMTP_SECURE: " \t " }), true);
  assert.equal(isSmtpEmailTransportConfigured({ ...configured, VIRKI_EMAIL_SMTP_SECURE: "true" }), true);
  assert.equal(
    isSmtpEmailTransportConfigured({ ...configured, VIRKI_EMAIL_FROM: "invalid" }),
    false
  );
  assert.equal(
    isSmtpEmailTransportConfigured({ ...configured, VIRKI_EMAIL_SMTP_PORT: "70000" }),
    false
  );
  assert.equal(
    isSmtpEmailTransportConfigured({ ...configured, VIRKI_EMAIL_SMTP_SECURE: "sometimes" }),
    false
  );
});

test("SMTP accepts exactly one mailbox and rejects parsed recipient lists", () => {
  for (const valid of ["alice@example.invalid", "alice.smith+trial@sub.example.invalid", "josé@exemplo.com", "alice@exemplo.com.br", "alice@bücher.example"]) {
    assert.equal(isSingleMailboxAddress(valid), true);
  }
  for (const invalid of [
    "alice@example.invalid,attacker@example.invalid",
    "Alice <alice@example.invalid>",
    "alice@example.invalid; attacker@example.invalid",
    '"Alice, Bob" <alice@example.invalid>',
    "alice@example.invalid\r\nBcc:attacker@example.invalid",
    "alice..smith@example.invalid",
    "alice@example.invalid (comment)"
  ]) assert.equal(isSingleMailboxAddress(invalid), false, invalid);
});

test("SMTP mocked delivery hands Nodemailer one structured recipient and rejects address lists", async (context) => {
  const recipients: unknown[] = [];
  context.mock.method(nodemailer, "createTransport", () => ({
    sendMail: async (message: { to: unknown }) => { recipients.push(message.to); return { messageId: "<synthetic-smtp-id@example.invalid>" }; }
  }) as never);
  const transport = createSmtpEmailTransport({
    VIRKI_EMAIL_SMTP_HOST: "smtp.example.invalid",
    VIRKI_EMAIL_SMTP_USER: "test@example.invalid",
    VIRKI_EMAIL_SMTP_PASSWORD: "synthetic-fixture-password",
    VIRKI_EMAIL_FROM: "no-reply@example.invalid"
  });
  assert.deepEqual(await transport.send({ to: "josé@bücher.example", subject: "fixture", text: "fixture" }), {
    smtpHeaderMessageId: "<synthetic-smtp-id@example.invalid>"
  });
  assert.deepEqual(recipients, [[{ name: "", address: "josé@bücher.example" }]]);
  await assert.rejects(transport.send({ to: "alice@example.invalid,attacker@example.invalid", subject: "fixture", text: "fixture" }));
  assert.equal(recipients.length, 1);
});

test("SMTP attempts use stable RFC Message-IDs across a worker retry, distinct across attempts", async (context) => {
  const accepted: Array<{ messageId?: string; to: unknown }> = [];
  context.mock.method(nodemailer, "createTransport", () => ({
    sendMail: async (mail: { messageId?: string; to: unknown }) => {
      accepted.push({ messageId: mail.messageId, to: mail.to });
      return { messageId: mail.messageId };
    }
  }) as never);
  const transport = createSmtpEmailTransport({
    VIRKI_EMAIL_SMTP_HOST: "smtp.example.invalid",
    VIRKI_EMAIL_SMTP_USER: "sender@example.invalid",
    VIRKI_EMAIL_SMTP_PASSWORD: "synthetic-fixture-password",
    VIRKI_EMAIL_FROM: "no-reply@example.invalid"
  });
  const mail = { to: "owner@example.invalid", subject: "fixture", text: "fixture" };
  const first = await transport.send({ ...mail, deliveryAttemptReference: "mail-recovered:2" });
  const same = await transport.send({ ...mail, deliveryAttemptReference: "mail-recovered:2" });
  const next = await transport.send({ ...mail, deliveryAttemptReference: "mail-recovered:3" });
  assert.deepEqual(first, same);
  assert.notDeepEqual(first, next);
  assert.match(first?.smtpHeaderMessageId ?? "", /^<[a-f0-9]{64}@example\.invalid>$/u);
  assert.deepEqual(accepted.map((entry) => entry.messageId), [
    first?.smtpHeaderMessageId, first?.smtpHeaderMessageId, next?.smtpHeaderMessageId
  ]);
  assert.equal(accepted.every((entry) => JSON.stringify(entry.to).includes("owner@example.invalid")), true);
  await assert.rejects(transport.send({ ...mail, deliveryAttemptReference: "mail-recovered:2\r\nBcc:other@example.invalid" }));
  assert.equal(accepted.length, 3);
});

test("SMTP correlation accepts long valid sender domains without exceeding the RFC Message-ID limit", async (context) => {
  const accepted: string[] = [];
  context.mock.method(nodemailer, "createTransport", () => ({
    sendMail: async (mail: { messageId?: string }) => {
      if (!mail.messageId) throw new Error("Missing correlation header");
      accepted.push(mail.messageId);
      return { messageId: mail.messageId };
    }
  }) as never);
  const domains = [
    // The exact boundary: 64 hex chars + <@> (3) + 188-domain = 255.
    ["a".repeat(63), "b".repeat(63), "c".repeat(60)].join("."),
    ["a".repeat(63), "b".repeat(63), "c".repeat(61)].join("."),
    ["a".repeat(63), "b".repeat(63), "c".repeat(63), "example", "invalid"].join("."),
    ["a".repeat(63), "b".repeat(63), "c".repeat(63), "d".repeat(43), "io"].join("."),
    "bücher.example"
  ];
  for (const domain of domains) {
    const from = `a@${domain}`;
    assert.equal(isSingleMailboxAddress(from), true, `fixture ${domain.length} domain must be accepted as SMTP mailbox`);
    const transport = createSmtpEmailTransport({
      VIRKI_EMAIL_SMTP_HOST: "smtp.example.invalid",
      VIRKI_EMAIL_SMTP_USER: "sender@example.invalid",
      VIRKI_EMAIL_SMTP_PASSWORD: "synthetic-fixture-password",
      VIRKI_EMAIL_FROM: from
    });
    const message = { to: "recipient@example.invalid", subject: "fixture", text: "fixture",
      deliveryAttemptReference: "opaque-message:1" };
    const first = await transport.send(message);
    const replay = await transport.send(message);
    const next = await transport.send({ ...message, deliveryAttemptReference: "opaque-message:2" });
    assert.equal(first?.smtpHeaderMessageId, replay?.smtpHeaderMessageId);
    assert.notEqual(first?.smtpHeaderMessageId, next?.smtpHeaderMessageId);
    assert.ok(first?.smtpHeaderMessageId);
    assert.ok(first.smtpHeaderMessageId.length <= 255, `domain length ${domain.length}`);
    assert.match(first.smtpHeaderMessageId, /^<[a-f0-9]{64}@[A-Za-z0-9.-]+>$/u);
    if (domain.length === 188) assert.ok(first.smtpHeaderMessageId.endsWith(`@${domain}>`));
  }
  assert.equal(accepted.length, domains.length * 3);
  assert.equal(new Set(accepted.filter((_, i) => i % 3 === 0)).size, domains.length,
    "different sender domains must not collide even when they share the same shortened suffix");
});

test("SMTP reuses the reserved Message-ID across sender rotation and rejects injected IDs", async (context) => {
  const emitted: string[] = [];
  context.mock.method(nodemailer, "createTransport", () => ({
    sendMail: async (mail: { messageId?: string }) => {
      if (mail.messageId) emitted.push(mail.messageId);
      return { messageId: mail.messageId };
    }
  }) as never);
  const transport = createSmtpEmailTransport({
    VIRKI_EMAIL_SMTP_HOST: "smtp.example.invalid",
    VIRKI_EMAIL_SMTP_USER: "sender@example.invalid",
    VIRKI_EMAIL_SMTP_PASSWORD: "synthetic-fixture-password",
    VIRKI_EMAIL_FROM: "no-reply@new.sender.example.invalid"
  });
  const reserved = `<${"a".repeat(64)}@old.sender.example.invalid>`;
  const mail = { to: "recipient@example.invalid", subject: "fixture", text: "fixture",
    deliveryAttemptReference: "mail-prior:2", preparedSmtpHeaderMessageId: reserved };
  assert.deepEqual(await transport.send(mail), { smtpHeaderMessageId: reserved });
  assert.deepEqual(emitted, [reserved]);
  for (const malicious of [
    `${reserved}\r\nBcc:attacker@example.invalid`,
    `<${"a".repeat(64)}@${"x".repeat(200)}.invalid>`,
    "<not-a-valid-hash@example.invalid>"
  ]) await assert.rejects(transport.send({ ...mail, preparedSmtpHeaderMessageId: malicious }));
  assert.deepEqual(emitted, [reserved], "no malformed header reaches Nodemailer");
});

test("SMTP handoff before a failed DB finalize remains traceable after lease reclaim", async () => {
  await withTestOutboxKey(async () => {
    const previousFrom = process.env.VIRKI_EMAIL_FROM;
    // The SMTP adapter accepts the same sender with surrounding whitespace.
    // The DB claim must normalize it identically before reserving the header.
    process.env.VIRKI_EMAIL_FROM = " \t no-reply@original.sender.example.invalid \t ";
    try {
    const now = new Date("2026-11-10T12:00:00.000Z");
    const queued = createMockOutboxDatabase({
      id: "mail-crash", idempotencyKey: "mail-crash", kind: "EMAIL_TWO_FACTOR",
      recipientEmail: "owner@example.invalid", locale: "en", payload: encryptedTestEmailPayload(),
      status: "QUEUED", attemptCount: 0, availableAt: new Date(0), sentAt: null,
      terminalFailedAt: null, processingLeaseExpiresAt: null, createdAt: new Date(0), updatedAt: new Date(0)
    }, { failAttemptStatus: "SENT" });
    const references: string[] = [];
    const preparedIds: string[] = [];
    const acceptedTransport = {
      async send(mail: { deliveryAttemptReference?: string; preparedSmtpHeaderMessageId?: string }) {
        references.push(mail.deliveryAttemptReference ?? "missing");
        preparedIds.push(mail.preparedSmtpHeaderMessageId ?? "missing");
        return { smtpHeaderMessageId: mail.preparedSmtpHeaderMessageId };
      }
    };

    await assert.rejects(processNextEmailMessage(acceptedTransport, now, queued.client as never), /attempt history unavailable/u);
    assert.equal(queued.message().status, "PROCESSING");
    assert.equal(queued.message().attemptCount, 1);
    assert.deepEqual(references, ["mail-crash:1"]);
    assert.match(preparedIds[0], /^<[a-f0-9]{64}@original\.sender\.example\.invalid>$/u);
    assert.equal(queued.attempts().length, 0);

    // A lease reclaim marks the uncertain first handoff interrupted, then
    // assigns a distinct persisted attempt. Rotating the SMTP sender must NOT
    // lose the first attempt's exact original Message-ID in the DB history.
    process.env.VIRKI_EMAIL_FROM = "no-reply@replacement.sender.example.invalid";
    const afterLease = new Date(now.getTime() + 6 * 60 * 1000);
    await assert.rejects(processNextEmailMessage(acceptedTransport, afterLease, queued.client as never), /attempt history unavailable/u);
    assert.deepEqual(references, ["mail-crash:1", "mail-crash:2"]);
    assert.equal(queued.message().attemptCount, 2);
    assert.deepEqual(queued.attempts().map((item) => [item.attempt, item.status, item.errorCode, item.smtpHeaderMessageId]), [
      [1, "FAILED", "worker-interrupted", preparedIds[0]]
    ]);
    assert.notEqual(preparedIds[0], preparedIds[1]);
    } finally {
      if (previousFrom === undefined) delete process.env.VIRKI_EMAIL_FROM;
      else process.env.VIRKI_EMAIL_FROM = previousFrom;
    }
  });
});

test("successful SMTP handoff stores a non-secret Message-ID without mistaking it for inbox delivery", async () => {
  await withTestOutboxKey(async () => {
    const now = new Date("2026-11-10T12:00:00.000Z");
    const queued = createMockOutboxDatabase({
      id: "mail-correlation",
      idempotencyKey: "mail-correlation",
      kind: "EMAIL_TWO_FACTOR",
      recipientEmail: "owner@example.invalid",
      locale: "en",
      payload: encryptedTestEmailPayload(),
      status: "QUEUED",
      attemptCount: 0,
      availableAt: new Date(0),
      sentAt: null,
      terminalFailedAt: null,
      processingLeaseExpiresAt: null,
      createdAt: new Date(0),
      updatedAt: new Date(0)
    });
    const transport = { async send() { return { smtpHeaderMessageId: "<correlation-123@example.invalid>" }; } };
    assert.equal(await processNextEmailMessage(transport, now, queued.client as never), "sent");
    assert.equal(queued.message().status, "SENT");
    assert.equal(queued.attempts()[0].smtpHeaderMessageId, "<correlation-123@example.invalid>");
  });
});

test("SMTP receipt with control characters is never stored in delivery metadata", async () => {
  await withTestOutboxKey(async () => {
    const now = new Date("2026-11-10T12:00:00.000Z");
    const queued = createMockOutboxDatabase({
      id: "mail-malformed-receipt", idempotencyKey: "mail-malformed-receipt", kind: "EMAIL_TWO_FACTOR",
      recipientEmail: "owner@example.invalid", locale: "en", payload: encryptedTestEmailPayload(),
      status: "QUEUED", attemptCount: 0, availableAt: new Date(0), sentAt: null,
      terminalFailedAt: null, processingLeaseExpiresAt: null, createdAt: new Date(0), updatedAt: new Date(0)
    });
    const result = await processNextEmailMessage({
      async send() { return { smtpHeaderMessageId: "<valid@example.invalid>\r\nAuthorization: secret" }; }
    }, now, queued.client as never);
    assert.equal(result, "sent");
    assert.equal(queued.attempts()[0].smtpHeaderMessageId, undefined);
  });
});

test("SMTP delivery failures are redacted without contacting an external provider", async () => {
  const server = createServer((socket) => socket.destroy());
  server.listen(0, "127.0.0.1");
  await once(server, "listening");

  try {
    const address = server.address();
    assert.ok(address && typeof address !== "string");
    const transport = createSmtpEmailTransport({
      VIRKI_EMAIL_SMTP_HOST: "127.0.0.1",
      VIRKI_EMAIL_SMTP_PORT: String(address.port),
      VIRKI_EMAIL_SMTP_SECURE: "false",
      VIRKI_EMAIL_SMTP_USER: "smtp-user@example.invalid",
      VIRKI_EMAIL_SMTP_PASSWORD: "smtp-password-placeholder",
      VIRKI_EMAIL_FROM: "no-reply@biel.dev.br"
    });

    await assert.rejects(
      () => transport.send({ to: "owner@example.invalid", subject: "Test", text: "Test" }),
      (error: unknown) => {
        assert.equal(error instanceof Error ? error.message : error, "SMTP email delivery failed.");
        return true;
      }
    );
  } finally {
    await new Promise<void>((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    });
  }
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

test("protected email values reject shortened authentic GCM tags", () => {
  const env = { NODE_ENV: "test" };
  const payload = protectEmailPayload({ publicValues: {}, protectedValues: { code: "123456" } }, env);
  assert.ok(payload.protectedValues);
  const shortened = {
    ...payload,
    protectedValues: {
      ...payload.protectedValues,
      tag: Buffer.from(payload.protectedValues.tag, "base64url").subarray(0, 4).toString("base64url")
    }
  };
  assert.throws(() => decryptEmailPayload(shortened, env));
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

test("email claims use a bounded processing lease and reclaim interrupted work with an attempt record", async () => {
  const now = new Date("2026-10-06T12:00:00.000Z");
  const stale = createMockOutboxDatabase({
    id: "mail-stale",
    idempotencyKey: "mail-stale",
    kind: "EMAIL_TWO_FACTOR",
    recipientEmail: "owner@example.invalid",
    locale: "en",
    payload: encryptedTestEmailPayload(),
    status: "PROCESSING",
    attemptCount: 2,
    availableAt: new Date(0),
    sentAt: null,
    terminalFailedAt: null,
    processingLeaseExpiresAt: new Date(now.getTime() - 1),
    createdAt: new Date(0),
    updatedAt: new Date(0)
  });

  const claimed = await claimNextEmailMessage(now, stale.client as never);
  assert.equal(claimed?.attemptCount, 3);
  assert.equal(stale.message().status, "PROCESSING");
  assert.equal((stale.message().processingLeaseExpiresAt as Date | null)?.getTime(), getEmailProcessingLeaseExpiresAt(now).getTime());
  assert.deepEqual(stale.attempts(), [{ messageId: "mail-stale", attempt: 2, status: "FAILED", errorCode: "worker-interrupted", attemptedAt: now }]);
});

test("a processing message with a missing lease is reclaimed once and stale claimers lose", async () => {
  const now = new Date("2026-10-06T12:00:00.000Z");
  const missingLease = createMockOutboxDatabase({
    id: "mail-missing-lease",
    idempotencyKey: "mail-missing-lease",
    kind: "EMAIL_TWO_FACTOR",
    recipientEmail: "owner@example.invalid",
    locale: "en",
    payload: encryptedTestEmailPayload(),
    status: "PROCESSING",
    attemptCount: 2,
    availableAt: new Date(0),
    sentAt: null,
    terminalFailedAt: null,
    processingLeaseExpiresAt: null,
    createdAt: new Date(0),
    updatedAt: new Date(0)
  });

  const claims = await Promise.all([
    claimNextEmailMessage(now, missingLease.client as never),
    claimNextEmailMessage(now, missingLease.client as never)
  ]);
  assert.equal(claims.filter(Boolean).length, 1);
  assert.equal(claims.find(Boolean)?.attemptCount, 3);
  assert.deepEqual(missingLease.attempts(), [{ messageId: "mail-missing-lease", attempt: 2, status: "FAILED", errorCode: "worker-interrupted", attemptedAt: now }]);
  assert.ok(missingLease.message().processingLeaseExpiresAt instanceof Date);
});

test("a stale final attempt is terminalized without sending again", async () => {
  const now = new Date("2026-10-06T12:00:00.000Z");
  const stale = createMockOutboxDatabase({
    id: "mail-exhausted",
    idempotencyKey: "mail-exhausted",
    kind: "EMAIL_TWO_FACTOR",
    recipientEmail: "owner@example.invalid",
    locale: "en",
    payload: encryptedTestEmailPayload(),
    status: "PROCESSING",
    attemptCount: 5,
    availableAt: new Date(0),
    sentAt: null,
    terminalFailedAt: null,
    processingLeaseExpiresAt: new Date(now.getTime() - 1),
    createdAt: new Date(0),
    updatedAt: new Date(0)
  });
  const sent = createDeterministicTestTransport();

  assert.equal(await processNextEmailMessage(sent.transport, now, stale.client as never), "idle");
  assert.equal(sent.sent.length, 0);
  assert.equal(stale.message().status, "TERMINAL_FAILURE");
  assert.deepEqual(stale.attempts(), [{ messageId: "mail-exhausted", attempt: 5, status: "FAILED", errorCode: "worker-interrupted", attemptedAt: now }]);
});

test("a fresh processing lease is not reclaimed", async () => {
  const now = new Date("2026-10-06T12:00:00.000Z");
  const fresh = createMockOutboxDatabase({
    id: "mail-fresh",
    idempotencyKey: "mail-fresh",
    kind: "EMAIL_TWO_FACTOR",
    recipientEmail: "owner@example.invalid",
    locale: "en",
    payload: encryptedTestEmailPayload(),
    status: "PROCESSING",
    attemptCount: 1,
    availableAt: new Date(0),
    sentAt: null,
    terminalFailedAt: null,
    processingLeaseExpiresAt: getEmailProcessingLeaseExpiresAt(now),
    createdAt: new Date(0),
    updatedAt: new Date(0)
  });

  assert.equal(await claimNextEmailMessage(now, fresh.client as never), null);
  assert.equal(fresh.message().attemptCount, 1);
  assert.deepEqual(fresh.attempts(), []);
});

test("only one concurrent claimer can recover the same stale processing lease", async () => {
  const now = new Date("2026-10-06T12:00:00.000Z");
  const stale = createMockOutboxDatabase({
    id: "mail-concurrent",
    idempotencyKey: "mail-concurrent",
    kind: "EMAIL_TWO_FACTOR",
    recipientEmail: "owner@example.invalid",
    locale: "en",
    payload: encryptedTestEmailPayload(),
    status: "PROCESSING",
    attemptCount: 2,
    availableAt: new Date(0),
    sentAt: null,
    terminalFailedAt: null,
    processingLeaseExpiresAt: new Date(now.getTime() - 1),
    createdAt: new Date(0),
    updatedAt: new Date(0)
  });

  const claims = await Promise.all([
    claimNextEmailMessage(now, stale.client as never),
    claimNextEmailMessage(now, stale.client as never)
  ]);
  assert.equal(claims.filter(Boolean).length, 1);
  assert.equal(stale.message().attemptCount, 3);
  assert.equal(stale.attempts().length, 1);
});

test("a reclaimed stale message can complete delivery", async () => {
  await withTestOutboxKey(async () => {
    const now = new Date("2026-10-06T12:00:00.000Z");
    const stale = createMockOutboxDatabase({
      id: "mail-recovered",
      idempotencyKey: "mail-recovered",
      kind: "EMAIL_TWO_FACTOR",
      recipientEmail: "owner@example.invalid",
      locale: "en",
      payload: encryptedTestEmailPayload(),
      status: "PROCESSING",
      attemptCount: 2,
      availableAt: new Date(0),
      sentAt: null,
      terminalFailedAt: null,
      processingLeaseExpiresAt: new Date(now.getTime() - 1),
      createdAt: new Date(0),
      updatedAt: new Date(0)
    });
    const sent = createDeterministicTestTransport();

    assert.equal(await processNextEmailMessage(sent.transport, now, stale.client as never), "sent");
    assert.equal(sent.sent.length, 1);
    assert.equal(sent.sent[0]?.deliveryAttemptReference, "mail-recovered:3");
    assert.equal(stale.message().status, "SENT");
    assert.equal(stale.message().attemptCount, 3);
    assert.deepEqual(stale.attempts().map(({ attempt, status, errorCode }) => ({ attempt, status, errorCode })), [
      { attempt: 2, status: "FAILED", errorCode: "worker-interrupted" },
      { attempt: 3, status: "SENT", errorCode: undefined }
    ]);
  });
});

test("email delivery status and attempt history commit together without requeuing a sent message on history failure", async () => {
  await withTestOutboxKey(async () => {
    const now = new Date("2026-10-06T12:00:00.000Z");
    const queued = createMockOutboxDatabase({
      id: "mail-atomic",
      idempotencyKey: "mail-atomic",
      kind: "EMAIL_TWO_FACTOR",
      recipientEmail: "owner@example.invalid",
      locale: "en",
      payload: encryptedTestEmailPayload(),
      status: "QUEUED",
      attemptCount: 0,
      availableAt: new Date(0),
      sentAt: null,
      terminalFailedAt: null,
      processingLeaseExpiresAt: null,
      createdAt: new Date(0),
      updatedAt: new Date(0)
    }, { failAttemptStatus: "SENT" });
    let sendCount = 0;

    await assert.rejects(() => processNextEmailMessage({ async send() { sendCount += 1; } }, now, queued.client as never), /attempt history unavailable/u);
    assert.equal(sendCount, 1);
    assert.equal(queued.message().status, "PROCESSING");
    assert.equal(queued.attempts().length, 0);
  });
});

test("retry backoff starts after a failed transport attempt completes", async () => {
  await withTestOutboxKey(async () => {
    const now = new Date("2026-10-06T12:00:00.000Z");
    const queued = createMockOutboxDatabase({
      id: "mail-retry-delay",
      idempotencyKey: "mail-retry-delay",
      kind: "EMAIL_TWO_FACTOR",
      recipientEmail: "owner@example.invalid",
      locale: "en",
      payload: encryptedTestEmailPayload(),
      status: "QUEUED",
      attemptCount: 0,
      availableAt: new Date(0),
      sentAt: null,
      terminalFailedAt: null,
      processingLeaseExpiresAt: null,
      createdAt: new Date(0),
      updatedAt: new Date(0)
    });
    const realDateNow = Date.now;
    const clockStart = realDateNow();
    let elapsedInTransportMs = 0;
    Date.now = () => clockStart + elapsedInTransportMs;

    try {
      assert.equal(await processNextEmailMessage({
        async send() {
          elapsedInTransportMs = 90_000;
          throw new Error("synthetic transport failure");
        }
      }, now, queued.client as never), "retryable-failure");
    } finally {
      Date.now = realDateNow;
    }

    assert.equal((queued.message().availableAt as Date).getTime(), now.getTime() + 150_000);
    assert.equal((queued.attempts()[0].attemptedAt as Date).getTime(), now.getTime() + 90_000);
  });
});

function createMockOutboxDatabase(initialMessage: Record<string, unknown>, options: { failAttemptStatus?: string } = {}) {
  let message = structuredClone(initialMessage) as Record<string, unknown>;
  let attemptRows: Array<Record<string, unknown>> = [];
  const transaction = {
    emailOutboxMessage: {
      async findFirst({ where }: { where: { OR: Array<Record<string, unknown>> } }) {
        const eligible = where.OR.some((condition) => {
          const status = condition.status as string | { in: string[] };
          if (typeof status === "object" && "in" in status) {
            return status.in.includes(String(message.status)) &&
              (message.availableAt as Date) <= (condition.availableAt as { lte: Date }).lte;
          }
          if (status === "PROCESSING") {
            if (condition.processingLeaseExpiresAt === null) {
              return message.status === status && message.processingLeaseExpiresAt === null;
            }
            const leaseWhere = condition.processingLeaseExpiresAt as { lte: Date } | undefined;
            const lease = message.processingLeaseExpiresAt as Date | null;
            return message.status === status && Boolean(lease && leaseWhere && lease <= leaseWhere.lte);
          }
          return false;
        });
        return eligible ? structuredClone(message) : null;
      },
      async updateMany({ where, data }: { where: Record<string, unknown>; data: Record<string, unknown> }) {
        const leaseWhere = where.processingLeaseExpiresAt as { lte?: Date } | undefined;
        const lease = message.processingLeaseExpiresAt as Date | null;
        const leaseMatches = where.processingLeaseExpiresAt === null
          ? lease === null
          : !leaseWhere || Boolean(lease && leaseWhere.lte && lease <= leaseWhere.lte);
        const matches = where.id === message.id && where.status === message.status &&
          (where.attemptCount === undefined || where.attemptCount === message.attemptCount) && leaseMatches;
        if (!matches) return { count: 0 };
        const increment = data.attemptCount as { increment?: number } | undefined;
        message = {
          ...message,
          ...data,
          attemptCount: increment ? Number(message.attemptCount) + Number(increment.increment) : message.attemptCount
        };
        return { count: 1 };
      }
    },
    emailDeliveryAttempt: {
      async create({ data }: { data: Record<string, unknown> }) {
        if (data.status === options.failAttemptStatus) throw new Error("attempt history unavailable");
        attemptRows.push(structuredClone(data));
        return data;
      }
    }
  };
  const client = {
    ...transaction,
    async $transaction<T>(callback: (client: typeof transaction) => Promise<T>): Promise<T> {
      const previousMessage = structuredClone(message);
      const previousAttempts = structuredClone(attemptRows);
      try { return await callback(transaction); }
      catch (error) { message = previousMessage; attemptRows = previousAttempts; throw error; }
    }
  };
  return { client, message: () => structuredClone(message), attempts: () => structuredClone(attemptRows) };
}

function encryptedTestEmailPayload() {
  return protectEmailPayload({ publicValues: {}, protectedValues: {} }, { VIRKI_EMAIL_OUTBOX_KEY: "a".repeat(64) });
}

async function withTestOutboxKey(run: () => Promise<void>) {
  const previous = process.env.VIRKI_EMAIL_OUTBOX_KEY;
  process.env.VIRKI_EMAIL_OUTBOX_KEY = "a".repeat(64);
  try {
    await run();
  } finally {
    if (previous === undefined) delete process.env.VIRKI_EMAIL_OUTBOX_KEY;
    else process.env.VIRKI_EMAIL_OUTBOX_KEY = previous;
  }
}
