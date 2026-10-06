import assert from "node:assert/strict";
import { once } from "node:events";
import { createServer } from "node:net";
import test from "node:test";
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

test("SMTP delivery failures are redacted without contacting an external provider", async () => {
  const server = createServer((socket) => socket.destroy());
  server.listen(0, "127.0.0.1");
  await once(server, "listening");

  try {
    const address = server.address();
    assert.ok(address && typeof address !== "string");
    const transport = createSmtpEmailTransport({
      BIELOS_EMAIL_SMTP_HOST: "127.0.0.1",
      BIELOS_EMAIL_SMTP_PORT: String(address.port),
      BIELOS_EMAIL_SMTP_SECURE: "false",
      BIELOS_EMAIL_SMTP_USER: "smtp-user@example.invalid",
      BIELOS_EMAIL_SMTP_PASSWORD: "smtp-password-placeholder",
      BIELOS_EMAIL_FROM: "no-reply@biel.dev.br"
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
        const leaseMatches = !leaseWhere || Boolean(lease && leaseWhere.lte && lease <= leaseWhere.lte);
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
  return protectEmailPayload({ publicValues: {}, protectedValues: {} }, { BIELOS_EMAIL_OUTBOX_KEY: "a".repeat(64) });
}

async function withTestOutboxKey(run: () => Promise<void>) {
  const previous = process.env.BIELOS_EMAIL_OUTBOX_KEY;
  process.env.BIELOS_EMAIL_OUTBOX_KEY = "a".repeat(64);
  try {
    await run();
  } finally {
    if (previous === undefined) delete process.env.BIELOS_EMAIL_OUTBOX_KEY;
    else process.env.BIELOS_EMAIL_OUTBOX_KEY = previous;
  }
}
