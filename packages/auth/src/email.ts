import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { prisma, type Prisma } from "@virki/database";
import { isSmtpEmailTransportConfigured } from "./email-smtp";

export type EmailMessageKind =
  | "NEW_DEVICE_VERIFICATION"
  | "EMAIL_TWO_FACTOR"
  | "PASSWORD_CHANGED"
  | "SESSION_TERMINATED"
  | "ACCOUNT_RECOVERY"
  | "SECOND_FACTOR_CHANGED"
  | "ADMIN_EMAIL_VERIFICATION"
  | "ADMIN_CREDENTIAL_CHANGED"
  | "ELEVATION_CHANGED"
  | "ACCOUNT_INVITATION";
const EMAIL_OUTBOX_PAYLOAD_VERSION = 1;
const EMAIL_OUTBOX_KEY_BYTES = 32;
const MAX_EMAIL_ATTEMPTS = 5;
const EMAIL_PROCESSING_LEASE_MS = 5 * 60 * 1000;

export type EmailLocale = "pt-BR" | "en";

type EmailMessageInput = {
  idempotencyKey: string;
  kind: EmailMessageKind;
  recipientEmail: string;
  locale: EmailLocale;
  payload?: EmailPayload;
  now?: Date;
};

export type EmailTransportMessage = {
  to: string;
  subject: string;
  text: string;
};

export type EmailTransport = {
  send(message: EmailTransportMessage): Promise<void>;
};

export type EmailTransportStatus =
  | { state: "configured" }
  | {
      state: "unavailable";
      reason: "transport-missing" | "outbox-key-missing" | "adapter-unavailable";
    };

export type EmailPayload = {
  publicValues?: Record<string, string>;
  protectedValues?: Record<string, string>;
};

type StoredEmailPayload = {
  version: number;
  publicValues: Record<string, string>;
  protectedValues?: {
    ciphertext: string;
    iv: string;
    tag: string;
  };
};

export function getEmailTransportStatus(
  env: NodeJS.ProcessEnv = process.env
): EmailTransportStatus {
  if (env.NODE_ENV === "production") {
    if (!env.VIRKI_EMAIL_TRANSPORT?.trim()) {
      return { state: "unavailable", reason: "transport-missing" };
    }

    if (!getOutboxKey(env)) {
      return { state: "unavailable", reason: "outbox-key-missing" };
    }

    if (
      env.VIRKI_EMAIL_TRANSPORT.trim().toLowerCase() !== "smtp" ||
      !isSmtpEmailTransportConfigured(env)
    ) {
      return { state: "unavailable", reason: "adapter-unavailable" };
    }

    return { state: "configured" };
  }

  if (!getOutboxKey(env)) {
    return { state: "unavailable", reason: "outbox-key-missing" };
  }

  return { state: "configured" };
}

export function enqueueEmailMessageForClient(
  client: Pick<Prisma.TransactionClient, "emailOutboxMessage">,
  input: EmailMessageInput
) {
  const message = prepareEmailMessage(input);
  return client.emailOutboxMessage.upsert({
    where: { idempotencyKey: input.idempotencyKey },
    update: {},
    create: {
      idempotencyKey: input.idempotencyKey,
      kind: input.kind,
      recipientEmail: message.recipientEmail,
      locale: input.locale,
      payload: message.storedPayload as Prisma.InputJsonValue,
      availableAt: message.now,
      updatedAt: message.now
    }
  });
}

export function enqueueEmailMessage(input: EmailMessageInput) {
  return enqueueEmailMessageForClient(prisma, input);
}

function prepareEmailMessage(input: EmailMessageInput) {
  const recipientEmail = normalizeEmail(input.recipientEmail);
  if (!recipientEmail || !input.idempotencyKey.trim()) {
    throw new Error("Invalid email message.");
  }

  return {
    recipientEmail,
    storedPayload: protectEmailPayload(input.payload ?? {}, process.env),
    now: input.now ?? new Date()
  };
}

export function getEmailProcessingLeaseExpiresAt(now: Date): Date {
  return new Date(now.getTime() + EMAIL_PROCESSING_LEASE_MS);
}

export async function claimNextEmailMessage(now = new Date(), database: typeof prisma = prisma) {
  return database.$transaction(async (transaction) => {
    const candidate = await transaction.emailOutboxMessage.findFirst({
      where: {
        OR: [
          { status: { in: ["QUEUED", "RETRYABLE_FAILURE"] }, availableAt: { lte: now } },
          { status: "PROCESSING", processingLeaseExpiresAt: { lte: now } }
        ]
      },
      orderBy: [{ availableAt: "asc" }, { createdAt: "asc" }]
    });

    if (!candidate) {
      return null;
    }

    const interrupted = candidate.status === "PROCESSING";
    const exhausted = candidate.attemptCount >= MAX_EMAIL_ATTEMPTS;
    const claimed = await transaction.emailOutboxMessage.updateMany({
      where: {
        id: candidate.id,
        status: candidate.status,
        attemptCount: candidate.attemptCount,
        ...(interrupted
          ? { processingLeaseExpiresAt: { lte: now } }
          : { availableAt: { lte: now } })
      },
      data: exhausted
        ? { status: "TERMINAL_FAILURE", terminalFailedAt: now, processingLeaseExpiresAt: null, updatedAt: now }
        : { status: "PROCESSING", attemptCount: { increment: 1 }, processingLeaseExpiresAt: getEmailProcessingLeaseExpiresAt(now), terminalFailedAt: null, updatedAt: now }
    });

    if (claimed.count !== 1) {
      return null;
    }

    if (interrupted && candidate.attemptCount > 0) {
      await transaction.emailDeliveryAttempt.create({
        data: { messageId: candidate.id, attempt: candidate.attemptCount, status: "FAILED", errorCode: "worker-interrupted", attemptedAt: now }
      });
    }

    if (exhausted) return null;

    return { ...candidate, status: "PROCESSING" as const, attemptCount: candidate.attemptCount + 1, processingLeaseExpiresAt: getEmailProcessingLeaseExpiresAt(now) };
  });
}

export async function processNextEmailMessage(
  transport: EmailTransport,
  now = new Date(),
  database: typeof prisma = prisma
): Promise<"idle" | "sent" | "retryable-failure" | "terminal-failure"> {
  const processingStartedAtMs = Date.now();
  const message = await claimNextEmailMessage(now, database);
  if (!message) {
    return "idle";
  }

  let sent = false;
  try {
    const payload = decryptEmailPayload(message.payload, process.env);
    await transport.send(
      renderEmailMessage(message.kind, message.locale as EmailLocale, {
        ...payload,
        recipientEmail: message.recipientEmail
      })
    );
    sent = true;
  } catch {
    sent = false;
  }

  const completedAt = new Date(now.getTime() + Math.max(0, Date.now() - processingStartedAtMs));
  const terminal = !sent && message.attemptCount >= MAX_EMAIL_ATTEMPTS;
  return database.$transaction(async (transaction) => {
    const finalized = await transaction.emailOutboxMessage.updateMany({
      where: { id: message.id, status: "PROCESSING", attemptCount: message.attemptCount },
      data: sent
        ? { status: "SENT", sentAt: completedAt, processingLeaseExpiresAt: null, updatedAt: completedAt }
        : {
            status: terminal ? "TERMINAL_FAILURE" : "RETRYABLE_FAILURE",
            terminalFailedAt: terminal ? completedAt : null,
            availableAt: terminal ? completedAt : new Date(completedAt.getTime() + retryDelayMs(message.attemptCount)),
            processingLeaseExpiresAt: null,
            updatedAt: completedAt
          }
    });
    if (finalized.count !== 1) return "idle";

    await transaction.emailDeliveryAttempt.create({
      data: sent
        ? { messageId: message.id, attempt: message.attemptCount, status: "SENT", attemptedAt: completedAt }
        : {
            messageId: message.id,
            attempt: message.attemptCount,
            status: "FAILED",
            errorCode: "transport-failure",
            attemptedAt: completedAt
          }
    });
    return sent ? "sent" : terminal ? "terminal-failure" : "retryable-failure";
  });
}

export function createDeterministicTestTransport() {
  const sent: EmailTransportMessage[] = [];
  return {
    sent,
    transport: {
      async send(message: EmailTransportMessage): Promise<void> {
        sent.push(message);
      }
    } satisfies EmailTransport
  };
}

export { createSmtpEmailTransport, isSmtpEmailTransportConfigured } from "./email-smtp";

export function renderEmailMessage(
  kind: EmailMessageKind,
  locale: EmailLocale,
  payload: Record<string, string>
): EmailTransportMessage {
  const subjectByKind: Record<EmailMessageKind, { "pt-BR": string; en: string }> = {
    NEW_DEVICE_VERIFICATION: { "pt-BR": "Verifique este dispositivo", en: "Verify this device" },
    EMAIL_TWO_FACTOR: { "pt-BR": "Seu código Virki", en: "Your Virki code" },
    PASSWORD_CHANGED: { "pt-BR": "Senha alterada", en: "Password changed" },
    SESSION_TERMINATED: { "pt-BR": "Sessão encerrada", en: "Session terminated" },
    ACCOUNT_RECOVERY: { "pt-BR": "Recuperação de conta", en: "Account recovery" },
    SECOND_FACTOR_CHANGED: { "pt-BR": "Segundo fator atualizado", en: "Second factor updated" },
    ADMIN_EMAIL_VERIFICATION: { "pt-BR": "Verificação administrativa", en: "Administrative verification" },
    ADMIN_CREDENTIAL_CHANGED: { "pt-BR": "Credencial administrativa atualizada", en: "Administrative credential updated" },
    ELEVATION_CHANGED: { "pt-BR": "Elevação de segurança atualizada", en: "Security elevation updated" },
    ACCOUNT_INVITATION: { "pt-BR": "Convite para o Virki", en: "Virki invitation" }
  };
  const greeting = payload.displayName ? `${payload.displayName},` : "Virki,";
  const action = payload.actionUrl ? `\n${payload.actionUrl}` : "";
  const code = payload.code ? `\nCódigo: ${payload.code}` : "";

  return {
    to: payload.recipientEmail ?? "",
    subject: subjectByKind[kind][locale],
    text: `${greeting}\n${subjectByKind[kind][locale]}${code}${action}`
  };
}

export function protectEmailPayload(
  payload: EmailPayload,
  env: NodeJS.ProcessEnv = process.env
): StoredEmailPayload {
  const publicValues = Object.fromEntries(
    Object.entries(payload.publicValues ?? {}).map(([key, value]) => [key, String(value)])
  );
  if (Object.keys(publicValues).some((key) => /token|code|password|secret|hash|cookie|jwt/i.test(key))) {
    throw new Error("Sensitive email values must be protected.");
  }
  const protectedValues = payload.protectedValues ?? {};

  if (Object.keys(protectedValues).length === 0) {
    return { version: EMAIL_OUTBOX_PAYLOAD_VERSION, publicValues };
  }

  const key = getOutboxKey(env);
  if (!key) {
    throw new Error("Email outbox encryption is unavailable.");
  }

  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([
    cipher.update(JSON.stringify(protectedValues), "utf8"),
    cipher.final()
  ]);

  return {
    version: EMAIL_OUTBOX_PAYLOAD_VERSION,
    publicValues,
    protectedValues: {
      ciphertext: ciphertext.toString("base64url"),
      iv: iv.toString("base64url"),
      tag: cipher.getAuthTag().toString("base64url")
    }
  };
}

export function decryptEmailPayload(
  value: unknown,
  env: NodeJS.ProcessEnv = process.env
): Record<string, string> {
  if (!isStoredEmailPayload(value) || value.version !== EMAIL_OUTBOX_PAYLOAD_VERSION) {
    throw new Error("Invalid email payload.");
  }

  const key = getOutboxKey(env);
  if (!key) {
    throw new Error("Email outbox encryption is unavailable.");
  }

  if (!value.protectedValues) {
    return value.publicValues;
  }

  const decipher = createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(value.protectedValues.iv, "base64url")
  );
  decipher.setAuthTag(Buffer.from(value.protectedValues.tag, "base64url"));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(value.protectedValues.ciphertext, "base64url")),
    decipher.final()
  ]);

  return { ...value.publicValues, ...JSON.parse(plaintext.toString("utf8")) };
}

function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

function getOutboxKey(env: NodeJS.ProcessEnv): Buffer | null {
  const configured = env.VIRKI_EMAIL_OUTBOX_KEY?.trim();
  if (configured) {
    const decoded = Buffer.from(configured, /^[0-9a-f]{64}$/i.test(configured) ? "hex" : "base64url");
    return decoded.length === EMAIL_OUTBOX_KEY_BYTES ? decoded : null;
  }

  return env.NODE_ENV === "test"
    ? createHash("sha256").update("virki-test-email-outbox-key", "utf8").digest()
    : null;
}

function retryDelayMs(attempt: number): number {
  return Math.min(60 * 60 * 1000, 2 ** Math.max(0, attempt - 1) * 60 * 1000);
}

function isStoredEmailPayload(value: unknown): value is StoredEmailPayload {
  if (!value || typeof value !== "object") {
    return false;
  }

  const candidate = value as Partial<StoredEmailPayload>;
  return candidate.version === EMAIL_OUTBOX_PAYLOAD_VERSION && typeof candidate.publicValues === "object";
}
