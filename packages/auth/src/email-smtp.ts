import { createHash } from "node:crypto";
import { domainToASCII } from "node:url";
import nodemailer from "nodemailer";
import type { EmailTransport, EmailTransportMessage, EmailTransportReceipt } from "./email";
import { isSingleMailboxAddress } from "./email-address";

const DEFAULT_SMTP_PORT = 587;
const SMTP_CONNECTION_TIMEOUT_MS = 10_000;
const SMTP_GREETING_TIMEOUT_MS = 10_000;
const SMTP_SOCKET_TIMEOUT_MS = 120_000;

type SmtpEnvironment = NodeJS.ProcessEnv;

function getSmtpConfig(env: SmtpEnvironment): {
  host: string;
  port: number;
  secure: boolean;
  user: string;
  credential: string;
  from: string;
  replyTo?: string;
} | null {
  const host = env.VIRKI_EMAIL_SMTP_HOST?.trim();
  const user = env.VIRKI_EMAIL_SMTP_USER?.trim();
  const credential = env.VIRKI_EMAIL_SMTP_PASSWORD?.trim();
  const from = env.VIRKI_EMAIL_FROM?.trim();
  const replyTo = env.VIRKI_EMAIL_REPLY_TO?.trim();
  const port = Number(env.VIRKI_EMAIL_SMTP_PORT ?? DEFAULT_SMTP_PORT);
  const secureValue = env.VIRKI_EMAIL_SMTP_SECURE?.trim().toLowerCase();
  const secure =
    !secureValue ? false : secureValue === "true" ? true : secureValue === "false" ? false : null;

  if (
    !host ||
    !user ||
    !credential ||
    !isEmailAddress(from) ||
    (replyTo && !isEmailAddress(replyTo)) ||
    secure === null ||
    !Number.isInteger(port) ||
    port < 1 ||
    port > 65_535
  ) {
    return null;
  }

  return { host, port, secure, user, credential, from, ...(replyTo ? { replyTo } : {}) };
}

export function isSmtpEmailTransportConfigured(env: SmtpEnvironment = process.env): boolean {
  return Boolean(getSmtpConfig(env));
}

export function createSmtpEmailTransport(
  env: SmtpEnvironment = process.env
): EmailTransport {
  const config = getSmtpConfig(env);
  if (!config) {
    throw new Error("SMTP email transport is not configured.");
  }

  const transporter = nodemailer.createTransport({
    host: config.host,
    port: config.port,
    secure: config.secure,
    requireTLS: true,
    auth: { user: config.user, pass: config.credential },
    tls: {
      minVersion: "TLSv1.2",
      rejectUnauthorized: true
    },
    connectionTimeout: SMTP_CONNECTION_TIMEOUT_MS,
    greetingTimeout: SMTP_GREETING_TIMEOUT_MS,
    socketTimeout: SMTP_SOCKET_TIMEOUT_MS,
    disableFileAccess: true,
    disableUrlAccess: true,
    logger: false,
    debug: false
  });

  return {
    async send(message: EmailTransportMessage): Promise<EmailTransportReceipt> {
      try {
        if (!isSingleMailboxAddress(message.to)) throw new Error("Invalid recipient.");
        const preparedId = message.preparedSmtpHeaderMessageId;
        if (preparedId !== undefined &&
            (preparedId.length > 255 || !/^<[a-f0-9]{64}@[a-z0-9.-]+>$/u.test(preparedId))) {
          throw new Error("Invalid prepared Message-ID.");
        }
        const stableId = preparedId ?? stableAttemptMessageId(message.deliveryAttemptReference, config.from);
        const info = await transporter.sendMail({
          from: config.from,
          to: [{ name: "", address: message.to }],
          subject: message.subject,
          text: message.text,
          ...(stableId ? { messageId: stableId } : {}),
          ...(config.replyTo ? { replyTo: config.replyTo } : {})
        });
        const messageId = info?.messageId ?? stableId;
        // Store only the generated, safe RFC header ID, never SMTP credentials,
        // response text, recipients, codes or message bodies.
        return typeof messageId === "string" && messageId.length <= 255 &&
          /^<[A-Za-z0-9._+-]+@[A-Za-z0-9.-]+>$/u.test(messageId)
          ? { smtpHeaderMessageId: messageId } : {};
      } catch {
        throw new Error("SMTP email delivery failed.");
      }
    }
  };
}

export function stableAttemptMessageId(reference: string | undefined, from: string): string | undefined {
  if (reference === undefined) return undefined;
  // The reference is constructed server-side from an opaque persisted outbox
  // ID and the attempt already claimed in PostgreSQL. Never interpolate an
  // unvalidated reference into an RFC header.
  if (!/^[A-Za-z0-9_-]{1,128}:[1-9][0-9]{0,5}$/u.test(reference)) throw new Error("Invalid attempt reference.");
  const domain = domainToASCII(from.slice(from.lastIndexOf("@") + 1)).toLowerCase();
  if (!domain || !/^[a-z0-9.-]+$/iu.test(domain)) throw new Error("Invalid sender domain.");
  // A valid sender domain can be 253 bytes, while the 64-character digest and
  // delimiters leave only 188 bytes for the Message-ID RHS. Preserve complete
  // DNS labels from the right (never truncate a label), and include the FULL
  // canonical sender domain in the digest so different long subdomains cannot
  // collide when their shortened suffix is identical.
  const maxDomainLength = 255 - 64 - 3;
  const labels = domain.split(".");
  let headerDomain = domain;
  while (headerDomain.length > maxDomainLength && labels.length > 2) {
    labels.shift();
    headerDomain = labels.join(".");
  }
  if (headerDomain.length > maxDomainLength) throw new Error("Invalid sender domain length.");
  const digest = createHash("sha256").update(`virki-smtp-attempt-v2:${reference}:sender:${domain}`).digest("hex");
  const messageId = `<${digest}@${headerDomain}>`;
  return messageId;
}

function isEmailAddress(value: string | undefined): value is string {
  return Boolean(value && isSingleMailboxAddress(value));
}
