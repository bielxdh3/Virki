import nodemailer from "nodemailer";
import type { EmailTransport, EmailTransportMessage } from "./email";

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
  const host = env.BIELOS_EMAIL_SMTP_HOST?.trim();
  const user = env.BIELOS_EMAIL_SMTP_USER?.trim();
  const credential = env.BIELOS_EMAIL_SMTP_PASSWORD?.trim();
  const from = env.BIELOS_EMAIL_FROM?.trim();
  const replyTo = env.BIELOS_EMAIL_REPLY_TO?.trim();
  const port = Number(env.BIELOS_EMAIL_SMTP_PORT ?? DEFAULT_SMTP_PORT);
  const secureValue = env.BIELOS_EMAIL_SMTP_SECURE?.trim().toLowerCase();
  const secure =
    secureValue === undefined ? false : secureValue === "true" ? true : secureValue === "false" ? false : null;

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
    async send(message: EmailTransportMessage): Promise<void> {
      try {
        await transporter.sendMail({
          from: config.from,
          to: message.to,
          subject: message.subject,
          text: message.text,
          ...(config.replyTo ? { replyTo: config.replyTo } : {})
        });
      } catch {
        throw new Error("SMTP email delivery failed.");
      }
    }
  };
}

function isEmailAddress(value: string | undefined): value is string {
  return Boolean(value && value.length <= 254 && /^[^\s@]+@[^\s@]+$/.test(value));
}
