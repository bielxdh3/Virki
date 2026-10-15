// Shared fixtures for *.integration.test.ts files. They run only through scripts/integration/run.mjs,
// which guards the disposable database target; elsewhere every integration test is skipped.
import { randomBytes, randomUUID } from "node:crypto";
import { prisma } from "@virki/database";
import { decryptEmailPayload } from "./email";
import { hashPassword } from "./index";
import { encryptTotpSecret } from "./security";

export const integrationEnabled = process.env.VIRKI_INTEGRATION_ENABLED === "true";
export const integrationOptions = { skip: integrationEnabled ? false : "disposable integration database not configured" } as const;

export function uniqueEmail(label: string): string {
  return `${label}-${randomUUID()}@integration.invalid`;
}

export async function createTestUser(input: {
  role?: "USER" | "ADMIN";
  password?: string;
  emailVerified?: boolean;
  totpSecret?: string;
  label?: string;
} = {}): Promise<{ id: string; email: string; password: string }> {
  const email = uniqueEmail(input.label ?? "user");
  const password = input.password ?? randomBytes(18).toString("base64url");
  const user = await prisma.user.create({
    data: {
      email,
      emailNormalized: email,
      displayName: "Integration",
      passwordHash: await hashPassword(password),
      role: input.role ?? "USER",
      emailVerifiedAt: input.emailVerified === false ? null : new Date(),
      secondFactorMethod: input.totpSecret ? "TOTP" : "EMAIL",
      ...(input.totpSecret
        ? { totpFactor: { create: { secretCiphertext: encryptTotpSecret(input.totpSecret), keyVersion: 1, status: "ACTIVE", confirmedAt: new Date() } } }
        : {})
    },
    select: { id: true }
  });
  return { id: user.id, email, password };
}

// Decrypts queued (never sent) outbox payloads so tests can follow emailed codes and links.
export async function queuedEmails(recipientEmail: string): Promise<Array<{ kind: string; code?: string; actionUrl?: string }>> {
  const messages = await prisma.emailOutboxMessage.findMany({ where: { recipientEmail }, orderBy: { createdAt: "asc" }, select: { kind: true, payload: true } });
  return messages.map((message) => {
    const payload = decryptEmailPayload(message.payload, process.env);
    return { kind: message.kind, code: payload.code, actionUrl: payload.actionUrl };
  });
}

export function requestKeyFromActionUrl(actionUrl: string | undefined): string {
  const key = actionUrl ? new URL(actionUrl).searchParams.get("request") : null;
  if (!key) throw new Error("Queued recovery email has no action link.");
  return key;
}

export function deviceToken(): string {
  return randomBytes(32).toString("base64url");
}
