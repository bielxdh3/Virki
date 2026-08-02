import { createHmac } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";

const MAX_BODY_BYTES = 32 * 1024;
const MAX_MODULES = 5;
const MAX_REASON_LENGTH = 1_000;
const MAX_DISPLAY_NAME_LENGTH = 80;
const EMAIL_PATTERN = /^[^\s@]{1,80}@([^\s@]{1,190})$/;

export type PublicIntakeModule = {
  key: string;
  name: string;
  runtimeAvailability: "AVAILABLE" | "UNAVAILABLE" | "INERT";
};

export type IntakeSubmission = {
  emailNormalized: string;
  displayName: string | null;
  abuseIdentifierHash: string;
  locale: "pt-BR" | "en";
  modules: Array<{ key: string; reason: string }>;
};

export type IntakeRepository = {
  listPublicModules(): Promise<PublicIntakeModule[]>;
  submitApplication(input: IntakeSubmission): Promise<void>;
};

export type IntakeConfig = {
  enabled: boolean;
  publicOrigin: string;
  abuseSecret: string | null;
};

export function createIntakeHandler(
  repository: IntakeRepository,
  config: IntakeConfig
): (request: IncomingMessage, response: ServerResponse) => Promise<void> {
  return async (request, response) => {
    response.setHeader("Cache-Control", "no-store");

    if (request.url === "/api/catalog" && request.method === "GET") {
      if (!config.enabled) {
        respond(response, 503, { available: false });
        return;
      }

      respond(response, 200, { available: true, modules: await repository.listPublicModules() });
      return;
    }

    if (request.url !== "/api/apply" || request.method !== "POST") {
      respond(response, 404, { error: "not-found" });
      return;
    }

    if (!config.enabled || !config.abuseSecret) {
      respond(response, 503, { accepted: false, available: false });
      return;
    }

    if (!isSameOriginRequest(request, config.publicOrigin)) {
      respond(response, 403, { accepted: false });
      return;
    }

    const contentType = request.headers["content-type"]?.split(";", 1)[0]?.trim().toLowerCase();
    if (contentType !== "application/json") {
      respond(response, 415, { accepted: false });
      return;
    }

    let body: unknown;
    try {
      body = JSON.parse(await readBody(request));
    } catch {
      respond(response, 400, { accepted: false });
      return;
    }

    const submission = parseSubmission(body, config.abuseSecret);
    if (!submission) {
      respond(response, 400, { accepted: false });
      return;
    }

    try {
      await repository.submitApplication(submission);
    } catch {
      respond(response, 503, { accepted: false, available: false });
      return;
    }

    respond(response, 202, { accepted: true });
  };
}

export function parseSubmission(value: unknown, abuseSecret: string): IntakeSubmission | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }

  const body = value as Record<string, unknown>;
  const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
  const displayName = typeof body.displayName === "string" ? body.displayName.trim() : "";
  const locale = body.locale === "en" ? "en" : "pt-BR";
  const rawModules = body.modules;

  if (
    !EMAIL_PATTERN.test(email) ||
    displayName.length > MAX_DISPLAY_NAME_LENGTH ||
    !Array.isArray(rawModules) ||
    rawModules.length === 0 ||
    rawModules.length > MAX_MODULES
  ) {
    return null;
  }

  const modules = rawModules.map((entry) => {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      return null;
    }
    const moduleEntry = entry as Record<string, unknown>;
    const key = typeof moduleEntry.key === "string" ? moduleEntry.key.trim().toLowerCase() : "";
    const reason = typeof moduleEntry.reason === "string" ? moduleEntry.reason.trim() : "";
    return /^[a-z0-9-]{1,48}$/.test(key) && reason.length > 0 && reason.length <= MAX_REASON_LENGTH
      ? { key, reason }
      : null;
  });

  if (modules.some((module) => module === null)) {
    return null;
  }

  const dedupedModules = [...new Map(modules.map((module) => [module!.key, module!])).values()];
  if (dedupedModules.length !== modules.length) {
    return null;
  }

  return {
    emailNormalized: email,
    displayName: displayName || null,
    abuseIdentifierHash: createHmac("sha256", abuseSecret).update(email, "utf8").digest("hex"),
    locale,
    modules: dedupedModules
  };
}

function isSameOriginRequest(request: IncomingMessage, publicOrigin: string): boolean {
  const origin = request.headers.origin;
  const fetchSite = request.headers["sec-fetch-site"];
  return (
    origin === publicOrigin &&
    (!fetchSite || fetchSite === "same-origin" || fetchSite === "same-site")
  );
}

function readBody(request: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks: Buffer[] = [];
    request.on("data", (chunk: Buffer | string) => {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      size += buffer.length;
      if (size > MAX_BODY_BYTES) {
        request.destroy();
        reject(new Error("Request too large."));
        return;
      }
      chunks.push(buffer);
    });
    request.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    request.on("error", reject);
  });
}

function respond(response: ServerResponse, status: number, body: Record<string, unknown>): void {
  response.statusCode = status;
  response.setHeader("Content-Type", "application/json; charset=utf-8");
  response.end(JSON.stringify(body));
}
