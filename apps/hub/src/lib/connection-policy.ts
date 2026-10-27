import { createHash } from "node:crypto";

export class ConnectionInputError extends Error {
  constructor() {
    super("Invalid project connection.");
  }
}

export function projectConnectionConfigurationRevision(connection: {
  id: string;
  name: string;
  slug: string;
  origin: string;
  launchUrl: string | null;
  redirectUris: readonly string[];
}): string {
  const configuration = [
    connection.id,
    connection.name,
    connection.slug,
    connection.origin,
    connection.launchUrl,
    connection.redirectUris,
  ];
  return createHash("sha256").update(JSON.stringify(configuration)).digest("base64url");
}

export function validateProjectConnectionInput(input: {
  name: string;
  slug: string;
  origin: string;
  launchUrl?: string;
  redirectUris: string;
}, options: { existingName?: string; preserveExistingName?: boolean } = {}) {
  const preservesExistingName = options.preserveExistingName !== false && options.existingName !== undefined
    && (input.name === options.existingName || input.name === options.existingName.replace(/[\r\n]/gu, ""));
  const name = preservesExistingName ? options.existingName : input.name.trim();
  const slugInput = input.slug.trim();
  const slug = slugInput.toLowerCase();
  const origin = requireCanonicalHttpsUrl(input.origin.trim(), true);
  const launchUrl = validateProjectLaunchUrl(origin, input.launchUrl ?? "");
  if (!name || name.length > 80 || !preservesExistingName && /\p{Cc}/u.test(input.name) || !/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?$/u.test(slugInput)) throw new ConnectionInputError();
  const redirectUris = input.redirectUris.split(/\r?\n/u).map((value) => value.trim()).filter(Boolean).map((value) => requireCanonicalHttpsUrl(value, false));
  if (redirectUris.length < 1 || redirectUris.length > 10 || new Set(redirectUris).size !== redirectUris.length) throw new ConnectionInputError();
  return { name, slug, origin, launchUrl, redirectUris };
}

export function validateProjectLaunchUrl(origin: string, value: string): string | null {
  const input = value.trim();
  if (!input) return null;
  if (input.length > 2048) throw new ConnectionInputError();
  let url: URL;
  try {
    url = new URL(input);
  } catch {
    throw new ConnectionInputError();
  }
  if (url.protocol !== "https:" || url.origin !== origin || url.username || url.password || url.search || url.hash) throw new ConnectionInputError();
  return url.toString();
}

export function isExactRedirectUriAllowed(allowlist: readonly string[], candidate: string): boolean {
  return allowlist.includes(candidate);
}

function requireCanonicalHttpsUrl(value: string, originOnly: boolean): string {
  if (!value || value.includes("*") || value.length > 2048) throw new ConnectionInputError();
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new ConnectionInputError();
  }
  const canonical = originOnly ? url.origin === value : url.href === value;
  if (url.protocol !== "https:" || url.username || url.password || url.hash || !canonical) throw new ConnectionInputError();
  if (originOnly && (url.pathname !== "/" || url.search)) throw new ConnectionInputError();
  return originOnly ? url.origin : value;
}
