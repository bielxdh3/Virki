export class ConnectionInputError extends Error {
  constructor() {
    super("Invalid project connection.");
  }
}

export function validateProjectConnectionInput(input: {
  name: string;
  slug: string;
  origin: string;
  launchUrl?: string;
  redirectUris: string;
}) {
  const name = input.name.trim();
  const slug = input.slug.trim().toLowerCase();
  const origin = requireCanonicalHttpsUrl(input.origin.trim(), true);
  const launchUrl = validateProjectLaunchUrl(origin, input.launchUrl ?? "");
  if (!name || name.length > 80 || !/^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/u.test(slug)) throw new ConnectionInputError();
  const redirectUris = input.redirectUris.split(/\r?\n/u).map((value) => requireCanonicalHttpsUrl(value.trim(), false));
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
