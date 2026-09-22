export type Surface = "hub" | "portal" | "local" | "unknown";

export function requestHost(headers: Pick<Headers, "get">): string {
  return (headers.get("host") ?? headers.get("x-forwarded-host") ?? "")
    .split(",", 1)[0]
    .trim()
    .replace(/:\d+$/u, "")
    .toLowerCase();
}

export function getSurface(headers: Pick<Headers, "get">, env: NodeJS.ProcessEnv = process.env): Surface {
  const host = requestHost(headers);
  if (host === (env.BIELOS_HUB_HOSTNAME ?? "hub.biel.dev.br").toLowerCase()) return "hub";
  if (host === (env.BIELOS_PORTAL_HOSTNAME ?? "portal.biel.dev.br").toLowerCase()) return "portal";
  if (host === "localhost" || host === "127.0.0.1" || host === "hub" || host === "portal") return "local";
  return "unknown";
}

export function getSurfaceBaseUrl(headers: Pick<Headers, "get">, fallback: string, env: NodeJS.ProcessEnv = process.env): URL {
  const surface = getSurface(headers, env);
  const configured = surface === "hub" ? env.NEXT_PUBLIC_HUB_URL : surface === "portal" ? env.NEXT_PUBLIC_PORTAL_URL : undefined;
  return new URL(configured ?? fallback);
}

export function safeReturnTo(value: string | null | undefined): string | null {
  if (!value || value.length > 2048 || !value.startsWith("/") || value.startsWith("//") || value.includes("\\")) return null;
  if (hasControlCharacters(value)) return null;
  let parsed: URL;
  try {
    parsed = new URL(value, "https://portal.invalid");
  } catch {
    return null;
  }
  if (parsed.origin !== "https://portal.invalid" || ["/login", "/api/login", "/api/logout"].includes(parsed.pathname)) return null;
  return `${parsed.pathname}${parsed.search}${parsed.hash}`;
}

function hasControlCharacters(value: string): boolean {
  return Array.from(value).some((character) => {
    const code = character.charCodeAt(0);
    return code <= 0x1f || code === 0x7f;
  });
}
