export type Surface = "hub" | "portal" | "local" | "unknown";

export const TRUSTED_REQUEST_PATH_HEADER = "x-virki-request-path";

export function requestHost(headers: Pick<Headers, "get">): string {
  const host = headers.get("host")?.trim() ?? "";
  if (!host || host.includes(",") || containsUnsafeHostCharacter(host)) return "";
  return host.replace(/:\d+$/u, "").replace(/\.$/u, "").toLowerCase();
}

export type SameOriginFailureReason =
  | "missing-origin"
  | "missing-host"
  | "invalid-host"
  | "malformed-origin"
  | "null-origin"
  | "comma-in-origin"
  | "disallowed-protocol"
  | "authority-mismatch"
  | "hostname-mismatch"
  | "port-mismatch"
  | "invalid-origin-components";

export function sameOriginFailureReason(headers: Pick<Headers, "get">): SameOriginFailureReason | null {
  const origin = headers.get("origin");
  if (!origin) return "missing-origin";
  const hostHeader = headers.get("host")?.trim().toLowerCase().replace(/\.$/u, "") ?? "";
  if (!hostHeader) return "missing-host";
  if (hostHeader.includes(",") || containsUnsafeHostCharacter(hostHeader)) return "invalid-host";
  try {
    const parsed = new URL(origin);
    const allowedProtocol = parsed.protocol === "https:" || (process.env.NODE_ENV !== "production" && parsed.protocol === "http:");
    const originHost = parsed.host.toLowerCase().replace(/\.$/u, "");
    const requestOriginHost = normalizeDefaultPort(hostHeader, parsed.protocol);
    if (!allowedProtocol) return "disallowed-protocol";
    if (normalizeDefaultPort(originHost, parsed.protocol) !== requestOriginHost) {
      return classifyAuthorityMismatch(parsed, hostHeader);
    }
    if (parsed.username !== "" || parsed.password !== "" || parsed.pathname !== "/" || parsed.search !== "" || parsed.hash !== "") {
      return "invalid-origin-components";
    }
    return null;
  } catch {
    if (origin.trim().toLowerCase() === "null") return "null-origin";
    if (origin.includes(",")) return "comma-in-origin";
    return "malformed-origin";
  }
}

function classifyAuthorityMismatch(origin: URL, hostHeader: string): "authority-mismatch" | "hostname-mismatch" | "port-mismatch" | "invalid-host" {
  try {
    const request = new URL(`${origin.protocol}//${hostHeader}`);
    if (request.username !== "" || request.password !== "" || request.pathname !== "/" || request.search !== "" || request.hash !== "") return "invalid-host";
    if (request.hostname.toLowerCase().replace(/\.$/u, "") !== origin.hostname.toLowerCase().replace(/\.$/u, "")) return "hostname-mismatch";
    if (request.port !== origin.port) return "port-mismatch";
    return "authority-mismatch";
  } catch {
    return "invalid-host";
  }
}

export function hasSameOrigin(headers: Pick<Headers, "get">): boolean {
  return sameOriginFailureReason(headers) === null;
}

function normalizeDefaultPort(host: string, protocol: string): string {
  return protocol === "https:" ? host.replace(/:443$/u, "") : protocol === "http:" ? host.replace(/:80$/u, "") : host;
}

function containsUnsafeHostCharacter(value: string): boolean {
  return Array.from(value).some((character) => {
    const code = character.codePointAt(0) ?? 0;
    return code <= 0x20 || character === "\\" || character === "/";
  });
}

export function getSurface(headers: Pick<Headers, "get">, env: NodeJS.ProcessEnv = process.env): Surface {
  const host = requestHost(headers);
  if (host === surfaceHostname("hub", env)) return "hub";
  if (host === surfaceHostname("portal", env)) return "portal";
  if (host === "localhost" || host === "127.0.0.1" || host === "hub" || host === "portal") return "local";
  return "unknown";
}

export function getSurfaceBaseUrl(headers: Pick<Headers, "get">, fallback: string, env: NodeJS.ProcessEnv = process.env): URL | null {
  const surface = getSurface(headers, env);
  if (surface === "unknown") return null;
  if (surface === "local") return env.NODE_ENV === "production" ? null : safeFallbackUrl(fallback);

  const hostname = surfaceHostname(surface, env);
  if (!hostname) return null;
  const configured = surface === "hub" ? env.VIRKI_HUB_URL : env.VIRKI_PORTAL_URL;
  if (!configured?.trim()) {
    if (env.NODE_ENV !== "production") return safeFallbackUrl(fallback);
    return new URL(`https://${hostname}/`);
  }

  try {
    const url = new URL(configured.trim());
    const production = env.NODE_ENV === "production";
    if (
      (url.protocol !== "https:" && (production || url.protocol !== "http:")) ||
      url.username !== "" ||
      url.password !== "" ||
      url.hostname.toLowerCase().replace(/\.$/u, "") !== hostname ||
      url.pathname !== "/" ||
      url.search !== "" ||
      url.hash !== "" ||
      (production && url.port !== "")
    ) return null;
    return url;
  } catch {
    return null;
  }
}

function surfaceHostname(surface: "hub" | "portal", env: NodeJS.ProcessEnv): string | null {
  const configured = surface === "hub"
    ? env.VIRKI_HUB_HOSTNAME ?? "hub.biel.dev.br"
    : env.VIRKI_PORTAL_HOSTNAME ?? "portal.biel.dev.br";
  if (configured !== configured.trim()) return null;
  const hostname = configured.toLowerCase().replace(/\.$/u, "");
  const labels = hostname.split(".");
  if (hostname.length > 253 || labels.length < 2 || labels.some((label) => label.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/u.test(label))) return null;
  return hostname;
}

function safeFallbackUrl(value: string): URL | null {
  try {
    const url = new URL(value);
    if ((url.protocol !== "https:" && url.protocol !== "http:") || url.username !== "" || url.password !== "") return null;
    return url;
  } catch {
    return null;
  }
}

export function safeReturnTo(value: string | null | undefined, surface: Surface = "local", role?: string): string | null {
  if (!value || value.length > 2048 || !value.startsWith("/") || value.startsWith("//") || value.includes("\\")) return null;
  if (hasControlCharacters(value)) return null;
  let parsed: URL;
  try {
    parsed = new URL(value, "https://portal.invalid");
  } catch {
    return null;
  }
  if (parsed.origin !== "https://portal.invalid" || isAuthenticationPath(parsed.pathname)) return null;
  if (!isReturnPathAllowed(parsed.pathname, surface, role)) return null;
  return `${parsed.pathname}${parsed.search}`;
}

export function trustedReturnTo(headers: Pick<Headers, "get">, surface: Surface, role?: string): string | null {
  return safeReturnTo(headers.get(TRUSTED_REQUEST_PATH_HEADER), surface, role);
}

function isAuthenticationPath(pathname: string): boolean {
  return pathname === "/login" || pathname.startsWith("/login/") || pathname === "/recover" || pathname.startsWith("/recover/") || pathname.startsWith("/api/");
}

function isReturnPathAllowed(pathname: string, surface: Surface, role?: string): boolean {
  const isHub = surface === "hub" || (surface === "local" && role === "ADMIN");
  const isPortal = surface === "portal" || (surface === "local" && role === "USER");
  if (isHub) return (pathname === "/account/security" && (role === undefined || role === "ADMIN")) || pathname === "/admin" || pathname.startsWith("/admin/");
  if (isPortal) {
    return pathname === "/" || pathname === "/account/security" || /^\/(?:interaction|resume)\/[A-Za-z0-9_-]{8,160}$/u.test(pathname);
  }
  if (surface === "local") {
    return pathname === "/" || pathname === "/account/security" || pathname === "/admin" || pathname.startsWith("/admin/") || /^\/(?:interaction|resume)\/[A-Za-z0-9_-]{8,160}$/u.test(pathname);
  }
  return false;
}

function hasControlCharacters(value: string): boolean {
  return Array.from(value).some((character) => {
    const code = character.charCodeAt(0);
    return code <= 0x1f || code === 0x7f;
  });
}
