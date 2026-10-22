const SESSION_COOKIE_NAMES = ["__Host-virki_session", "virki_session"];

// Next dev overwrites the Proxy Cache-Control for rendered documents. Production
// history traversal must still enforce the exact sensitive-page no-store policy.
export function isLow05ProtectedDocumentCacheControl(value, hubMode) {
  if (value === "private, no-store, max-age=0, must-revalidate") return true;
  return hubMode === "development" && value === "no-cache, must-revalidate";
}

export function classifyLow05Url(value, portalUrl) {
  let expectedOrigin;
  let url;
  try {
    expectedOrigin = new URL(portalUrl).origin;
    url = new URL(value, portalUrl);
  } catch {
    return { origin: "other", route: "other", returnTo: "other" };
  }

  if (url.origin !== expectedOrigin) return { origin: "other", route: "other", returnTo: "other" };

  const route = url.pathname === "/account/security"
    ? "account-security"
    : url.pathname === "/login"
      ? "login"
      : url.pathname === "/"
        ? "root"
        : "other";
  const requestedReturnTo = url.searchParams.get("returnTo");
  const returnTo = requestedReturnTo === "/account/security"
    ? "account-security"
    : requestedReturnTo
      ? "other"
      : "absent";

  return { origin: "portal", route, returnTo };
}

export function classifyLow05RequestBoundary(portalUrl, hubMode) {
  let parsed;
  try { parsed = new URL(portalUrl); }
  catch { return { origin: "other", scheme: "other", originHasExplicitPort: false }; }
  const expectedOrigin = new URL(hubMode === "production"
    ? "https://portal.localhost"
    : "https://portal.localhost:3001").origin;
  return {
    // Require the exact scheme, hostname and effective port. Prefix matching
    // could otherwise mislabel an attacker-controlled hostname as portal proof.
    origin: parsed.origin === expectedOrigin ? "portal" : "other",
    scheme: parsed.protocol === "https:" ? "https" : "other",
    originHasExplicitPort: Boolean(parsed.port),
  };
}

export function describeLow05Response(response, url, portalUrl) {
  const rawHeaders = typeof response?.headers === "function" ? response.headers() : response?.headers;
  const headers = rawHeaders && typeof rawHeaders === "object" ? rawHeaders : {};
  const rawStatus = typeof response?.status === "function"
    ? response.status()
    : response?.status ?? response?.statusCode;
  const status = Number(rawStatus);

  return {
    route: classifyLow05Url(url, portalUrl),
    status: Number.isInteger(status) && status >= 100 && status <= 599 ? status : null,
    location: headerValue(headers, "location")
      ? classifyLow05Url(headerValue(headers, "location"), portalUrl)
      : null,
    contentType: classifyContentType(headerValue(headers, "content-type")),
    cacheControl: classifyCacheControl(headerValue(headers, "cache-control")),
    requestIdPresent: hasHeader(headers, "x-virki-request-id")
  };
}

export function summarizeLow05ProxyBoundary({ request, response, forwardedHeaders = request.headers, environment = process.env, portalUrl }) {
  const host = headerValue(request.headers ?? {}, "host");
  const cookieHeader = headerValue(request.headers ?? {}, "cookie");
  const forwardedHost = headerValue(forwardedHeaders ?? {}, "x-forwarded-host");
  const forwardedProto = headerValue(forwardedHeaders ?? {}, "x-forwarded-proto").toLowerCase();
  const forwardedClientAddress = headerValue(forwardedHeaders ?? {}, "cf-connecting-ip");
  const sessionCookiePresent = SESSION_COOKIE_NAMES.some((name) => new RegExp(`(?:^|;\\s*)${escapeRegExp(name)}=`).test(cookieHeader));
  const targetPortalUrl = environment.VIRKI_PORTAL_URL;

  return {
    boundary: "https-proxy-to-next",
    request: {
      method: classifyMethod(request.method),
      route: classifyLow05Url(request.url ?? "/", portalUrl).route,
      origin: classifyHost(host),
      scheme: request.socket?.encrypted === true ? "https" : "http",
      host: classifyHost(host),
      hostHasExplicitPort: hasExplicitPort(host),
      encrypted: request.socket?.encrypted === true,
      sessionCookiePresent,
      forwardedHost: classifyHost(forwardedHost),
      forwardedHostHasExplicitPort: hasExplicitPort(forwardedHost),
      forwardedProto: forwardedProto === "https" ? "https" : forwardedProto === "http" ? "http" : forwardedProto ? "other" : "absent",
      forwardedClientAddressPresent: Boolean(forwardedClientAddress)
    },
    environment: {
      production: environment.NODE_ENV === "production",
      productionHubMode: environment.VIRKI_E2E_HUB_MODE === "production",
      portalHostConfigured: environment.VIRKI_PORTAL_HOSTNAME === "portal.localhost",
      portalUrlConfigured: isExpectedPortalUrl(targetPortalUrl, portalUrl),
      portalUrlHasExplicitPort: hasExplicitPort(targetPortalUrl)
    },
    response: describeLow05Response(response, request.url ?? "/", portalUrl)
  };
}

export function classifyLow05NavigationError(error) {
  const message = typeof error?.message === "string" ? error.message : String(error ?? "");
  if (/ERR_CERT|certificate|TLS/iu.test(message)) return "tls";
  if (/ERR_NAME_NOT_RESOLVED|ENOTFOUND|EAI_AGAIN/iu.test(message)) return "host-resolution";
  if (/ERR_CONNECTION_REFUSED|ECONNREFUSED|ERR_CONNECTION_RESET/iu.test(message)) return "connection";
  if (/timeout|timed out|ERR_TIMED_OUT/iu.test(message)) return "timeout";
  return "navigation-error";
}

function classifyHost(value) {
  if (typeof value !== "string" || !value) return "absent";
  try {
    const hostname = new URL(`https://${value}`).hostname.toLowerCase().replace(/\.$/u, "");
    if (hostname === "portal.localhost") return "portal";
    if (hostname === "hub.localhost") return "hub";
    return "other";
  } catch {
    return "other";
  }
}

function classifyMethod(value) {
  const method = typeof value === "string" ? value.toUpperCase() : "";
  return ["GET", "HEAD", "POST"].includes(method) ? method : "other";
}

function classifyContentType(value) {
  if (!value) return "absent";
  const contentType = value.split(";", 1)[0].trim().toLowerCase();
  if (contentType === "text/html") return "html";
  if (contentType === "application/json") return "json";
  return "other";
}

function classifyCacheControl(value) {
  if (!value) return "absent";
  const directives = new Set(value.split(",").map((directive) => directive.trim().toLowerCase()));
  if (directives.has("no-store")) return directives.has("private") ? "private-no-store" : "no-store";
  if (directives.has("no-cache")) return "no-cache";
  return "other";
}

function headerValue(headers, name) {
  const value = headers[name] ?? headers[name.toLowerCase()];
  return typeof value === "string" ? value : "";
}

function hasHeader(headers, name) {
  return Boolean(headerValue(headers, name));
}

function isExpectedPortalUrl(value, portalUrl) {
  if (typeof value !== "string" || !value) return false;
  try {
    return new URL(value).origin === new URL(portalUrl).origin;
  } catch {
    return false;
  }
}

function hasExplicitPort(value) {
  if (typeof value !== "string" || !value) return false;
  try {
    return new URL(value.startsWith("//") ? `https:${value}` : value.includes("://") ? value : `https://${value}`).port !== "";
  } catch {
    return false;
  }
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}
