/**
 * Read-only external acceptance probe for the native ADMIN ingress.
 * This runs without credentials, does not follow redirects, and never changes Cloudflare or production state.
 * An Access interstitial cannot be mistaken for Virki's own login page.
 */
import { pathToFileURL } from "node:url";
import { isCanonicalNativeAdminRedirect } from "./lib/native-hub-login-redirect.mjs";

export async function checkNativeHubIngress(target, fetcher = fetch) {
  let origin;
  try {
    const parsed = new URL(target);
    if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.pathname !== "/" || parsed.search || parsed.hash || parsed.port) {
      throw new Error("not a clean HTTPS origin");
    }
    origin = parsed.origin;
  } catch {
    throw new Error("An unadorned HTTPS origin is required (no paths, credentials, ports, or query parameters).");
  }

  const probes = [
    { path: "/login" },
    { path: "/recover" },
    { path: "/admin/accounts" },
    { path: "/admin/audit" },
    { path: "/admin/security" },
    { path: "/admin/access" },
    { path: "/admin/connections" },
    { path: "/admin/accounts", forgedCookie: true },
    { path: "/login", forgedAccessJwt: true },
    { path: "/admin/accounts", forgedAccessJwt: true }
  ];
  for (const { path, forgedCookie, forgedAccessJwt } of probes) {
    const label = forgedCookie ? `${path} (forged cookie)` : forgedAccessJwt ? `${path} (forged Access JWT)` : path;
    const response = await fetcher(`${origin}${path}`, {
      method: "GET",
      redirect: "manual",
      headers: { Accept: "text/html", "Cache-Control": "no-cache", ...(forgedCookie ? { Cookie: "__Host-virki_session=forged" } : {}),
        ...(forgedAccessJwt ? { "cf-access-jwt-assertion": "forged" } : {}) },
      signal: AbortSignal.timeout(10000)
    });
    const privileged = path.startsWith("/admin/");
    if (!privileged && response.status !== 200) {
      throw new Error(`${label}: HTTP ${response.status}; native login/recovery is not publicly reachable without an external authentication gate.`);
    }
    if (privileged && response.status !== 307) {
      throw new Error(`${label}: HTTP ${response.status}; unauthenticated ADMIN must redirect to Virki login.`);
    }
    if (!response.headers.get("x-virki-request-id") || !response.headers.get("content-security-policy")) {
      throw new Error(`${label}: missing Virki request identity/security headers; response may come from Cloudflare Access or another gateway.`);
    }
    if (!hasRequiredSecurityHeaders(response.headers)) {
      throw new Error(`${label}: missing native ingress security headers (HSTS, no-store, clickjacking and CSP controls).`);
    }
    if (!privileged) {
      const markup = await response.text();
      const isLogin = path === "/login";
      const hasNativeForm = isLogin
        ? markup.includes('<h1 id="login-title">Entrar</h1>') && markup.includes('<form') &&
          markup.includes('action="/api/login" method="post"') && markup.includes('name="password"') && markup.includes('name="email"')
        : markup.includes('<h1 id="recover-title">Recuperar acesso administrativo</h1>') &&
          markup.includes('<form') && markup.includes('name="email"') && markup.includes('name="method"');
      if (!hasNativeForm || !hasScopedCsrfField(markup, isLogin ? "login" : "recovery-admin-request")) {
        throw new Error(`${label}: Virki's native login/recovery form or correctly scoped CSRF field is missing.`);
      }
    }
    if (privileged) {
      const location = response.headers.get("location");
      if (!isCanonicalNativeAdminRedirect(location, origin, path)) {
        throw new Error(`${label}: redirect is not the canonical Virki login; possible external identity gate.`);
      }
    }
  }
  return { origin, checked: probes.map(({ path, forgedCookie, forgedAccessJwt }) => forgedCookie
    ? `${path} (forged cookie)` : forgedAccessJwt ? `${path} (forged Access JWT)` : path) };
}

function hasRequiredSecurityHeaders(headers) {
  const csp = new Map();
  for (const directive of (headers.get("content-security-policy") ?? "").split(";").map((value) => value.trim().toLowerCase()).filter(Boolean)) {
    const name = directive.split(/\s+/u, 1)[0];
    // Browsers use the first occurrence of duplicated directives; don't accept
    // a later safe value when an earlier effective one is permissive.
    if (csp.has(name)) return false;
    csp.set(name, directive);
  }
  const hstsMaxAges = (headers.get("strict-transport-security") ?? "").split(";").map((value) => value.trim())
    .filter((value) => /^max-age\s*=/iu.test(value));
  const hstsAge = hstsMaxAges.length === 1 ? /^max-age=(\d+)$/iu.exec(hstsMaxAges[0]) : null;
  return csp.get("frame-ancestors") === "frame-ancestors 'none'" && csp.get("base-uri") === "base-uri 'none'" &&
    (csp.get("object-src") === "object-src 'none'" || (!csp.has("object-src") && csp.get("default-src") === "default-src 'none'")) &&
    // Cloudflare's independently observed staging HTTPS policy currently sets 30 days.
    Number(hstsAge?.[1]) >= 2_592_000 &&
    (headers.get("cache-control") ?? "").split(",").some((directive) => directive.trim().toLowerCase() === "no-store") &&
    headers.get("x-frame-options") === "DENY" && headers.get("x-content-type-options") === "nosniff";
}

function hasScopedCsrfField(markup, scope) {
  const encodedScope = Buffer.from(scope, "utf8").toString("base64url");
  return [...markup.matchAll(/name="csrfToken" value="([^"]+)"/gu)].some((match) => {
    const parts = match[1].split(".");
    return parts.length === 6 && parts[0] === "v2" && /^[a-f0-9]{64}$/u.test(parts[1]) &&
      /^[0-9]{13}$/u.test(parts[2]) && /^[A-Za-z0-9_-]{32}$/u.test(parts[3]) &&
      parts[4] === encodedScope && /^[A-Za-z0-9_-]{43}$/u.test(parts[5]);
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const target = process.argv[2];
  checkNativeHubIngress(target).then(
    ({ origin }) => console.log(`PASS: anonymous native ingress probe on ${origin}; this does not attest Cloudflare account configuration, MFA, or production cutover.`),
    (error) => { console.error(`NO-GO native ingress: ${error.message}`); process.exitCode = 1; }
  );
}
