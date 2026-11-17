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

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const target = process.argv[2];
  checkNativeHubIngress(target).then(
    ({ origin }) => console.log(`PASS: anonymous native ingress probe on ${origin}; this does not attest Cloudflare account configuration, MFA, or production cutover.`),
    (error) => { console.error(`NO-GO native ingress: ${error.message}`); process.exitCode = 1; }
  );
}
