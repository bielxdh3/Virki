import { createHash } from "node:crypto";
import { randomRpSessionId } from "@virki/oidc-node";

const LOGIN_COOKIE = "__Host-virki_rp_login";
const SESSION_COOKIE = "__Host-virki_rp_session";
const MAX_SESSION_AGE_MS = 8 * 60 * 60 * 1000;
const PREAUTH_MAX_AGE_SECONDS = 10 * 60;

/** A runnable Node backend RP example, using an in-process local session store.
 * For production multi-host RPs replace both Map-based stores with DB/Redis.
 */
export function createRpHandler({ client, redirectUri }) {
  if (!client || typeof client.beginLogin !== "function" || typeof client.completeCallback !== "function") throw new Error("RP client is unavailable.");
  const registered = new URL(redirectUri);
  if (registered.protocol !== "https:" || registered.hash || registered.search || registered.href !== redirectUri) throw new Error("RP callback configuration is invalid.");
  const origin = registered.origin;
  const host = registered.host;
  const sessions = new Map();

  async function handle(request, response) {
    response.setHeader("Cache-Control", "no-store");
    response.setHeader("Referrer-Policy", "no-referrer");
    response.setHeader("X-Content-Type-Options", "nosniff");
    response.setHeader("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
    if (request.headers.host !== host) return respond(response, 421, "Unknown RP host.");
    const requestUrl = new URL(request.url ?? "/", origin);
    if (requestUrl.pathname === "/health" && request.method === "GET") return respond(response, 200, "healthy");
    if (requestUrl.pathname === "/" && request.method === "GET") return respond(response, 200, "Virki OIDC Node RP example. Visit /login.");

    if (requestUrl.pathname === "/login" && request.method === "GET") {
      const original = readCookie(request.headers.cookie, LOGIN_COOKIE);
      const binding = isOpaqueId(original) ? original : randomRpSessionId();
      const { url } = await client.beginLogin(binding);
      if (!isOpaqueId(original)) response.setHeader("Set-Cookie", cookie(LOGIN_COOKIE, binding, PREAUTH_MAX_AGE_SECONDS));
      response.statusCode = 303;
      response.setHeader("Location", url.href);
      return response.end();
    }

    if (requestUrl.pathname === registered.pathname && request.method === "GET") {
      const binding = readCookie(request.headers.cookie, LOGIN_COOKIE);
      if (!isOpaqueId(binding)) return respond(response, 400, "Authentication unavailable.");
      let identity;
      try {
        const result = await client.completeCallback(new URL(`${registered.pathname}${requestUrl.search}`, origin), binding);
        identity = result.identity;
      } catch {
        return respond(response, 400, "Authentication unavailable.");
      }
      // Only store a minimal identity — never persist or serialize tokens.serverOnly.
      if (typeof identity?.sub !== "string" || !identity.sub) return respond(response, 400, "Authentication unavailable.");
      const sessionId = randomRpSessionId();
      pruneSessions(sessions);
      sessions.set(hashId(sessionId), { sub: identity.sub, amr: identity.amr ?? [], acr: identity.acr ?? null, expiresAt: Date.now() + MAX_SESSION_AGE_MS });
      response.setHeader("Set-Cookie", cookie(SESSION_COOKIE, sessionId, Math.floor(MAX_SESSION_AGE_MS / 1000)));
      response.setHeader("Location", "/account");
      response.statusCode = 303;
      return response.end();
    }

    if (requestUrl.pathname === "/account" && request.method === "GET") {
      const sessionId = readCookie(request.headers.cookie, SESSION_COOKIE);
      const session = isOpaqueId(sessionId) ? sessions.get(hashId(sessionId)) : undefined;
      if (!session || session.expiresAt <= Date.now()) return respond(response, 401, "Session unavailable.");
      response.setHeader("Content-Type", "application/json; charset=utf-8");
      response.statusCode = 200;
      return response.end(JSON.stringify({ sub: session.sub, amr: session.amr, acr: session.acr }));
    }

    if (requestUrl.pathname === "/logout" && request.method === "POST") {
      if (request.headers.origin !== origin) return respond(response, 403, "Forbidden.");
      const sessionId = readCookie(request.headers.cookie, SESSION_COOKIE);
      if (isOpaqueId(sessionId)) sessions.delete(hashId(sessionId));
      response.setHeader("Set-Cookie", cookie(SESSION_COOKIE, "", 0));
      response.setHeader("Location", "/");
      response.statusCode = 303;
      return response.end();
    }
    return respond(response, 404, "Not found.");
  }

  return (request, response) => {
    Promise.resolve(handle(request, response)).catch(() => {
      if (!response.headersSent) respond(response, 503, "Service unavailable.");
      else response.destroy();
    });
  };
}

function respond(response, status, message) {
  response.statusCode = status;
  response.setHeader("Content-Type", "text/plain; charset=utf-8");
  response.end(message);
}

function readCookie(header, name) {
  if (typeof header !== "string") return null;
  const candidates = header.split(";").map((entry) => entry.trim()).filter((entry) => entry.startsWith(`${name}=`));
  if (candidates.length !== 1) return null;
  return candidates[0].slice(name.length + 1);
}

function isOpaqueId(value) { return typeof value === "string" && /^[A-Za-z0-9_-]{43}$/u.test(value); }

function cookie(name, value, seconds) {
  return `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${seconds}`;
}

function hashId(value) { return createHash("sha256").update("virki-example-rp-session\0").update(value).digest("hex"); }

function pruneSessions(sessions) {
  const now = Date.now();
  for (const [key, session] of sessions) if (session.expiresAt <= now) sessions.delete(key);
  if (sessions.size > 1000) throw new Error("RP demo session capacity exhausted.");
}
