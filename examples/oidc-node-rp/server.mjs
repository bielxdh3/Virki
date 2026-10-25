import {
  PREAUTH_COOKIE, SESSION_COOKIE, acceptedPost, clearCookie, decryptToken,
  encryptToken, escapeHtml, hashId, parseCookie, parseServerOrigin, randomId,
  sessionCookie, validId
} from './security.mjs';

const SESSION_LIFETIME_MS = 8 * 60 * 60_000;

function securityHeaders(res) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Content-Security-Policy', "default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
}

function plain(res, status, content) {
  res.writeHead(status, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end(content);
}

function redirect(res, destination, cookies = []) {
  if (cookies.length) res.setHeader('Set-Cookie', cookies);
  res.writeHead(303, { Location: destination });
  res.end();
}

function html(res, contents) {
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(`<!doctype html><html lang="en"><head><meta charset="utf-8"><title>RP sign-in</title></head><body><main><h1>Independent RP session</h1>${contents}</main></body></html>`);
}

function rateLimiter({ max = 15, windowMs = 60_000, clock = Date.now } = {}) {
  const visits = new Map();
  return (address) => {
    const now = clock();
    const id = typeof address === 'string' && address.length < 100 ? address : 'unknown';
    const previous = visits.get(id);
    if (previous && now - previous.start < windowMs) {
      previous.count += 1;
      return previous.count <= max;
    }
    visits.delete(id);
    if (visits.size >= 4096) visits.delete(visits.keys().next().value);
    visits.set(id, { start: now, count: 1 });
    return true;
  };
}

async function insertSession(db, oldSessionId, newSessionId, identity, ciphertext) {
  // Pool.query BEGIN/COMMIT is NOT connection-affine; reserve one pg client.
  const connection = await db.connect();
  try {
    await connection.query('BEGIN');
    if (validId(oldSessionId)) {
      await connection.query('DELETE FROM "VirkiRpSession" WHERE "idHash" = $1', [hashId(oldSessionId)]);
    }
    await connection.query(
      'INSERT INTO "VirkiRpSession" ("idHash", "issuer", "subject", "tokenCiphertext", "expiresAt") VALUES ($1,$2,$3,$4,$5)',
      [hashId(newSessionId), identity.iss, identity.sub, ciphertext, new Date(Date.now() + SESSION_LIFETIME_MS)]
    );
    await connection.query('COMMIT');
  } catch {
    try { await connection.query('ROLLBACK'); } catch { /* Treat as failed; never issue cookie. */ }
    throw new Error('RP session unavailable.');
  } finally {
    connection.release();
  }
}

/**
 * HTTPS server handler. No Virki portal cookies, no ID Token or access token in HTML,
 * HTTP headers, redirects or logs; only a random RP session ID reaches the browser.
 */
export function createRpHandler({ oidc, db, origin, sessionKey, revokeOnLogout = true, generateId = randomId }) {
  const rpOrigin = parseServerOrigin(origin);
  if (!oidc || !db || typeof db.connect !== 'function' || typeof db.query !== 'function' || !(sessionKey instanceof Uint8Array) || sessionKey.byteLength !== 32) throw new Error('RP dependencies unavailable.');
  const limited = rateLimiter();

  return async function handle(req, res) {
    securityHeaders(res);
    try {
      if (!req.socket.encrypted || req.headers.host !== rpOrigin.host || typeof req.url !== 'string'
        || !req.url.startsWith('/') || req.url.startsWith('//')) return plain(res, 400, 'Request rejected.');
      const url = new URL(req.url, rpOrigin);
      if (url.origin !== rpOrigin.origin || url.hash) return plain(res, 400, 'Request rejected.');
      const existingSession = parseCookie(req.headers.cookie, SESSION_COOKIE);

      if (req.method === 'GET' && url.pathname === '/' && !url.search) {
        let current = null;
        if (existingSession) {
          const result = await db.query('SELECT "subject" AS subject FROM "VirkiRpSession" WHERE "idHash" = $1 AND "expiresAt" > NOW() LIMIT 1', [hashId(existingSession)]);
          current = result.rows[0]?.subject;
        }
        return html(res, current
          ? `<p>Signed in as subject <code>${escapeHtml(current)}</code></p><form method="post" action="/logout"><button>Sign out locally</button></form>`
          : '<p>Not signed in.</p><form method="post" action="/login"><button>Sign in through Virki</button></form>');
      }

      if (req.method === 'POST' && url.pathname === '/login' && !url.search) {
        if (!acceptedPost(req, rpOrigin.origin)) return plain(res, 403, 'Request rejected.');
        if (!limited(req.socket.remoteAddress)) return plain(res, 429, 'Too many requests.');
        const binding = generateId();
        if (!validId(binding)) throw new Error('Invalid RP random generator.');
        const flow = await oidc.beginLogin(binding);
        // beginLogin validates the authorization endpoint against the pinned issuer.
        return redirect(res, String(flow.url), [sessionCookie(PREAUTH_COOKIE, binding, 600)]);
      }

      if (req.method === 'GET' && url.pathname === '/oidc/callback') {
        if (!limited(req.socket.remoteAddress)) return plain(res, 429, 'Too many requests.');
        const binding = parseCookie(req.headers.cookie, PREAUTH_COOKIE);
        const params = url.searchParams;
        if (!binding || params.getAll('state').length !== 1 || params.getAll('code').length > 1
          || params.getAll('error').length > 1 || (params.has('code') && params.has('error'))) {
          res.setHeader('Set-Cookie', [clearCookie(PREAUTH_COOKIE)]);
          return plain(res, 400, 'Sign-in failed.');
        }
        let verified;
        try {
          // SDK atomically consumes state, checks cookie binding, PKCE, nonce, issuer,
          // audience, ES256/JWKS and signature before returning verified identity.
          verified = await oidc.completeCallback(url, binding);
        } catch {
          res.setHeader('Set-Cookie', [clearCookie(PREAUTH_COOKIE)]);
          return plain(res, 400, 'Sign-in failed.');
        }
        // The SDK already verifies issuer/JWKS and does not expose protocol proof fields.
        if (!verified?.identity?.sub || !verified?.serverOnly?.accessToken) {
          res.setHeader('Set-Cookie', [clearCookie(PREAUTH_COOKIE)]);
          return plain(res, 400, 'Sign-in failed.');
        }
        const newSessionId = generateId();
        if (!validId(newSessionId) || newSessionId === existingSession) throw new Error('Invalid RP random generator.');
        const tokenCiphertext = encryptToken(verified.serverOnly.accessToken, sessionKey, hashId(newSessionId));
        await insertSession(db, existingSession, newSessionId, verified.identity, tokenCiphertext);
        return redirect(res, '/', [clearCookie(PREAUTH_COOKIE), sessionCookie(SESSION_COOKIE, newSessionId)]);
      }

      if (req.method === 'POST' && url.pathname === '/logout' && !url.search) {
        if (!acceptedPost(req, rpOrigin.origin)) return plain(res, 403, 'Request rejected.');
        if (!limited(req.socket.remoteAddress)) return plain(res, 429, 'Too many requests.');
        let removed = null;
        if (existingSession) {
          const result = await db.query('DELETE FROM "VirkiRpSession" WHERE "idHash" = $1 RETURNING "tokenCiphertext" AS ciphertext', [hashId(existingSession)]);
          removed = result.rows[0]?.ciphertext;
        }
        // Local logout remains effective even if revocation is unavailable upstream.
        if (revokeOnLogout && typeof removed === 'string') {
          try { await oidc.revokeAccessToken(decryptToken(removed, sessionKey, hashId(existingSession))); } catch { /* No sensitive exception output. */ }
        }
        return redirect(res, '/', [clearCookie(SESSION_COOKIE), clearCookie(PREAUTH_COOKIE)]);
      }

      if (['/login', '/logout', '/oidc/callback'].includes(url.pathname)) {
        res.setHeader('Allow', url.pathname === '/oidc/callback' ? 'GET' : 'POST');
        return plain(res, 405, 'Method not allowed.');
      }
      return plain(res, 404, 'Not found.');
    } catch {
      // Never surface PG credentials, token grants, callback query or stack traces.
      return plain(res, 503, 'RP unavailable.');
    }
  };
}
