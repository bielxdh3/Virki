import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { test } from 'node:test';
import { createRpHandler } from './server.mjs';
import { PREAUTH_COOKIE, SESSION_COOKIE, hashId, randomId } from './security.mjs';

const ORIGIN = 'https://rp.example.test';
const ISSUER = 'https://portal.example.test';
const POST = { origin: ORIGIN, 'content-type': 'application/x-www-form-urlencoded', 'sec-fetch-site': 'same-origin' };

function fixture({ failInsert = false, failRevoke = false } = {}) {
  const sessions = new Map();
  const preauth = new Map();
  const events = { login: [], callbacks: [], revoked: [], sql: [] };
  const redeemed = new Set();
  const db = {
    async query(sql, params = []) {
      events.sql.push(sql);
      if (sql.startsWith('INSERT INTO "VirkiRpPreauth"')) {
        preauth.set(params[0], params[1]);
        return { rows: [] };
      }
      if (sql.includes('DELETE FROM "VirkiRpPreauth"')) {
        const entry = preauth.get(params[0]);
        preauth.delete(params[0]);
        return { rows: entry ? [{ expiresAt: entry, bindingHash: params[0] }] : [] };
      }
      if (sql.startsWith('SELECT "subject"')) {
        const entry = sessions.get(params[0]);
        return { rows: entry ? [{ subject: entry.subject }] : [] };
      }
      if (sql.startsWith('DELETE FROM "VirkiRpSession"') || sql.startsWith('WITH consumed AS (DELETE FROM "VirkiRpSession"')) {
        const removed = sessions.get(params[0]);
        sessions.delete(params[0]);
        return { rows: removed ? [{ ciphertext: removed.ciphertext, idHash: params[0] }] : [] };
      }
      if (sql.startsWith('INSERT INTO "VirkiRpSession"')) {
        if (failInsert) throw new Error('simulated DB write failure with sensitive material');
        // Physical PostgreSQL has issuer TEXT NOT NULL; this assertion must
        // reject undefined instead of allowing a fake DB to mask a broken login.
        assert.equal(params[1], ISSUER);
        sessions.set(params[0], { subject: params[2], ciphertext: params[3] });
        return { rows: [] };
      }
      if (['BEGIN', 'COMMIT', 'ROLLBACK'].includes(sql)) return { rows: [] };
      throw new Error('Unexpected test SQL');
    },
    async connect() { return { query: db.query, release() {} }; }
  };
  const oidc = {
    async beginLogin(binding) {
      events.login.push(binding);
      return { url: new URL('https://portal.example.test/auth?state=valid-state&code_challenge=stub') };
    },
    async completeCallback(url, binding) {
      events.callbacks.push({ url, binding });
      if (binding !== events.login.at(-1) || url.searchParams.get('state') !== 'valid-state' || redeemed.has('valid-state')) throw new Error('state replay');
      redeemed.add('valid-state');
      // The real SDK validates issuer internally and exposes only mapped claims.
      return { identity: { sub: '<script>bad()</script>' }, serverOnly: { accessToken: 'sensitive-access-token' } };
    },
    async revokeAccessToken(token) {
      events.revoked.push(token);
      if (failRevoke) throw new Error('simulated token endpoint failure with sensitive material');
    }
  };
  const handler = createRpHandler({ oidc, db, origin: ORIGIN, issuer: ISSUER, sessionKey: randomBytes(32) });
  const request = async (method, path, headers = {}, encrypted = true) => {
    const result = { status: 0, headers: {}, body: '' };
    const res = {
      setHeader(k, v) { result.headers[k.toLowerCase()] = v; },
      writeHead(status, hs = {}) { result.status = status; for (const [k, v] of Object.entries(hs)) this.setHeader(k, v); },
      end(body = '') { result.body = body; }
    };
    await handler({ method, url: path, headers: { host: 'rp.example.test', ...headers }, socket: { encrypted, remoteAddress: '127.0.0.1' } }, res);
    return result;
  };
  return { request, sessions, preauth, events, db };
}

function cookieValue(response, name) {
  const header = response.headers['set-cookie'];
  const line = header?.find(value => value.startsWith(`${name}=`));
  return line?.split(';')[0];
}

test('CSRF, method, TLS and Host are checked before issuing any binding', async () => {
  const { request, events } = fixture();
  assert.equal((await request('GET', '/login')).status, 405);
  assert.equal((await request('POST', '/login', { ...POST, origin: 'https://evil.example.test' })).status, 403);
  assert.equal((await request('POST', '/login', { ...POST, 'sec-fetch-site': 'cross-site' })).status, 403);
  assert.equal((await request('POST', '/login', POST, false)).status, 400);
  assert.equal((await request('POST', '/login', { ...POST, host: 'evil.example.test' })).status, 400);
  assert.equal(events.login.length, 0);
});

test('RP accepts only an exact configured HTTPS issuer and never browser-provided issuer values', () => {
  const oidc = { beginLogin: async () => {}, completeCallback: async () => {} };
  const db = { connect: async () => {}, query: async () => {} };
  for (const issuer of [undefined, 'http://portal.example.test', 'https://portal.example.test/other', 'https://portal.example.test?client=evil', 'https://attacker@portal.example.test']) {
    assert.throws(() => createRpHandler({ oidc, db, origin: ORIGIN, issuer, sessionKey: randomBytes(32) }));
  }
});

test('login -> callback -> RP session rotation -> logout remains server-only', async () => {
  const { request, events, sessions } = fixture();
  const previous = randomId();
  sessions.set(hashId(previous), { subject: 'stale old account', ciphertext: '' });
  const login = await request('POST', '/login', POST);
  assert.equal(login.status, 303);
  assert.ok(login.headers.location.startsWith('https://portal.example.test/auth?'));
  const binding = cookieValue(login, PREAUTH_COOKIE);
  assert.ok(binding);
  assert.equal(login.headers['cache-control'], 'no-store');
  assert.equal(login.headers['referrer-policy'], 'no-referrer');
  assert.ok(!JSON.stringify(login).includes('sensitive-access-token'));

  const callback = await request('GET', '/oidc/callback?state=valid-state&code=single-use-code', { cookie: `${binding}; ${SESSION_COOKIE}=${previous}` });
  assert.equal(callback.status, 303);
  const newCookie = cookieValue(callback, SESSION_COOKIE);
  assert.ok(newCookie);
  assert.notEqual(newCookie, `${SESSION_COOKIE}=${previous}`);
  assert.ok(callback.headers['set-cookie'].some(v => v.startsWith(`${PREAUTH_COOKIE}=`) && v.includes('Max-Age=0')));
  assert.equal(sessions.has(hashId(previous)), false);
  assert.equal(sessions.size, 1);
  assert.equal(events.callbacks.length, 1);
  assert.ok(!JSON.stringify(callback).includes('sensitive-access-token'));

  const page = await request('GET', '/', { cookie: newCookie });
  assert.equal(page.status, 200);
  assert.ok(page.body.includes('&lt;script&gt;bad()&lt;/script&gt;'));
  assert.ok(!page.body.includes('sensitive-access-token'));
  assert.equal((await request('POST', '/logout', { ...POST, origin: 'https://evil.example.test', cookie: newCookie })).status, 403);
  const staleLogout = await request('POST', '/logout', { ...POST, cookie: `${SESSION_COOKIE}=${previous}` });
  assert.equal(staleLogout.status, 409, 'Rotated predecessor cannot report successful signout');
  assert.equal(staleLogout.headers['set-cookie'], undefined);
  assert.equal(sessions.size, 1);
  const logout = await request('POST', '/logout', { ...POST, cookie: newCookie });
  assert.equal(logout.status, 303);
  assert.equal(sessions.size, 0);
  assert.deepEqual(events.revoked, ['sensitive-access-token']);
  assert.ok(!JSON.stringify(logout).includes('sensitive-access-token'));
  assert.equal((await request('GET', '/', { cookie: newCookie })).body.includes('Not signed in.'), true);
});

test('wrong/missing/duplicate cookie and duplicate state deny callback; replay blocked', async () => {
  const { request, events, sessions } = fixture();
  const login = await request('POST', '/login', POST);
  const binding = cookieValue(login, PREAUTH_COOKIE);
  const path = '/oidc/callback?state=valid-state&code=code';
  for (const headers of [
    {},
    { cookie: `${PREAUTH_COOKIE}=${randomId()}` },
    { cookie: `${binding}; ${binding}` }
  ]) assert.equal((await request('GET', path, headers)).status, 400);
  assert.equal((await request('GET', `${path}&state=valid-state`, { cookie: binding })).status, 400);
  assert.equal((await request('GET', `${path}&code=second`, { cookie: binding })).status, 400);
  // The wrong-browser attempt reaches the SDK and is denied there. Malformed
  // duplicate query/cookie cases are rejected before any SDK call.
  assert.equal(events.callbacks.length, 1);
  assert.equal((await request('GET', path, { cookie: binding })).status, 303);
  assert.equal((await request('GET', path, { cookie: binding })).status, 400);
  assert.equal(sessions.size, 1);
});

test('session insert failure rolls back and never issues a session cookie', async () => {
  const { request, events, sessions } = fixture({ failInsert: true });
  const login = await request('POST', '/login', POST);
  const binding = cookieValue(login, PREAUTH_COOKIE);
  const response = await request('GET', '/oidc/callback?state=valid-state&code=code', { cookie: binding });
  assert.equal(response.status, 503);
  assert.equal(response.headers['set-cookie'], undefined);
  assert.equal(response.body, 'RP unavailable.');
  assert.equal(sessions.size, 0);
  assert.ok(events.sql.includes('ROLLBACK'));
  assert.ok(!JSON.stringify(response).includes('sensitive material'));
});

test('old session cookie with no live DB predecessor cannot create a successor', async () => {
  const { request, sessions, events } = fixture();
  const login = await request('POST', '/login', POST);
  const binding = cookieValue(login, PREAUTH_COOKIE);
  const unknownSession = `${SESSION_COOKIE}=${randomId()}`;
  const callback = await request('GET', '/oidc/callback?state=valid-state&code=code',
    { cookie: `${binding}; ${unknownSession}` });
  assert.equal(callback.status, 503);
  assert.equal(callback.headers['set-cookie'], undefined);
  assert.equal(sessions.size, 0);
  assert.ok(events.sql.includes('ROLLBACK'));
});

test('upstream token revocation failure cannot restore a locally deleted RP session', async () => {
  const { request, sessions, events } = fixture({ failRevoke: true });
  const login = await request('POST', '/login', POST);
  const signedIn = await request('GET', '/oidc/callback?state=valid-state&code=code', { cookie: cookieValue(login, PREAUTH_COOKIE) });
  const session = cookieValue(signedIn, SESSION_COOKIE);
  assert.equal(sessions.size, 1);
  const logout = await request('POST', '/logout', { ...POST, cookie: session });
  assert.equal(logout.status, 303);
  assert.equal(sessions.size, 0);
  assert.equal(events.revoked.length, 1);
  assert.ok(!JSON.stringify(logout).includes('sensitive material'));
});

test('logout during pending anonymous callback fences session creation', async () => {
  const { request, sessions, db } = fixture();
  const login = await request('POST', '/login', POST);
  const binding = cookieValue(login, PREAUTH_COOKIE);
  assert.ok(binding);
  let entering;
  const entered = new Promise(resolve => { entering = resolve; });
  let resume;
  const held = new Promise(resolve => { resume = resolve; });
  const actualConnect = db.connect;
  let delayed = false;
  db.connect = async () => {
    if (!delayed) { delayed = true; entering(); await held; }
    return actualConnect();
  };
  const callback = request('GET', '/oidc/callback?state=valid-state&code=code', { cookie: binding });
  await entered;
  const logout = await request('POST', '/logout', { ...POST, cookie: binding });
  assert.equal(logout.status, 409, 'Anonymous logout cannot claim all in-flight logins were cancelled');
  assert.equal(logout.headers['set-cookie'], undefined);
  resume();
  const returned = await callback;
  assert.equal(returned.status, 503, 'Cancelled pending login cannot mint a new session');
  assert.equal(returned.headers['set-cookie'], undefined);
  assert.equal(sessions.size, 0);
});

test('cookie-less logout cannot falsely confirm sign-out while another callback may be in flight', async () => {
  const { request } = fixture();
  const response = await request('POST', '/logout', POST);
  assert.equal(response.status, 409);
  assert.equal(response.headers['set-cookie'], undefined);
});
