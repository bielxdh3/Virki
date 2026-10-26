// Opt-in: real issuer, real confidential SDK, real HTTPS RP and two owned PG schemas.
import assert from 'node:assert/strict';
import { randomBytes, randomUUID, generateKeyPairSync } from 'node:crypto';
import { createServer as httpServer, request as httpRequest } from 'node:http';
import { createServer as httpsServer } from 'node:https';
import { connect } from 'node:net';
import { spawn } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { Pool } from 'pg';
import { prisma } from '@virki/database';
import { createSession, SESSION_COOKIE_NAME } from '@virki/auth';
import { encryptOidcClientSecret } from '@virki/auth/oidc-secrets';
import { createTestUser } from '../../packages/auth/src/integration-fixtures.ts';
import { createVirkiOidcClient } from '@virki/oidc-node';
import { EncryptedPostgresTransactionStore } from '@virki/oidc-node/postgres-store';
import { createRpHandler } from './server.mjs';
import { PREAUTH_COOKIE, SESSION_COOKIE, hashId } from './security.mjs';

const issuer = 'https://portal.localhost';
const rpOrigin = 'https://rp.localhost';
const redirectUri = rpOrigin + '/oidc/callback';
const randomKey = () => randomBytes(32);
const cookieId = () => randomKey().toString('base64url');
const owned = process.env.VIRKI_COMPOSED_OIDC_TEST === 'true';
function listen(server) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.removeListener('error', reject);
      resolve(server.address().port);
    });
  });
}
const stop = server => new Promise(resolve => {
  server.closeAllConnections?.();
  server.close(() => resolve());
});
const cookie = (response, name) => response.headers.getSetCookie()
  .find(value => value.startsWith(name + '='))?.split(';')[0];

test('actual issuer + SDK + HTTPS RP: signed login, durable session, logout and revoked grant', {
  skip: owned ? false : 'Owned private laboratory opt-in required',
  timeout: 120000
}, async () => {
  const { ProxyAgent, setGlobalDispatcher, getGlobalDispatcher } = await import('undici');
  const originalDispatcher = getGlobalDispatcher();
  const key = await readFile(process.env.VIRKI_COMPOSED_TLS_KEY);
  const cert = await readFile(process.env.VIRKI_COMPOSED_TLS_CERT);
  const pool = new Pool({ connectionString: process.env.VIRKI_COMPOSED_RP_DATABASE_URL, max: 10 });
  let child, proxy, facade, rp;
  try {
    const reservation = httpServer();
    const issuerPort = await listen(reservation);
    await stop(reservation);
    const jwk = generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({ format: 'jwk' });
    child = spawn(process.execPath, ['--import', 'tsx', 'apps/issuer/src/server.ts'], {
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, VIRKI_OIDC_ISSUER: issuer,
        OIDC_ISSUER_PORT: String(issuerPort), VIRKI_OIDC_BIND_ADDRESS: '127.0.0.1',
        VIRKI_AUDIT_HASH_SECRET: randomKey().toString('hex'), VIRKI_OIDC_COOKIE_KEY: cookieId(),
        VIRKI_OIDC_SIGNING_JWKS: JSON.stringify({ keys: [{ ...jwk, kid: 'native-composed', use: 'sig', alg: 'ES256' }] })
      }
    });
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('Owned issuer startup timeout')), 18000);
      const onExit = () => { clearTimeout(timer); reject(new Error('Owned issuer unexpectedly exited')); };
      child.once('exit', onExit);
      child.stdout.on('data', value => {
        if (String(value).includes('Virki OIDC issuer ready.')) {
          clearTimeout(timer); child.off('exit', onExit); resolve();
        }
      });
    });
    facade = httpsServer({ key, cert }, (req, res) => {
      const upstream = httpRequest({ hostname: '127.0.0.1', port: issuerPort, path: req.url,
        method: req.method, headers: { ...req.headers, host: 'portal.localhost',
          'x-forwarded-proto': 'https' }
      }, result => { res.writeHead(result.statusCode, result.headers); result.pipe(res); });
      upstream.on('error', () => { if (!res.headersSent) res.writeHead(502); res.end(); });
      req.pipe(upstream);
    });
    const facadePort = await listen(facade);
    const destinations = new Map([['portal.localhost:443', facadePort]]);
    proxy = httpServer((req, res) => { res.writeHead(403); res.end(); });
    proxy.on('connect', (req, socket, head) => {
      const target = destinations.get(req.url);
      if (!target || head.length !== 0) { socket.end('HTTP/1.1 403 Forbidden\r\n\r\n'); return; }
      const upstream = connect(target, '127.0.0.1');
      upstream.once('connect', () => {
        socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        socket.pipe(upstream); upstream.pipe(socket);
      });
      upstream.on('error', () => socket.destroy());
      socket.on('error', () => upstream.destroy());
    });
    const proxyPort = await listen(proxy);
    setGlobalDispatcher(new ProxyAgent('http://127.0.0.1:' + proxyPort));
    const user = await createTestUser({ label: 'oidc-composed' });
    const clientId = 'client-' + randomUUID();
    const secret = cookieId();
    const connection = await prisma.projectConnection.create({ data: {
      name: 'Disposable integrated issuer', slug: clientId, origin: rpOrigin, clientId,
      clientSecretCiphertext: encryptOidcClientSecret(secret), redirectUris: [redirectUri]
    } });
    await prisma.userProjectGrant.create({ data: { userId: user.id, connectionId: connection.id } });
    const session = await createSession(user.id);
    const oidc = await createVirkiOidcClient({ issuer, clientId, clientSecret: secret,
      redirectUri, store: new EncryptedPostgresTransactionStore(pool, randomKey()) });
    rp = httpsServer({ key, cert }, createRpHandler({
      oidc, db: pool, origin: rpOrigin, issuer, sessionKey: randomKey(), revokeOnLogout: false
    }));
    const rpPort = await listen(rp);
    destinations.set('rp.localhost:443', rpPort);
    const rpFetch = (path, init = {}) => fetch(rpOrigin + path, { redirect: 'manual', ...init });
    async function authorize() {
      const started = await rpFetch('/login', { method: 'POST', headers: {
        origin: rpOrigin, 'content-type': 'application/x-www-form-urlencoded',
        'sec-fetch-site': 'same-origin'
      } });
      assert.equal(started.status, 303, 'Real RP must issue OIDC redirect');
      const preauth = cookie(started, PREAUTH_COOKIE);
      assert.ok(preauth);
      let url = started.headers.get('location');
      assert.ok(url?.startsWith(issuer + '/auth?'));
      const cookies = new Map([[SESSION_COOKIE_NAME, session.token]]);
      for (let attempt = 0; attempt < 20; attempt++) {
        const response = await fetch(url, { redirect: 'manual',
          headers: { cookie: [...cookies].map(([k, v]) => k + '=' + v).join('; ') }
        });
        for (const raw of response.headers.getSetCookie()) {
          const part = raw.split(';')[0]; const eq = part.indexOf('=');
          if (eq > 0) cookies.set(part.slice(0, eq), part.slice(eq + 1));
        }
        const next = response.headers.get('location');
        assert.ok(next, 'Issuer did not redirect at status ' + response.status);
        url = new URL(next, url).href;
        if (url.startsWith(redirectUri + '?')) {
          assert.ok(new URL(url).searchParams.get('code'));
          return { callback: new URL(url), preauth };
        }
        assert.ok(url.startsWith(issuer + '/'), 'Issuer tried unexpected authority');
      }
      assert.fail('Issuer authorization never completed');
    }
    const signed = await authorize();
    const success = await rpFetch(signed.callback.pathname + signed.callback.search, {
      headers: { cookie: signed.preauth }
    });
    assert.equal(success.status, 303, 'Verified real issuer callback must create RP session');
    const localSession = cookie(success, SESSION_COOKIE);
    assert.ok(localSession, 'RP did not issue a host-only independent session');
    const stored = await pool.query('SELECT "issuer", "subject", "tokenCiphertext" FROM "VirkiRpSession" WHERE "idHash" = $1',
      [hashId(localSession.split('=')[1])]);
    assert.equal(stored.rows.length, 1);
    assert.equal(stored.rows[0].issuer, issuer);
    assert.equal(stored.rows[0].subject, user.id);
    assert.match(stored.rows[0].tokenCiphertext, /^v1\./u);
    assert.equal((await rpFetch('/', { headers: { cookie: localSession } })).status, 200);
    const logout = await rpFetch('/logout', { method: 'POST', headers: {
      cookie: localSession, origin: rpOrigin, 'content-type': 'application/x-www-form-urlencoded',
      'sec-fetch-site': 'same-origin'
    } });
    assert.equal(logout.status, 303);
    assert.equal((await pool.query('SELECT COUNT(*)::int AS n FROM "VirkiRpSession"')).rows[0].n, 0);
    const pending = await authorize();
    await prisma.userProjectGrant.deleteMany({ where: { userId: user.id, connectionId: connection.id } });
    const rejected = await rpFetch(pending.callback.pathname + pending.callback.search,
      { headers: { cookie: pending.preauth } });
    assert.equal(rejected.status, 400, 'Revoked grant after code issuance must fail closed');
    assert.equal(cookie(rejected, SESSION_COOKIE), undefined);
    assert.equal((await pool.query('SELECT COUNT(*)::int AS n FROM "VirkiRpSession"')).rows[0].n, 0);
  } finally {
    setGlobalDispatcher(originalDispatcher);
    if (rp) await stop(rp);
    if (proxy) await stop(proxy);
    if (facade) await stop(facade);
    if (child && child.exitCode === null && child.signalCode === null) {
      const exited = new Promise(resolve => child.once('exit', resolve));
      child.kill(); await exited;
    }
    await pool.end();
    await prisma.$disconnect();
  }
});
