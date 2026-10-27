// Opt-in: real issuer, real confidential SDK, real HTTPS RP and two owned PG schemas.
import assert from 'node:assert/strict';
import { randomBytes, randomUUID, generateKeyPairSync } from 'node:crypto';
import { createServer as httpServer, request as httpRequest } from 'node:http';
import { createServer as httpsServer } from 'node:https';
import { connect } from 'node:net';
import { spawn } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
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

function requireOwnedLab() {
  if (process.env.VIRKI_COMPOSED_OIDC_TEST !== 'true'
    || process.env.NODE_ENV !== 'test' || process.env.VIRKI_INTEGRATION_ENABLED !== 'true'
    || process.env.VIRKI_CORE_TEST_DATABASE_CONFIRM !== 'disposable'
    || process.env.NODE_TLS_REJECT_UNAUTHORIZED === '0') throw new Error('Owned PostgreSQL/TLS proof is not enabled.');
  const directory = process.env.VIRKI_COMPOSED_EXPECTED_PGDATA ?? '';
  if (!/^\/tmp\/virki63-compose-transfer-[a-f0-9]{32}\/pgdata$/u.test(directory)) throw new Error('Owned scratch identity required.');
  if (!process.env.NODE_EXTRA_CA_CERTS?.startsWith(directory.slice(0, -7) + '/tls/')) throw new Error('Trusted scratch certificate required.');
  let core, rp;
  try {
    core = new URL(process.env.DATABASE_URL ?? 'invalid:');
    rp = new URL(process.env.VIRKI_COMPOSED_RP_DATABASE_URL ?? 'invalid:');
  } catch {
    // URL errors may carry the entire connection string (including password)
    // in error.input. Never forward them into TAP diagnostics or CI logs.
    throw new Error('Unexpected PostgreSQL target.');
  }
  for (const [url, role, database] of [[core, 'virki_runtime_test', 'virki_composed_core'], [rp, 'rp_composed_owner', 'rp_composed']]) {
    if (url.protocol !== 'postgresql:' || url.hostname !== '127.0.0.1' || !/^[0-9]{4,5}$/u.test(url.port)
      || url.username !== role || !/^[a-f0-9]{64}$/u.test(url.password)
      || url.pathname !== '/' + database || url.hash) throw new Error('Unexpected PostgreSQL target.');
  }
  if (core.port !== rp.port || core.search !== '?schema=public' || rp.search) throw new Error('PostgreSQL URL override rejected.');
  if (process.env.VIRKI_COMPOSED_TLS_KEY?.startsWith(directory.slice(0, -7) + '/tls/') !== true
    || process.env.VIRKI_COMPOSED_TLS_CERT?.startsWith(directory.slice(0, -7) + '/tls/') !== true
    || !/^\/tmp\/virki63-compose-transfer-[a-f0-9]{32}\/transport\/node_modules\/undici\/index\.js$/u.test(process.env.VIRKI_COMPOSED_UNDICI_PATH ?? '')) {
    throw new Error('Owned TLS/HTTP transport missing.');
  }
  return Number(core.port);
}

test('lab gate rejects DSN override, malformed secret-bearing URLs and insecure TLS', () => {
  const names = [
    'VIRKI_COMPOSED_OIDC_TEST', 'NODE_ENV', 'VIRKI_INTEGRATION_ENABLED',
    'VIRKI_CORE_TEST_DATABASE_CONFIRM', 'NODE_TLS_REJECT_UNAUTHORIZED',
    'VIRKI_COMPOSED_EXPECTED_PGDATA', 'DATABASE_URL', 'VIRKI_COMPOSED_RP_DATABASE_URL',
    'NODE_EXTRA_CA_CERTS', 'VIRKI_COMPOSED_TLS_KEY', 'VIRKI_COMPOSED_TLS_CERT',
    'VIRKI_COMPOSED_UNDICI_PATH'
  ];
  const original = new Map(names.map(name => [name, process.env[name]]));
  const root = '/tmp/virki63-compose-transfer-' + 'a'.repeat(32);
  const password = 'b'.repeat(64);
  const coreUrl = 'postgresql://virki_runtime_test:' + password + '@127.0.0.1:54444/virki_composed_core?schema=public';
  const rpUrl = 'postgresql://rp_composed_owner:' + password + '@127.0.0.1:54444/rp_composed';
  try {
    Object.assign(process.env, {
      VIRKI_COMPOSED_OIDC_TEST: 'true', NODE_ENV: 'test',
      VIRKI_INTEGRATION_ENABLED: 'true', VIRKI_CORE_TEST_DATABASE_CONFIRM: 'disposable',
      VIRKI_COMPOSED_EXPECTED_PGDATA: root + '/pgdata',
      DATABASE_URL: coreUrl, VIRKI_COMPOSED_RP_DATABASE_URL: rpUrl,
      NODE_EXTRA_CA_CERTS: root + '/tls/ca.crt',
      VIRKI_COMPOSED_TLS_KEY: root + '/tls/server.key',
      VIRKI_COMPOSED_TLS_CERT: root + '/tls/server.crt',
      VIRKI_COMPOSED_UNDICI_PATH: root + '/transport/node_modules/undici/index.js'
    });
    delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
    assert.equal(requireOwnedLab(), 54444);
    process.env.DATABASE_URL = coreUrl + '&host=untrusted.example';
    assert.throws(requireOwnedLab, /URL override rejected/u);
    process.env.DATABASE_URL = coreUrl;
    process.env.VIRKI_COMPOSED_RP_DATABASE_URL = rpUrl + '?sslmode=no-verify';
    assert.throws(requireOwnedLab, /URL override rejected/u);
    process.env.VIRKI_COMPOSED_RP_DATABASE_URL = rpUrl;
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
    assert.throws(requireOwnedLab, /not enabled/u);
    delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
    process.env.DATABASE_URL = coreUrl.replace(':54444/', ':invalid-port/');
    assert.throws(requireOwnedLab, error =>
      error?.message === 'Unexpected PostgreSQL target.' && !String(error).includes(password),
      'Node URL parser must not expose database credentials in errors');
  } finally {
    for (const [name, value] of original) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
});

test('actual issuer + SDK + HTTPS RP: signed login, durable session, logout and revoked grant', {
  skip: owned ? false : 'Owned private laboratory opt-in required',
  timeout: 120000
}, async () => {
  const ownedPgPort = requireOwnedLab();
  const { ProxyAgent, setGlobalDispatcher, getGlobalDispatcher } = await import(pathToFileURL(process.env.VIRKI_COMPOSED_UNDICI_PATH).href);
  const originalDispatcher = getGlobalDispatcher();
  const key = await readFile(process.env.VIRKI_COMPOSED_TLS_KEY);
  const cert = await readFile(process.env.VIRKI_COMPOSED_TLS_CERT);
  const pool = new Pool({ connectionString: process.env.VIRKI_COMPOSED_RP_DATABASE_URL, max: 10 });
  let child, proxy, facade, rp, dispatcher;
  const proxyTunnels = new Set();
  try {
    // The bootstrap runner verifies PGDATA and Unix-socket identity using its
    // own cluster superuser BEFORE schema DDL. Runtime roles are intentionally
    // denied pg_read_all_settings; do not elevate them to inspect data_directory.
    const queryIdentity = 'SELECT current_user AS role, current_database() AS db, host(inet_server_addr()) AS server_addr, inet_server_port()::int AS port';
    const coreMeta = await prisma.$queryRawUnsafe(queryIdentity);
    const rpMeta = await pool.query(queryIdentity);
    for (const [record, role, database] of [
      [coreMeta[0], 'virki_runtime_test', 'virki_composed_core'],
      [rpMeta.rows[0], 'rp_composed_owner', 'rp_composed']
    ]) {
      assert.equal(record?.role, role, 'Connected database role must be the isolated test role');
      assert.equal(record?.db, database, 'Connected database must match the isolated test database');
      assert.match(record?.server_addr ?? '', /^127\.0\.0\.1(?:\/32)?$/u, 'Connected database must be loopback');
      assert.equal(record?.port, ownedPgPort, 'Connected database must use the owned cluster port');
    }
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
      proxyTunnels.add(socket);
      socket.once('close', () => proxyTunnels.delete(socket));
      const target = destinations.get(req.url);
      if (!target || head.length !== 0) { socket.end('HTTP/1.1 403 Forbidden\r\n\r\n'); return; }
      const upstream = connect(target, '127.0.0.1');
      proxyTunnels.add(upstream);
      upstream.once('close', () => proxyTunnels.delete(upstream));
      upstream.once('connect', () => {
        socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        socket.pipe(upstream); upstream.pipe(socket);
      });
      upstream.on('error', () => socket.destroy());
      socket.on('error', () => upstream.destroy());
    });
    const proxyPort = await listen(proxy);
    dispatcher = new ProxyAgent('http://127.0.0.1:' + proxyPort);
    setGlobalDispatcher(dispatcher);
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
    const signedInPage = await rpFetch('/', { headers: { cookie: localSession } });
    assert.equal(signedInPage.status, 200);
    const signedInHtml = await signedInPage.text();
    assert.match(signedInHtml, /Signed in as subject/u,
      'A successful HTTP response alone does not prove an authenticated RP page');
    assert.ok(signedInHtml.includes(`<code>${user.id}</code>`),
      'The RP must render the identity verified by the issuer, not an anonymous page');
    const logout = await rpFetch('/logout', { method: 'POST', headers: {
      cookie: localSession, origin: rpOrigin, 'content-type': 'application/x-www-form-urlencoded',
      'sec-fetch-site': 'same-origin'
    } });
    assert.equal(logout.status, 303);
    assert.equal((await pool.query('SELECT COUNT(*)::int AS n FROM "VirkiRpSession"')).rows[0].n, 0);
    const signedOutPage = await rpFetch('/', { headers: { cookie: localSession } });
    assert.equal(signedOutPage.status, 200);
    assert.match(await signedOutPage.text(), /Not signed in\./u,
      'The former RP cookie must not show an authenticated page after logout');
    const pending = await authorize();
    await prisma.userProjectGrant.deleteMany({ where: { userId: user.id, connectionId: connection.id } });
    const rejected = await rpFetch(pending.callback.pathname + pending.callback.search,
      { headers: { cookie: pending.preauth } });
    assert.equal(rejected.status, 400, 'Revoked grant after code issuance must fail closed');
    assert.equal(cookie(rejected, SESSION_COOKIE), undefined);
    assert.equal((await pool.query('SELECT COUNT(*)::int AS n FROM "VirkiRpSession"')).rows[0].n, 0);
  } finally {
    setGlobalDispatcher(originalDispatcher);
    // CONNECT upgrades are not covered by HTTP server.closeAllConnections().
    // Destroy only sockets accepted by this private test proxy before waiting
    // for server.close(), including failure paths with an in-flight tunnel.
    for (const socket of proxyTunnels) socket.destroy();
    if (rp) await stop(rp);
    if (proxy) await stop(proxy);
    if (facade) await stop(facade);
    if (child && child.exitCode === null && child.signalCode === null) {
      const exited = new Promise(resolve => child.once('exit', resolve));
      child.kill(); await exited;
    }
    await pool.end();
    await prisma.$disconnect();
    if (dispatcher) await dispatcher.destroy();
  }
});
