import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { after, test } from 'node:test';
import { Pool } from 'pg';
import { createRpHandler } from './server.mjs';
import { PREAUTH_COOKIE, SESSION_COOKIE, hashId } from './security.mjs';

// Explicit opt-in ONLY. This test must never attach to the Virki database.
const socket = process.env.VIRKI_RP_PG_TEST_SOCKET;
const port = Number(process.env.VIRKI_RP_PG_TEST_PORT);
const expectedPrefix = /^\/dev\/shm\/virki59-pg18-[A-Za-z0-9]{8}$/u;
if (!expectedPrefix.test(socket ?? '') || !Number.isSafeInteger(port) || port < 1024 || port > 65535) {
  throw new Error('Dedicated disposable PostgreSQL socket and port required.');
}

const origin = 'https://rp.example.test';
const issuer = 'https://portal.example.test';
const postHeaders = { origin, 'content-type': 'application/x-www-form-urlencoded', 'sec-fetch-site': 'same-origin' };
const pool = new Pool({ host: socket, port, database: 'postgres', user: process.env.VIRKI_RP_PG_TEST_ROLE,
  max: 12, connectionTimeoutMillis: 3000, idleTimeoutMillis: 1000, ssl: false });
after(async () => { await pool.end(); });

function cookieValue(reply, name) {
  const line = reply.headers['set-cookie']?.find(value => value.startsWith(`${name}=`));
  return line?.split(';')[0];
}

function fixture(db = pool) {
  const flowState = new Map();
  const oidc = {
    async beginLogin(binding) {
      const state = randomBytes(32).toString('base64url');
      flowState.set(state, binding);
      return { url: new URL(`https://portal.example.test/auth?state=${state}`) };
    },
    async completeCallback(url, binding) {
      const state = url.searchParams.get('state');
      if (!state || flowState.get(state) !== binding) throw new Error('Invalid state or browser.');
      flowState.delete(state);
      return { identity: { sub: 'physical-user' }, serverOnly: { accessToken: 'opaque-server-token' } };
    },
    async revokeAccessToken() {}
  };
  const handler = createRpHandler({ oidc, db, origin, issuer, sessionKey: randomBytes(32) });
  const request = async (method, url, headers = {}) => {
    const result = { status: 0, headers: {}, body: '' };
    const response = {
      setHeader(k, v) { result.headers[k.toLowerCase()] = v; },
      writeHead(status, hs = {}) { result.status = status; for (const [k, v] of Object.entries(hs)) this.setHeader(k, v); },
      end(body = '') { result.body = body; }
    };
    await handler({ method, url, headers: { host: 'rp.example.test', ...headers },
      socket: { encrypted: true, remoteAddress: '127.0.0.1' } }, response);
    return result;
  };
  const authorize = async (oldSessionCookie = null) => {
    const start = await request('POST', '/login', postHeaders);
    assert.equal(start.status, 303);
    const binding = cookieValue(start, PREAUTH_COOKIE);
    assert.ok(binding);
    const url = new URL(start.headers.location);
    const cookies = [binding];
    if (oldSessionCookie) cookies.push(oldSessionCookie);
    return request('GET', `/oidc/callback?state=${url.searchParams.get('state')}&code=test-code`,
      { cookie: cookies.join('; ') });
  };
  return { request, authorize };
}

test('real PG18 RP login, issuer binding, rotation and logout are durable and server-only', async () => {
  try {
    const db = await pool.query('SELECT current_setting($1) AS version', ['server_version']);
    assert.ok(db.rows[0].version.startsWith('18.'));
    const { request, authorize } = fixture();
    const first = await authorize();
    assert.equal(first.status, 303);
    const oldCookie = cookieValue(first, SESSION_COOKIE);
    assert.ok(oldCookie);
    const initial = await pool.query('SELECT "issuer", "subject", "tokenCiphertext", "expiresAt" FROM "VirkiRpSession" WHERE "idHash" = $1',
      [hashId(oldCookie.split('=')[1])]);
    assert.equal(initial.rows.length, 1);
    assert.equal(initial.rows[0].issuer, issuer);
    assert.equal(initial.rows[0].subject, 'physical-user');
    assert.ok(!initial.rows[0].tokenCiphertext.includes('opaque-server-token'));
    assert.ok(new Date(initial.rows[0].expiresAt).getTime() > Date.now());

    const second = await authorize(oldCookie);
    assert.equal(second.status, 303);
    const newCookie = cookieValue(second, SESSION_COOKIE);
    assert.ok(newCookie && newCookie !== oldCookie);
    assert.equal((await pool.query('SELECT count(*)::int AS count FROM "VirkiRpSession" WHERE "idHash" = $1',
      [hashId(oldCookie.split('=')[1])])).rows[0].count, 0);
    assert.equal((await request('GET', '/', { cookie: newCookie })).status, 200);
    const logout = await request('POST', '/logout', { ...postHeaders, cookie: newCookie });
    assert.equal(logout.status, 303);
    assert.equal((await request('GET', '/', { cookie: newCookie })).body.includes('Not signed in.'), true);
  } finally {
    await pool.query('DELETE FROM "VirkiRpSession" WHERE "subject" = $1', ['physical-user']);
  }
});

test('real PG18 concurrent callbacks cannot both rotate the same old RP session', async () => {
  try {
    const { authorize } = fixture();
    const initial = await authorize();
    assert.equal(initial.status, 303);
    const old = cookieValue(initial, SESSION_COOKIE);
    assert.ok(old);
    const [a, b] = await Promise.all([authorize(old), authorize(old)]);
    assert.deepEqual([a.status, b.status].sort(), [303, 503]);
    const rows = await pool.query('SELECT "idHash" FROM "VirkiRpSession" WHERE "subject" = $1', ['physical-user']);
    assert.equal(rows.rows.length, 1);
    assert.equal(rows.rows[0].idHash, hashId(cookieValue(a.status === 303 ? a : b, SESSION_COOKIE).split('=')[1]));
  } finally {
    await pool.query('DELETE FROM "VirkiRpSession" WHERE "subject" = $1', ['physical-user']);
  }
});

test('PG18 expired/replayed/unknown predecessor can never mint a successor', async () => {
  try {
    const { authorize } = fixture();
    const initial = await authorize();
    assert.equal(initial.status, 303);
    const old = cookieValue(initial, SESSION_COOKIE);
    const previousHash = hashId(old.split('=')[1]);
    await pool.query('UPDATE "VirkiRpSession" SET "expiresAt" = NOW() - INTERVAL \'1 second\' WHERE "idHash" = $1', [previousHash]);
    const expired = await authorize(old);
    assert.equal(expired.status, 503);
    assert.equal(expired.headers['set-cookie'], undefined);
    const unknown = await authorize(`${SESSION_COOKIE}=${randomBytes(32).toString('base64url')}`);
    assert.equal(unknown.status, 503);
    assert.equal(unknown.headers['set-cookie'], undefined);
    assert.equal((await pool.query('SELECT count(*)::int AS count FROM "VirkiRpSession" WHERE "subject"=$1', ['physical-user'])).rows[0].count, 1);
    assert.equal((await pool.query('SELECT "expiresAt" < NOW() AS expired FROM "VirkiRpSession" WHERE "idHash"=$1', [previousHash])).rows[0].expired, true);
  } finally {
    await pool.query('DELETE FROM "VirkiRpSession" WHERE "subject" = $1', ['physical-user']);
  }
});

test('PG18 insert failure after predecessor DELETE rolls back old session and never sends cookie', async () => {
  try {
    const { request, authorize } = fixture();
    const initial = await authorize();
    assert.equal(initial.status, 303);
    const old = cookieValue(initial, SESSION_COOKIE);
    const oldHash = hashId(old.split('=')[1]);
    // A NOT VALID constraint affects new inserts but preserves the old row.
    // The DELETE must roll back when the new INSERT is rejected.
    await pool.query('ALTER TABLE "VirkiRpSession" ADD CONSTRAINT "rp_test_abort" CHECK ("issuer" = \'reject all inserts\') NOT VALID');
    const failed = await authorize(old);
    assert.equal(failed.status, 503);
    assert.equal(failed.headers['set-cookie'], undefined);
    assert.equal((await pool.query('SELECT count(*)::int AS count FROM "VirkiRpSession" WHERE "idHash"=$1', [oldHash])).rows[0].count, 1);
    assert.match((await request('GET', '/', { cookie: old })).body, /Signed in as subject/u);
    await pool.query('ALTER TABLE "VirkiRpSession" DROP CONSTRAINT "rp_test_abort"');
    const recovered = await authorize(old);
    assert.equal(recovered.status, 303);
    const next = cookieValue(recovered, SESSION_COOKIE);
    assert.ok(next && next !== old);
    assert.equal((await pool.query('SELECT count(*)::int AS count FROM "VirkiRpSession" WHERE "idHash"=$1', [oldHash])).rows[0].count, 0);
    // A fresh handler (after a process restart) must still observe the durable row.
    const restarted = fixture().request;
    assert.match((await restarted('GET', '/', { cookie: next })).body, /Signed in as subject/u);
  } finally {
    await pool.query('ALTER TABLE "VirkiRpSession" DROP CONSTRAINT IF EXISTS "rp_test_abort"');
    await pool.query('DELETE FROM "VirkiRpSession" WHERE "subject" = $1', ['physical-user']);
  }
});

test('PG18 lock waiting past predecessor expiry must reject rotation after lock release', async () => {
  const { authorize } = fixture();
  const first = await authorize();
  assert.equal(first.status, 303);
  const old = cookieValue(first, SESSION_COOKIE);
  const hash = hashId(old.split('=')[1]);
  const lock = await pool.connect();
  try {
    await pool.query('UPDATE "VirkiRpSession" SET "expiresAt" = clock_timestamp() + interval \'3 seconds\' WHERE "idHash"=$1', [hash]);
    await lock.query('BEGIN');
    await lock.query('SELECT "idHash" FROM "VirkiRpSession" WHERE "idHash"=$1 FOR UPDATE', [hash]);
    const contender = authorize(old);
    let observedBlockedBeforeExpiry = false;
    for (let attempt = 0; attempt < 60; attempt++) {
      const state = await pool.query(`
        SELECT
          (SELECT COUNT(*)::int FROM pg_stat_activity
             WHERE pid <> pg_backend_pid() AND state='active'
               AND wait_event_type='Lock' AND query LIKE '%VirkiRpSession%') AS waiting,
          (SELECT "expiresAt" > clock_timestamp() FROM "VirkiRpSession" WHERE "idHash"=$1) AS live
      `, [hash]);
      if (state.rows[0].waiting > 0 && state.rows[0].live) {
        observedBlockedBeforeExpiry = true;
        break;
      }
      await new Promise((resolve) => setTimeout(resolve, 30));
    }
    assert.ok(observedBlockedBeforeExpiry, 'Callback DELETE must be physically blocked BEFORE expiry');
    let expired = false;
    for (let attempt = 0; attempt < 80; attempt++) {
      const result = await pool.query('SELECT "expiresAt" <= clock_timestamp() AS expired FROM "VirkiRpSession" WHERE "idHash"=$1', [hash]);
      if (result.rows[0]?.expired) { expired = true; break; }
      await new Promise((resolve) => setTimeout(resolve, 40));
    }
    assert.ok(expired, 'Physical PG clock must cross expiry WHILE DELETE holds lock wait');
    await lock.query('COMMIT');
    const response = await contender;
    assert.equal(response.status, 503, 'Expired prior session must not rotate after lock delay');
  } finally {
    try { await lock.query('ROLLBACK'); } catch { /* Transaction may already be closed. */ }
    lock.release();
    await pool.query('DELETE FROM "VirkiRpSession" WHERE "subject" = $1', ['physical-user']);
  }
});

test('PG18 stale logout never claims success while rotated successor survives', async () => {
  try {
    const { request, authorize } = fixture();
    const initial = await authorize();
    assert.equal(initial.status, 303);
    const old = cookieValue(initial, SESSION_COOKIE);
    const rotated = await authorize(old);
    assert.equal(rotated.status, 303);
    const next = cookieValue(rotated, SESSION_COOKIE);
    const staleLogout = await request('POST', '/logout', { ...postHeaders, cookie: old });
    assert.equal(staleLogout.status, 409, 'A stale logout cannot claim completed revocation');
    assert.equal(staleLogout.headers['set-cookie'], undefined, 'Must not clear newer cookie through response races');
    assert.match((await request('GET', '/', { cookie: next })).body, /Signed in as subject/u);
    assert.equal((await request('POST', '/logout', { ...postHeaders, cookie: next })).status, 303);
    assert.match((await request('GET', '/', { cookie: next })).body, /Not signed in/u);
  } finally {
    await pool.query('DELETE FROM "VirkiRpSession" WHERE "subject" = $1', ['physical-user']);
  }
});

test('PG18 logout consumes pending login intent before an anonymous callback can commit', async () => {
  let entered;
  const begun = new Promise(resolve => { entered = resolve; });
  let release;
  const hold = new Promise(resolve => { release = resolve; });
  let first = true;
  const db = {
    query: (...args) => pool.query(...args),
    connect: async () => {
      if (first) { first = false; entered(); await hold; }
      return pool.connect();
    }
  };
  const { request } = fixture(db);
  const login = await request('POST', '/login', postHeaders);
  assert.equal(login.status, 303);
  const binding = cookieValue(login, PREAUTH_COOKIE);
  const state = new URL(login.headers.location).searchParams.get('state');
  const pending = request('GET', `/oidc/callback?state=${state}&code=code`, { cookie: binding });
  try {
    await Promise.race([begun, new Promise((_, reject) => setTimeout(() => reject(new Error('Callback did not reach PG connection gate.')), 3000))]);
    const logout = await request('POST', '/logout', { ...postHeaders, cookie: binding });
    assert.equal(logout.status, 409, 'No RP session was presented; pending-login cancellation is not global proof.');
    assert.equal(logout.headers['set-cookie'], undefined);
  } finally {
    release();
  }
  const callback = await pending;
  assert.equal(callback.status, 503);
  assert.equal(callback.headers['set-cookie'], undefined);
  const count = await pool.query('SELECT COUNT(*)::int AS n FROM "VirkiRpSession" WHERE "subject"=$1', ['physical-user']);
  assert.equal(count.rows[0].n, 0);
});

test('PG18 completed pending callback makes racing logout return 409, never false success', async () => {
  let entered;
  const committing = new Promise(resolve => { entered = resolve; });
  let release;
  const held = new Promise(resolve => { release = resolve; });
  let first = true;
  const db = {
    query: (...args) => pool.query(...args),
    connect: async () => {
      const client = await pool.connect();
      if (!first) return client;
      first = false;
      return {
        query: async (...args) => {
          if (args[0] === 'COMMIT') { entered(); await held; }
          return client.query(...args);
        },
        release: () => client.release()
      };
    }
  };
  const { request } = fixture(db);
  const login = await request('POST', '/login', postHeaders);
  const binding = cookieValue(login, PREAUTH_COOKIE);
  const state = new URL(login.headers.location).searchParams.get('state');
  const callback = request('GET', `/oidc/callback?state=${state}&code=code`, { cookie: binding });
  let logout;
  try {
    await Promise.race([committing, new Promise((_, reject) => setTimeout(() => reject(new Error('Callback did not reach COMMIT gate.')), 3000))]);
    logout = request('POST', '/logout', { ...postHeaders, cookie: binding });
    // The competing logout must wait on the deleted intent row.
    let waiting = false;
    for (let i = 0; i < 50; i += 1) {
      const observed = await pool.query("SELECT COUNT(*)::int AS n FROM pg_stat_activity WHERE pid <> pg_backend_pid() AND wait_event_type='Lock' AND query LIKE '%VirkiRpPreauth%'");
      if (observed.rows[0].n > 0) { waiting = true; break; }
      await new Promise(resolve => setTimeout(resolve, 20));
    }
    assert.ok(waiting, 'Logout must wait on callback intent row lock.');
  } finally {
    release();
  }
  const successful = await callback;
  const stale = await logout;
  assert.equal(successful.status, 303);
  assert.equal(stale.status, 409);
  assert.equal(stale.headers['set-cookie'], undefined);
  const session = cookieValue(successful, SESSION_COOKIE);
  assert.ok(session);
  assert.match((await request('GET', '/', { cookie: session })).body, /Signed in as subject/u);
  assert.equal((await request('POST', '/logout', { ...postHeaders, cookie: session })).status, 303);
});

test('PG18 preauth intent expired while its DELETE waits on a row lock cannot mint a session', async () => {
  const { request } = fixture();
  const login = await request('POST', '/login', postHeaders);
  assert.equal(login.status, 303);
  const binding = cookieValue(login, PREAUTH_COOKIE);
  const bindingHash = hashId(binding.split('=')[1]);
  const state = new URL(login.headers.location).searchParams.get('state');
  await pool.query('UPDATE "VirkiRpPreauth" SET "expiresAt"=clock_timestamp() + interval \'2 seconds\' WHERE "bindingHash"=$1', [bindingHash]);
  const lock = await pool.connect();
  let pending;
  try {
    await lock.query('BEGIN');
    await lock.query('SELECT "bindingHash" FROM "VirkiRpPreauth" WHERE "bindingHash"=$1 FOR UPDATE', [bindingHash]);
    pending = request('GET', `/oidc/callback?state=${state}&code=code`, { cookie: binding });
    let blockedBeforeExpiry = false;
    for (let i = 0; i < 65; i += 1) {
      const observed = await pool.query(`
        SELECT
          (SELECT COUNT(*)::int FROM pg_stat_activity WHERE pid <> pg_backend_pid()
             AND wait_event_type='Lock' AND query LIKE '%VirkiRpPreauth%') AS waiting,
          (SELECT "expiresAt" > clock_timestamp() FROM "VirkiRpPreauth"
             WHERE "bindingHash"=$1) AS live
      `, [bindingHash]);
      if (observed.rows[0].waiting > 0 && observed.rows[0].live) {
        blockedBeforeExpiry = true;
        break;
      }
      await new Promise(resolve => setTimeout(resolve, 25));
    }
    assert.ok(blockedBeforeExpiry, 'Callback must wait on preauth row before expiry.');
    let expired = false;
    for (let i = 0; i < 85; i += 1) {
      const observed = await pool.query('SELECT "expiresAt" <= clock_timestamp() AS expired FROM "VirkiRpPreauth" WHERE "bindingHash"=$1', [bindingHash]);
      if (observed.rows[0]?.expired) { expired = true; break; }
      await new Promise(resolve => setTimeout(resolve, 30));
    }
    assert.ok(expired, 'Preauth must expire while callback is physically waiting.');
    await lock.query('COMMIT');
    const response = await pending;
    assert.equal(response.status, 503);
    assert.equal(response.headers['set-cookie'], undefined);
    assert.equal((await pool.query('SELECT COUNT(*)::int AS n FROM "VirkiRpSession" WHERE "subject"=$1', ['physical-user'])).rows[0].n, 0);
  } finally {
    try { await lock.query('ROLLBACK'); } catch { /* Connection already committed. */ }
    lock.release();
    await pool.query('DELETE FROM "VirkiRpPreauth" WHERE "bindingHash"=$1', [bindingHash]);
  }
});
