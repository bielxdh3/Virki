import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { test } from 'node:test';
import {
  PREAUTH_COOKIE, SESSION_COOKIE, acceptedPost, clearCookie, decryptToken, encryptToken,
  escapeHtml, hashId, parseCookie, parseServerOrigin, randomId, sessionCookie, sessionCryptoKey
} from './security.mjs';

test('all cookies are independent host-only, Secure, HttpOnly and Lax with bounded lifetime', () => {
  const id = randomId();
  assert.equal(id.length, 43);
  for (const name of [PREAUTH_COOKIE, SESSION_COOKIE]) {
    const header = sessionCookie(name, id, 600);
    assert.match(header, /^__Host-/u);
    for (const field of ['Path=/', 'Secure', 'HttpOnly', 'SameSite=Lax', 'Max-Age=600']) assert.ok(header.includes(field));
    assert.ok(!header.includes('Domain='));
    assert.equal(parseCookie(`other=abc; ${name}=${id}`, name), id);
    assert.equal(parseCookie(`${name}=${id}; ${name}=${id}`, name), null);
    assert.equal(parseCookie(`${name}=${id.slice(1)}`, name), null);
    assert.ok(clearCookie(name).includes('Max-Age=0'));
  }
  assert.notEqual(PREAUTH_COOKIE, SESSION_COOKIE);
  assert.throws(() => sessionCookie(SESSION_COOKIE, id, 9999999));
});

test('POST origin and Fetch Metadata must identify same-origin form', () => {
  const correct = 'https://rp.example.test';
  const base = { origin: correct, 'content-type': 'application/x-www-form-urlencoded', 'sec-fetch-site': 'same-origin' };
  assert.equal(acceptedPost({ headers: base }, correct), true);
  for (const headers of [
    { ...base, origin: 'https://evil.example.test' },
    { ...base, origin: undefined },
    { ...base, 'sec-fetch-site': 'cross-site' },
    { ...base, 'content-type': 'text/plain' }
  ]) assert.equal(acceptedPost({ headers }, correct), false);
  assert.throws(() => parseServerOrigin('http://rp.example.test'));
  assert.throws(() => parseServerOrigin('https://rp.example.test/path'));
  assert.equal(parseServerOrigin(correct).origin, correct);
});

test('encrypted RP backend token bound to session hash with domain-separated key', () => {
  const key = sessionCryptoKey(randomBytes(32));
  const idHash = hashId(randomId());
  const ciphertext = encryptToken('opaque-backend-access-token', key, idHash);
  assert.ok(!ciphertext.includes('opaque-backend-access-token'));
  assert.equal(decryptToken(ciphertext, key, idHash), 'opaque-backend-access-token');
  assert.throws(() => decryptToken(ciphertext, key, hashId(randomId())));
  assert.throws(() => decryptToken(ciphertext.replace(/^v1/u, 'v2'), key, idHash));
  assert.throws(() => decryptToken(ciphertext, sessionCryptoKey(randomBytes(32)), idHash));
});

test('HTML subject escaped and cannot inject script or markup', () => {
  assert.equal(escapeHtml('<img src=x onerror="bad()">'), '&lt;img src=x onerror=&quot;bad()&quot;&gt;');
});
