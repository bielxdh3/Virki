import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { ISSUE119_HEADER_TARGETS, classifyIssue119Response,
  collectIssue119HeaderEvidence } from './issue119-headers-evidence.mjs';

const goodHTML = '<html><script nonce="SAFE" src="/_next/static/app.js"></script><script nonce="SAFE">boot()</script></html>';
const goodCSP = "default-src 'self'; script-src 'self' 'nonce-SAFE' 'strict-dynamic'; object-src 'none'";

function response(status, csp = goodCSP, html = goodHTML, extraHeaders = {}) {
  return { status, headers: new Headers({ 'content-security-policy': csp,
    'strict-transport-security': 'max-age=2592000', 'content-type': 'text/html; charset=utf-8', ...extraHeaders }), body: html };
}

test('HTTP evidence stays bounded to four exact requests; Access and redirects are explicitly not origin proof', async () => {
  const requests = [];
  const result = await collectIssue119HeaderEvidence((target) => {
    requests.push([target.host, target.path, target.method]);
    return Promise.resolve(response(target.expected ?? (target.surface === 'access-protected' ? 302 : 307)));
  });
  assert.deepEqual(requests, ISSUE119_HEADER_TARGETS.map((t) => [t.host, t.path, t.method]));
  assert.equal(result.passed, true);
  assert.equal(result.originAndAuthProven, false);
  assert.equal(result.checks[2].result, 'blocked-by-access');
  assert.equal(result.checks[3].result, 'redirect-headers-only');
  assert.ok(!JSON.stringify(result).includes(goodHTML));
});

test('unsafe-inline, powered-by, mismatched nonce, missing HSTS and wrong 404 all fail closed', async () => {
  const base = ISSUE119_HEADER_TARGETS[0];
  const badCases = [
    response(200, "script-src 'unsafe-inline' 'nonce-SAFE'"),
    response(200, goodCSP, goodHTML, { 'X-Powered-By': 'Next.js' }),
    response(200, `${goodCSP}; script-src-elem 'unsafe-inline'`),
    response(200, `${goodCSP}; script-src-attr 'unsafe-inline'`),
    response(200, `${goodCSP}; script-src-elem 'nonce-EVIL'`),
    response(200, goodCSP, '<html><script data-nonce="SAFE">boot()</script></html>'),
    response(200, goodCSP, `<html><script data-test=" nonce='SAFE' ">boot()</script></html>`),
    response(200, `${goodCSP}; script-src-attr 'UNSAFE-INLINE'`),
    response(200, `${goodCSP}; script-src-elem 'UnSaFe-InLiNe'`),
    response(200, "script-src 'NONCE-SAFE' 'UNSAFE-INLINE'", goodHTML),
    response(200, `${goodCSP}, script-src 'none'`),
    response(200, `${goodCSP}, script-src 'nonce-SAFE'`),
    response(200, goodCSP, goodHTML, { 'strict-transport-security': 'max-age=1e6' }),
    response(200, goodCSP, goodHTML, { 'strict-transport-security': 'max-age=2592000junk' }),
    response(200, goodCSP, goodHTML, { 'strict-transport-security': 'max-age=2592000; max-age=3000' }),
    response(200, goodCSP, goodHTML, { 'content-type': 'application/json' }),
    response(200, goodCSP, '<script nonce="SAFE">boot()</script>'),
    response(200, "script-src 'nonce-SA&#70;E'", '<html><script nonce="SA&#70;E">boot()</script></html>'),
    response(200, goodCSP, '<html><script nonce="EVIL">boot()</script></html>'),
    { status: 200, headers: new Headers({ 'content-security-policy': goodCSP }), body: goodHTML },
    response(302),
  ];
  for (const value of badCases) assert.equal(classifyIssue119Response(base, value).result, 'fail');
  const result = await collectIssue119HeaderEvidence((target) => Promise.resolve(
    target.surface === 'public-404' ? response(200) : response(target.expected ?? 302)));
  assert.equal(result.passed, false);
});

test('two independent CSP headers are not mistaken for one passing hydration policy', () => {
  const base = ISSUE119_HEADER_TARGETS[0];
  const value = response(200);
  value.headers.append('content-security-policy', "script-src 'none'");
  const result = classifyIssue119Response(base, value);
  assert.equal(result.result, 'fail');
  assert.equal(result.cspPolicy, 'multiple-or-missing');
});

test('actual nonce attributes and quoted decimal HSTS are recognized without lowercasing nonce values', () => {
  const base = ISSUE119_HEADER_TARGETS[0];
  const quoted = response(200, "script-src 'nonce-SAFE'", goodHTML,
    { 'strict-transport-security': 'max-age="2592000"' });
  assert.equal(classifyIssue119Response(base, quoted).result, 'pass');
  assert.equal(classifyIssue119Response(base, response(200, "script-src 'nonce-safe'", goodHTML)).result, 'fail');
  assert.equal(classifyIssue119Response(base, response(200, goodCSP,
    '<html><script data-nonce="SAFE" nonce="SAFE">boot()</script></html>')).result, 'pass');
});

test('network failure is inconclusive and CLI refuses network without explicit --live', async () => {
  const result = await collectIssue119HeaderEvidence(() => Promise.reject(new Error('secret-network-path')));
  assert.equal(result.passed, false);
  assert.ok(result.checks.every((check) => check.result === 'inconclusive'));
  assert.ok(!JSON.stringify(result).includes('secret-network-path'));

  const cli = spawnSync(process.execPath, ['scripts/security/issue119-headers-evidence.mjs'], {
    cwd: process.cwd(), encoding: 'utf8', timeout: 4000,
  });
  assert.equal(cli.status, 2);
  assert.match(cli.stderr, /No network request made/);
  assert.equal(cli.stdout, '');
});
