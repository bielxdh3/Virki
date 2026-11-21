import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { ISSUE119_HEADER_TARGETS, classifyIssue119Response,
  collectIssue119HeaderEvidence } from './issue119-headers-evidence.mjs';

const htmlDoc = (body, head = '') => `<!doctype html><html lang="pt-BR"><head>${head}</head><body>${body}</body></html>`;
const goodHTML = htmlDoc('<script nonce="SAFE" src="/_next/static/app.js"></script><script nonce="SAFE">boot()</script>');
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
    response(200, `${goodCSP}; script-src-elem`),
    response(200, `${goodCSP}; SCRIPT-SRC-ELEM   `),
    response(200, goodCSP, htmlDoc('<script data-nonce="SAFE">boot()</script>')),
    response(200, goodCSP, htmlDoc(`<script data-test=" nonce='SAFE' ">boot()</script>`)),
    response(200, `${goodCSP}; script-src-attr 'UNSAFE-INLINE'`),
    response(200, `${goodCSP}; script-src-elem 'UnSaFe-InLiNe'`),
    response(200, "script-src 'NONCE-SAFE' 'UNSAFE-INLINE'", goodHTML),
    response(200, `${goodCSP}, script-src 'none'`),
    response(200, `${goodCSP}, script-src 'nonce-SAFE'`),
    response(200, goodCSP, goodHTML, { 'strict-transport-security': 'max-age=1e6' }),
    response(200, goodCSP, goodHTML, { 'strict-transport-security': 'max-age=2592000junk' }),
    response(200, goodCSP, goodHTML, { 'strict-transport-security': 'max-age=2592000; max-age=3000' }),
    response(200, goodCSP, goodHTML, { 'content-type': 'application/json' }),
    response(200, goodCSP, goodHTML, { 'content-type': 'text/plain' }),
    response(200, goodCSP, goodHTML, { 'content-type': 'text/html; boundary=forged' }),
    response(200, goodCSP, '<script nonce="SAFE">boot()</script>'),
    response(200, goodCSP, '<html><script nonce="SAFE">boot()</script></html>'),
    response(200, goodCSP, htmlDoc('<script nonce="SAFE">boot()</script>').replace('<head>', '')),
    response(200, goodCSP, htmlDoc('<script nonce="SAFE">boot()</script>').replace('</body>', '')),
    response(200, goodCSP, htmlDoc('<script nonce="SAFE">boot()</script>').replace('<!doctype html>', '')),
    response(200, goodCSP, htmlDoc('<!-- <script nonce="SAFE">boot()</script> -->')),
    response(200, goodCSP, htmlDoc('<template><script nonce="SAFE">boot()</script></template>')),
    response(200, goodCSP, htmlDoc('<noscript><script nonce="SAFE">boot()</script></noscript>')),
    response(200, goodCSP, htmlDoc('<iframe><script nonce="SAFE">boot()</script></iframe>')),
    response(200, goodCSP, htmlDoc('<noembed><script nonce="SAFE">boot()</script></noembed>')),
    response(200, goodCSP, htmlDoc('<noframes><script nonce="SAFE">boot()</script></noframes>')),
    response(200, goodCSP, htmlDoc('<div data-html="<script nonce=\'SAFE\'>">not an executable script</div>')),
    response(200, goodCSP, htmlDoc('<script nonce="SAFE" type="application/json">{"not":"JS"}</script>')),
    response(200, goodCSP, htmlDoc('<script nonce="SAFE" type="importmap">{}</script>')),
    response(200, goodCSP, htmlDoc('<script nonce="SAFE" type="speculationrules">{}</script>')),
    response(200, goodCSP, htmlDoc('<template><style>body{content:"</template>"}</style>' +
      '<script nonce="SAFE">boot()</script></template>')),
    response(200, goodCSP, htmlDoc('<template><script>const x="</template>";</script>' +
      '<script nonce="SAFE">boot()</script></template>')),
    response(200, goodCSP, htmlDoc('<template><style>body{content:"</template>"}</style>' +
      '<script nonce="SAFE">boot()</script><template></template>')),
    response(200, goodCSP, htmlDoc('<template><script></template><script nonce="SAFE"></script>')),
    response(200, goodCSP, htmlDoc('<script nonce="SAFE">good()</script>' +
      '<noscript><style></noscript><script nonce="EVIL">boot()</script></style></noscript>')),
    response(200, "script-src 'nonce-SA&#70;E'", htmlDoc('<script nonce="SA&#70;E">boot()</script>')),
    response(200, goodCSP, htmlDoc('<script nonce="EVIL">boot()</script>')),
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
    htmlDoc('<script data-nonce="SAFE" nonce="SAFE">boot()</script>'))).result, 'pass');
});

test('a real executable script is required even with valid HTML5 skeleton, comments and inert templates', () => {
  const base = ISSUE119_HEADER_TARGETS[0];
  const real = htmlDoc('<!-- <script nonce="EVIL">ignored</script> -->' +
    '<template><script nonce="EVIL">ignored</script></template>' +
    '<noscript><script nonce="EVIL">ignored</script></noscript>' +
    '<script nonce="SAFE">boot()</script>');
  const result = classifyIssue119Response(base, response(200, goodCSP, real));
  assert.equal(result.htmlDocument, 'confirmed');
  assert.equal(result.scriptNonce, 'matched');
  assert.equal(result.result, 'pass');
});

test('inert JSON data scripts do not prove hydration or require nonce if real script exists', () => {
  const base = ISSUE119_HEADER_TARGETS[0];
  const document = htmlDoc('<script type="application/json">{"hydration":false}</script>' +
    '<script type="module" nonce="SAFE">boot()</script>');
  const result = classifyIssue119Response(base, response(200, goodCSP, document));
  assert.equal(result.result, 'pass');
  assert.equal(result.scriptNonce, 'matched');
  assert.equal(classifyIssue119Response(base, response(200, goodCSP,
    htmlDoc('<script type="module" data-nonce="SAFE">boot()</script>'))).result, 'fail');
});

test('raw-text false template closures cannot transform inert scripts into executable evidence', () => {
  const base = ISSUE119_HEADER_TARGETS[0];
  const inner = '<template><style>body::after{content:"</template>"}</style>' +
    '<script nonce="EVIL">ignored</script></template>';
  const actual = htmlDoc(`${inner}<script nonce="SAFE">boot()</script>`);
  const result = classifyIssue119Response(base, response(200, goodCSP, actual));
  assert.equal(result.result, 'pass', 'only the final outside script may count');
  assert.equal(result.scriptNonce, 'matched');
});

test('noscript raw text cannot conceal a subsequent executable script with wrong nonce', () => {
  const base = ISSUE119_HEADER_TARGETS[0];
  const forged = htmlDoc('<script nonce="SAFE">safe()</script>' +
    '<noscript><style></noscript><script nonce="EVIL">boot()</script></style></noscript>');
  assert.equal(classifyIssue119Response(base, response(200, goodCSP, forged)).result, 'fail');
  const legitimate = htmlDoc('<noscript><script nonce="EVIL">ignored()</script></noscript>' +
    '<script nonce="SAFE">real()</script>');
  assert.equal(classifyIssue119Response(base, response(200, goodCSP, legitimate)).result, 'pass');
});

test('iframe, noembed and noframes fallback content does not count as executable nonce evidence', () => {
  const base = ISSUE119_HEADER_TARGETS[0];
  for (const tag of ['iframe', 'noembed', 'noframes']) {
    const fallbackOnly = htmlDoc(`<${tag}><script nonce="SAFE">boot()</script></${tag}>`);
    assert.equal(classifyIssue119Response(base, response(200, goodCSP, fallbackOnly)).result, 'fail', tag);
    const actual = htmlDoc(`<${tag}><script nonce="EVIL">ignored()</script></${tag}>` +
      '<script nonce="SAFE">boot()</script>');
    assert.equal(classifyIssue119Response(base, response(200, goodCSP, actual)).result, 'pass', tag);
  }
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
