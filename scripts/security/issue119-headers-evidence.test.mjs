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
    // RFC 7230 OWS permits SP / HTAB, not arbitrary JS Unicode whitespace.
    // A JavaScript \s or trim() check would fabricate browser HSTS evidence.
    response(200, goodCSP, goodHTML, { 'strict-transport-security': 'max-age=2592000\u00a0' }),
    response(200, goodCSP, goodHTML, { 'strict-transport-security': 'max-age\u00a0=2592000' }),
    response(200, goodCSP, goodHTML, { 'content-type': 'application/json' }),
    response(200, goodCSP, goodHTML, { 'content-type': 'text/plain' }),
    response(200, goodCSP, goodHTML, { 'content-type': 'text/html; boundary=forged' }),
    response(200, goodCSP, goodHTML, { 'content-type': 'text/html\u00a0' }),
    response(200, goodCSP, goodHTML, { 'content-type': 'text/html;\u00a0charset=utf-8' }),
    response(200, goodCSP, goodHTML.replace('<!doctype html>', '<!doctype\u00a0html>')),
    response(200, goodCSP, '<script nonce="SAFE">boot()</script>'),
    response(200, goodCSP, '<html><script nonce="SAFE">boot()</script></html>'),
    response(200, goodCSP, htmlDoc('<script nonce="SAFE">boot()</script>').replace('<head>', '')),
    response(200, goodCSP, htmlDoc('<script nonce="SAFE">boot()</script>').replace('</body>', '')),
    response(200, goodCSP, htmlDoc('<script nonce="SAFE">boot()</script>').replace('<!doctype html>', '')),
    response(200, goodCSP, htmlDoc('<!-- <script nonce="SAFE">boot()</script> -->')),
    response(200, goodCSP, htmlDoc('<template><script nonce="SAFE">boot()</script></template>')),
    response(200, goodCSP, htmlDoc('<noscript><script nonce="SAFE">boot()</script></noscript>')),
    response(200, goodCSP, htmlDoc('<script nonce="SAFE">safe()</script>' +
      '<noscript>fallback</noscript data-note="end"><script nonce="EVIL">bad()</script>' +
      '<noscript>second</noscript>')),
    response(200, goodCSP, htmlDoc('<script nonce="SAFE">safe()</script>' +
      '<iframe>fallback</iframe data-note="end"><script nonce="EVIL">bad()</script>' +
      '<iframe>second</iframe>')),
    response(200, goodCSP, htmlDoc('<iframe><script nonce="SAFE">boot()</script></iframe>')),
    response(200, goodCSP, htmlDoc('<noembed><script nonce="SAFE">boot()</script></noembed>')),
    response(200, goodCSP, htmlDoc('<noframes><script nonce="SAFE">boot()</script></noframes>')),
    response(200, goodCSP, htmlDoc('<div data-html="<script nonce=\'SAFE\'>">not an executable script</div>')),
    response(200, goodCSP, htmlDoc('<script nonce="SAFE" type="application/json">{"not":"JS"}</script>')),
    response(200, goodCSP, htmlDoc('<script nonce="SAFE" type="importmap">{}</script>')),
    response(200, goodCSP, htmlDoc('<script nonce="SAFE" type="speculationrules">{}</script>')),
    response(200, goodCSP, htmlDoc('<script nonce="SAFE">good()</script>' +
      '<script type="text/jscript" nonce="EVIL">bad()</script>')),
    response(200, goodCSP, htmlDoc('<script nonce="SAFE">good()</script>' +
      '<script type="text/javascript1.5" nonce="EVIL">bad()</script>')),
    response(200, goodCSP, htmlDoc('<script nonce="SAFE">good()</script>' +
      '<script type="application/x-ecmascript" nonce="EVIL">bad()</script>')),
    response(200, goodCSP, htmlDoc('<script nonce="SAFE">good()</script>' +
      '<!--><script nonce="EVIL">bad()</script><!-- -->')),
    response(200, goodCSP, htmlDoc('<script nonce="SAFE">good()</script>' +
      '<!---><script nonce="EVIL">bad()</script><!-- -->')),
    response(200, goodCSP, htmlDoc('<script nonce="SAFE">good()</script>' +
      '<!-- boundary --!><script nonce="EVIL">bad()</script><!-- later -->')),
    response(200, goodCSP, htmlDoc('<script nonce="SAFE">good()</script>' +
      '<script type="text&#47;javascript" nonce="EVIL">bad()</script>')),
    response(200, goodCSP, htmlDoc('<script type="text&#47;javascript" nonce="SAFE">bad()</script>')),
    response(200, goodCSP, htmlDoc('<script nonce="SAFE">good()</script>' +
      '<svg><title><script nonce="EVIL">bad()</script></title></svg>')),
    response(200, goodCSP, htmlDoc('<script nonce="SAFE">good()</script>' +
      '<math><mtext><script nonce="EVIL">bad()</script></mtext></math>')),
    response(200, goodCSP, htmlDoc('<script nonce="SAFE" type="text/javascript; charset=utf-8">boot()</script>')),
    response(200, goodCSP, htmlDoc('<script language="python" nonce="SAFE">boot()</script>')),
    response(200, goodCSP, htmlDoc('<script language="text&#47;javascript" nonce="SAFE">boot()</script>')),
    response(200, goodCSP, htmlDoc('<script nonce="SAFE">safe()</script>< style><script nonce="EVIL">bad()</script></style>')),
    response(200, goodCSP, htmlDoc('<script nonce="SAFE">safe()</script><style.foo><script nonce="EVIL">bad()</script></style>')),
    response(200, goodCSP, htmlDoc('<script.foo nonce="SAFE">boot()</script>')),
    response(200, goodCSP, htmlDoc('<script nonce="SAFE"/nomodule>boot()</script>')),
    response(200, goodCSP, htmlDoc('<script nonce="SAFE"/type="application/json">data()</script>')),
    response(200, goodCSP, htmlDoc('<script nonce="SAFE"/>boot()</script>')),
    response(200, goodCSP, htmlDoc('<script\u00a0nonce="SAFE">boot()</script>')),
    response(200, goodCSP, htmlDoc('<script nonce=SAFE\u00a0ignored>boot()</script>')),
    response(200, goodCSP, htmlDoc('<script nonce=SAFE\u000bignored>boot()</script>')),
    response(200, goodCSP, htmlDoc('<script nonce="SAFE">good()</script><style\u00a0id=x><script nonce="EVIL">bad()</script></style>')),
    response(200, goodCSP, htmlDoc('<script nonce="SAFE">good()</script><style\u00a0><script nonce="EVIL">bad()</script></style>')),
    response(200, goodCSP, htmlDoc('<script nonce="SAFE">good()</script><script nonce="EVIL"\u00a0type="application/json">bad()</script>')),
    response(200, goodCSP, htmlDoc('<script nonce="SAFE">good()</script><div data=x"><script nonce="EVIL">bad()</script>" />')),
    response(200, goodCSP, htmlDoc("<script nonce=\"SAFE\">good()</script><div data=x'><script nonce=\"EVIL\">bad()</script>' />")),
    response(200, goodCSP, htmlDoc('<script nonce="SAFE" type="\u00a0module\u00a0">boot()</script>')),
    response(200, goodCSP, htmlDoc('<script nonce="SAFE" type="\u2003module\u2003">boot()</script>')),
    response(200, "default-src 'none'; script-src\u00a0'nonce-SAFE'", goodHTML),
    response(200, "default-src 'none'; script-src\u000b'nonce-SAFE'", goodHTML),
    response(200, goodCSP, htmlDoc('<script nonce="SAFE" type="application/javascript; charset=utf-8">boot()</script>')),
    response(200, goodCSP, htmlDoc('<script nonce="SAFE" type="module; charset=utf-8">boot()</script>')),
    response(200, `${goodCSP}; sandbox`),
    response(200, `${goodCSP}; sandbox allow-same-origin`),
    response(200, `${goodCSP}; sandbox allow-popups`),
    response(200, `${goodCSP}; sandbox allow-scripts; sandbox`),
    response(200, goodCSP, htmlDoc('<script nomodule nonce="SAFE">boot()</script>')),
    response(200, goodCSP, htmlDoc('<script NOMODULE="false" nonce="SAFE">boot()</script>')),
    response(200, goodCSP, htmlDoc('<script type="text/javascript" nomodule nonce="SAFE">boot()</script>')),
    response(200, goodCSP, htmlDoc('<script type="application/ld+json" nonce="SAFE">{}</script>' +
      '<script nomodule nonce="SAFE">boot()</script>')),
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

test('quoted attribute values may contain > and fake scripts without hiding real nonce evidence', () => {
  const base = ISSUE119_HEADER_TARGETS[0];
  const valid = htmlDoc('<div data-note="> <script nonce=EVIL>fake</script>">safe</div>' +
    '<script nonce="SAFE">boot()</script>');
  assert.equal(classifyIssue119Response(base, response(200, goodCSP, valid)).result,
    'pass', 'valid quoted > stays inside a single HTML attribute');
});

test('HTML select insertion mode cannot hide executable wrong-nonce scripts behind ignored raw-text tags', () => {
  const base = ISSUE119_HEADER_TARGETS[0];
  for (const tag of ['style', 'iframe', 'noembed', 'noframes', 'title', 'noscript']) {
    const html = htmlDoc('<script nonce="SAFE">ok()</script>' +
      `<select><${tag}><script nonce="EVIL">bad()</script></${tag}></select>`);
    assert.equal(classifyIssue119Response(base, response(200, goodCSP, html)).result,
      'fail', `HTML5 in-select mode ignores <${tag}> but processes <script>`);
  }
  assert.equal(classifyIssue119Response(base, response(200, goodCSP,
    htmlDoc('<script nonce="SAFE">ok()</script><select><option>entry</option></select>'))).result,
  'fail', 'select insertion mode is deliberately outside this bounded acceptance parser');
});

test('actual nonce attributes and quoted decimal HSTS are recognized without lowercasing nonce values', () => {
  const base = ISSUE119_HEADER_TARGETS[0];
  const quoted = response(200, "script-src 'nonce-SAFE'", goodHTML,
    { 'strict-transport-security': 'max-age="2592000"' });
  assert.equal(classifyIssue119Response(base, quoted).result, 'pass');
  assert.equal(classifyIssue119Response(base, response(200, goodCSP, goodHTML,
    { 'strict-transport-security': 'max-age \t= \t2592000' })).result, 'pass',
  'HTTP SP and HTAB remain valid optional whitespace');
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

test('nomodule boolean is exact and ignored for classic scripts in modern module-capable browsers', () => {
  const base = ISSUE119_HEADER_TARGETS[0];
  for (const opening of [
    '<script nomodule nonce="SAFE">',
    '<script NOMODULE="false" nonce="SAFE">',
    '<script type="text/javascript" nomodule nonce="SAFE">',
    '<script data-nomodule="anything" nomodule nonce="SAFE">',
  ]) {
    assert.equal(classifyIssue119Response(base, response(200, goodCSP,
      htmlDoc(`${opening}boot()</script>`))).result, 'fail', opening);
  }
  for (const opening of [
    '<script data-nomodule="true" nonce="SAFE">',
    '<script x-nomodule nonce="SAFE">',
    '<script no-module nonce="SAFE">',
    '<script type="module" nomodule nonce="SAFE">',
  ]) {
    assert.equal(classifyIssue119Response(base, response(200, goodCSP,
      htmlDoc(`${opening}boot()</script>`))).result, 'pass', opening);
  }
  // Fallback and data-only are insufficient without an actual module script.
  const fallbackOnly = htmlDoc('<script nomodule nonce="SAFE">legacy()</script>' +
    '<script type="application/json">{"data":true}</script>');
  assert.equal(classifyIssue119Response(base, response(200, goodCSP, fallbackOnly)).result, 'fail');
  const modernWithLegacy = htmlDoc('<script nomodule nonce="EVIL">legacy()</script>' +
    '<script type="module" nonce="SAFE">modern()</script>');
  assert.equal(classifyIssue119Response(base, response(200, goodCSP, modernWithLegacy)).result, 'pass');
  assert.equal(classifyIssue119Response(base, response(200, goodCSP,
    htmlDoc('<script type="module" nonce="SAFE">modern()</script>'))).result, 'pass');
});

test('HTML script type is a MIME essence, not Content-Type with parameters', () => {
  const base = ISSUE119_HEADER_TARGETS[0];
  for (const value of ['text/javascript; charset=utf-8', 'application/javascript; charset=UTF-8',
    'module; charset=utf-8', 'application/ecmascript;version=6']) {
    assert.equal(classifyIssue119Response(base, response(200, goodCSP,
      htmlDoc(`<script type="${value}" nonce="SAFE">boot()</script>`))).result, 'fail', value);
  }
  for (const value of ['module', 'text/javascript', 'application/javascript']) {
    assert.equal(classifyIssue119Response(base, response(200, goodCSP,
      htmlDoc(`<script type="${value}" nonce="SAFE">boot()</script>`))).result, 'pass', value);
  }
});

test('legacy WHATWG JavaScript MIME essences cannot hide wrong-nonce executable scripts', () => {
  const base = ISSUE119_HEADER_TARGETS[0];
  for (const essence of [
    'application/ecmascript', 'application/javascript', 'application/x-ecmascript',
    'application/x-javascript', 'text/ecmascript', 'text/javascript',
    'text/javascript1.0', 'text/javascript1.1', 'text/javascript1.2',
    'text/javascript1.3', 'text/javascript1.4', 'text/javascript1.5',
    'text/jscript', 'text/livescript', 'text/x-ecmascript', 'text/x-javascript',
  ]) {
    const body = htmlDoc('<script nonce="SAFE">good()</script>' +
      `<script type="${essence}" nonce="EVIL">bad()</script>`);
    assert.equal(classifyIssue119Response(base, response(200, goodCSP, body)).result,
      'fail', essence);
    assert.equal(classifyIssue119Response(base, response(200, goodCSP,
      htmlDoc(`<script type="${essence}" nonce="SAFE">good()</script>`))).result,
    'pass', `valid alias ${essence}`);
  }
  assert.equal(classifyIssue119Response(base, response(200, goodCSP,
    htmlDoc('<script type="text/jscript; charset=utf-8" nonce="SAFE">data()</script>'))).result,
  'fail', 'the MIME essence cannot be matched by allowing additional MIME parameters');
});

test('abrupt HTML comment closure and foreign namespaces cannot create false nonce success', () => {
  const base = ISSUE119_HEADER_TARGETS[0];
  for (const invalidHTML of [
    '<!--><script nonce="EVIL">bad()</script><!-- -->',
    '<!---><script nonce="EVIL">bad()</script><!-- -->',
    '<!-- ordinary text --!><script nonce="EVIL">bad()</script><!-- ordinary -->',
    '<svg><title><script nonce="EVIL">bad()</script></title></svg>',
    '<math><mtext><script nonce="EVIL">bad()</script></mtext></math>',
  ]) {
    const body = htmlDoc(`<script nonce="SAFE">good()</script>${invalidHTML}`);
    assert.equal(classifyIssue119Response(base, response(200, goodCSP, body)).result,
      'fail', invalidHTML);
  }
  assert.equal(classifyIssue119Response(base, response(200, goodCSP,
    htmlDoc('<!-- safe ordinary comment -->' + '<script nonce="SAFE">good()</script>'))).result,
  'pass', 'well-formed ordinary comments retain their existing behavior');
});

test('HTML character references in script type attributes cannot hide executable scripts', () => {
  const base = ISSUE119_HEADER_TARGETS[0];
  for (const attr of ['text&#47;javascript', 'text&#x2f;javascript',
    'text&#x2F;javascript', 'text&sol;javascript']) {
    assert.equal(classifyIssue119Response(base, response(200, goodCSP,
      htmlDoc(`<script nonce="SAFE">good()</script><script type="${attr}" nonce="EVIL">bad()</script>`))).result,
    'fail', attr);
  }
  assert.equal(classifyIssue119Response(base, response(200, goodCSP,
    htmlDoc('<script type="text/javascript" nonce="SAFE">good()</script>'))).result, 'pass');
});

test('CSP meta policies cannot silently override an otherwise passing header nonce receipt', () => {
  const base = ISSUE119_HEADER_TARGETS[0];
  for (const head of [
    '<meta http-equiv="Content-Security-Policy" content="script-src \'none\'">',
    '<meta HTTP-EQUIV=content-security-policy content="script-src \'nonce-EVIL\'">',
    '<meta http-equiv="Content-Security-Policy" content="script-src &#39;none&#39;">',
    '<meta/http-equiv="Content-Security-Policy" content="script-src \'none\'">',
    '<meta /http-equiv="Content-Security-Policy" content="script-src \'none\'">',
    '<meta name="x"http-equiv="Content-Security-Policy" content="script-src \'none\'">',
  ]) {
    assert.equal(classifyIssue119Response(base, response(200, goodCSP,
      htmlDoc('<script nonce="SAFE">boot()</script>', head))).result, 'fail', head);
  }
  assert.equal(classifyIssue119Response(base, response(200, goodCSP,
    htmlDoc('<script nonce="SAFE">boot()</script>',
      '<meta charset="utf-8"><meta name="viewport" content="width=device-width">'))).result,
  'pass', 'ordinary metadata does not create a second enforced CSP');
  assert.equal(classifyIssue119Response(base, response(200, goodCSP,
    htmlDoc('<script nonce="SAFE">boot()</script>',
      '<meta data-http-equiv="Content-Security-Policy" content="script-src \'none\'">'))).result,
  'pass', 'data-http-equiv is not a real meta policy');
  assert.equal(classifyIssue119Response(base, response(200, goodCSP,
    htmlDoc('<script language="" nonce="SAFE">boot()</script>'))).result, 'pass',
  'empty legacy language fallback is not an inert non-JavaScript MIME');
});

test('enforced CSP sandbox without allow-scripts prevents executable nonce receipt', () => {
  const base = ISSUE119_HEADER_TARGETS[0];
  for (const policy of ['sandbox', 'sandbox allow-same-origin',
    'sandbox allow-popups', 'SANDBOX allow-forms', 'sandbox allow-scripts; sandbox']) {
    assert.equal(classifyIssue119Response(base, response(200, `${goodCSP}; ${policy}`)).result,
      'fail', policy);
  }
  assert.equal(classifyIssue119Response(base, response(200,
    `${goodCSP}; sandbox allow-scripts`)).result, 'pass',
  'sandbox with allow-scripts permits code execution, not guaranteed hydration');
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

test('attributed raw-text end tags cannot hide wrong-nonce executable scripts', () => {
  const base = ISSUE119_HEADER_TARGETS[0];
  for (const tag of ['noscript', 'iframe', 'noembed', 'noframes', 'style', 'script']) {
    const document = htmlDoc('<script nonce="SAFE">safe()</script>' +
      `<${tag}>some raw text</${tag} data-note="end">` +
      '<script nonce="EVIL">bad()</script>' + `<${tag}>again</${tag}>`);
    assert.equal(classifyIssue119Response(base, response(200, goodCSP, document)).result, 'fail', tag);
  }
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
