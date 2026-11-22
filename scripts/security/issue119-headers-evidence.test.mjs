import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { ISSUE119_HEADER_TARGETS, classifyIssue119Response, extractIssue119PublicStylesheetPaths,
  collectIssue119HeaderEvidence } from './issue119-headers-evidence.mjs';

const stylesheet = '<link rel="stylesheet" href="/_next/static/css/site.css">';
const htmlDoc = (body, head = '', includeStylesheet = true) =>
  `<!doctype html><html lang="pt-BR"><head>${includeStylesheet ? stylesheet : ''}${head}</head><body>${body}</body></html>`;
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

test('duplicate CSP directives never attest strict policy, including first-wins browser semantics', () => {
  const html = htmlDoc('<script nonce="SAFE">window.__hydrated = true</script>');
  const duplicatePairs = [
    // The browser ignores the later directive: neither conflict nor duplicate
    // is a second independently enforced CSP policy. Our receipt still fails
    // closed rather than certifying an ambiguous configuration.
    ["script-src-elem 'nonce-SAFE'", "script-src-elem 'nonce-EVIL'"],
    ["script-src-elem 'nonce-SAFE'", "script-src-elem https:"],
    ["script-src-elem 'nonce-SAFE'", "script-src-elem 'nonce-SAFE'"],
    ["script-src-elem 'nonce-EVIL'", "script-src-elem 'nonce-SAFE'"],
    ["script-src-attr 'none'", "script-src-attr 'unsafe-inline'"],
    ["script-src-attr 'none'", "script-src-attr 'none'"],
    ["SCRIPT-SRC-ATTR 'none'", "script-src-attr 'none'"],
    ["script-src 'self' 'nonce-SAFE' 'strict-dynamic'", "script-src 'nonce-SAFE'"],
    ["style-src-elem 'self'", "STYLE-SRC-ELEM https:"],
    ["style-src-attr 'none'", "style-src-attr 'none'"],
    ["default-src 'self'", "default-src 'self'"],
    ["object-src 'none'", "object-src 'none'"],
    ["unknown-future-directive 'none'", "UNKNOWN-FUTURE-DIRECTIVE 'none'"],
  ];
  for (const target of ISSUE119_HEADER_TARGETS.slice(0, 2)) {
    for (const [first, second] of duplicatePairs) {
      let csp = `${goodCSP}; ${first}; ${second}`;
      if (first.toLowerCase().startsWith('script-src ') ||
          first.toLowerCase().startsWith('default-src ') ||
          first.toLowerCase().startsWith('object-src ')) {
        const directiveName = first.split(' ')[0].toLowerCase();
        csp = `${goodCSP.split('; ').filter((d) => !d.startsWith(`${directiveName} `)).join('; ')}; ${first}; ${second}`;
      }
      const result = classifyIssue119Response(target, response(target.expected, csp, html));
      assert.equal(result.result, 'fail', `${target.surface} must refuse duplicate ${first} / ${second}`);
      assert.equal(result.cspPolicy, 'duplicate-or-multiple-or-missing', 'ambiguity should be visible in sanitized receipt');
    }
    // A CSP can contain multiple different directives; reject duplicates,
    // never a legitimate distinct directive or ordinary whitespace.
    for (const tail of ["", "; script-src-elem 'nonce-SAFE'", "; script-src-attr 'none'",
      "; style-src-elem 'self'", "; style-src-attr 'none'",
      "; script-src-elem 'nonce-SAFE'; script-src-attr 'none'; style-src-elem 'self'; style-src-attr 'none'"]) {
      const result = classifyIssue119Response(target,
        response(target.expected, `${goodCSP}; style-src 'self'${tail}`, html));
      assert.equal(result.result, 'pass', `${target.surface} single-instance policy must pass: ${tail}`);
      assert.equal(result.cspPolicy, 'single');
    }
  }
});

test('CSP sandbox cannot forge a same-origin hydration receipt with an opaque document origin', () => {
  const html = htmlDoc('<script nonce="SAFE">window.__hydrated = true</script>');
  for (const target of ISSUE119_HEADER_TARGETS.slice(0, 2)) {
    // A sandbox without allow-same-origin still permits nonce-bearing scripts
    // when allow-scripts is present, but isolates the document into an opaque
    // origin. It cannot attest the public same-origin stylesheet/hydration
    // contract simply because the expected nonce appears in the HTML.
    for (const sandbox of [
      'sandbox allow-scripts',
      'sandbox ALLOW-SCRIPTS',
      'sandbox allow-scripts allow-forms',
    ]) {
      assert.equal(classifyIssue119Response(target,
        response(target.expected, `${goodCSP}; ${sandbox}`, html)).result, 'fail',
      `${target.surface} must refuse an opaque-origin document: ${sandbox}`);
    }
    for (const tail of ['', '; sandbox allow-scripts allow-same-origin']) {
      assert.equal(classifyIssue119Response(target,
        response(target.expected, `${goodCSP}${tail}`, html)).result, 'pass');
    }
  }
});

test('public CSP evidence cannot silently accept inline-style bypass directives', () => {
  const target = ISSUE119_HEADER_TARGETS[0];
  for (const directive of [
    "style-src 'self' 'unsafe-inline'",
    "style-src-elem 'unsafe-inline'",
    "style-src-attr 'unsafe-inline'",
  ]) {
    const result = classifyIssue119Response(target, response(200, `${goodCSP}; ${directive}`));
    assert.equal(result.result, 'fail', `public 200/404 acceptance must reject ${directive}`);
  }
  assert.equal(classifyIssue119Response(target, response(200,
    goodCSP.replace("default-src 'self'", "default-src 'self' 'unsafe-inline'"))).result, 'fail',
  'default-src also permits inline styles when no more specific style directive exists');
});

test('CSP3 effective script element and attribute directives cannot broaden the nonce-only receipt', () => {
  const document = htmlDoc('<script nonce="SAFE">window.__hydrated=true</script>');
  for (const target of ISSUE119_HEADER_TARGETS.slice(0, 2)) {
    for (const directive of [
      "script-src-elem 'nonce-SAFE' https://attacker.invalid",
      "script-src-elem 'nonce-SAFE' https:",
      "script-src-elem 'self' 'nonce-SAFE' data:",
      "script-src-elem 'nonce-SAFE' 'nonce-EVIL'",
      "script-src-elem 'nonce-SAFE' 'nonce-SAFE'",
      "script-src-elem 'self' 'nonce-SAFE' 'unsafe-eval'",
      "script-src-attr 'unsafe-hashes' 'sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='",
      "script-src-attr 'nonce-SAFE'",
      "script-src 'self' 'nonce-SAFE' 'strict-dynamic' 'unsafe-hashes' 'sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='",
    ]) {
      const csp = directive.startsWith('script-src ') ?
        goodCSP.replace(/script-src [^;]+/u, directive) : `${goodCSP}; ${directive}`;
      assert.equal(classifyIssue119Response(target,
        response(target.expected, csp, document)).result, 'fail',
      `${target.surface} must refuse script source expansion: ${directive}`);
    }
    for (const directive of [
      "script-src-elem 'nonce-SAFE'",
      "script-src-elem 'self' 'nonce-SAFE'",
      "script-src-elem 'nonce-SAFE'; script-src-attr 'none'",
      "script-src-elem 'self' 'nonce-SAFE' 'strict-dynamic'; script-src-attr 'none'",
    ]) {
      assert.equal(classifyIssue119Response(target,
        response(target.expected, `${goodCSP}; ${directive}`, document)).result, 'pass',
      `${target.surface} must retain narrow nonceable controls: ${directive}`);
    }
  }
});

test('CSS subdirectives cannot defeat the public external stylesheet acceptance receipt', () => {
  const html = htmlDoc('<script nonce="SAFE">boot()</script>',
    '<link rel="stylesheet" href="/_next/static/css/site.css">');
  const base = `${goodCSP}; style-src 'self'`;
  for (const target of ISSUE119_HEADER_TARGETS.slice(0, 2)) {
    for (const directive of [
      "style-src-elem 'none'",
      'style-src-elem',
      'style-src-elem https://attacker.invalid',
      "style-src-elem 'self' https://attacker.invalid",
      "style-src-attr 'unsafe-hashes' 'sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='",
      'style-src-attr',
    ]) {
      const result = classifyIssue119Response(target,
        response(target.expected, `${base}; ${directive}`, html));
      assert.equal(result.result, 'fail', `${target.surface} must refuse ${directive}`);
    }
    for (const directives of ['', "; style-src-elem 'self'", "; style-src-attr 'none'",
      "; style-src-elem 'self'; style-src-attr 'none'"]) {
      const result = classifyIssue119Response(target,
        response(target.expected, base + directives, html));
      assert.equal(result.result, 'pass', `${target.surface} should accept ${directives}`);
    }
  }
});

test('effective CSP style-src and default-src fallback must permit the same-origin external stylesheet', () => {
  const html = htmlDoc('<script nonce="SAFE">boot()</script>',
    '<link rel="stylesheet" href="/_next/static/css/site.css">');
  for (const target of ISSUE119_HEADER_TARGETS.slice(0, 2)) {
    for (const csp of [
      `${goodCSP}; style-src 'none'`,
      `${goodCSP}; style-src https://attacker.invalid`,
      `${goodCSP}; style-src`,
      `${goodCSP}; style-src 'self' https://attacker.invalid`,
      goodCSP.replace("default-src 'self'", "default-src 'none'"),
      goodCSP.replace("default-src 'self'", 'default-src https://attacker.invalid'),
      goodCSP.replace("default-src 'self'; ", ''),
    ]) {
      assert.equal(classifyIssue119Response(target,
        response(target.expected, csp, html)).result, 'fail',
      `${target.surface} must refuse effective stylesheet sources: ${csp}`);
    }
    for (const csp of [
      `${goodCSP}; style-src 'self'`,
      `${goodCSP}; style-src 'none'; style-src-elem 'self'`,
      `${goodCSP}; style-src https://attacker.invalid; style-src-elem 'self'`,
      goodCSP,
    ]) {
      assert.equal(classifyIssue119Response(target,
        response(target.expected, csp, html)).result, 'pass',
      `${target.surface} should accept effective self-only stylesheet: ${csp}`);
    }
  }
});

test('public 200/404 CSS receipt requires an applicable real same-origin Next stylesheet and no live inline styles', () => {
  const script = '<script nonce="SAFE">boot()</script>';
  const badDocuments = [
    htmlDoc(script, '', false),
    htmlDoc(script, '<link rel="stylesheet" href="/_next/static/css/site.css" disabled>', false),
    htmlDoc(script, '<link rel="stylesheet" href="/_next/static/css/site.css" disabled="false">', false),
    htmlDoc(script, '<link rel="stylesheet" href="/_next/static/css/site.css" media="print">', false),
    htmlDoc(script, '<link rel="alternate stylesheet" href="/_next/static/css/site.css">', false),
    htmlDoc(script, '<link rel="stylesheet" href="https://attacker.invalid/site.css">', false),
    htmlDoc(script, '<link rel="stylesheet" href="/missing.css">', false),
    htmlDoc(script, '<base href="https://attacker.invalid/">'),
    htmlDoc(script, '<link rel="stylesheet" href="/_next/static/css/site.css" type="text/plain">', false),
    htmlDoc(script, '<link rel="stylesheet" href="/_next/static/css/site.css" integrity="sha256-invalid">', false),
    htmlDoc('<style>body{color:red}</style>' + script),
    htmlDoc('<div style="color:red">live inline style</div>' + script),
    htmlDoc('<div /style="color:red">live HTML5 slash attribute</div>' + script),
    htmlDoc(script, '<style>body{color:red}</style>'),
  ];
  for (const target of ISSUE119_HEADER_TARGETS.slice(0, 2)) {
    for (const [index, html] of badDocuments.entries()) {
      assert.equal(classifyIssue119Response(target,
        response(target.expected, `${goodCSP}; style-src 'self'`, html)).result,
      'fail', `public ${target.expected} must reject invalid CSS document #${index}`);
    }
    for (const html of [
      htmlDoc(script),
      htmlDoc(script, '<link rel="stylesheet" href="/_next/static/css/next42.css" nonce="SAFE" data-precedence="next">'),
      htmlDoc('<!-- <style>inert</style> --><template><style>inert</style></template>' + script),
      htmlDoc('<div data-note="not a style= attribute">text</div>' + script),
    ]) {
      assert.equal(classifyIssue119Response(target,
        response(target.expected, `${goodCSP}; style-src 'self'`, html)).result,
      'pass', `public ${target.expected} valid stylesheet and inert content must pass`);
    }
  }
});

test('disposable production CSS probe receives only paths accepted by the HTML stylesheet parser', () => {
  const script = '<script nonce="SAFE">boot()</script>';
  assert.deepEqual(extractIssue119PublicStylesheetPaths(htmlDoc(script), 'text/html'),
    ['/_next/static/css/site.css']);
  assert.deepEqual(extractIssue119PublicStylesheetPaths(htmlDoc(script,
    '<link href="/_next/static/css/second.css" rel="stylesheet" nonce="SAFE">'), 'text/html'),
  ['/_next/static/css/site.css', '/_next/static/css/second.css']);
  for (const doc of [
    htmlDoc(script, '', false),
    htmlDoc(script, '<link href="https://attacker.invalid/missing.css" rel="stylesheet">', false),
    htmlDoc(script, '<base href="https://attacker.invalid/">'),
    htmlDoc(script, '<link rel="stylesheet" href="/_next/static/css/missing.css" media="print">', false),
  ]) assert.deepEqual(extractIssue119PublicStylesheetPaths(doc, 'text/html'), []);
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

test('frameset insertion mode cannot fabricate an executable nonce-bearing script', () => {
  const base = ISSUE119_HEADER_TARGETS[0];
  for (const markup of [
    '<frameset><script nonce="SAFE">boot()</script></frameset>',
    '<frameset cols="100%"><frame src="about:blank"><script nonce="SAFE">boot()</script></frameset>',
    '<frameset><noframes>fallback</noframes><script nonce="SAFE">boot()</script></frameset>',
    '<frame src="about:blank"><script nonce="SAFE">boot()</script>',
  ]) {
    assert.equal(classifyIssue119Response(base, response(200, goodCSP,
      htmlDoc(markup))).result, 'fail', markup);
  }
  assert.equal(classifyIssue119Response(base, response(200, goodCSP,
    htmlDoc('<script nonce="SAFE">boot()</script>'))).result, 'pass',
  'normal script receipt remains valid');
});

test('whitespace-only legacy script language is not equivalent to omitted language', () => {
  const base = ISSUE119_HEADER_TARGETS[0];
  for (const language of [' ', '\t', '\n', '\r', '\f', ' \t\n\f ']) {
    const html = htmlDoc(`<script nonce="SAFE" language="${language}">boot()</script>`);
    assert.equal(classifyIssue119Response(base, response(200, goodCSP, html)).result,
      'fail', `nonempty legacy language is not a JavaScript script type: ${JSON.stringify(language)}`);
  }
  assert.equal(classifyIssue119Response(base, response(200, goodCSP,
    htmlDoc('<script nonce="SAFE" language="">boot()</script>'))).result,
  'pass', 'empty language remains equivalent to no legacy language');
});

test('script-data double escaping cannot fabricate a later executable script nonce', () => {
  const base = ISSUE119_HEADER_TARGETS[0];
  for (const prefix of [
    '<script type="application/json"><!--<script></script>',
    '<script nomodule><!--<script></script>',
    '<script type="application/json"><!--<SCRIPT ></script>',
  ]) {
    assert.equal(classifyIssue119Response(base, response(200, goodCSP,
      htmlDoc(`${prefix}<script nonce="SAFE">boot()</script>`))).result,
    'fail', 'an apparent closing tag in a double-escaped script is not its actual end');
  }
  for (const markup of [
    '<script type="application/json"><!-- harmless -->{}</script><script nonce="SAFE">boot()</script>',
    '<script type="application/json">{"text":"<script>"}</script><script nonce="SAFE">boot()</script>',
  ]) {
    assert.equal(classifyIssue119Response(base, response(200, goodCSP,
      htmlDoc(markup))).result, 'pass', 'ordinary inert data precedes a real script');
  }
});

test('actual nonce attributes and quoted decimal HSTS are recognized without lowercasing nonce values', () => {
  const base = ISSUE119_HEADER_TARGETS[0];
  const quoted = response(200, "default-src 'self'; script-src 'nonce-SAFE'", goodHTML,
    { 'strict-transport-security': 'max-age="2592000"' });
  assert.equal(classifyIssue119Response(base, quoted).result, 'pass');
  assert.equal(classifyIssue119Response(base, response(200, goodCSP, goodHTML,
    { 'strict-transport-security': 'max-age \t= \t2592000' })).result, 'pass',
  'HTTP SP and HTAB remain valid optional whitespace');
  assert.equal(classifyIssue119Response(base, response(200, "default-src 'self'; script-src 'nonce-safe'", goodHTML)).result, 'fail');
  assert.equal(classifyIssue119Response(base, response(200, goodCSP,
    htmlDoc('<script data-nonce="SAFE" nonce="SAFE">boot()</script>'))).result, 'pass');
});

test('external script tags never attest executable hydration without a real inline nonce', () => {
  const target = ISSUE119_HEADER_TARGETS[0];
  for (const src of ['', ' ', '\t', '/unavailable.js', 'https://example.invalid/missing.js']) {
    const html = htmlDoc(`<script nonce="SAFE" src="${src}">window.__hit=true</script>`);
    assert.equal(classifyIssue119Response(target, response(200, goodCSP, html)).result,
      'fail', `external script src=${JSON.stringify(src)} must not attest execution`);
  }
  assert.equal(classifyIssue119Response(target, response(200, goodCSP,
    htmlDoc('<script nonce="SAFE" src>window.__hit=true</script>'))).result, 'fail');
  assert.equal(classifyIssue119Response(target, response(200, goodCSP,
    htmlDoc('<script nonce="SAFE">window.__hit=true</script>'))).result, 'pass',
  'genuine nonce-bound inline script remains valid');
  assert.equal(classifyIssue119Response(target, response(200, goodCSP, goodHTML)).result, 'pass',
    'real Next-like external assets and inline bootstrap remain valid together');
  assert.equal(classifyIssue119Response(target, response(200, goodCSP,
    htmlDoc('<script nonce="EVIL" src="/_next/bad.js"></script>' +
      '<script nonce="SAFE">window.__hit=true</script>'))).result, 'fail',
  'an external wrong-nonce script must still be rejected even with inline evidence');
});

test('empty inline nonce tags cannot fabricate a positive executable bootstrap receipt', () => {
  const target = ISSUE119_HEADER_TARGETS[0];
  for (const empty of ['', ' ', String.fromCharCode(9, 10), String.fromCharCode(13, 10, 32, 32),
    String.fromCharCode(0xa0), String.fromCharCode(0xfeff)]) {
    for (const type of ['', ' type="module"']) {
      const html = htmlDoc(`<script nonce="SAFE"${type}>${empty}</script>`);
      assert.equal(classifyIssue119Response(target, response(200, goodCSP, html)).result,
        'fail', `no inline JavaScript bytes execute in ${JSON.stringify(empty)}`);
    }
  }
  assert.equal(classifyIssue119Response(target, response(200, goodCSP,
    htmlDoc('<script nonce="SAFE"></script><script nonce="SAFE">boot()</script>'))).result,
  'pass', 'an empty tag does not disqualify a separate actual inline bootstrap');
});

test('CSP3 nonceable rejects script attributes containing script/style/link start-token sequences', () => {
  const target = ISSUE119_HEADER_TARGETS[0];
  for (const suspicious of [
    'data-note="<script"',
    'data-note="<STYLE"',
    'data-note="<link"',
    'data-note="&lt;script"',
    'data-note="&#x3c;style"',
    'data-note="&#60;link"',
    'x<script="ordinary"',
  ]) {
    const candidate = response(200, goodCSP,
      htmlDoc(`<script ${suspicious} nonce="SAFE">boot()</script>`));
    assert.equal(classifyIssue119Response(target, candidate).result, 'fail',
      `nonce must not authorize script containing ${suspicious}`);
  }
  assert.equal(classifyIssue119Response(target, response(200, goodCSP,
    htmlDoc('<script data-note="ordinary" nonce="SAFE">boot()</script>'))).result,
  'pass', 'ordinary attributes remain valid nonceable script evidence');
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

test('script type distinguishes truly empty, module exactness and MIME whitespace', () => {
  const base = ISSUE119_HEADER_TARGETS[0];
  // These are nonempty HTML type strings. Neither is a JavaScript MIME
  // essence, and the second is not the exact module keyword in HTML5.
  for (const inertType of [' ', '\t', '\n\f ', ' module ', '\tMoDuLe', 'module\n']) {
    const receipt = classifyIssue119Response(base, response(200, goodCSP,
      htmlDoc(`<script nonce="SAFE" type="${inertType}">boot()</script>`)));
    assert.equal(receipt.result, 'fail', `non-executable type must never attest hydration: ${JSON.stringify(inertType)}`);
  }
  for (const executableType of ['', 'module', 'MoDuLe', 'text/javascript', ' text/javascript ', '\tapplication/javascript\n']) {
    const receipt = classifyIssue119Response(base, response(200, goodCSP,
      htmlDoc(`<script nonce="SAFE" type="${executableType}">boot()</script>`)));
    assert.equal(receipt.result, 'pass', `valid classic/module type stays executable: ${JSON.stringify(executableType)}`);
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

test('enforced CSP sandbox needs both script execution and same-origin rights for the public receipt', () => {
  const base = ISSUE119_HEADER_TARGETS[0];
  for (const policy of ['sandbox', 'sandbox allow-same-origin',
    'sandbox allow-popups', 'SANDBOX allow-forms', 'sandbox allow-scripts; sandbox']) {
    assert.equal(classifyIssue119Response(base, response(200, `${goodCSP}; ${policy}`)).result,
      'fail', policy);
  }
  assert.equal(classifyIssue119Response(base, response(200,
    `${goodCSP}; sandbox allow-scripts`)).result, 'fail',
  'sandbox with allow-scripts permits JavaScript but forces an opaque origin, so it cannot attest same-origin hydration');
  assert.equal(classifyIssue119Response(base, response(200,
    `${goodCSP}; sandbox allow-scripts allow-same-origin`)).result, 'pass',
  'both explicit sandbox flags permit same-origin scripts without weakening the nonce policy');
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
