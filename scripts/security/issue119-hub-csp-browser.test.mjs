import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer, request as httpRequest } from 'node:http';
import { once } from 'node:events';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { chromium } from '@playwright/test';

const root = resolve(import.meta.dirname, '../..');
const app = join(root, 'apps/hub');
const sessionCookie = '__Host-virki_session=issue119-synthetic';
const host = 'hub.biel.dev.br';

async function listen(server) {
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  return server.address().port;
}

async function reservePort() {
  const server = createServer();
  const port = await listen(server);
  await new Promise((resolveClose) => server.close(resolveClose));
  return port;
}

function request(port, path, extraHeaders = {}, options = {}) {
  return new Promise((resolveRequest, rejectRequest) => {
    const req = httpRequest({ hostname: '127.0.0.1', port, path, method: options.method ?? 'GET',
      headers: { host, accept: 'text/html', ...extraHeaders } }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('error', rejectRequest);
      res.on('end', () => resolveRequest({ status: res.statusCode,
        headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('error', rejectRequest);
    req.end(options.body);
  });
}

function assertHeaders(response, status) {
  assert.equal(response.status, status);
  assert.match(response.headers['content-type'] ?? '', /^text\/html; charset=utf-8/u);
  assert.equal(response.headers['x-powered-by'], undefined);
  assert.equal(response.headers['strict-transport-security'], 'max-age=31536000');
  const csp = response.headers['content-security-policy'] ?? '';
  assert.doesNotMatch(csp, /unsafe-inline|unsafe-eval/iu);
  const nonce = /'nonce-([^']+)'/u.exec(csp)?.[1];
  assert.ok(nonce, `missing CSP nonce on HTTP ${status}`);
  return nonce;
}

function inspectCriticalStyles(page) {
  return page.evaluate(() => {
    const authPage = document.querySelector('main.auth-page');
    return {
      links: [...document.querySelectorAll('link[rel="stylesheet"]')].map((link) => ({
        href: link.href,
        // Accessing cssRules is not permitted for crossorigin stylesheets,
        // even when they loaded and apply successfully.
        loaded: !!link.sheet
      })),
      authPageDisplay: authPage ? getComputedStyle(authPage).display : null
    };
  });
}

function assertCriticalStyles(path, styles, responses) {
  assert.ok(styles.links.length > 0, `${path}: missing critical stylesheet links`);
  for (const link of styles.links) {
    assert.ok(link.loaded,
      `${path}: critical stylesheet failed to load (${link.href})`);
    assert.ok(responses.some((response) =>
      response.url === link.href && response.status === 200 && /^text\/css(?:\s*;|$)/iu.test(response.contentType)),
      `${path}: critical stylesheet lacked a successful HTTP 200 text/css response (${link.href})`);
  }
  assert.equal(styles.authPageDisplay, 'grid', `${path}: .auth-page layout CSS was not applied`);
}

async function collectCspViolations(page) {
  const byFrame = await Promise.all(page.frames().map(async (frame) => {
    const violations = await frame.evaluate(() => window.__issue119Violations ?? null);
    assert.ok(Array.isArray(violations),
      `CSP violation collector unavailable in frame ${frame.url()}`);
    return violations;
  }));
  return byFrame.flat();
}

test('Hub production 200/404 use nonce-bearing Next scripts and CSP-compatible 404 styles in a real HTML5 browser', { timeout: 90000 }, async () => {
  const port = await reservePort();
  const node = spawn(process.execPath, [join(root, 'node_modules/next/dist/bin/next'), 'start',
    '-p', String(port), '-H', '127.0.0.1'], {
    cwd: app, windowsHide: true, stdio: 'ignore',
    env: { ...process.env, NODE_ENV: 'production',
      VIRKI_CSRF_SIGNING_KEY: '11'.repeat(32), VIRKI_HUB_PERIMETER_MODE: 'native',
      VIRKI_HUB_HOSTNAME: host, VIRKI_PORTAL_HOSTNAME: 'portal.biel.dev.br' }
  });
  let browser;
  let proxy;
  try {
    let ready = false;
    for (let attempt = 0; attempt < 200; attempt++) {
      if (node.exitCode !== null) break;
      try {
        const health = await request(port, '/api/health');
        if (health.status === 200) { ready = true; break; }
      } catch { /* Next is still starting. */ }
      await delay(100);
    }
    assert.ok(ready, 'disposable Hub did not start');

    // Native Next renders the 404 only after the proxy's session-present gate.
    // No database, valid session or production service is used by this fixture.
    const login = await request(port, '/login');
    const notFound = await request(port, '/missing-issue119', { cookie: sessionCookie });
    const loginNonce = assertHeaders(login, 200);
    const notFoundNonce = assertHeaders(notFound, 404);
    assert.notEqual(loginNonce, notFoundNonce, 'CSP nonce was reused between responses');
    assert.doesNotMatch(notFound.body, /\sstyle=/iu, '404 server HTML embeds forbidden inline style attributes');

    // A crafted Server Action POST with a hostile or missing Origin must be
    // rejected at ingress, before Next responds with an application error.
    // Neither page processes POST: their forms target /api/login/* routes.
    for (const path of ['/login', '/login/verify']) {
      for (const origin of [undefined, 'https://attacker.invalid']) {
        const headers = { 'next-action': 'invalid-issue119-action',
          'content-type': 'text/plain;charset=UTF-8' };
        if (origin) headers.origin = origin;
        const blocked = await request(port, path, headers, { method: 'POST', body: '[]' });
        assert.equal(blocked.status, 403,
          `${path}: Server Action POST must reject ${origin ?? 'missing Origin'} before Next dispatch`);
        assert.equal(blocked.headers['x-powered-by'], undefined);
        assert.match(blocked.headers['cache-control'] ?? '', /no-store/u);
      }
    }

    // A loopback-only HTTP forwarder preserves the canonical Host upstream, and
    // lets Chromium test production CSP without relying on real DNS or TLS.
    proxy = createServer((downstream, response) => {
      const headers = { ...downstream.headers, host };
      if (downstream.url === '/missing-issue119') headers.cookie = sessionCookie;
      else delete headers.cookie;
      const upstream = httpRequest({ hostname: '127.0.0.1', port,
        method: downstream.method, path: downstream.url, headers }, (upstreamResponse) => {
        response.writeHead(upstreamResponse.statusCode, upstreamResponse.headers);
        upstreamResponse.pipe(response);
      });
      upstream.on('error', () => response.destroy());
      downstream.pipe(upstream);
    });
    const proxyPort = await listen(proxy);
    browser = await chromium.launch({ headless: true,
      ...(process.env.VIRKI_ISSUE119_BROWSER_CHANNEL
        ? { channel: process.env.VIRKI_ISSUE119_BROWSER_CHANNEL } : {}) });
    const pageErrors = [];
    let abortedStylesheets = 0;
    const snapshots = [];
    for (const [path, expectedStatus] of [['/login', 200], ['/missing-issue119', 404]]) {
      // Fresh browser contexts avoid treating CSS cached by the 200 page as
      // evidence that the 404 fetched and applied its own stylesheet.
      const page = await browser.newPage();
      const stylesheetResponses = [];
      page.on('pageerror', (error) => pageErrors.push(error.message));
      page.on('response', (response) => {
        if (response.request().resourceType() === 'stylesheet') {
          stylesheetResponses.push({
            url: response.url(), status: response.status(),
            contentType: response.headers()['content-type'] ?? ''
          });
        }
      });
      // Fault injection deliberately exercises the SAME production assertions
      // below. Setting the flag must fail the gate, not skip any checks.
      if (process.env.VIRKI_ISSUE119_TEST_ABORT_CSS === 'true') {
        await page.route(/\.css(?:\?|$)/u, (route) => {
          abortedStylesheets++;
          return route.abort();
        });
      }
      await page.addInitScript(() => {
        window.__issue119Violations = [];
        document.addEventListener('securitypolicyviolation', (event) =>
          window.__issue119Violations.push(event.effectiveDirective));
      });
      const documentResponse = await page.goto(`http://127.0.0.1:${proxyPort}${path}`,
        { waitUntil: 'networkidle' });
      assert.equal(documentResponse?.status(), expectedStatus, `${path} browser status`);
      const headers = await documentResponse.allHeaders();
      const nonce = /'nonce-([^']+)'/u.exec(headers['content-security-policy'] ?? '')?.[1];
      assert.ok(nonce, `${path} browser CSP nonce missing`);
      const inspected = await page.evaluate(() => ({
        scripts: [...document.scripts].filter((script) =>
          !script.type || script.type === 'module' || /javascript|ecmascript/iu.test(script.type))
          .map((script) => ({ nonce: script.nonce, inline: !script.src && !!script.textContent?.trim() })),
        styleTagNonces: [...document.querySelectorAll('style')].map((style) => style.nonce),
        heading: document.querySelector('h1')?.textContent ?? '',
        hasNext: !!window.next
      }));
      inspected.violations = await collectCspViolations(page);
      assert.ok(inspected.scripts.some((script) => script.inline), `${path}: missing hydration bootstrap`);
      snapshots.push({ path, inspected, nonce, styles: await inspectCriticalStyles(page), stylesheetResponses });
      await page.close();
    }

    if (process.env.VIRKI_ISSUE119_TEST_ABORT_CSS === 'true') {
      assert.ok(abortedStylesheets > 0, 'negative control must abort a real CSS request');
    }
    for (const { path, inspected, nonce, styles, stylesheetResponses } of snapshots) {
      assert.ok(inspected.scripts.every((script) => script.nonce === nonce),
        `${path}: real HTML5 parser found executable scripts missing the response CSP nonce`);
      assert.equal(inspected.violations.length, 0,
        `${path}: browser enforced CSP rejected resource or inline code`);
      assert.equal(inspected.hasNext, true, `${path}: Next runtime did not execute`);
      assertCriticalStyles(path, styles, stylesheetResponses);
    }
    assert.ok(snapshots[1].inspected.styleTagNonces.every((nonce) => nonce === snapshots[1].nonce),
      '404 rendered an inline stylesheet without the request CSP nonce');
    assert.match(snapshots[1].inspected.heading, /404/u);
    assert.deepEqual(pageErrors, []);

    if (process.env.VIRKI_ISSUE119_TEST_ABORT_CSS !== 'true') {
      // Every CI run exercises a negative control as well as the ordinary
      // positive gate. A browser that loses its CSS must not satisfy it.
      const negativePage = await browser.newPage();
      let blockedCssCount = 0;
      await negativePage.route(/\.css(?:\?|$)/u, (route) => {
        blockedCssCount++;
        return route.abort();
      });
      const negativeResponse = await negativePage.goto(
        `http://127.0.0.1:${proxyPort}/missing-issue119`, { waitUntil: 'networkidle' });
      assert.equal(negativeResponse?.status(), 404);
      assert.ok(blockedCssCount > 0, 'negative control did not intercept an actual CSS request');
      const negativeStyles = await inspectCriticalStyles(negativePage);
      assert.throws(
        () => assertCriticalStyles('/missing-issue119 (CSS intentionally blocked)', negativeStyles, []),
        /critical stylesheet (?:failed to load|lacked a successful HTTP 200 text\/css response)/u,
        'negative control: absent CSS must fail the production stylesheet gate'
      );
      await negativePage.close();
    }
  } finally {
    await browser?.close();
    if (proxy) await new Promise((resolveClose) => proxy.close(resolveClose));
    node.kill();
  }
});

test('browser evidence detects CSP violations inside iframe srcdoc even when the parent has none', async () => {
  const browser = await chromium.launch({ headless: true,
    ...(process.env.VIRKI_ISSUE119_BROWSER_CHANNEL
      ? { channel: process.env.VIRKI_ISSUE119_BROWSER_CHANNEL } : {}) });
  try {
    const page = await browser.newPage();
    await page.addInitScript(() => {
      window.__issue119Violations = [];
      document.addEventListener('securitypolicyviolation', (event) =>
        window.__issue119Violations.push(event.effectiveDirective));
    });
    const csp = "default-src 'self'; script-src 'nonce-SAFE'; style-src 'self'";
    await page.route('https://issue119.invalid/', (route) => route.fulfill({
      status: 200, headers: { 'content-type': 'text/html; charset=utf-8',
        'content-security-policy': csp },
      body: '<!doctype html><html><head></head><body>' +
        '<script nonce="SAFE">window.__safe = true</script>' +
        '<iframe srcdoc="&lt;script nonce=EVIL&gt;parent.__evil = true&lt;/script&gt;"></iframe>' +
        '</body></html>'
    }));
    await page.goto('https://issue119.invalid/', { waitUntil: 'networkidle' });
    assert.equal(page.frames().length, 2, 'the controlled srcdoc frame must exist');
    assert.deepEqual(await page.evaluate(() => window.__issue119Violations), [],
      'a parent-only listener cannot see the child-frame CSP failure');
    assert.ok((await collectCspViolations(page)).includes('script-src-elem'),
      'the acceptance gate must see script violations from every frame');
    await page.close();
  } finally {
    await browser.close();
  }
});
