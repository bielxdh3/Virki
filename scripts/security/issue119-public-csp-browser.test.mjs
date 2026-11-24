import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { createServer } from 'node:http';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { chromium } from '@playwright/test';
import { buildChromiumEnvironment, buildServiceEnvironment } from '../e2e/isolated-service.mjs';

const root = resolve(import.meta.dirname, '../..');
const portal = 'https://portal.example.invalid';

async function reservePort() {
  const server = createServer();
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const { port } = server.address();
  await new Promise((done, reject) => server.close((error) => error ? reject(error) : done()));
  return port;
}

async function assertDocument(page, response, status, origin, stylesheets) {
  assert.equal(response?.status(), status);
  const headers = await response.allHeaders();
  assert.match(headers['content-type'] ?? '', /^text\/html(?:;|$)/iu);
  assert.equal(headers['x-powered-by'], undefined);
  assert.equal(headers['strict-transport-security'], 'max-age=31536000');
  assert.equal(headers['x-content-type-options'], 'nosniff');
  assert.equal(headers['x-frame-options'], 'DENY');
  assert.equal(headers['referrer-policy'], 'no-referrer');
  assert.equal(headers['permissions-policy'], 'camera=(), geolocation=(), microphone=()');
  const csp = headers['content-security-policy'] ?? '';
  assert.doesNotMatch(csp, /unsafe-inline|unsafe-eval/iu);
  const nonce = /'nonce-([^']+)'/u.exec(csp)?.[1];
  assert.ok(nonce, 'missing response CSP nonce');
  assert.ok(csp.split(';').map((value) => value.trim()).includes("style-src 'self'"));
  const document = await page.evaluate((serverHtml) => ({
    scripts: [...window.document.scripts]
      .filter((script) => !script.type || script.type === 'module' || /javascript|ecmascript/iu.test(script.type))
      .map((script) => ({ nonce: script.nonce, inline: !script.src && !!script.textContent?.trim() })),
    serverInlineStyles: new DOMParser().parseFromString(serverHtml, 'text/html')
      .querySelectorAll('style, [style]').length,
    inlineStyles: [...window.document.querySelectorAll('style, [style]')].map((element) => ({
      tag: element.localName,
      inMain: !!element.closest('main'),
      style: element.getAttribute('style'),
      announcer: element.shadowRoot?.querySelector('#__next-route-announcer__')?.getAttribute('role') ?? null
    })),
    links: [...window.document.querySelectorAll('link[rel="stylesheet"]')]
      .map((link) => ({ href: link.href, loaded: !!link.sheet })),
    display: getComputedStyle(window.document.querySelector('main.public-page')).display,
    next: !!window.next,
    violations: window.__issue119PublicViolations
  }), await response.text());
  assert.ok(document.scripts.some((script) => script.inline), 'missing Next bootstrap');
  assert.ok(document.scripts.every((script) => script.nonce === nonce), 'script nonce mismatch');
  assert.equal(document.next, true, 'Next runtime did not execute');
  assert.deepEqual(document.violations, [], 'browser reported CSP violations');
  assert.equal(document.serverInlineStyles, 0, 'public HTTP document contains inline styles');
  // Next creates its accessibility announcer using CSSOM after hydration, not
  // an inline style from the HTTP document. Allow only this exact runtime node.
  assert.deepEqual(document.inlineStyles, [{
    tag: 'next-route-announcer', inMain: false, style: 'position: absolute;', announcer: 'alert'
  }], 'unexpected inline styling in the hydrated public document');
  assert.ok(document.links.length > 0, 'missing public stylesheet');
  for (const link of document.links) {
    assert.equal(new URL(link.href).origin, origin);
    assert.ok(link.loaded, 'public stylesheet failed to load');
    assert.ok(stylesheets.some((item) => item.url === link.href && item.status === 200 &&
      /^text\/css(?:\s*;|$)/iu.test(item.contentType)), 'missing real 200 text/css response');
  }
  assert.equal(document.display, 'grid', 'public layout stylesheet did not apply');
  return nonce;
}

test('public production 200/404 execute Next bootstrap, load CSS and preserve navigation under CSP', { timeout: 90000 }, async () => {
  const port = await reservePort();
  const origin = `http://127.0.0.1:${port}`;
  const env = buildServiceEnvironment('public-site', process.env);
  env.NODE_ENV = 'production';
  env.VIRKI_PORTAL_URL = portal;
  const child = spawn(process.execPath, [join(root, 'node_modules/next/dist/bin/next'),
    'start', '-p', String(port), '-H', '127.0.0.1'], {
    cwd: join(root, 'apps/public-site'), env, stdio: 'ignore', windowsHide: true
  });
  let startError;
  child.once('error', (error) => { startError = error; });
  const stopped = once(child, 'close').catch(() => {});
  let browser;
  try {
    let ready = false;
    for (let attempt = 0; attempt < 200 && !startError && child.exitCode === null; attempt++) {
      try {
        const response = await fetch(origin, { redirect: 'manual', signal: AbortSignal.timeout(1000) });
        await response.body?.cancel();
        if (response.status === 200) { ready = true; break; }
      } catch { /* Next is still starting. */ }
      await delay(100);
    }
    assert.ok(ready, 'disposable public Next server did not start');
    browser = await chromium.launch({
      headless: true, env: buildChromiumEnvironment(),
      ...(process.env.VIRKI_ISSUE119_BROWSER_CHANNEL
        ? { channel: process.env.VIRKI_ISSUE119_BROWSER_CHANNEL } : {})
    });
    const nonces = [];
    for (const [path, status, heading, linkName, href] of [
      ['/', 200, 'Virki', 'Entrar', portal],
      ['/missing-issue119-public', 404, '404', 'Voltar ao início', '/']
    ]) {
      const page = await browser.newPage({ serviceWorkers: 'block' });
      const errors = [];
      const external = [];
      const stylesheets = [];
      try {
        // No request in this fixture may leave the disposable loopback origin.
        await page.route('**/*', (route) => {
          if (new URL(route.request().url()).origin === origin) return route.continue();
          external.push(route.request().resourceType());
          return route.abort();
        });
        page.on('pageerror', (error) => errors.push(error.message));
        page.on('response', (response) => {
          if (response.request().resourceType() === 'stylesheet') {
            stylesheets.push({ url: response.url(), status: response.status(),
              contentType: response.headers()['content-type'] ?? '' });
          }
        });
        await page.addInitScript(() => {
          window.__issue119PublicViolations = [];
          document.addEventListener('securitypolicyviolation', (event) =>
            window.__issue119PublicViolations.push(event.effectiveDirective));
        });
        const response = await page.goto(origin + path, { waitUntil: 'networkidle' });
        nonces.push(await assertDocument(page, response, status, origin, stylesheets));
        assert.equal(await page.getByRole('heading', { level: 1 }).innerText(), heading);
        const link = page.getByRole('link', { name: linkName, exact: true });
        assert.equal(await link.getAttribute('href'), href);
        assert.ok(await link.isVisible(), 'expected navigation link is not visible');
        if (status === 404) {
          const [homeResponse] = await Promise.all([
            page.waitForNavigation({ waitUntil: 'networkidle' }), link.click()
          ]);
          nonces.push(await assertDocument(page, homeResponse, 200, origin, stylesheets));
          assert.equal(page.url(), origin + '/');
          assert.equal(await page.getByRole('heading', { level: 1 }).innerText(), 'Virki');
        }
        assert.deepEqual(errors, [], 'public page reported JavaScript errors');
        assert.deepEqual(external, [], 'public page attempted an external request');
      } finally {
        await page.close();
      }
    }
    assert.equal(new Set(nonces).size, nonces.length, 'public document nonce reused across responses');
  } finally {
    await browser?.close();
    child.kill();
    await stopped;
  }
});
