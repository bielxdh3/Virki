// Opt-in Chromium probe of the RP's actual CSP. This isolates browser form
// navigation rules; OIDC cryptography remains covered by the composed PG lab.
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { createServer } from 'node:http';
import { test } from 'node:test';
import { createRpHandler } from './server.mjs';

const enabled = process.env.VIRKI_RP_CSP_BROWSER_TEST === 'true';
const configuredIssuer = 'https://portal.example.test';

async function listen(server) {
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  return `http://127.0.0.1:${server.address().port}`;
}

async function cspFromRp() {
  const handler = createRpHandler({
    oidc: {}, db: { query: async () => ({ rows: [] }), connect: async () => {} },
    origin: 'https://rp.example.test', issuer: configuredIssuer,
    sessionKey: randomBytes(32)
  });
  const headers = {};
  await handler({
    method: 'GET', url: '/', headers: { host: 'rp.example.test' },
    socket: { encrypted: true, remoteAddress: '127.0.0.1' }
  }, {
    setHeader(name, value) { headers[name.toLowerCase()] = value; },
    writeHead() {}, end() {}
  });
  assert.equal(typeof headers['content-security-policy'], 'string');
  return headers['content-security-policy'];
}

test('real Chromium follows the RP login form redirect only to the pinned issuer', {
  skip: enabled ? false : 'Enable only with VIRKI_RP_CSP_BROWSER_TEST=true and installed Playwright/Chromium',
  timeout: 20_000
}, async () => {
  const { chromium } = await import('playwright');
  const policy = await cspFromRp();
  let expectedRequests = 0;
  let unauthorizedRequests = 0;
  const issuer = createServer((_request, response) => {
    expectedRequests += 1;
    response.writeHead(200, { 'content-type': 'text/plain' });
    response.end('Issuer navigation received.');
  });
  const unauthorized = createServer((_request, response) => {
    unauthorizedRequests += 1;
    response.writeHead(200).end();
  });
  let rp;
  let browser;
  try {
    const issuerOrigin = await listen(issuer);
    const unauthorizedOrigin = await listen(unauthorized);
    // Chromium's CSP form-action check is scheme-independent. Translate only
    // the pinned HTTPS issuer origin to an owned, inert loopback HTTP endpoint
    // to avoid needing the PostgreSQL lab, credentials, or TLS trust changes.
    const browserPolicy = policy.replace(configuredIssuer, issuerOrigin);
    rp = createServer((request, response) => {
      if (request.method === 'GET' && request.url === '/') {
        response.writeHead(200, {
          'content-type': 'text/html; charset=utf-8',
          'content-security-policy': browserPolicy
        });
        response.end('<form method="post" action="/login"><button>Sign in through Virki</button></form>');
      } else if (request.method === 'POST' && request.url === '/login') {
        response.writeHead(303, { location: issuerOrigin + '/auth' });
        response.end();
      } else {
        response.writeHead(404).end();
      }
    });
    const rpOrigin = await listen(rp);
    browser = await chromium.launch({
      headless: true,
      ...(process.env.VIRKI_RP_CSP_CHROMIUM_PATH ? { executablePath: process.env.VIRKI_RP_CSP_CHROMIUM_PATH } : {})
    });
    const page = await browser.newPage();
    await page.goto(rpOrigin);
    await page.getByRole('button', { name: 'Sign in through Virki' }).click();
    await page.waitForURL(issuerOrigin + '/auth', { timeout: 4_000 });
    assert.equal(expectedRequests, 1, 'The pinned issuer must receive the browser navigation');

    await page.goto(rpOrigin);
    const deniedByCsp = page.waitForEvent('console', {
      predicate: message => message.type() === 'error' && message.text().includes('form-action'),
      timeout: 4_000
    });
    await page.locator('form').evaluate((form, target) => {
      form.action = target;
      form.submit();
    }, unauthorizedOrigin + '/auth');
    // An unauthorized destination must be rejected by Chromium before network I/O.
    await deniedByCsp;
    assert.equal(unauthorizedRequests, 0);
    assert.equal(new URL(page.url()).origin, rpOrigin);
  } finally {
    await browser?.close();
    await Promise.all([rp, issuer, unauthorized].filter(Boolean).map(server => new Promise(resolve => server.close(resolve))));
  }
});
