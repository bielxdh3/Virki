import assert from 'node:assert/strict';
import test from 'node:test';
import { assertOidcBuildHost, OIDC_REWRITE_SOURCES, OIDC_REWRITE_REGEX } from './assert-oidc-build-host.mjs';

const productionHost = 'portal.biel.dev.br';
const stagingHost = 'portal-pr88-temp-20261102.biel.dev.br';
const routesFor = (host) => OIDC_REWRITE_SOURCES.map((source) => ({
  source, has: [{ type: 'host', value: host.replaceAll('.', String.raw`\.`) }],
  regex: OIDC_REWRITE_REGEX[source],
  destination: `http://oidc-issuer:3003${source}`,
}));
const manifest = (host) => ({
  rewrites: { beforeFiles: [], afterFiles: routesFor(host), fallback: [] },
});

test('built manifest is accepted only for matching production or stage portal host', () => {
  assert.equal(assertOidcBuildHost(manifest(productionHost), productionHost), true);
  assert.equal(assertOidcBuildHost(manifest(stagingHost), stagingHost), true);
  assert.throws(() => assertOidcBuildHost(manifest(productionHost), stagingHost), /host.*mismatch/u);
  assert.throws(() => assertOidcBuildHost(manifest(stagingHost), productionHost), /host.*mismatch/u);
});

test('fail closed on missing, repeated, wildcard or cross-host OIDC route', () => {
  const good = routesFor(stagingHost);
  const tryRoutes = (routes) => assertOidcBuildHost({ rewrites: routes }, stagingHost);
  assert.throws(() => tryRoutes(good.map((route, index) => index === 0
    ? { ...route, regex: '^/.*$' } : route)), /mismatch/u);
  assert.throws(() => tryRoutes(good.map((route, index) => index === 0
    ? { ...route, regex: '^/not-oidc$' } : route)), /mismatch/u);
  assert.throws(() => tryRoutes(good.slice(1)), /unexpected rewrite count/u);
  assert.throws(() => tryRoutes([...good, good[0]]), /unexpected rewrite count/u);
  assert.throws(() => tryRoutes([...good, { source: '/:path*',
    has: [{ type: 'host', value: '.*' }],
    destination: 'http://evil.invalid/:path*' }]), /unexpected rewrite count/u);
  assert.throws(() => assertOidcBuildHost({
    rewrites: { beforeFiles: [{ source: '/:path*',
      has: [{ type: 'host', value: '.*' }],
      destination: 'http://evil.invalid/:path*' }],
      afterFiles: good, fallback: [] },
  }, stagingHost), /unexpected rewrite count/u);
  assert.throws(() => assertOidcBuildHost({
    rewrites: { beforeFiles: [], afterFiles: good,
      fallback: [{ source: '/:path*', destination: 'http://evil.invalid/:path*' }] },
  }, stagingHost), /unexpected rewrite count/u);
  assert.throws(() => tryRoutes(good.map((r, i) => i === 0 ? { ...r, has: [] } : r)), /mismatch/u);
  assert.throws(() => tryRoutes(good.map((r, i) => i === 0 ? { ...r, has: [{ type: 'host', value: 'hub.biel.dev.br' }] } : r)), /mismatch/u);
  assert.throws(() => tryRoutes(good.map((r, i) => i === 0 ? { ...r, has: [{ type: 'host', value: stagingHost }] } : r)), /mismatch/u);
  assert.throws(() => tryRoutes(good.map((r, i) => i === 0 ? {
    ...r, missing: [{ type: 'header', key: 'x-optional-oidc-header', value: '.*' }],
  } : r)), /mismatch/u);
  assert.throws(() => tryRoutes(good.map((r, i) => i === 0 ? { ...r, locale: false } : r)), /mismatch/u);
  assert.throws(() => tryRoutes(good.map((r, i) => i === 0 ? {
    ...r, has: [{ type: 'host', value: stagingHost.replaceAll('.', String.raw`\.`), key: 'unexpected' }],
  } : r)), /mismatch/u);
  assert.throws(() => tryRoutes(good.map((r, i) => i === 0 ? { ...r, destination: 'http://evil.test/.well-known/:path*' } : r)), /mismatch/u);
  assert.throws(() => assertOidcBuildHost({}, stagingHost), /unavailable/u);
});

test('reject invalid host arguments rather than broadening the OIDC proxy', () => {
  for (const host of ['', 'localhost', 'hub.biel.dev.br', 'foo..example.com',
    'Portal.Example.com', '*.example.com', 'foo.example.com:3001',
    'foo.example.com/path', 'a'.repeat(254)]) {
    assert.throws(() => assertOidcBuildHost(manifest(stagingHost), host), /invalid portal hostname/u);
  }
});
