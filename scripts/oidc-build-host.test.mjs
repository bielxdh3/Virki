import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const dockerfile = readFileSync(new URL('../infra/Dockerfile.prod', import.meta.url), 'utf8');

test('OIDC portal hostname is an explicit immutable Next build argument with production default', () => {
  assert.match(dockerfile, /^ARG VIRKI_PORTAL_HOSTNAME=portal\.biel\.dev\.br\s*$/mu);
  assert.match(dockerfile, /RUN node -e '[^\n]+' "\$VIRKI_PORTAL_HOSTNAME"/u,
    'the untrusted build argument must be validated before build');
  assert.match(dockerfile, /^RUN VIRKI_PORTAL_HOSTNAME="\$VIRKI_PORTAL_HOSTNAME" npm run build\s*$/mu,
    'the same validated hostname must be present during next build');
  assert.match(dockerfile, /^RUN node scripts\/assert-oidc-build-host\.mjs "\$VIRKI_PORTAL_HOSTNAME"\s*$/mu,
    'the actual built Next routes manifest must be verified before accepting the image');
});

test('the actual Dockerfile build-arg validator rejects unsafe or incorrect host values', () => {
  const validator = /RUN node -e '([^'\r\n]+)' "\$VIRKI_PORTAL_HOSTNAME"/u.exec(dockerfile)?.[1];
  assert.ok(validator, 'missing executable Dockerfile hostname validator');
  for (const [hostname, allowed] of [
    ['portal.biel.dev.br', true],
    ['portal-pr88-temp-20261102.biel.dev.br', true],
    ['hub.biel.dev.br', false],
    ['PORTAL.BIEL.DEV.BR', false],
    ['portal..biel.dev.br', false],
    ['portal.biel.dev.br:443', false],
    ['portal.biel.dev.br/path', false],
    ['localhost', false],
    ['a'.repeat(254), false],
  ]) {
    const actual = spawnSync(process.execPath, ['-e', validator, hostname], {
      encoding: 'utf8', timeout: 5000, shell: false,
    });
    assert.equal(actual.status === 0, allowed, `unexpected build hostname validator result for ${hostname}`);
  }
});

test('OIDC Next rewrites are scoped to the exact configured portal host', async () => {
  const { default: config } = await import('../apps/hub/next.config.mjs');
  const priorPortal = process.env.VIRKI_PORTAL_HOSTNAME;
  const priorProxy = process.env.VIRKI_OIDC_PROXY_URL;
  try {
    delete process.env.VIRKI_OIDC_PROXY_URL;
    for (const host of ['portal.biel.dev.br', 'portal-pr88-temp-20261102.biel.dev.br']) {
      process.env.VIRKI_PORTAL_HOSTNAME = host;
      const routes = await config.rewrites();
      assert.ok(routes.length >= 8);
      for (const route of routes) {
        assert.deepEqual(route.has, [{ type: 'host', value: host.replaceAll('.', String.raw`\.`) }]);
        assert.match(route.destination, /^http:\/\/oidc-issuer:3003\//u);
        const routeHostMatcher = new RegExp(`^${route.has[0].value}$`, 'u');
        assert.equal(routeHostMatcher.test(host), true, 'the exact Portal host must match');
        assert.equal(routeHostMatcher.test(host.replace('.biel.', 'xbiel.')), false,
          'a different host must not match the OIDC rewrite');
      }
      assert.ok(routes.some((route) => route.source === '/.well-known/:path*'));
      assert.ok(routes.some((route) => route.source === '/jwks'));
      assert.ok(routes.some((route) => route.source === '/auth'));
    }
  } finally {
    if (priorPortal === undefined) delete process.env.VIRKI_PORTAL_HOSTNAME;
    else process.env.VIRKI_PORTAL_HOSTNAME = priorPortal;
    if (priorProxy === undefined) delete process.env.VIRKI_OIDC_PROXY_URL;
    else process.env.VIRKI_OIDC_PROXY_URL = priorProxy;
  }
});
