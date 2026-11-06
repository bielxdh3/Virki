import assert from 'node:assert/strict';
import test from 'node:test';
import { evaluateStageAccessBoundary, isStageAccessChallenge, probeStageAccessBoundary, STAGE_E_TARGETS } from './stage-e-access-boundary-check.mjs';

const challenge = (target, extra = {}) => ({
  status: 302,
  server: 'cloudflare',
  cfRay: '0123456789abcdef-GRU',
  location: `https://bielxdh.cloudflareaccess.com/cdn-cgi/access/login/${target.host}?redirect_url=${encodeURIComponent(target.path)}&meta=synthetic-private-value`,
  ...extra,
});
const challenged = () => Object.fromEntries(Object.entries(STAGE_E_TARGETS).map(([name, target]) => [name, challenge(target)]));

test('stage policy rejects Portal login exposure even when Hub Access challenges', () => {
  const observations = challenged();
  observations.portal = { status: 200, server: 'cloudflare', cfRay: '0123456789abcdef-GRU' };
  observations.discovery = { status: 200, server: 'cloudflare' };
  observations.jwks = { status: 200, server: 'cloudflare' };
  const result = evaluateStageAccessBoundary(observations);
  assert.equal(result.verdict, 'NO_GO_PORTAL_ACCESS_NOT_PROVEN');
  assert.deepEqual(result.statuses, { hub: 302, portal: 200, discovery: 200, jwks: 200 });
  assert.doesNotMatch(JSON.stringify(result), /synthetic-private-value/u);
});

test('staging both-host Access challenge is necessary, but public OIDC exceptions need separate review', () => {
  const observations = challenged();
  assert.equal(evaluateStageAccessBoundary(observations).verdict, 'OUTER_ACCESS_CHALLENGES_PASS');
  observations.discovery = { status: 200, server: 'cloudflare' };
  assert.equal(evaluateStageAccessBoundary(observations).verdict, 'REVIEW_PUBLIC_OIDC_ACCESS_EXCEPTIONS');
  observations.hub = { status: 403, server: 'cloudflare' };
  assert.equal(evaluateStageAccessBoundary(observations).verdict, 'NO_GO_HUB_ACCESS_NOT_PROVEN');
});

test('refuses fake, cross-host, insecure and weakened Access redirects', () => {
  const target = STAGE_E_TARGETS.portal;
  for (const extra of [
    { status: 200 },
    { status: 302, location: 'https://attacker.invalid/cdn-cgi/access/login/portal-pr88-temp-20261102.biel.dev.br' },
    { location: `http://bielxdh.cloudflareaccess.com/cdn-cgi/access/login/${target.host}?redirect_url=%2Flogin` },
    { location: `https://bielxdh.cloudflareaccess.com/cdn-cgi/access/login/${STAGE_E_TARGETS.hub.host}?redirect_url=%2Flogin` },
    { location: `https://bielxdh.cloudflareaccess.com/cdn-cgi/access/login/${target.host}?redirect_url=%2Fadmin` },
    { cfRay: null },
    { server: 'nginx' },
    { location: '%%%not-a-url' },
  ]) assert.equal(isStageAccessChallenge(challenge(target, extra), target), false);
});

test('probe uses only fresh, credential-free, nonfollowing GETs and strips Access metadata from its report', async () => {
  const visited = [];
  const observations = challenged();
  const result = await probeStageAccessBoundary(async (url, options) => {
    const match = Object.entries(STAGE_E_TARGETS).find(([, target]) => url === `https://${target.host}${target.path}`);
    assert.ok(match, `Unexpected outbound target ${url}`);
    visited.push(match[0]);
    assert.equal(options.method, 'GET');
    assert.equal(options.redirect, 'manual');
    assert.equal(options.cache, 'no-store');
    assert.equal(options.headers.authorization, undefined);
    assert.equal(options.headers.cookie, undefined);
    const entry = observations[match[0]];
    return new Response(null, { status: entry.status, headers: {
      'server': entry.server, 'cf-ray': entry.cfRay, 'location': entry.location,
      'set-cookie': 'CF_AppSession=very-sensitive',
    } });
  });
  assert.deepEqual(visited, Object.keys(STAGE_E_TARGETS));
  assert.equal(result.verdict, 'OUTER_ACCESS_CHALLENGES_PASS');
  assert.doesNotMatch(JSON.stringify(result), /very-sensitive|synthetic-private-value|location/u);
});
