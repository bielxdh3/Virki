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

test('staging both-host challenge is only advisory; public OIDC exceptions need separate review', () => {
  const observations = challenged();
  assert.equal(evaluateStageAccessBoundary(observations).verdict, 'ADVISORY_CHALLENGES_OBSERVED_AUTHORITY_UNVERIFIED');
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
  assert.equal(result.verdict, 'ADVISORY_CHALLENGES_OBSERVED_AUTHORITY_UNVERIFIED');
  assert.doesNotMatch(JSON.stringify(result), /very-sensitive|synthetic-private-value|location/u);
});

test('forged-origin redirects with real-looking CDN headers can never be reported as an authoritative GO', () => {
  const originForged = challenged();
  // A proxy/origin can supply these redirects while Cloudflare adds Server
  // and CF-RAY. They do not prove an Access app/policy or Tunnel JWT guard.
  const result = evaluateStageAccessBoundary(originForged);
  assert.equal(result.verdict, 'ADVISORY_CHALLENGES_OBSERVED_AUTHORITY_UNVERIFIED');
  assert.doesNotMatch(result.verdict, /\bGO\b|\bPASS\b/u);
});

test('four challenged paths do not prove that other Portal and Hub paths are protected', async () => {
  const checked = [];
  const result = await probeStageAccessBoundary(async (url) => {
    checked.push(url);
    const target = Object.values(STAGE_E_TARGETS).find((v) => url === `https://${v.host}${v.path}`);
    // This fixture models a path-scoped Access policy with a public route
    // outside the small set probed by the observer.
    if (!target) return new Response('public origin body', { status: 200 });
    const observed = challenge(target);
    return new Response(null, { status: observed.status, headers: {
      server: observed.server, 'cf-ray': observed.cfRay, location: observed.location,
    } });
  });
  assert.equal(checked.length, 4);
  assert.equal(result.verdict, 'ADVISORY_CHALLENGES_OBSERVED_AUTHORITY_UNVERIFIED');
});
