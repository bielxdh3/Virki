import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

export const OIDC_REWRITE_SOURCES = Object.freeze([
  '/.well-known/:path*', '/auth', '/auth/:uid',
  '/token', '/token/revocation', '/jwks', '/me',
  '/session/end', '/session/end/:path*',
  '/interaction/:path*', '/resume/:path*',
]);

// Exact custom-route regex values emitted by the pinned Next.js 16.4.2 build.
// An unexpected change needs re-review: source alone does not prove routing.
const slash = String.raw`(?:/)?$`;
const repeat = String.raw`(?:/((?:[^/]+?)(?:/(?:[^/]+?))*))?`;
const one = String.raw`(?:/([^/]+?))`;
export const OIDC_REWRITE_REGEX = Object.freeze({
  '/.well-known/:path*': String.raw`^/\.well-known` + repeat + slash,
  '/auth': '^/auth' + slash,
  '/auth/:uid': '^/auth' + one + slash,
  '/token': '^/token' + slash,
  '/token/revocation': '^/token/revocation' + slash,
  '/jwks': '^/jwks' + slash,
  '/me': '^/me' + slash,
  '/session/end': '^/session/end' + slash,
  '/session/end/:path*': '^/session/end' + repeat + slash,
  '/interaction/:path*': '^/interaction' + repeat + slash,
  '/resume/:path*': '^/resume' + repeat + slash,
});

export function assertOidcBuildHost(manifest, hostname) {
  const validHost = typeof hostname === 'string' && hostname.length <= 253
    && /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/u.test(hostname)
    && hostname !== 'hub.biel.dev.br';
  if (!validHost) throw Error('invalid portal hostname');
  const exactHostMatcher = hostname.replaceAll('.', String.raw`\.`);

  const rewrites = manifest?.rewrites;
  const routes = Array.isArray(rewrites)
    ? rewrites
    : rewrites && typeof rewrites === 'object' && !Array.isArray(rewrites)
      ? [rewrites.beforeFiles, rewrites.afterFiles, rewrites.fallback].flat()
      : null;
  if (!routes || !routes.every((route) => route && typeof route === 'object')) {
    throw Error('OIDC build routes unavailable');
  }
  // Fail closed on an unexpected beforeFiles/fallback rewrite: these may
  // override an otherwise-correct OIDC route set.
  if (routes.length !== OIDC_REWRITE_SOURCES.length) {
    throw Error('unexpected rewrite count');
  }

  for (const source of OIDC_REWRITE_SOURCES) {
    const matches = routes.filter((route) => route.source === source);
    if (matches.length !== 1) throw Error('missing or repeated OIDC rewrite');
    const route = matches[0];
    // Optional missing/locale/basePath and future routing modifiers can
    // change matching semantics while leaving host and destination unchanged.
    const allowedRouteKeys = new Set(['source', 'has', 'destination', 'regex']);
    const hasKeys = route.has?.[0] && typeof route.has[0] === 'object'
      ? Object.keys(route.has[0]) : [];
    if (Object.keys(route).some((key) => !allowedRouteKeys.has(key))
        || !Array.isArray(route.has) || route.has.length !== 1
        || hasKeys.length !== 2 || !hasKeys.includes('type') || !hasKeys.includes('value')
        || route.has[0]?.type !== 'host' || route.has[0]?.value !== exactHostMatcher
        || route.regex !== OIDC_REWRITE_REGEX[source]
        || route.destination !== `http://oidc-issuer:3003${source}`) {
      throw Error('OIDC rewrite host or internal destination mismatch');
    }
  }
  return true;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  try {
    const manifest = JSON.parse(readFileSync(
      new URL('../apps/hub/.next/routes-manifest.json', import.meta.url), 'utf8'));
    assertOidcBuildHost(manifest, process.argv[2]);
    process.stdout.write('OIDC_BUILD_HOST_PINNED_PASS\n');
  } catch {
    process.stderr.write('OIDC_BUILD_HOST_REFUSED\n');
    process.exitCode = 2;
  }
}
