import { pathToFileURL } from 'node:url';

// This check is intentionally scoped to the existing, isolated VM E hostnames.
// It never sends a session, token, cookie, or authorization header.
export const STAGE_E_TARGETS = Object.freeze({
  hub: Object.freeze({ host: 'hub-pr88-temp-20261102.biel.dev.br', path: '/admin/security' }),
  portal: Object.freeze({ host: 'portal-pr88-temp-20261102.biel.dev.br', path: '/login' }),
  discovery: Object.freeze({ host: 'portal-pr88-temp-20261102.biel.dev.br', path: '/.well-known/openid-configuration' }),
  jwks: Object.freeze({ host: 'portal-pr88-temp-20261102.biel.dev.br', path: '/jwks' }),
});

const ACCESS_ORIGIN = 'https://bielxdh.cloudflareaccess.com';

export function isStageAccessChallenge(observation, target) {
  if (observation.status !== 302 || observation.server?.toLowerCase() !== 'cloudflare'
      || !/^[a-f0-9]{16}-[A-Z]{3}$/u.test(observation.cfRay ?? '')) return false;
  try {
    const redirect = new URL(observation.location);
    return redirect.origin === ACCESS_ORIGIN
      && redirect.pathname === `/cdn-cgi/access/login/${target.host}`
      && redirect.searchParams.get('redirect_url') === target.path;
  } catch {
    return false;
  }
}

export function evaluateStageAccessBoundary(observations) {
  const statuses = Object.fromEntries(Object.entries(STAGE_E_TARGETS).map(([name]) => [name, observations[name]?.status ?? null]));
  const hubChallenged = isStageAccessChallenge(observations.hub ?? {}, STAGE_E_TARGETS.hub);
  const portalChallenged = isStageAccessChallenge(observations.portal ?? {}, STAGE_E_TARGETS.portal);
  const metadataChallenged = isStageAccessChallenge(observations.discovery ?? {}, STAGE_E_TARGETS.discovery);
  const jwksChallenged = isStageAccessChallenge(observations.jwks ?? {}, STAGE_E_TARGETS.jwks);
  // An explicit exception for public OIDC discovery/JWKS would need separate
  // owner approval: the temporary stage's original policy covered BOTH hosts.
  const verdict = !hubChallenged ? 'NO_GO_HUB_ACCESS_NOT_PROVEN'
    : !portalChallenged ? 'NO_GO_PORTAL_ACCESS_NOT_PROVEN'
      : !metadataChallenged || !jwksChallenged ? 'REVIEW_PUBLIC_OIDC_ACCESS_EXCEPTIONS'
        : 'OUTER_ACCESS_CHALLENGES_PASS';
  return { verdict, statuses };
}

export async function probeStageAccessBoundary(fetcher = fetch) {
  const observations = {};
  for (const [name, target] of Object.entries(STAGE_E_TARGETS)) {
    const response = await fetcher(`https://${target.host}${target.path}`, {
      method: 'GET', redirect: 'manual', cache: 'no-store',
      headers: { accept: name === 'jwks' || name === 'discovery' ? 'application/json' : 'text/html' },
      signal: AbortSignal.timeout(10_000),
    });
    // Do not read response bodies, cookies, or Access login URLs into output.
    observations[name] = {
      status: response.status,
      server: response.headers.get('server'),
      cfRay: response.headers.get('cf-ray'),
      location: response.headers.get('location'),
    };
  }
  return evaluateStageAccessBoundary(observations);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const report = await probeStageAccessBoundary();
    process.stdout.write(`${report.verdict} ${JSON.stringify(report.statuses)}\n`);
    if (report.verdict !== 'OUTER_ACCESS_CHALLENGES_PASS') process.exitCode = 2;
  } catch {
    process.stderr.write('NO_GO_STAGE_ACCESS_PROBE_FAILED\n');
    process.exitCode = 2;
  }
}
