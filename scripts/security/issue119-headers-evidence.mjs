// Read-only, opt-in acceptance probe for issue #119. Never follow redirects,
// send credentials, print HTML, contact arbitrary hosts or mutate production.
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';

const TARGETS = Object.freeze([
  { host: 'biel.dev.br', path: '/', method: 'GET', expected: 200, surface: 'public-site' },
  { host: 'biel.dev.br', path: '/__virki_issue119_not_found_20261121__', method: 'GET', expected: 404, surface: 'public-404' },
  { host: 'hub.biel.dev.br', path: '/', method: 'HEAD', surface: 'access-protected' },
  { host: 'portal.biel.dev.br', path: '/', method: 'HEAD', surface: 'portal' },
]);

export const ISSUE119_HEADER_TARGETS = TARGETS;

function directiveSources(csp, directiveName) {
  const expression = new RegExp(`^${directiveName}(?:\\s|$)`, 'i');
  const directive = csp.split(';').map((item) => item.trim()).find((item) => expression.test(item));
  return directive ? directive.split(/\s+/).slice(1) : [];
}

function htmlScriptNonces(html) {
  const tags = html.match(/<script\b[^>]*>/gi) ?? [];
  return tags.map((tag) => /\bnonce\s*=\s*["']([^"']+)["']/i.exec(tag)?.[1] ?? null);
}

export function classifyIssue119Response(target, response) {
  const headers = response.headers;
  const csp = headers.get('content-security-policy') ?? '';
  const hsts = headers.get('strict-transport-security') ?? '';
  const hasPoweredBy = headers.has('x-powered-by');
  const isAccessRedirect = target.surface === 'access-protected' && response.status === 302;
  const hstsPresent = /(?:^|;)\s*max-age\s*=\s*[1-9]\d*/i.test(hsts);
  const common = { host: target.host, path: target.path, status: response.status,
    hsts: hstsPresent ? 'present' : 'missing', poweredBy: hasPoweredBy ? 'exposed' : 'absent' };

  if (target.surface === 'access-protected') {
    return { ...common, result: isAccessRedirect ? 'blocked-by-access' : 'inconclusive',
      note: 'Access redirect never proves origin headers or authenticated session security' };
  }
  if (target.surface === 'portal') {
    return { ...common, result: response.status >= 300 && response.status < 400 && !hasPoweredBy && hstsPresent
      ? 'redirect-headers-only' : 'inconclusive',
      note: 'Redirect response does not prove Portal origin, authenticated headers or recovery' };
  }

  const sources = directiveSources(csp, 'script-src');
  const elementSources = directiveSources(csp, 'script-src-elem');
  const attributeSources = directiveSources(csp, 'script-src-attr');
  // A more permissive element/attribute directive overrides script-src for
  // that execution type. Checking only script-src would be a false PASS.
  const subdirectiveUnsafe = elementSources.includes("'unsafe-inline'") ||
    attributeSources.includes("'unsafe-inline'");
  const nonceSources = sources.filter((source) => /^'nonce-[^']+'$/.test(source));
  const tags = htmlScriptNonces(response.body ?? '');
  const inlineScriptTags = (response.body ?? '').match(/<script\b[^>]*>[^<]+<\/script\s*>/gi) ?? [];
  const inlineHaveNonce = inlineScriptTags.every((tag) => /<script\b[^>]*\bnonce\s*=/i.test(tag));
  const nonceValues = new Set(nonceSources.map((source) => source.slice(7, -1)));
  const nonceMatches = tags.length > 0 && tags.every((nonce) => nonce !== null && nonceValues.has(nonce));
  const accepted = response.status === target.expected && !hasPoweredBy && hstsPresent &&
    sources.length > 0 && !sources.includes("'unsafe-inline'") && !subdirectiveUnsafe &&
    (elementSources.length === 0 || elementSources.some((source) => nonceSources.includes(source))) &&
    nonceSources.length === 1 && nonceMatches && inlineHaveNonce;

  return { ...common, csp: csp ? 'present' : 'missing',
    scriptNonce: nonceMatches ? 'matched' : 'missing-or-mismatched',
    unsafeInlineScript: sources.includes("'unsafe-inline'") || subdirectiveUnsafe,
    result: accepted ? 'pass' : 'fail' };
}

async function fetchTarget(target) {
  const response = await fetch(`https://${target.host}${target.path}`, {
    method: target.method, redirect: 'manual', credentials: 'omit',
    headers: { 'Accept': target.method === 'GET' ? 'text/html' : '*/*' },
    signal: AbortSignal.timeout(12000),
  });
  // Bound *bytes actually downloaded*: slicing response.text() after reading
  // would allow an untrusted edge to exhaust local memory before truncation.
  let body = '';
  if (target.method === 'GET' && response.body) {
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let size = 0;
    try {
      while (true) {
        const chunk = await reader.read();
        if (chunk.done) break;
        size += chunk.value.byteLength;
        if (size > 2 * 1024 * 1024) throw new Error('public HTML exceeds bounded evidence limit');
        body += decoder.decode(chunk.value, { stream: true });
      }
      body += decoder.decode();
    } finally {
      await reader.cancel().catch(() => {});
    }
  }
  return { status: response.status, headers: response.headers, body };
}

export async function collectIssue119HeaderEvidence(request = fetchTarget) {
  const checks = [];
  for (const target of TARGETS) {
    try {
      checks.push(classifyIssue119Response(target, await request(target)));
    } catch (_error) {
      checks.push({ host: target.host, path: target.path, result: 'inconclusive',
        note: 'Request failed; no exception, address or token retained' });
    }
  }
  return { schema: 'virki.issue119.http-headers.v1',
    mode: 'read-only-unauthenticated-no-redirect',
    checks, passed: checks.filter((c) => c.host === 'biel.dev.br').length === 2 &&
      checks.filter((c) => c.host === 'biel.dev.br').every((c) => c.result === 'pass'),
    originAndAuthProven: false };
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  if (process.argv.length !== 3 || process.argv[2] !== '--live') {
    process.stderr.write('No network request made. To inspect public headers: node scripts/security/issue119-headers-evidence.mjs --live\n');
    process.exitCode = 2;
  } else {
    const result = await collectIssue119HeaderEvidence();
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    if (!result.passed) process.exitCode = 2;
  }
}
