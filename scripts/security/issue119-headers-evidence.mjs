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

function actualScriptNonce(tag) {
  const opening = /^<script\b/i.exec(tag);
  if (!opening) return null;
  let pos = opening[0].length;
  while (pos < tag.length) {
    while (/\s/.test(tag[pos] ?? '')) pos++;
    if (tag[pos] === '>' || tag[pos] === '/') break;
    const start = pos;
    while (pos < tag.length && !/[\s=/>]/.test(tag[pos])) pos++;
    if (pos === start) return null;
    const name = tag.slice(start, pos).toLowerCase();
    while (/\s/.test(tag[pos] ?? '')) pos++;
    let value = null;
    if (tag[pos] === '=') {
      pos++;
      while (/\s/.test(tag[pos] ?? '')) pos++;
      if (tag[pos] === '"' || tag[pos] === "'") {
        const quote = tag[pos++];
        const end = tag.indexOf(quote, pos);
        if (end < 0) return null;
        value = tag.slice(pos, end);
        pos = end + 1;
      } else {
        const valueStart = pos;
        while (pos < tag.length && !/[\s>]/.test(tag[pos])) pos++;
        value = tag.slice(valueStart, pos);
      }
    }
    // Parse whole attribute names: data-nonce, x-nonce or a quoted string
    // containing ' nonce=' are never the script element's nonce attribute.
    // A CSP nonce is a Base64/Base64url token. Reject entity-encoded or
    // malformed attribute values instead of comparing raw HTML source to a
    // browser-decoded value and accidentally approving a broken handshake.
    if (name === 'nonce') return value && /^[A-Za-z0-9+/_-]+={0,2}$/.test(value) ? value : null;
  }
  return null;
}

function htmlScriptNonces(html) {
  const tags = html.match(/<script\b[^>]*>/gi) ?? [];
  return tags.map(actualScriptNonce);
}

function hasValidHstsAge(value) {
  const maxAge = value.split(';').map((part) => part.trim())
    .filter((part) => /^max-age\s*=/i.test(part));
  if (maxAge.length !== 1) return false;
  // RFC 6797 permits a decimal age either unquoted or within double quotes.
  // Never accept only the numeric prefix of malformed values like 1e6.
  const match = /^max-age\s*=\s*(?:"([0-9]+)"|([0-9]+))\s*$/i.exec(maxAge[0]);
  if (!match) return false;
  const seconds = Number(match[1] ?? match[2]);
  return Number.isSafeInteger(seconds) && seconds > 0;
}

function hasUnsafeInline(sources) {
  // CSP keywords are ASCII case-insensitive; nonce *values* are not.
  return sources.some((source) => source.toLowerCase() === "'unsafe-inline'");
}

export function classifyIssue119Response(target, response) {
  const headers = response.headers;
  const csp = headers.get('content-security-policy') ?? '';
  const mime = headers.get('content-type') ?? '';
  // Multiple enforced CSP response headers are combined with a comma by
  // Fetch's Headers API. The browser intersects ALL such policies; checking
  // only the first could falsely approve a 200/404 page whose second policy
  // blocks its scripts. Until we evaluate each policy independently, refuse
  // any comma-separated/ambiguous policy list rather than claiming hydration.
  const singleCsp = csp !== '' && !csp.includes(',');
  const hsts = headers.get('strict-transport-security') ?? '';
  const hasPoweredBy = headers.has('x-powered-by');
  const isAccessRedirect = target.surface === 'access-protected' && response.status === 302;
  const hstsPresent = hasValidHstsAge(hsts);
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
  const nonceSources = sources.filter((source) => /^'nonce-[A-Za-z0-9+/_-]+={0,2}'$/i.test(source));
  const tags = htmlScriptNonces(response.body ?? '');
  const inlineScriptTags = (response.body ?? '').match(/<script\b[^>]*>[^<]+<\/script\s*>/gi) ?? [];
  const inlineHaveNonce = inlineScriptTags.every((tag) => {
    const opening = /^<script\b[^>]*>/i.exec(tag)?.[0] ?? '';
    return actualScriptNonce(opening) !== null;
  });
  const nonceValues = new Set(nonceSources.map((source) => source.slice(7, -1)));
  const nonceMatches = tags.length > 0 && tags.every((nonce) => nonce !== null && nonceValues.has(nonce));
  const subdirectiveUnsafe = hasUnsafeInline(elementSources) || hasUnsafeInline(attributeSources);
  const htmlDocument = /^text\/html(?:\s*;|\s*$)/i.test(mime) && /<html\b/i.test(response.body ?? '');
  const accepted = response.status === target.expected && htmlDocument &&
    !hasPoweredBy && hstsPresent && singleCsp &&
    sources.length > 0 && !hasUnsafeInline(sources) && !subdirectiveUnsafe &&
    (elementSources.length === 0 || elementSources.some((source) =>
      /^'nonce-[A-Za-z0-9+/_-]+={0,2}'$/i.test(source) && nonceValues.has(source.slice(7, -1)))) &&
    nonceSources.length === 1 && nonceMatches && inlineHaveNonce;

  return { ...common, csp: csp ? 'present' : 'missing',
    htmlDocument: htmlDocument ? 'confirmed' : 'not-confirmed',
    cspPolicy: singleCsp ? 'single' : 'multiple-or-missing',
    scriptNonce: nonceMatches ? 'matched' : 'missing-or-mismatched',
    unsafeInlineScript: hasUnsafeInline(sources) || subdirectiveUnsafe,
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
