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

// WHATWG MIME Sniffing: JavaScript MIME type essence match. HTML <script>
// `type` is compared by its whole essence, NOT by parsing Content-Type
// parameters. Omitting the legacy aliases can hide a live, wrong-nonce script.
const JAVASCRIPT_MIME_ESSENCES = new Set([
  'application/ecmascript', 'application/javascript', 'application/x-ecmascript',
  'application/x-javascript', 'text/ecmascript', 'text/javascript',
  'text/javascript1.0', 'text/javascript1.1', 'text/javascript1.2',
  'text/javascript1.3', 'text/javascript1.4', 'text/javascript1.5',
  'text/jscript', 'text/livescript', 'text/x-ecmascript', 'text/x-javascript',
]);

export const ISSUE119_HEADER_TARGETS = TARGETS;

function directiveSources(csp, directiveName) {
  const expression = new RegExp(`^${directiveName}(?:\\s|$)`, 'i');
  const directive = csp.split(';').map((item) => item.trim()).find((item) => expression.test(item));
  return { present: directive !== undefined,
    sources: directive === undefined ? [] : directive.split(/\s+/).slice(1) };
}

function inspectScriptTag(tag) {
  const invalid = () => ({ valid: false, executable: false, nonce: null });
  const opening = /^<script\b/i.exec(tag);
  if (!opening) return invalid();
  let pos = opening[0].length;
  let nonce = null;
  let type = null;
  const seen = new Set();
  while (pos < tag.length) {
    while (/\s/.test(tag[pos] ?? '')) pos++;
    if (tag[pos] === '>' || tag[pos] === '/') break;
    const start = pos;
    while (pos < tag.length && !/[\s=/>]/.test(tag[pos])) pos++;
    if (pos === start) return invalid();
    const name = tag.slice(start, pos).toLowerCase();
    if (seen.has(name)) return invalid();
    seen.add(name);
    while (/\s/.test(tag[pos] ?? '')) pos++;
    let value = null;
    if (tag[pos] === '=') {
      pos++;
      while (/\s/.test(tag[pos] ?? '')) pos++;
      if (tag[pos] === '"' || tag[pos] === "'") {
        const quote = tag[pos++];
        const end = tag.indexOf(quote, pos);
        if (end < 0) return invalid();
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
    if (name === 'nonce') nonce = value && /^[A-Za-z0-9+/_-]+={0,2}$/.test(value) ? value : null;
    if (name === 'type') type = value;
  }
  if (type !== null && typeof type !== 'string') return invalid();
  const kind = (type ?? '').trim().toLowerCase();
  // HTML script data blocks (JSON, LD+JSON, importmaps, speculation rules or
  // unknown MIME types) do not execute. Likewise modern module-capable
  // browsers skip classic scripts with the exact boolean `nomodule` HTML
  // attribute, regardless of whether it has an assigned value. Only a real
  // executable classic/module script may establish a nonce-bearing receipt.
  // Do NOT mistake data-nomodule, x-nomodule or no-module for this attribute.
  const moduleScript = kind === 'module';
  const classicScript = kind === '' || JAVASCRIPT_MIME_ESSENCES.has(kind);
  const executable = moduleScript || (classicScript && !seen.has('nomodule'));
  return { valid: true, executable, nonce };
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

// Enforced CSP sandbox can disable all script execution, independently of
// script-src nonces. Reject missing allow-scripts, duplicated/ambiguous
// sandbox directives and case variants that fail to grant script execution.
// This conservatively tests executability; it does NOT prove browser hydration
// or full origin/cookie/session behavior of a sandboxed document.
function cspSandboxAllowsScripts(csp) {
  const sandbox = csp.split(';').map((part) => part.trim())
    .filter((part) => /^sandbox(?:\s|$)/i.test(part));
  if (sandbox.length === 0) return true;
  if (sandbox.length !== 1) return false;
  return sandbox[0].split(/\s+/).slice(1)
    .some((token) => token.toLowerCase() === 'allow-scripts');
}

// Return the FIRST appropriate raw-text end-tag candidate, or reject the
// document. HTML5 browsers may consume `</noscript attr="...">` as a closing
// tag; skipping it to search for a later plain `</noscript>` could hide a
// wrong-nonce executable script. Until full HTML5 parsing is available,
// refuse any extra attributes/ambiguous end-tag syntax rather than skipping
// the actual boundary and claiming hydration passed.
function rawTextCloseOffset(body, afterStartTag, name) {
  const start = new RegExp(`</${name}(?=[\\s/>])`, 'gi');
  start.lastIndex = afterStartTag;
  const match = start.exec(body);
  if (!match) return -1;
  const end = body.indexOf('>', start.lastIndex);
  if (end < 0) return -1;
  const token = body.slice(match.index, end + 1);
  const simpleEndTag = new RegExp(`^</${name}\\s*>$`, 'i');
  return simpleEndTag.test(token) ? end + 1 : -1;
}

// Strict, small acceptance tokenizer: this is *not* a replacement for a
// browser E2E hydration test. It recognizes real tags without matching fake
// <script> text inside comments, attribute quotes, inert <template>/<noscript>
// subtrees, script raw text or other raw-text elements. Malformed/ambiguous
// markup fails closed rather than manufacturing a passing nonce receipt.
function inspectHtmlDocument(body, mime) {
  const fail = () => ({ valid: false, nonces: [] });
  if (!/^text\/html(?:\s*;\s*charset\s*=\s*(?:[\w-]+|"[\w-]+")\s*)?$/i.test(mime.trim())) return fail();
  const start = /^\s*<!doctype\s+html\s*>/i.exec(body);
  if (!start) return fail();
  let at = start[0].length;
  let phase = 0; // html open, head open/closed, body open/closed, html closed
  const inert = [];
  const nonces = [];
  while (at < body.length) {
    const lt = body.indexOf('<', at);
    if (lt < 0) break;
    if (phase === 6 && body.slice(at).trim()) return fail();
    if (body.startsWith('<!--', lt)) {
      // WHATWG HTML treats `<!-->` and `<!--->` as immediately closed,
      // not as comments extending to a later `-->`. A string search could
      // swallow executable scripts between the true and imaginary closures.
      // Malformed syntax is rejected rather than creating a false PASS.
      if (body.startsWith('<!-->', lt) || body.startsWith('<!--->', lt)) return fail();
      const end = body.indexOf('-->', lt + 4);
      if (end < 0) return fail();
      at = end + 3;
      continue;
    }
    let quote = null;
    let end = lt + 1;
    for (; end < body.length; end++) {
      const char = body[end];
      if (quote) {
        if (char === quote) quote = null;
      } else if (char === '"' || char === "'") quote = char;
      else if (char === '>') break;
    }
    if (end === body.length) return fail();
    const raw = body.slice(lt, end + 1);
    at = end + 1;
    const match = /^<\s*(\/?)\s*([a-z][a-z0-9:-]*)\b/i.exec(raw);
    if (!match) return fail();
    const closing = match[1] === '/';
    const tag = match[2].toLowerCase();
    // This bounded receipt does not implement SVG/MathML namespaces. In
    // particular SVG <title> is an HTML integration point; HTML <title>
    // raw-text semantics there would conceal executable child scripts.
    // Fail closed on foreign-content elements rather than making incorrect
    // security claims using namespace-blind tag-name heuristics.
    if (tag === 'svg' || tag === 'math') return fail();
    // With scripting enabled, HTML5 treats <noscript> as raw text until its
    // first actual closing tag. Do not interpret apparent <style>/<script>
    // start tags inside it: doing so could skip the real </noscript>, hide
    // a later executable script with the wrong nonce, and return false PASS.
    if (tag === 'noscript' && !closing) {
      const after = rawTextCloseOffset(body, at, 'noscript');
      if (after < 0) return fail();
      at = after;
      continue;
    }
    if (tag === 'noscript' && closing) return fail();
    if (tag === 'template') {
      if (!closing) inert.push(tag);
      else if (inert.pop() !== tag) return fail();
      continue;
    }
    // Raw-text tags must be consumed BEFORE deciding whether their parent is
    // inert. Otherwise a literal `</template>` inside <style> or <script>
    // could pop the real template and make the next inert script look live.
    // HTML5 also treats iframe/noembed/noframes contents as raw fallback
    // text, not executable descendant elements. A fake <script nonce=...>
    // inside such text must never satisfy the live hydration evidence gate.
    if (['script', 'style', 'title', 'textarea', 'xmp', 'iframe', 'noembed', 'noframes', 'plaintext'].includes(tag) && !closing) {
      if (tag === 'plaintext') return fail();
      if (tag === 'script' && !inert.length) {
        if (phase !== 2 && phase !== 4) return fail();
        const script = inspectScriptTag(raw);
        if (!script.valid) return fail();
        if (script.executable) nonces.push(script.nonce);
      }
      const after = rawTextCloseOffset(body, at, tag);
      if (after < 0) return fail();
      at = after;
      continue;
    }
    if (inert.length) continue;
    if (tag === 'html' && ((phase === 0 && !closing) || (phase === 5 && closing))) {
      phase = phase === 0 ? 1 : 6;
    } else if (tag === 'head' && ((phase === 1 && !closing) || (phase === 2 && closing))) {
      phase = phase === 1 ? 2 : 3;
    } else if (tag === 'body' && ((phase === 3 && !closing) || (phase === 4 && closing))) {
      phase = phase === 3 ? 4 : 5;
    } else if (['html', 'head', 'body'].includes(tag)) return fail();
    if (tag === 'script' && closing) return fail();
  }
  return phase === 6 && inert.length === 0 && body.slice(at).trim() === ''
    ? { valid: true, nonces } : fail();
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

  const script = directiveSources(csp, 'script-src');
  const element = directiveSources(csp, 'script-src-elem');
  const attribute = directiveSources(csp, 'script-src-attr');
  const sources = script.sources;
  const elementSources = element.sources;
  const attributeSources = attribute.sources;
  // A more permissive element/attribute directive overrides script-src for
  // that execution type. Checking only script-src would be a false PASS.
  const nonceSources = sources.filter((source) => /^'nonce-[A-Za-z0-9+/_-]+={0,2}'$/i.test(source));
  const document = inspectHtmlDocument(response.body ?? '', mime);
  const tags = document.nonces;
  const nonceValues = new Set(nonceSources.map((source) => source.slice(7, -1)));
  const nonceMatches = tags.length > 0 && tags.every((nonce) => nonce !== null && nonceValues.has(nonce));
  const subdirectiveUnsafe = hasUnsafeInline(elementSources) || hasUnsafeInline(attributeSources);
  const htmlDocument = document.valid;
  const accepted = response.status === target.expected && htmlDocument &&
    !hasPoweredBy && hstsPresent && singleCsp && cspSandboxAllowsScripts(csp) &&
    sources.length > 0 && !hasUnsafeInline(sources) && !subdirectiveUnsafe &&
    (!element.present || elementSources.some((source) =>
      /^'nonce-[A-Za-z0-9+/_-]+={0,2}'$/i.test(source) && nonceValues.has(source.slice(7, -1)))) &&
    nonceSources.length === 1 && nonceMatches;

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
