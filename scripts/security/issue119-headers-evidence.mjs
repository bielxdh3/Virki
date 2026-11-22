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

// HTML5 attribute/tag delimiters and CSP directive separators are ASCII
// whitespace only. JavaScript's \s/trim() additionally accept NBSP, VT and
// other Unicode spaces, which can fabricate script evidence in both parsers.
const ASCII_SPACE = '[\\t\\n\\f\\r ]';
const asciiTrim = (value) => value.replace(/^[\t\n\f\r ]+|[\t\n\f\r ]+$/g, '');
const asciiSpaces = /[\t\n\f\r ]+/;

function directiveSources(csp, directiveName) {
  const expression = new RegExp(`^${directiveName}(?:${ASCII_SPACE}|$)`, 'i');
  const directive = csp.split(';').map(asciiTrim).find((item) => expression.test(item));
  return { present: directive !== undefined,
    sources: directive === undefined ? [] : directive.split(asciiSpaces).slice(1) };
}

function inspectScriptTag(tag) {
  const invalid = () => ({ valid: false, executable: false, nonce: null });
  const opening = /^<script(?=[\t\n\f\r />])/i.exec(tag);
  if (!opening) return invalid();
  let pos = opening[0].length;
  let nonce = null;
  let type = null;
  const seen = new Set();
  while (pos < tag.length) {
    while (/[\t\n\f\r ]/.test(tag[pos] ?? '')) pos++;
    if (tag[pos] === '>') break;
    // A slash before nonterminal content is reprocessed by HTML5 as an
    // attribute separator. Refuse even terminal script '/>' syntax rather
    // than hiding nomodule or a non-executable type behind early stopping.
    if (tag[pos] === '/') return invalid();
    const start = pos;
    while (pos < tag.length && !/[\t\n\f\r =/>]/.test(tag[pos])) pos++;
    if (pos === start) return invalid();
    const name = tag.slice(start, pos).toLowerCase();
    if (seen.has(name)) return invalid();
    seen.add(name);
    while (/[\t\n\f\r ]/.test(tag[pos] ?? '')) pos++;
    let value = null;
    if (tag[pos] === '=') {
      pos++;
      while (/[\t\n\f\r ]/.test(tag[pos] ?? '')) pos++;
      if (tag[pos] === '"' || tag[pos] === "'") {
        const quote = tag[pos++];
        const end = tag.indexOf(quote, pos);
        if (end < 0) return invalid();
        value = tag.slice(pos, end);
        pos = end + 1;
      } else {
        const valueStart = pos;
        while (pos < tag.length && !/[\t\n\f\r >]/.test(tag[pos])) pos++;
        value = tag.slice(valueStart, pos);
      }
    }
    // Parse whole attribute names: data-nonce, x-nonce or a quoted string
    // containing ' nonce=' are never the script element's nonce attribute.
    // A CSP nonce is a Base64/Base64url token. Reject entity-encoded or
    // malformed attribute values instead of comparing raw HTML source to a
    // browser-decoded value and accidentally approving a broken handshake.
    if (name === 'nonce') nonce = value && /^[A-Za-z0-9+/_-]+={0,2}$/.test(value) ? value : null;
    // HTML attribute character references are decoded by the browser, so
    // `text&#47;javascript` is executable despite looking unlike a raw MIME
    // essence. This deliberately bounded scanner cannot fully decode HTML5
    // entities; refuse encoded type values rather than silently classifying
    // a potentially live script as inert. Do not weaken the nonce check.
    if (name === 'type') {
      if (value !== null && value.includes('&')) return invalid();
      type = value;
    }
    // An omitted type does not always mean JavaScript: a nonempty HTML
    // `language` attribute is used as a legacy type fallback. Even a raw
    // whitespace-only value is nonempty and becomes an inert legacy MIME
    // type (e.g. "text/ "), not an omitted language. Refuse every nonempty
    // value rather than fabricating a hydration receipt.
    if (name === 'language' && value !== null && value !== '') return invalid();
  }
  if (type !== null && typeof type !== 'string') return invalid();
  const rawType = type ?? '';
  const mimeEssence = asciiTrim(rawType).toLowerCase();
  // HTML script data blocks (JSON, LD+JSON, importmaps, speculation rules or
  // unknown MIME types) do not execute. Likewise modern module-capable
  // browsers skip classic scripts with the exact boolean `nomodule` HTML
  // attribute, regardless of whether it has an assigned value. Only a real
  // executable classic/module script may establish a nonce-bearing receipt.
  // Do NOT mistake data-nomodule, x-nomodule or no-module for this attribute.
  // HTML script preparation distinguishes an actually empty attribute from
  // whitespace-only text. The `module` keyword is exact (ASCII case-insensitive)
  // without trimming. Only JavaScript MIME essences can use surrounding ASCII
  // whitespace normalization; otherwise inert types could attest fake hydration.
  const moduleScript = rawType.toLowerCase() === 'module';
  const classicScript = rawType === '' || JAVASCRIPT_MIME_ESSENCES.has(mimeEssence);
  const executable = moduleScript || (classicScript && !seen.has('nomodule'));
  return { valid: true, executable, nonce };
}

function hasValidHstsAge(value) {
  // HTTP optional whitespace is SP / HTAB, NOT JavaScript's Unicode \s.
  // A non-breaking space is allowed as an HTTP obs-text octet but is not
  // grammar whitespace: accepting it can falsely attest a malformed HSTS.
  const maxAge = value.split(';').map((part) => part.replace(/^[ \t]+|[ \t]+$/g, ''))
    .filter((part) => /^max-age[ \t]*=/i.test(part));
  if (maxAge.length !== 1) return false;
  // RFC 6797 permits a decimal age either unquoted or within double quotes.
  // Never accept only the numeric prefix of malformed values like 1e6.
  const match = /^max-age[ \t]*=[ \t]*(?:"([0-9]+)"|([0-9]+))[ \t]*$/i.exec(maxAge[0]);
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
  const sandbox = csp.split(';').map(asciiTrim)
    .filter((part) => /^sandbox(?:[\t\n\f\r ]|$)/i.test(part));
  if (sandbox.length === 0) return true;
  if (sandbox.length !== 1) return false;
  return sandbox[0].split(asciiSpaces).slice(1)
    .some((token) => token.toLowerCase() === 'allow-scripts');
}

// Return the FIRST appropriate raw-text end-tag candidate, or reject the
// document. HTML5 browsers may consume `</noscript attr="...">` as a closing
// tag; skipping it to search for a later plain `</noscript>` could hide a
// wrong-nonce executable script. Until full HTML5 parsing is available,
// refuse any extra attributes/ambiguous end-tag syntax rather than skipping
// the actual boundary and claiming hydration passed.
function rawTextCloseOffset(body, afterStartTag, name) {
  const start = new RegExp(`</${name}(?=${ASCII_SPACE}|[/>])`, 'gi');
  start.lastIndex = afterStartTag;
  const match = start.exec(body);
  if (!match) return -1;
  const end = body.indexOf('>', start.lastIndex);
  if (end < 0) return -1;
  const token = body.slice(match.index, end + 1);
  const simpleEndTag = new RegExp(`^</${name}${ASCII_SPACE}*>$`, 'i');
  return simpleEndTag.test(token) ? end + 1 : -1;
}

// Strict, small acceptance tokenizer: this is *not* a replacement for a
// browser E2E hydration test. It recognizes real tags without matching fake
// <script> text inside comments, attribute quotes, inert <template>/<noscript>
// subtrees, script raw text or other raw-text elements. Malformed/ambiguous
// markup fails closed rather than manufacturing a passing nonce receipt.
function inspectHtmlDocument(body, mime) {
  const fail = () => ({ valid: false, nonces: [] });
  // HTTP field-value whitespace is SP / HTAB, not JavaScript Unicode trim.
  // A NBSP next to text/html or a charset separator is not valid MIME OWS
  // and cannot establish a browser-executable HTML receipt.
  const mimeValue = mime.replace(/^[ \t]+|[ \t]+$/g, '');
  if (!/^text\/html(?:[ \t]*;[ \t]*charset[ \t]*=[ \t]*(?:[\w-]+|"[\w-]+")[ \t]*)?$/i.test(mimeValue)) return fail();
  // HTML5 DOCTYPE delimiters also use ASCII whitespace, not JavaScript \s.
  const start = /^[\t\n\f\r ]*<!doctype[\t\n\f\r ]+html[\t\n\f\r ]*>/i.exec(body);
  if (!start) return fail();
  let at = start[0].length;
  let phase = 0; // html open, head open/closed, body open/closed, html closed
  const inert = [];
  const nonces = [];
  while (at < body.length) {
    const lt = body.indexOf('<', at);
    if (lt < 0) break;
    if (phase === 6 && asciiTrim(body.slice(at))) return fail();
    if (body.startsWith('<!--', lt)) {
      // WHATWG HTML treats `<!-->` and `<!--->` as immediately closed,
      // not as comments extending to a later `-->`. A string search could
      // swallow executable scripts between the true and imaginary closures.
      // Malformed syntax is rejected rather than creating a false PASS.
      if (body.startsWith('<!-->', lt) || body.startsWith('<!--->', lt)) return fail();
      const end = body.indexOf('-->', lt + 4);
      if (end < 0) return fail();
      // HTML5 also closes comments at the comment-end-bang sequence `--!>`.
      // If that boundary occurs first, a later `-->` must not swallow a live
      // script. Fail closed because this minimal tokenizer does not implement
      // every malformed-comment parser state.
      const endBang = body.indexOf('--!>', lt + 4);
      if (endBang !== -1 && endBang < end) return fail();
      at = end + 3;
      continue;
    }
    // HTML5 only enters a quoted attribute value immediately after '='
    // (with optional ASCII spaces). A quote embedded in an UNQUOTED value
    // is a parse error, but does not shield the next '>' from the browser.
    // Reject that syntax instead of swallowing a later wrong-nonce script.
    let quote = null;
    let attrState = 'outside';
    let end = lt + 1;
    for (; end < body.length; end++) {
      const char = body[end];
      if (quote) {
        if (char === quote) {
          quote = null;
          attrState = 'after-quote';
        }
        continue;
      }
      if (char === '>') break;
      if (attrState === 'before-value') {
        if (/[\t\n\f\r ]/.test(char)) continue;
        if (char === '"' || char === "'") {
          quote = char;
          attrState = 'quoted';
          continue;
        }
        attrState = 'unquoted';
      }
      if (attrState === 'unquoted') {
        if (/[\t\n\f\r ]/.test(char)) attrState = 'outside';
        else if (char === '"' || char === "'") return fail();
        continue;
      }
      if (attrState === 'after-quote') {
        if (/[\t\n\f\r /]/.test(char)) {
          attrState = 'outside';
          continue;
        }
        return fail();
      }
      if (char === '=') attrState = 'before-value';
      else if (char === '"' || char === "'") return fail();
    }
    if (end === body.length) return fail();
    const raw = body.slice(lt, end + 1);
    at = end + 1;
    // HTML5 never accepts whitespace after `<` or `</` as a tag opener.
    // Normalizing `< style>` to `<style>` would incorrectly consume a real
    // following script as raw text and hide a CSP nonce mismatch.
    // A word boundary is insufficient: <style.foo> must not enter the style
    // raw-text state, nor can <script.foo> count as an executable script.
    const match = /^<(\/?)([a-z][a-z0-9:-]*)(?=[\t\n\f\r />])/i.exec(raw);
    if (!match) return fail();
    const closing = match[1] === '/';
    const tag = match[2].toLowerCase();
    // A meta CSP can add a second enforced policy AFTER the response headers
    // were parsed. Browser semantics intersect policies, so a seemingly valid
    // nonce-bearing response header alone could falsely pass if a meta CSP
    // disables script execution. This bounded tokenizer does not reconcile
    // HTML meta CSP and header policies: reject any real http-equiv meta tag
    // (including encoded values) instead of silently ignoring its policy.
    // Slash in the self-closing-start-tag state is reprocessed by HTML5 as
    // an attribute boundary (`<meta/http-equiv=...>` is real http-equiv).
    if (tag === 'meta' && !closing && /[\s/]http-equiv(?=\s|=|\/>|>)/i.test(raw)) return fail();
    // This bounded receipt does not implement SVG/MathML namespaces. In
    // particular SVG <title> is an HTML integration point; HTML <title>
    // raw-text semantics there would conceal executable child scripts.
    // Fail closed on foreign-content elements rather than making incorrect
    // security claims using namespace-blind tag-name heuristics.
    if (tag === 'svg' || tag === 'math') return fail();
    // HTML5's "in select" insertion mode ignores start tags such as style,
    // iframe, noembed and noframes, but still processes script start tags.
    // Treating those ignored tags as raw-text would conceal a live script with
    // a mismatched nonce. This bounded scanner does not implement select's
    // insertion mode, so refuse a select document rather than issue false PASS.
    if (tag === 'select') return fail();
    // HTML5 uses a separate "in frameset" insertion mode which ignores
    // script start tags. A nonce on such an ignored script cannot provide
    // evidence of executable hydration. Fail closed on this legacy surface.
    if (tag === 'frameset' || tag === 'frame') return fail();
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
      if (tag === 'script') {
        // Script-data double escaping differs from ordinary raw-text: after
        // `<!--<script>` the first apparent `</script>` does NOT end the
        // element, it only exits the double-escaped state. A naive first-close
        // search would count a later fake nonce-bearing <script> as executable.
        // This bounded parser cannot model every script tokenizer state; reject
        // potential double-escape sequences instead of issuing false PASS.
        const contentThroughClose = body.slice(at, after);
        const escapedStart = contentThroughClose.indexOf('<!--');
        if (escapedStart >= 0 && /<script(?=[\t\n\f\r \x2f>])/i.test(
          contentThroughClose.slice(escapedStart + 4))) return fail();
      }
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
  return phase === 6 && inert.length === 0 && asciiTrim(body.slice(at)) === ''
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
