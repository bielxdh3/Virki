// Offline, fail-closed Cloudflare *settings* acceptance. Accepts a locally
// supplied API GET /zones/{id}/settings JSON document over stdin; no API calls,
// tokens, zone IDs, DNS writes or configuration changes are performed here.
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';

const WANTED = ['min_tls_version', 'tls_1_3', 'always_use_https', 'ssl', 'security_header'];
const TLS_LEVELS = { '1.0': 10, '1.1': 11, '1.2': 12, '1.3': 13 };

export function classifyIssue119CloudflareSettings(document) {
  const items = Array.isArray(document) ? document : document?.result;
  const found = new Map();
  const duplicates = new Set();
  if (Array.isArray(items)) {
    for (const item of items) {
      if (!WANTED.includes(item?.id)) continue;
      if (found.has(item.id)) duplicates.add(item.id);
      found.set(item.id, item.value);
    }
  }
  const min = found.get('min_tls_version');
  const modern = found.get('tls_1_3');
  const redirect = found.get('always_use_https');
  const ssl = found.get('ssl');
  const hsts = found.get('security_header')?.strict_transport_security;
  const visitorReady = duplicates.size === 0 &&
    typeof min === 'string' && (TLS_LEVELS[min] ?? 0) >= 12 &&
    (modern === 'on' || modern === 'zrt') && redirect === 'on';
  return {
    schema: 'virki.issue119.cloudflare-settings.v1',
    mode: 'offline-read-only-config-classification',
    minTLS: typeof min === 'string' && Object.hasOwn(TLS_LEVELS, min) ? min : 'unknown',
    modernTLS: modern === 'on' || modern === 'zrt' ? 'enabled' : 'not-confirmed',
    redirectHTTPS: redirect === 'on' ? 'enabled' : 'not-confirmed',
    sslMode: typeof ssl === 'string' && ['flexible', 'full', 'strict'].includes(ssl) ? ssl : 'unknown',
    originTransport: 'requires-independent-tunnel-and-origin-evidence',
    hsts: hsts?.enabled === true && Number.isSafeInteger(hsts.max_age) && hsts.max_age > 0
      ? 'enabled' : 'missing-or-unconfirmed',
    visitorReady,
    closureReady: false,
    // A zone setting does not prove a particular hostname's TLS handshake,
    // active origin deployment, Cloudflare Access or an authenticated flow.
    needPerHostHandshake: true,
  };
}

async function readBoundedStdin() {
  let input = '';
  for await (const chunk of process.stdin) {
    input += chunk.toString('utf8');
    if (Buffer.byteLength(input) > 65536) throw new Error('snapshot too large');
  }
  return JSON.parse(input);
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  if (process.argv.length !== 3 || process.argv[2] !== '--stdin') {
    process.stderr.write('No Cloudflare API request made. Supply sanitized GET /settings JSON via --stdin.\n');
    process.exitCode = 2;
  } else {
    try {
      const result = classifyIssue119CloudflareSettings(await readBoundedStdin());
      process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
      if (!result.visitorReady) process.exitCode = 2;
    } catch (_error) {
      process.stderr.write('Settings snapshot unreadable; acceptance inconclusive.\n');
      process.exitCode = 2;
    }
  }
}
