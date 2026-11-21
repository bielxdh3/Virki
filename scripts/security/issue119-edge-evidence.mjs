// Issue #119: opt-in, read-only TLS edge probe. No credentials, cookies,
// production changes, redirects, retries or scan traffic.
import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';

export const EDGE_HOSTS = Object.freeze([
  'biel.dev.br',
  'hub.biel.dev.br',
  'portal.biel.dev.br',
]);

export const TLS_PROBES = Object.freeze([
  { flag: '-tls1', expected: 'TLSv1', permitted: false },
  { flag: '-tls1_1', expected: 'TLSv1.1', permitted: false },
  { flag: '-tls1_2', expected: 'TLSv1.2', permitted: true },
  { flag: '-tls1_3', expected: 'TLSv1.3', permitted: true },
]);

export function classifyTlsProbe(probe, result) {
  const output = `${result.stdout ?? ''}\n${result.stderr ?? ''}`;
  const negotiated = output.match(/(?:Protocol(?:\s+version)?\s*:\s*)(TLSv1(?:\.[123])?)(?![\w.])/i)?.[1];
  if (result.status === 0 && negotiated) {
    if (negotiated !== probe.expected) {
      return 'inconclusive';
    }
    return 'accepted';
  }
  // A peer's alert is evidence of server-side rejection. Local OpenSSL
  // "no protocols available", unsupported flag and handshake failures are
  // deliberately NOT interpreted as secure TLS policy.
  if (!probe.permitted && /(?:tlsv1 alert protocol version|alert number 70)\b/i.test(output)) {
    return 'rejected_by_peer';
  }
  return 'inconclusive';
}

function spawnTlsProbe(host, probe) {
  // Hosts are fixed and arguments are passed as argv, never as shell source.
  const args = ['s_client', '-brief', '-connect', `${host}:443`, '-servername', host,
    probe.flag];
  if (!probe.permitted) args.push('-cipher', 'DEFAULT:@SECLEVEL=0');
  return spawnSync('openssl', args, {
    input: '', encoding: 'utf8', shell: false, timeout: 12000, maxBuffer: 128 * 1024,
    env: { PATH: process.env.PATH ?? '' },
  });
}

export function collectEdgeEvidence(runProbe = spawnTlsProbe) {
  const checks = [];
  for (const host of EDGE_HOSTS) {
    for (const probe of TLS_PROBES) {
      const result = runProbe(host, probe);
      checks.push({ host, protocol: probe.expected, required: probe.permitted ? 'accept' : 'reject',
        observed: classifyTlsProbe(probe, result) });
    }
  }
  const legacy = checks.filter((c) => c.required === 'reject');
  const modern = checks.filter((c) => c.required === 'accept');
  return {
    schema: 'virki.issue119.edge-tls-evidence.v1',
    mode: 'read-only-unauthenticated',
    scope: 'Cloudflare visitor-to-edge TLS; not origin/Tunnel, Access, DNS or app security',
    checks,
    passed: legacy.every((c) => c.observed === 'rejected_by_peer') &&
      modern.some((c) => c.protocol === 'TLSv1.2') &&
      modern.every((c) => c.observed === 'accepted'),
  };
}

function isMain() {
  return process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url;
}

if (isMain()) {
  if (process.argv.length !== 3 || process.argv[2] !== '--live') {
    process.stderr.write('No network request made. To collect low-rate edge TLS evidence: node scripts/security/issue119-edge-evidence.mjs --live\n');
    process.exitCode = 2;
  } else {
    const evidence = collectEdgeEvidence();
    process.stdout.write(`${JSON.stringify(evidence, null, 2)}\n`);
    if (!evidence.passed) process.exitCode = 2;
  }
}
