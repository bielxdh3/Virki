import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { classifyIssue119CloudflareSettings } from './issue119-cloudflare-settings.mjs';

const snapshot = (min = '1.2', ssl = 'flexible') => ({ result: [
  { id: 'min_tls_version', value: min },
  { id: 'tls_1_3', value: 'zrt' },
  { id: 'always_use_https', value: 'on' },
  { id: 'ssl', value: ssl },
  { id: 'security_header', value: { strict_transport_security: { enabled: true, max_age: 2592000 } } },
] });

test('zone TLS 1.0 fails despite TLS1.3, HTTPS and HSTS', () => {
  const result = classifyIssue119CloudflareSettings(snapshot('1.0'));
  assert.equal(result.visitorReady, false);
  assert.equal(result.minTLS, '1.0');
  assert.equal(result.closureReady, false);
});

test('TLS1.2 zone setting passes only visitor configuration; Flexible never proves origin transport', () => {
  const result = classifyIssue119CloudflareSettings(snapshot());
  assert.equal(result.visitorReady, true);
  assert.equal(result.originTransport, 'requires-independent-tunnel-and-origin-evidence');
  assert.equal(result.needPerHostHandshake, true);
  assert.equal(result.closureReady, false);
});

test('missing, duplicate, malformed TLS fields or disabled redirect fail closed', () => {
  assert.equal(classifyIssue119CloudflareSettings({}).visitorReady, false);
  const bad = snapshot(); bad.result.push({ id: 'min_tls_version', value: '1.2' });
  assert.equal(classifyIssue119CloudflareSettings(bad).visitorReady, false);
  for (const min of ['0.9', '1.1', 1.2, null]) {
    assert.equal(classifyIssue119CloudflareSettings(snapshot(min)).visitorReady, false);
  }
  const noHTTPS = snapshot(); noHTTPS.result.find((x) => x.id === 'always_use_https').value = 'off';
  assert.equal(classifyIssue119CloudflareSettings(noHTTPS).visitorReady, false);
});

test('CLI has no implicit API access and outputs sanitized fields only', () => {
  const args = ['scripts/security/issue119-cloudflare-settings.mjs'];
  const disabled = spawnSync(process.execPath, args, { encoding: 'utf8', timeout: 4000 });
  assert.equal(disabled.status, 2);
  assert.equal(disabled.stdout, '');
  const fixture = snapshot(); fixture.zone_id = 'secret-identifier';
  const approved = spawnSync(process.execPath, [...args, '--stdin'], {
    encoding: 'utf8', input: JSON.stringify(fixture), timeout: 4000,
  });
  assert.equal(approved.status, 0);
  assert.ok(!approved.stdout.includes('secret-identifier'));
  assert.equal(JSON.parse(approved.stdout).closureReady, false);
});
