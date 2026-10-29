import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { EventEmitter } from 'node:events';
import { Agent as HttpsAgent, globalAgent as globalHttpsAgent } from 'node:https';
import { PassThrough } from 'node:stream';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  officialTarballPlan, verifyNpmCacacheContent, derivePinnedOfflineDockerfile,
  fetchAndCacheOfficialTarball, verifyNpmCacacheIndex, loadPinnedNpmCacache,
} from './offline-npm-cache.mjs';

const repo = fileURLToPath(new URL('..', import.meta.url));
const lock = JSON.parse(readFileSync(path.join(repo, 'package-lock.json'), 'utf8'));
const originalDockerfile = readFileSync(path.join(repo, 'infra', 'Dockerfile.prod'), 'utf8').replaceAll('\r\n', '\n');
const sampleUrl = 'https://registry.npmjs.org/is-number/-/is-number-7.0.0.tgz';
const sampleBytes = Buffer.from('test fixture tarball bytes');
const sampleIntegrity = 'sha512-' + createHash('sha512').update(sampleBytes).digest('base64');
const exactLocalEntries = Object.fromEntries(Object.entries(lock.packages)
  .filter(([, value]) => value.link === true || value.resolved === undefined));
const fixturePlan = (packages) => officialTarballPlan({ lockfileVersion: 3, packages: {
  ...exactLocalEntries, ...packages,
} });

test('lockfile enumerates every integrity-bound official registry package, including optional Linux packages', () => {
  const entries = officialTarballPlan(lock);
  assert.equal(entries.length, 339);
  assert.equal(new Set(entries.map(x => x.url)).size, 339);
  assert.ok(entries.every(x => x.url.startsWith('https://registry.npmjs.org/')));
  assert.ok(entries.some(x => x.optional));
  assert.ok(entries.some(x => x.packageName.includes('linux')));
});

test('the actual lock has exactly seven canonical local records and six exact workspace symlink pairs', () => {
  const expectedLocal = ['', 'apps/hub', 'apps/issuer', 'apps/public-site',
    'packages/auth', 'packages/database', 'packages/oidc-node'];
  const expectedLinks = {
    'node_modules/@virki/auth': 'packages/auth',
    'node_modules/@virki/database': 'packages/database',
    'node_modules/@virki/hub': 'apps/hub',
    'node_modules/@virki/issuer': 'apps/issuer',
    'node_modules/@virki/oidc-node': 'packages/oidc-node',
    'node_modules/@virki/public-site': 'apps/public-site',
  };
  assert.deepEqual(Object.entries(lock.packages).filter(([,v]) => !v.resolved && !v.link)
    .map(([k]) => k).sort(), expectedLocal.slice().sort());
  assert.deepEqual(Object.fromEntries(Object.entries(lock.packages).filter(([,v]) => v.link)
    .map(([k,v]) => [k,v.resolved])), expectedLinks);
  assert.equal(officialTarballPlan(lock).length, 339);
  const mutated = structuredClone(lock);
  mutated.packages['node_modules/unknown'] = { version: '1.0.0' };
  assert.throws(() => officialTarballPlan(mutated), /unresolved|local/u);
  delete mutated.packages['node_modules/unknown'];
  mutated.packages['node_modules/@virki/auth'].resolved = 'packages/issuer';
  assert.throws(() => officialTarballPlan(mutated), /workspace/u);
  mutated.packages['node_modules/@virki/auth'].resolved = 'packages/auth';
  mutated.packages['apps/new-local'] = { name: '@virki/new-local', version: '1.0.0' };
  assert.throws(() => officialTarballPlan(mutated), /local/u);
});

function mockedTransport({ code = 200, data = sampleBytes, headers = {}, complete = true, fail = false } = {}) {
  const calls = [];
  return {
    calls,
    request(url, options, onResponse) {
      calls.push({ url: String(url), options });
      const req = new EventEmitter();
      req.destroy = () => {};
      queueMicrotask(() => {
        const response = new PassThrough();
        response.statusCode = code;
        response.headers = headers;
        response.complete = complete;
        onResponse(response);
        if (fail) response.destroy(Error('mocked stream interrupted'));
        else response.end(data);
      });
      return req;
    },
  };
}

test('direct HTTPS refuses 302 without making a second request or touching cacache', async () => {
  const transport = mockedTransport({ code: 302,
    headers: { location: 'https://foreign.invalid/steal-package.tgz' } });
  let putCalls = 0;
  const fakeCacache = { put: async () => { putCalls++; } };
  const entry = fixturePlan({
    'node_modules/a': { resolved: sampleUrl, integrity: sampleIntegrity },
  })[0];
  await assert.rejects(fetchAndCacheOfficialTarball(entry, { cacheDirectory: '/unused',
    request: transport.request, cacache: fakeCacache }), /HTTP 302|redirect/u);
  assert.equal(transport.calls.length, 1);
  assert.equal(transport.calls[0].url, sampleUrl);
  assert.equal(transport.calls[0].options.rejectUnauthorized, true);
  assert.ok(transport.calls[0].options.agent instanceof HttpsAgent);
  assert.notEqual(transport.calls[0].options.agent, globalHttpsAgent);
  assert.deepEqual(transport.calls[0].options.agent.options.proxyEnv, {});
  assert.equal(putCalls, 0);
});

test('partial, corrupt and interrupted HTTPS responses never reach the npm cache index', async () => {
  const entry = fixturePlan({
    'node_modules/a': { resolved: sampleUrl, integrity: sampleIntegrity },
  })[0];
  let writes = 0;
  const cacache = { put: async () => { writes++; } };
  const failures = [
    mockedTransport({ data: sampleBytes.subarray(0, 4), headers: { 'content-length': String(sampleBytes.length) } }),
    mockedTransport({ data: sampleBytes.subarray(0, 4), complete: false }),
    mockedTransport({ data: Buffer.from('altered') }),
    mockedTransport({ fail: true }),
  ];
  for (const t of failures) {
    await assert.rejects(fetchAndCacheOfficialTarball(entry, {
      cacheDirectory: '/unused', request: t.request, cacache,
    }));
  }
  assert.equal(writes, 0);
});

test('valid HTTPS payload is stored via npm cacache.put with exact URL key and SRI', async (t) => {
  if (process.platform !== 'win32') {
    assert.throws(() => loadPinnedNpmCacache(), /Windows/u);
    t.skip('exact pinned npm 20.0.3 library is from trusted Windows Node installation');
    return;
  }
  const c = loadPinnedNpmCacache();
  const dir = mkdtempSync(path.join(os.tmpdir(), 'virki-npm-index-'));
  try {
    const entry = fixturePlan({
      'node_modules/a': { resolved: sampleUrl, integrity: sampleIntegrity },
    })[0];
    const transport = mockedTransport();
    await fetchAndCacheOfficialTarball(entry, { cacheDirectory: dir, request: transport.request, cacache: c });
    assert.equal((await verifyNpmCacacheIndex(dir, [entry], c)).verified, 1);
    assert.equal(verifyNpmCacacheContent(dir, [entry]).verified, 1);
    await c.rm.entry(path.join(dir, '_cacache'), sampleUrl);
    await assert.rejects(verifyNpmCacacheIndex(dir, [entry], c), /index/u);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('fail closed on unpinned URL, omitted integrity, duplicate conflict and malformed SHA512', () => {
  const fixture = { lockfileVersion: 3, packages: { ...exactLocalEntries,
    'node_modules/a': { resolved: sampleUrl, integrity: sampleIntegrity } } };
  assert.equal(officialTarballPlan(fixture).length, 1);
  const invalid = [
    { resolved: 'http://registry.npmjs.org/a/-/a.tgz', integrity: sampleIntegrity },
    { resolved: 'https://registry.npmjs.org.evil.invalid/a/-/a.tgz', integrity: sampleIntegrity },
    { resolved: 'https://evil:secret@registry.npmjs.org/a/-/a.tgz', integrity: sampleIntegrity },
    { resolved: 'https://registry.npmjs.org/a/-/a.tgz?token=bad', integrity: sampleIntegrity },
    { resolved: 'https://registry.npmjs.org/a/-/a.tgz', integrity: 'sha1-AAAA' },
    { resolved: 'https://registry.npmjs.org/a/-/a.tgz' },
  ];
  for (const entry of invalid) assert.throws(() => fixturePlan({ 'node_modules/a': entry }));
  assert.throws(() => fixturePlan({
    'node_modules/a': fixture.packages['node_modules/a'],
    'node_modules/b': { resolved: sampleUrl, integrity: 'sha512-' + createHash('sha512').update('different').digest('base64') },
  }));
});

test('verify cache bytes against lockfile SHA512, including mutation and missing blobs', () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'virki-npm-cache-'));
  try {
    const entry = fixturePlan({ 'node_modules/a': {
      resolved: sampleUrl, integrity: sampleIntegrity,
    } })[0];
    assert.throws(() => verifyNpmCacacheContent(dir, [entry]), /missing/u);
    const file = path.join(dir, '_cacache', 'content-v2', 'sha512',
      entry.hex.slice(0, 2), entry.hex.slice(2, 4), entry.hex.slice(4));
    mkdirSync(path.dirname(file), { recursive: true });
    writeFileSync(file, sampleBytes);
    assert.equal(verifyNpmCacacheContent(dir, [entry]).verified, 1);
    writeFileSync(file, 'tampered');
    assert.throws(() => verifyNpmCacacheContent(dir, [entry]), /integrity/u);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('derived Dockerfile preserves pinned canonical source and converts only the two npm ci commands', () => {
  const derived = derivePinnedOfflineDockerfile(originalDockerfile);
  assert.equal((derived.match(/--mount=type=bind,from=offline-npm-cacache/g) ?? []).length, 2);
  assert.equal((derived.match(/npm ci --offline/g) ?? []).length, 2);
  assert.ok(derived.includes('npm ci --offline --omit=dev --omit=peer --omit=optional --ignore-scripts --no-audit'));
  assert.ok(derived.includes('rm -rf /tmp/virki-npm-cache'));
  assert.ok(!derived.includes('npm ci\n'));
  assert.throws(() => derivePinnedOfflineDockerfile(originalDockerfile + '\nFROM evil.invalid/image\n'));
  assert.throws(() => derivePinnedOfflineDockerfile(originalDockerfile.replace('RUN npm ci', 'RUN npm install')));
});

test('prewarm CLI fails without explicit opt-in before any registry or Docker access', {
  skip: process.platform !== 'win32',
}, () => {
  const script = fileURLToPath(new URL('./offline-npm-cache.mjs', import.meta.url));
  const result = spawnSync(process.execPath, [script, '--repository', repo,
    '--staging-parent', os.tmpdir()], { encoding: 'utf8', timeout: 5000,
    env: { ...process.env, VIRKI_OFFLINE_NPM_CACHE_WARM: '' } });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /explicit cache prewarm opt-in missing/u);
  assert.equal(result.stdout, '');
});

test('non-Windows prewarm refuses immediately with explicit opt-in and does not create a cache', () => {
  if (process.platform === 'win32') return;
  const script = fileURLToPath(new URL('./offline-npm-cache.mjs', import.meta.url));
  const result = spawnSync(process.execPath, [script, '--repository', repo,
    '--staging-parent', os.tmpdir()], { encoding: 'utf8', timeout: 5000,
    env: { ...process.env, VIRKI_OFFLINE_NPM_CACHE_WARM: '1' } });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /Windows x64/u);
});

test('non-Windows disposable Docker fixture refuses immediately, even when opted in', () => {
  if (process.platform === 'win32') return;
  const script = fileURLToPath(new URL('./offline-npm-buildkit-fixture.mjs', import.meta.url));
  const result = spawnSync(process.execPath, [script], { encoding: 'utf8', timeout: 5000,
    env: { ...process.env, VIRKI_NPM_BUILDKIT_DEV_FIXTURE: '1' } });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /requires Windows x64/u);
});
