import assert from 'node:assert/strict';
import test from 'node:test';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import os from 'node:os';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { createOfflineManualImagePlan, assertOfflineLocalImageInspect, assertOfflineCachedBaseImage,
  assertSourceMatchesCommittedBlobs, requirePrivateWindowsStagingParent,
  assertPinnedOfflineDockerfileText } from './offline-manual-image-build.mjs';

const revision = 'a'.repeat(40);
const stage = process.platform === 'win32' ? 'E:\\VirkiBuilds\\attempt-1234' : '/tmp/virki-builds/attempt-1234';

test('a manual local image plan exports both exact-SHA roles without GitHub Actions or GHCR', () => {
  const plan = createOfflineManualImagePlan({ revision, stagingDirectory: stage, attemptId: '1234567890abcdef12345678' });
  assert.equal(plan.length, 2);
  assert.deepEqual(plan.map((item) => item.role), ['runtime', 'migrator']);
  for (const item of plan) {
    assert.equal(item.buildArgs[0], 'build');
    assert.ok(item.buildArgs.includes('--pull=false'));
    assert.ok(item.buildArgs.includes('--network=none'));
    assert.ok(item.buildArgs.includes('linux/amd64'));
    assert.ok(item.buildArgs.includes(`VIRKI_BUILD_REVISION=${revision}`));
    assert.equal(item.buildArgs.at(-1), `${stage}${process.platform === 'win32' ? '\\' : '/'}source`);
    assert.ok(!/github|ghcr|actions|--push|--load|--secret/iu.test(item.buildArgs.join(' ')));
    assert.ok(item.tarPath.endsWith(`${item.role}.tar`));
  }
  assert.notEqual(plan[0].tag, plan[1].tag);
});

test('manual build plan rejects role, revision, directory and attempt-id substitutions', () => {
  const base = { revision, stagingDirectory: stage, attemptId: '1234567890abcdef12345678' };
  for (const input of [
    { ...base, revision: 'main' },
    { ...base, revision: revision.toUpperCase() },
    { ...base, attemptId: 'a/b' },
    { ...base, attemptId: '..' },
    { ...base, stagingDirectory: '../relative' },
    { ...base, stagingDirectory: `${stage}${process.platform === 'win32' ? '\\' : '/'}..` },
  ]) assert.throws(() => createOfflineManualImagePlan(input));
});

test('Docker image inspect binds immutable image ID, exact commit, source, nonroot and linux/amd64', () => {
  const entry = {
    Id: `sha256:${'b'.repeat(64)}`, Os: 'linux', Architecture: 'amd64',
    Config: { User: 'node:node', Labels: {
      'org.opencontainers.image.revision': revision,
      'org.opencontainers.image.source': 'https://github.com/bielxdh3/Virki',
    } },
  };
  const good = assertOfflineLocalImageInspect(JSON.stringify(entry), { revision, role: 'runtime' });
  assert.equal(good.imageId, entry.Id);
  for (const altered of [
    { ...entry, Id: 'sha256:short' },
    { ...entry, Architecture: 'arm64' },
    { ...entry, Config: { ...entry.Config, User: 'root' } },
    { ...entry, Config: { ...entry.Config, Labels: {
      ...entry.Config.Labels, 'org.opencontainers.image.revision': 'c'.repeat(40),
    } } },
    { ...entry, Config: { ...entry.Config, Labels: {
      ...entry.Config.Labels, 'org.opencontainers.image.source': 'https://evil.invalid',
    } } },
  ]) assert.throws(() => assertOfflineLocalImageInspect(JSON.stringify(altered), { revision, role: 'runtime' }));
  assert.throws(() => assertOfflineLocalImageInspect('{}', { revision, role: 'migrator' }));
  assert.throws(() => assertOfflineLocalImageInspect(JSON.stringify(entry), { revision, role: 'arbitrary' }));
});

test('CLI without explicit local Docker opt-in never invokes an image build', () => {
  const entry = fileURLToPath(new URL('./offline-manual-image-build.mjs', import.meta.url));
  const repo = path.resolve(fileURLToPath(new URL('..', import.meta.url)));
  const result = spawnSync(process.execPath, [entry,
    '--repository', repo, '--staging-parent', path.dirname(repo),
  ], { encoding: 'utf8', timeout: 5000, env: {
    ...process.env, VIRKI_MANUAL_IMAGES_LOCAL_BUILD: '',
  } });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /NOT_READY/u);
  assert.doesNotMatch(result.stdout, /deployAuthorized|LOCAL_SOURCE_AND_IMAGES_VERIFIED_ONLY/u);
});

test('offline build refuses absent or spoofed pinned Docker base before build', () => {
  const digest = '0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402';
  const good = {
    Id: `sha256:${'e'.repeat(64)}`, Os: 'linux', Architecture: 'amd64',
    RepoDigests: [`node@sha256:${digest}`],
  };
  assert.doesNotThrow(() => assertOfflineCachedBaseImage(JSON.stringify(good)));
  for (const bad of [
    { ...good, RepoDigests: [] },
    { ...good, RepoDigests: [`other@sha256:${digest}`] },
    { ...good, RepoDigests: [`node@sha256:${'f'.repeat(64)}`] },
    { ...good, Os: 'windows' },
    { ...good, Architecture: 'arm64' },
  ]) assert.throws(() => assertOfflineCachedBaseImage(JSON.stringify(bad)));
});

test('extracted Docker build source is bound to exact Git blob bytes and rejects added/raced files', () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'virki-manual-git-source-'));
  try {
    const bytes = Buffer.from('fixed source\n', 'utf8');
    const blob = createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex');
    const item = { file: 'source.txt', objectId: blob };
    writeFileSync(path.join(dir, item.file), bytes);
    assert.doesNotThrow(() => assertSourceMatchesCommittedBlobs(dir, [item]));
    writeFileSync(path.join(dir, item.file), 'modified source\n');
    assert.throws(() => assertSourceMatchesCommittedBlobs(dir, [item]));
    writeFileSync(path.join(dir, item.file), bytes);
    writeFileSync(path.join(dir, 'foreign.txt'), 'untracked\n');
    assert.throws(() => assertSourceMatchesCommittedBlobs(dir, [item]));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a foreign writable Windows staging DACL is refused before local image construction', {
  skip: process.platform !== 'win32',
}, () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'virki-manual-acl-negative-'));
  try {
    const grant = spawnSync('icacls.exe', [dir, '/grant', '*S-1-5-32-545:(OI)(CI)(M)'],
      { encoding: 'utf8', timeout: 5000 });
    assert.equal(grant.status, 0, 'owned throwaway directory must permit the negative fixture ACL');
    assert.throws(() => requirePrivateWindowsStagingParent(dir), /protected current-user\/system\/admin-only Windows DACL/u);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('offline Dockerfile cannot smuggle unreviewed FROM, COPY --from or frontend syntax', () => {
  const repo = path.resolve(fileURLToPath(new URL('..', import.meta.url)));
  const git = spawnSync('git', ['show', 'HEAD:infra/Dockerfile.prod'],
    { cwd: repo, encoding: 'utf8', timeout: 10000 });
  // WSL cannot open a Windows-native Git worktree .git pointer. In that
  // specific test environment normalize the checkout's CRLF text to the
  // reviewed Git blob's LF; production export itself never does this.
  const source = git.status === 0 ? git.stdout
    : process.platform === 'linux' && /microsoft|wsl/iu.test(os.release())
      ? readFileSync(path.join(repo, 'infra', 'Dockerfile.prod'), 'utf8').replaceAll('\r\n', '\n')
      : null;
  assert.ok(source, 'reviewed canonical Dockerfile test fixture unavailable');
  assert.doesNotThrow(() => assertPinnedOfflineDockerfileText(source));
  for (const altered of [
    `${source}\nFROM --platform=linux/amd64 ghcr.io/foreign/image AS surprise\n`,
    `${source}\nCOPY --from=ghcr.io/foreign/image /app /app\n`,
    `# syntax=docker/dockerfile:edge\n${source}`,
    source.replace('FROM build AS migrator',
      'FROM --platform=linux/amd64 ghcr.io/foreign/image AS migrator'),
  ]) assert.throws(() => assertPinnedOfflineDockerfileText(altered));
});
