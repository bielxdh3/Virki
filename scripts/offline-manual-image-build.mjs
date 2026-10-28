import { spawnSync } from 'node:child_process';
import { randomBytes, createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { mkdirSync, mkdtempSync, realpathSync, readFileSync, readdirSync, lstatSync, statSync, writeFileSync } from 'node:fs';
import { finished } from 'node:stream/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyOfflineDockerSaveTar } from './lib/offline-docker-tar-verifier.mjs';

// An independent GitHub/GHCR-free DEVELOPER image builder. It builds only
// committed source and emits unsigned local evidence, never release authority.
// Real manual production acceptance MUST be a separate owner-installed path.
const FULL_SHA = /^[a-f0-9]{40}$/u;
const ATTEMPT = /^[a-f0-9]{24}$/u;
const IMAGE_ID = /^sha256:[a-f0-9]{64}$/u;
const OCI_SOURCE = 'https://github.com/bielxdh3/Virki';
const BASE_DIGEST = '0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402';
const BASE_IMAGE = `node:22-alpine@sha256:${BASE_DIGEST}`;
// Independently reviewed pinned Dockerfile Git-blob bytes for this DEV image
// builder. Any future Dockerfile source change requires a conscious re-review
// and a new fixed pin; arbitrary FROM/COPY/frontend syntax cannot enter via a
// supposedly pinned source SHA without invalidating this precise content hash.
const REVIEWED_DOCKERFILE_SHA256 = '9c75a70445f8df7184d6c4e321c95524210504e18760c3ff1d280534a40563ef';
const WINDOWS_DOCKER = 'C:\\Program Files\\Docker\\Docker\\resources\\bin\\docker.exe';
const WINDOWS_POWERSHELL = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';
const ENGINE = 'npipe:////./pipe/dockerDesktopLinuxEngine';
const ROLES = Object.freeze([['runtime', 'production'], ['migrator', 'migrator']]);

function requireIt(ok, label) { if (!ok) throw Error('Manual image build blocked: ' + label); }
function canonicalAbsolute(filename) {
  requireIt(typeof filename === 'string' && filename.length > 3 && filename.length < 4096 &&
    path.isAbsolute(filename) && path.normalize(filename) === filename && !filename.includes('\0'), 'noncanonical absolute path');
  return filename;
}
function childOf(root, child) { return child.startsWith(root + path.sep); }
function failIfAliases(filename) {
  for (let cursor = filename;; cursor = path.dirname(cursor)) {
    const stat = lstatSync(cursor);
    requireIt(!stat.isSymbolicLink() && stat.isDirectory(), 'symlinked or non-directory ancestor');
    if (cursor === path.dirname(cursor)) break;
  }
  requireIt(realpathSync.native(filename) === filename, 'noncanonical realpath');
}

export function requirePrivateWindowsStagingParent(directory) {
  // This is a *precondition*, not an ACL repair API. Node's `mode:0700`
  // creation does NOT make a Windows directory private. Only a separately
  // provisioned owner-owned non-inheriting DACL is accepted.
  const script = String.raw`$ErrorActionPreference='Stop';
try {
  $a=Get-Acl -LiteralPath $env:VIRKI_LOCAL_STAGING_PARENT;
  $owner=(New-Object System.Security.Principal.NTAccount($a.Owner)).Translate([System.Security.Principal.SecurityIdentifier]).Value;
  $me=[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value;
  if ($owner -ne $me -or -not $a.AreAccessRulesProtected) { exit 2 }
  $allowed=@($me,'S-1-5-18','S-1-5-32-544');
  foreach ($rule in $a.Access) {
    $sid=$rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value;
    if ($rule.AccessControlType.ToString() -ne 'Allow' -or $allowed -notcontains $sid) { exit 3 }
  }
  Write-Output 'OWNER_PRIVATE_DACL'; exit 0
} catch { exit 4 }`;
  const result = spawnSync(WINDOWS_POWERSHELL, [
    '-NoProfile', '-NonInteractive', '-Command', script,
  ], { encoding: 'utf8', shell: false, windowsHide: true, timeout: 10000,
    env: { ...process.env, VIRKI_LOCAL_STAGING_PARENT: directory }, maxBuffer: 2048 });
  requireIt(!result.error && !result.signal && result.status === 0 &&
    result.stdout?.trim() === 'OWNER_PRIVATE_DACL',
  'staging parent must have a protected current-user/system/admin-only Windows DACL');
}

export function createOfflineManualImagePlan({ revision, stagingDirectory, attemptId } = {}) {
  requireIt(FULL_SHA.test(revision ?? '') && ATTEMPT.test(attemptId ?? ''), 'invalid revision or attempt identifier');
  const root = canonicalAbsolute(stagingDirectory);
  const context = path.join(root, 'source');
  return Object.freeze(ROLES.map(([role, target]) => {
    const tag = `virki-local-${attemptId}-${role}:build`;
    const tarPath = path.join(root, `${role}.tar`);
    return Object.freeze({
      role, target, tag, tarPath,
      buildArgs: Object.freeze([
        'build', '--pull=false', '--network=none', '--platform', 'linux/amd64',
        '-f', path.join(context, 'infra', 'Dockerfile.prod'), '--target', target,
        '--build-arg', `VIRKI_BUILD_REVISION=${revision}`, '--tag', tag, context,
      ]),
    });
  }));
}

export function assertOfflineLocalImageInspect(raw, { revision, role } = {}) {
  requireIt(FULL_SHA.test(revision ?? '') && ROLES.some(([item]) => item === role), 'invalid expected image identity');
  let inspected;
  try { inspected = JSON.parse(raw); } catch { requireIt(false, 'invalid Docker inspection JSON'); }
  requireIt(inspected && typeof inspected === 'object' && !Array.isArray(inspected) &&
    IMAGE_ID.test(inspected.Id) && inspected.Os === 'linux' && inspected.Architecture === 'amd64' &&
    inspected.Config && typeof inspected.Config === 'object' &&
    inspected.Config.Labels?.['org.opencontainers.image.revision'] === revision &&
    inspected.Config.Labels?.['org.opencontainers.image.source'] === OCI_SOURCE &&
    inspected.Config.User === 'node:node', 'unexpected Docker image provenance, platform or runtime UID');
  return Object.freeze({ role, imageId: inspected.Id, os: inspected.Os,
    architecture: inspected.Architecture, labels: Object.freeze({
      'org.opencontainers.image.revision': revision,
      'org.opencontainers.image.source': OCI_SOURCE,
    }) });
}

// `docker build --pull=false` does NOT guarantee no registry access when a
// digest-pinned base is missing. Require its exact local RepoDigest first.
export function assertOfflineCachedBaseImage(raw) {
  let image;
  try { image = JSON.parse(raw); } catch { requireIt(false, 'invalid cached-base Docker JSON'); }
  const recognized = new Set([`node@sha256:${BASE_DIGEST}`, `docker.io/library/node@sha256:${BASE_DIGEST}`]);
  requireIt(image && !Array.isArray(image) && IMAGE_ID.test(image.Id) &&
    image.Os === 'linux' && image.Architecture === 'amd64' &&
    Array.isArray(image.RepoDigests) &&
    image.RepoDigests.some((ref) => recognized.has(ref)),
  'pinned base image is not cached locally; no registry fallback is allowed');
}

export function assertPinnedOfflineDockerfileText(contents) {
  requireIt(typeof contents === 'string' &&
    createHash('sha256').update(contents, 'utf8').digest('hex') === REVIEWED_DOCKERFILE_SHA256,
  'Dockerfile is not the exact owner-reviewed canonical Git source');
  const bases = contents.split(/\r?\n/u).map((line) => /^FROM\s+([^\s]+)(?:\s+AS\s+[^\s]+)?\s*$/iu.exec(line.trim()))
    .filter(Boolean).map((match) => match[1]);
  requireIt(bases.length >= 2 && bases.every((ref) => ref === BASE_IMAGE ||
    ['build', 'production-dependencies'].includes(ref)),
  'Dockerfile introduces an unreviewed or non-cached base');
}

function assertPinnedDockerfile(sourceDir) {
  assertPinnedOfflineDockerfileText(readFileSync(path.join(sourceDir, 'infra', 'Dockerfile.prod'), 'utf8'));
}

function run(binary, args, options = {}) {
  const result = spawnSync(binary, args, {
    cwd: options.cwd, env: options.env, input: options.input, encoding: 'utf8',
    windowsHide: true, shell: false, timeout: options.timeout ?? 30000,
    maxBuffer: 2 * 1024 * 1024,
  });
  requireIt(!result.error && !result.signal && result.status === 0,
    'local command failed; preserve partial artifacts for inspection');
  return result.stdout ?? '';
}

function inspectCommittedTree(repositoryRoot, revision, execute) {
  const git = (args) => execute('git', args, { cwd: repositoryRoot });
  requireIt(git(['rev-parse', '--verify', 'HEAD']).trim() === revision, 'Git HEAD mismatches requested source');
  requireIt(git(['status', '--porcelain', '--untracked-files=normal']).trim() === '', 'source worktree not clean');
  const tree = git(['ls-tree', '-rz', '--full-tree', revision]);
  requireIt(tree.endsWith('\0') && tree.length > 0, 'source tree missing');
  const entries = [];
  const casefolded = new Set();
  for (const record of tree.split('\0').filter(Boolean)) {
    const match = /^(100644|100755) blob ([a-f0-9]{40})\t(.+)$/us.exec(record);
    requireIt(match, 'unsafe tracked symlink, submodule or Git tree entry');
    const filename = match[3].replaceAll('\\', '/').toLowerCase();
    requireIt(!filename.startsWith('/') && !filename.includes('../') &&
      !filename.split('/').some((part) => part === '..' || part === '.env' ||
      part === '.production.operator.json' || part === '.git' || part === '.ghcr-read-token' ||
      part === '.npmrc' || part === 'secrets' ||
      (part === 'backups' && filename !== 'infra/backups/.gitkeep') ||
      (part.startsWith('.env.') && part !== '.env.example') ||
      part.startsWith('.dev.vars')) &&
      !/\.(?:pem|key|p12|pfx|dump|sqlite|sqlite3|db|mbox|zip|tar|tgz)$/u.test(filename),
    'committed tree contains restricted backup/credential/archive path');
    const rawName = match[3];
    const parts = rawName.split('/');
    requireIt(!parts.some((part) => part === '' || part.endsWith('.') || part.endsWith(' ') ||
      /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/iu.test(part) ||
      /[<>:"\\|?*\u0000-\u001f]/u.test(part)) && !casefolded.has(filename),
    'Git source cannot be faithfully extracted to Windows pathnames');
    casefolded.add(filename);
    entries.push(Object.freeze({ file: rawName, objectId: match[2] }));
  }
  requireIt(entries.length > 0, 'empty committed source tree');
  return Object.freeze(entries);
}

export function assertSourceMatchesCommittedBlobs(directory, entries) {
  requireIt(Array.isArray(entries) && entries.length > 0, 'missing pinned Git blob list');
  const expected = new Map(entries.map((entry) => [entry.file, entry.objectId]));
  requireIt(expected.size === entries.length, 'duplicate Git blob identity');
  const observed = new Set();
  const visit = (root, prefix = '') => {
    for (const entry of readdirSync(root, { withFileTypes: true })) {
      const child = path.join(root, entry.name);
      const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
      const st = lstatSync(child, { bigint: true });
      requireIt(!st.isSymbolicLink(), 'source contains a symbolic link or reparse point');
      if (st.isDirectory()) { visit(child, relative); continue; }
      requireIt(st.isFile() && st.nlink === 1n && st.size <= 64n * 1024n * 1024n && expected.has(relative) &&
        !observed.has(relative), 'source contains unexpected, oversized or repeated file');
      const bytes = readFileSync(child);
      const oid = createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex');
      const after = lstatSync(child, { bigint: true });
      requireIt(oid === expected.get(relative) &&
        ['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs'].every((key) => st[key] === after[key]),
      'extracted source differs from committed Git blob or mutated mid-read');
      observed.add(relative);
    }
  };
  visit(directory);
  requireIt(observed.size === expected.size, 'extracted source missing Git blobs');
}

async function fileSha256(filename) {
  const sha = createHash('sha256');
  const stream = createReadStream(filename, { highWaterMark: 256 * 1024 });
  stream.on('data', (chunk) => sha.update(chunk));
  await finished(stream);
  return sha.digest('hex');
}

/**
 * Opt-in, LOCAL-ONLY build+export. No owner signature, GHCR network access,
 * deployment, image import to a remote host, rollback or success assertion.
 * All generated source/image receipts remain unsigned and NOT_AUTHORIZED.
 */
export async function buildOfflineManualImages({ repositoryRoot, stagingParent, revision } = {}) {
  requireIt(process.platform === 'win32' && process.arch === 'x64', 'only reviewed local Windows Docker Desktop supported');
  requireIt(process.env.VIRKI_MANUAL_IMAGES_LOCAL_BUILD === '1', 'explicit local build opt-in missing');
  const repo = canonicalAbsolute(repositoryRoot);
  const parent = canonicalAbsolute(stagingParent);
  failIfAliases(repo);
  failIfAliases(parent);
  requirePrivateWindowsStagingParent(parent);
  requireIt(!childOf(repo, parent) && !childOf(parent, repo) && repo !== parent,
    'temporary source and repository roots must be disjoint');
  requireIt(FULL_SHA.test(revision ?? ''), 'invalid requested source SHA');
  requireIt(lstatSync(WINDOWS_DOCKER).isFile(), 'pinned Docker Desktop executable missing');

  // Authenticode verifies the CLI before first daemon contact; a third-party
  // replacement at the reviewed location must never be accepted silently.
  const quoted = WINDOWS_DOCKER.replaceAll("'", "''");
  const signature = run('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command',
    `(Get-AuthenticodeSignature -LiteralPath '${quoted}').Status.ToString()`]).trim();
  requireIt(signature === 'Valid', 'Docker Desktop Authenticode signature invalid');

  const emptyConfig = mkdtempSync(path.join(parent, 'docker-cli-'));
  const session = mkdtempSync(path.join(parent, 'manual-images-'));
  const attemptId = randomBytes(12).toString('hex');
  const plan = createOfflineManualImagePlan({ revision, stagingDirectory: session, attemptId });
  const env = { ...process.env };
  for (const key of Object.keys(env)) {
    if (/^(DOCKER_|BUILDKIT_|GIT_)/iu.test(key) || /^(HTTPS?_PROXY|ALL_PROXY|NO_PROXY)$/iu.test(key)) delete env[key];
  }
  env.DOCKER_CONFIG = emptyConfig;
  env.DOCKER_HOST = ENGINE;
  env.DOCKER_CONTEXT = 'default';
  const docker = (args, timeout = 30000) => run(WINDOWS_DOCKER, ['--host', ENGINE, '--config', emptyConfig, ...args],
    { env, timeout });
  let phase = 'source-preflight';
  try {
    const blobs = inspectCommittedTree(repo, revision, run);
    // Git archive contains ONLY committed Git source; no ignored local secrets.
    const archive = path.join(session, 'source.tar');
    const context = path.join(session, 'source');
    mkdirSync(context, { mode: 0o700 });
    // Git for Windows with global core.autocrlf=true may otherwise re-encode
    // archive members as CRLF even though the signed Git blob is LF. Pin
    // archive conversion off: at-use Git blob SHA verification follows.
    run('git', ['-c', 'core.autocrlf=false', 'archive', '--format=tar', '--output=' + archive, revision], { cwd: repo });
    phase = 'source-extract';
    run('tar', ['-xf', archive, '-C', context], { timeout: 120000 });
    requireIt(readdirSync(context).length > 0 && statSync(path.join(context, 'infra', 'Dockerfile.prod')).isFile(),
      'source archive extraction invalid');
    phase = 'source-blob-integrity';
    assertSourceMatchesCommittedBlobs(context, blobs);
    assertPinnedDockerfile(context);
    // Docker image inspect is a local-only metadata query, unlike build/pull.
    phase = 'cached-base-inspect';
    assertOfflineCachedBaseImage(docker(['image', 'inspect', BASE_IMAGE, '--format', '{{json .}}']));
    const imageIds = new Set();
    const metadata = {};
    for (const item of plan) {
      phase = `${item.role}-source-integrity`;
      assertSourceMatchesCommittedBlobs(context, blobs);
      phase = `${item.role}-image-build`;
      docker(item.buildArgs, 1200000);
      phase = `${item.role}-post-build-integrity`;
      assertSourceMatchesCommittedBlobs(context, blobs);
      phase = `${item.role}-image-inspect`;
      const inspected = assertOfflineLocalImageInspect(docker(['image', 'inspect', item.tag, '--format', '{{json .}}']),
        { revision, role: item.role });
      requireIt(!imageIds.has(inspected.imageId), 'both image roles unexpectedly have one image identity');
      imageIds.add(inspected.imageId);
      phase = `${item.role}-image-save`;
      docker(['image', 'save', inspected.imageId, '-o', item.tarPath], 300000);
      const size = statSync(item.tarPath).size;
      requireIt(Number.isSafeInteger(size) && size > 0 && size <= 8 * 1024 ** 3, 'unsafe exported Docker TAR length');
      const digest = await fileSha256(item.tarPath);
      phase = `${item.role}-tar-verify`;
      await verifyOfflineDockerSaveTar({
        archivePath: item.tarPath, expectedImageId: inspected.imageId,
        expectedRevision: revision, expectedArchiveSha256: digest,
        expectedArchiveSizeBytes: size, role: item.role,
      });
      metadata[item.role] = { ...inspected, archivePath: item.tarPath, archiveSha256: digest, archiveSizeBytes: size };
    }
    phase = 'final-source-integrity';
    assertSourceMatchesCommittedBlobs(context, blobs);
    const output = Object.freeze({
      status: 'LOCAL_SOURCE_AND_IMAGES_VERIFIED_ONLY',
      sourceSha: revision, directory: session, sourceArchive: archive,
      sourceArchiveSha256: await fileSha256(archive), images: metadata,
      hostedCi: 'NOT_RUN', codeql: 'NOT_RUN', ghcr: 'NOT_USED',
      ownerSignatureVerified: false, deployAuthorized: false, transferAuthorized: false,
    });
    writeFileSync(path.join(session, 'local-image-receipt.json'), JSON.stringify(output) + '\n',
      { flag: 'wx', mode: 0o600 });
    return output;
  } catch {
    // Retain this attempt and its unique tags for manual reconciliation; do
    // not delete guessed Docker image IDs or hide incomplete source archives.
    throw Error('Local manual image build failed closed at ' + phase + '; owner-scoped staging preserved');
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const runEntry = async () => {
    requireIt(process.argv.length === 6 && process.argv[2] === '--repository' &&
      process.argv[4] === '--staging-parent', 'usage: --repository <absolute-path> --staging-parent <absolute-path>');
    const revision = run('git', ['rev-parse', '--verify', 'HEAD'], { cwd: process.argv[3] }).trim();
    const result = await buildOfflineManualImages({ repositoryRoot: process.argv[3],
      stagingParent: process.argv[5], revision });
    process.stdout.write(JSON.stringify(result) + '\n');
  };
  runEntry().catch((error) => {
    const phase = /^Local manual image build failed closed at ([-a-z]+);/u.exec(error?.message ?? '')?.[1];
    process.stderr.write(`Manual local images NOT_READY${phase ? ` phase=${phase}` : ''}; no production authorization or deployment.\n`);
    process.exitCode = 1;
  });
}
