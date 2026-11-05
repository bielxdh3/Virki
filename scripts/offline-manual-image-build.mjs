import { spawnSync } from 'node:child_process';
import { randomBytes, createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { mkdirSync, mkdtempSync, realpathSync, readFileSync, readdirSync, lstatSync, statSync, writeFileSync } from 'node:fs';
import { finished } from 'node:stream/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

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
const REVIEWED_DOCKERFILE_SHA256 = 'bc8d52637046cb517982bae67641c35a9a17b7c6b240498b2dc163736efd45ca';
const WINDOWS_DOCKER = 'C:\\Program Files\\Docker\\Docker\\resources\\bin\\docker.exe';
const WINDOWS_POWERSHELL = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';
const WINDOWS_WSL = 'C:\\Windows\\System32\\wsl.exe';
const ENGINE = 'npipe:////./pipe/dockerDesktopLinuxEngine';
const ROLES = Object.freeze([['runtime', 'production'], ['migrator', 'migrator']]);
const UNSEALED_DOCKER_CONTEXT = 'immutable source context, Dockerfile, npm cache and Prisma engine bytes cannot be independently bound at Docker read-time';

function requireIt(ok, label) { if (!ok) throw Error('Manual image build blocked: ' + label); }
function refuseUnsealedDockerContext() { requireIt(false, UNSEALED_DOCKER_CONTEXT); }
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

export function createOfflineManualBuildWithCachePlan({
  revision, stagingDirectory, attemptId, npmCacacheDirectory, prismaEngineDirectory,
} = {}) {
  const plan = createOfflineManualImagePlan({ revision, stagingDirectory, attemptId });
  const cacache = canonicalAbsolute(npmCacacheDirectory);
  const engines = canonicalAbsolute(prismaEngineDirectory);
  requireIt(path.basename(cacache) === '_cacache',
    'offline npm BuildKit context must contain only the npm content-addressed cache');
  const dockerfile = path.join(canonicalAbsolute(stagingDirectory), 'Dockerfile.manual-offline');
  return Object.freeze(plan.map((item) => {
    const args = [...item.buildArgs];
    const index = args.indexOf('-f');
    requireIt(index >= 0 && args[index + 1], 'Dockerfile pin missing');
    args[index + 1] = dockerfile;
    args.splice(index, 0, '--no-cache', '--build-context', `offline-npm-cacache=${cacache}`,
      '--build-context', `offline-prisma-engines=${engines}`);
    return Object.freeze({ ...item, buildArgs: Object.freeze(args) });
  }));
}

export function assertOfflineNpmCacheReceipt(receipt, {
  parent, receiptDirectory, revision, lockSha256,
} = {}) {
  const keys = ['status', 'sourceSha', 'packageLockSha256', 'packages', 'totalBytes',
    'cacheDirectory', 'buildNetwork', 'ghcr', 'ownerSignatureVerified', 'deployAuthorized'];
  requireIt(receipt && typeof receipt === 'object' && !Array.isArray(receipt) &&
    Object.keys(receipt).length === keys.length &&
    keys.every((key) => Object.hasOwn(receipt, key)) &&
    receipt.status === 'DEV_CACHE_VERIFIED_ONLY' &&
    FULL_SHA.test(revision ?? '') && receipt.sourceSha === revision &&
    /^[a-f0-9]{64}$/u.test(lockSha256 ?? '') && receipt.packageLockSha256 === lockSha256 &&
    receipt.packages === 339 && Number.isSafeInteger(receipt.totalBytes) &&
    receipt.totalBytes > 0 && receipt.totalBytes <= 8 * 1024 ** 3 &&
    receipt.buildNetwork === 'none' && receipt.ghcr === 'NOT_USED' &&
    receipt.ownerSignatureVerified === false && receipt.deployAuthorized === false &&
    canonicalAbsolute(receiptDirectory) === receiptDirectory &&
    path.dirname(receiptDirectory) === canonicalAbsolute(parent) &&
    /^npm-offline-[a-zA-Z0-9_-]{6,}$/u.test(path.basename(receiptDirectory)) &&
    receipt.cacheDirectory === path.join(receiptDirectory, 'cache', '_cacache'),
  'offline npm cache receipt does not bind exact source/lock or owner-private cache');
  return receipt.cacheDirectory;
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

/** Dedicated Linux Node O_NOFOLLOW broker; no shell, Windows to WSL E: only. */
export function pinnedWindowsPathToWsl(filename) {
  requireIt(typeof filename === 'string' && /^E:\\[A-Za-z0-9_.-]+(?:\\[A-Za-z0-9_.-]+)*$/u.test(filename) &&
    path.win32.normalize(filename) === filename &&
    filename.split('\\').slice(1).every((part) => part !== '.' && part !== '..' &&
      !part.endsWith('.') && !part.endsWith(' ')),
  'WSL source path is not a canonical limited E: local pathname');
  return '/mnt/e/' + filename.slice(3).split('\\').join('/');
}

export function assertLinuxTarVerificationResult(raw, expected) {
  let result;
  try { result = JSON.parse(raw); } catch { requireIt(false, 'invalid Linux Docker TAR verification reply'); }
  const fields = ['status', 'role', 'imageId', 'revision', 'source', 'platform', 'user',
    'archiveSha256', 'archiveSizeBytes', 'layerCount', 'ownerSignatureVerified',
    'dockerLoadAuthorized', 'transferAuthorized', 'deployAuthorized'];
  requireIt(result && typeof result === 'object' && !Array.isArray(result) &&
    Object.keys(result).length === fields.length && fields.every((f) => Object.hasOwn(result, f)) &&
    result.status === 'LOCAL_DOCKER_TAR_BYTES_VERIFIED_ONLY' &&
    result.role === expected?.role && result.imageId === expected?.imageId &&
    result.revision === expected?.revision && result.archiveSha256 === expected?.archiveSha256 &&
    result.archiveSizeBytes === expected?.archiveSizeBytes &&
    result.source === OCI_SOURCE && result.platform === 'linux/amd64' &&
    result.user === 'node:node' && Number.isSafeInteger(result.layerCount) &&
    result.layerCount >= 1 && result.layerCount <= 256 &&
    result.ownerSignatureVerified === false && result.dockerLoadAuthorized === false &&
    result.transferAuthorized === false && result.deployAuthorized === false,
  'Linux Docker TAR response mismatches pinned image identity or falsely authorizes deployment');
  return result;
}

function verifyWindowsTarThroughLinux({ archivePath, expectedImageId, expectedRevision,
  expectedArchiveSha256, expectedArchiveSizeBytes, role }) {
  requireIt(process.platform === 'win32' && lstatSync(WINDOWS_WSL).isFile(),
    'pinned Windows WSL executable unavailable');
  const script = fileURLToPath(new URL('./offline-local-tar-verify-linux.mjs', import.meta.url));
  const source = pinnedWindowsPathToWsl(script);
  const linuxArchive = pinnedWindowsPathToWsl(archivePath);
  const result = spawnSync(WINDOWS_WSL, [
    '-d', 'Ubuntu', '-u', 'root', '--', '/usr/bin/node', source,
    '--archive', linuxArchive, '--image-id', expectedImageId,
    '--revision', expectedRevision, '--sha256', expectedArchiveSha256,
    '--size', String(expectedArchiveSizeBytes), '--role', role,
  ], { shell: false, windowsHide: true, encoding: 'utf8',
    timeout: 600000, maxBuffer: 8192, env: {
      SystemRoot: process.env.SystemRoot, windir: process.env.windir,
      PATH: 'C:\\Windows\\System32;C:\\Windows',
      WSLENV: '',
    } });
  requireIt(!result.error && !result.signal && result.status === 0 &&
    typeof result.stdout === 'string' && result.stdout.length < 4096,
  'Linux O_NOFOLLOW Docker TAR verifier did not confirm the immutable archive');
  return assertLinuxTarVerificationResult(result.stdout.trim(), {
    role, imageId: expectedImageId, revision: expectedRevision,
    archiveSha256: expectedArchiveSha256,
    archiveSizeBytes: expectedArchiveSizeBytes,
  });
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
      (/[<>:"\\|?*]/u.test(part) || [...part].some((character) =>
        character.codePointAt(0) < 32))) && !casefolded.has(filename),
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

/**
 * FAIL-CLOSED until an independently enforced, immutable at-use transport is
 * available for ALL build inputs. Checking Git hashes before/after `docker build`
 * does not bind what the daemon reads from current-user-writable Windows paths:
 * the source directory, derived Dockerfile, npm cacache and Prisma engines can
 * each be substituted and restored while Docker consumes them. A private DACL
 * restricted to this same Windows user does NOT prevent such an attacker.
 *
 * This guard is deliberately not bypassable with a caller-supplied flag,
 * environment variable or fabricated receipt. It blocks local image creation;
 * it never asserts owner authentication or deployment authorization.
 */
export function launchOfflineManualDockerBuild(item, docker) {
  requireIt(item && Array.isArray(item.buildArgs) && item.buildArgs[0] === 'build' &&
    typeof docker === 'function', 'invalid offline Docker build launch request');
  refuseUnsealedDockerContext();
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
export async function buildOfflineManualImages({ repositoryRoot, stagingParent, revision,
  npmCacheReceiptPath, prismaEngineDirectory } = {}) {
  requireIt(process.platform === 'win32' && process.arch === 'x64', 'only reviewed local Windows Docker Desktop supported');
  requireIt(process.env.VIRKI_MANUAL_IMAGES_LOCAL_BUILD === '1', 'explicit local build opt-in missing');
  // Hard stop before filesystem reads, staging writes, Docker base inspection,
  // or any daemon contact. A same-user DACL cannot seal the four build inputs.
  // Planning and nonauthorizing cache-inspection APIs remain available.
  refuseUnsealedDockerContext();
  const repo = canonicalAbsolute(repositoryRoot);
  const parent = canonicalAbsolute(stagingParent);
  failIfAliases(repo);
  failIfAliases(parent);
  requirePrivateWindowsStagingParent(parent);
  requireIt(!childOf(repo, parent) && !childOf(parent, repo) && repo !== parent,
    'temporary source and repository roots must be disjoint');
  requireIt(FULL_SHA.test(revision ?? ''), 'invalid requested source SHA');
  const enginesPath = canonicalAbsolute(prismaEngineDirectory);
  const relativeEngines = path.relative(parent, enginesPath);
  requireIt(relativeEngines && relativeEngines !== '.' &&
    !relativeEngines.startsWith('..' + path.sep) && relativeEngines !== '..' &&
    !path.isAbsolute(relativeEngines) && relativeEngines.split(path.sep).length <= 2,
  'Prisma engine context must be within the owner-private staging parent');
  failIfAliases(enginesPath);
  requireIt(typeof npmCacheReceiptPath === 'string' &&
    canonicalAbsolute(npmCacheReceiptPath) === npmCacheReceiptPath &&
    path.basename(npmCacheReceiptPath) === 'npm-offline-cache-receipt.json',
  'exact owner-private npm cache receipt is required before a network-isolated image build');
  const receiptDirectory = path.dirname(npmCacheReceiptPath);
  requireIt(path.dirname(receiptDirectory) === parent, 'npm cache must share the protected owner staging parent');
  failIfAliases(receiptDirectory);
  const receiptStat = lstatSync(npmCacheReceiptPath);
  requireIt(receiptStat.isFile() && !receiptStat.isSymbolicLink() &&
    receiptStat.nlink === 1 && receiptStat.size > 0 && receiptStat.size <= 4096,
  'npm cache receipt is an unsafe or oversized file');
  const receipt = JSON.parse(readFileSync(npmCacheReceiptPath, 'utf8'));
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
  const env = { ...process.env };
  for (const key of Object.keys(env)) {
    if (/^(DOCKER_|BUILDKIT_|GIT_)/iu.test(key) || /^(HTTPS?_PROXY|ALL_PROXY|NO_PROXY)$/iu.test(key)) delete env[key];
  }
  env.DOCKER_CONFIG = emptyConfig;
  env.DOCKER_HOST = ENGINE;
  env.DOCKER_CONTEXT = 'default';
  env.DOCKER_BUILDKIT = '1';
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
    // Cache receipt and all 339 SRI-bound blobs MUST match Git's canonical
    // package-lock; an unsigned JSON success claim cannot substitute for bytes.
    phase = 'npm-cache-integrity';
    const { officialTarballPlan, verifyNpmCacacheIndex } = await import('./offline-npm-cache.mjs');
    const { verifyOfflinePrismaEngineDirectory,
      derivePinnedOfflineDockerfileWithPrismaEngines } =
      await import('./offline-prisma-engine-cache.mjs');
    const lockBytes = readFileSync(path.join(context, 'package-lock.json'));
    const lockSha256 = createHash('sha256').update(lockBytes).digest('hex');
    const cacheDirectory = assertOfflineNpmCacheReceipt(receipt, {
      parent, receiptDirectory, revision, lockSha256,
    });
    failIfAliases(path.dirname(cacheDirectory));
    failIfAliases(cacheDirectory);
    const entries = officialTarballPlan(JSON.parse(lockBytes.toString('utf8')));
    requireIt(entries.length === 339, 'npm lockfile tarball inventory changed');
    const verified = await verifyNpmCacacheIndex(path.dirname(cacheDirectory), entries);
    requireIt(verified.verified === receipt.packages && verified.totalBytes === receipt.totalBytes,
    'npm cache contains unverified or inconsistent package bytes');
    phase = 'prisma-engine-integrity';
    const engines = verifyOfflinePrismaEngineDirectory(enginesPath);
    const derivedDockerfile = path.join(session, 'Dockerfile.manual-offline');
    writeFileSync(derivedDockerfile, derivePinnedOfflineDockerfileWithPrismaEngines(
      readFileSync(path.join(context, 'infra', 'Dockerfile.prod'), 'utf8')),
    { flag: 'wx', mode: 0o600 });
    const buildPlan = createOfflineManualBuildWithCachePlan({ revision,
      stagingDirectory: session, attemptId, npmCacacheDirectory: cacheDirectory,
      prismaEngineDirectory: enginesPath });
    // Docker image inspect is a local-only metadata query, unlike build/pull.
    phase = 'cached-base-inspect';
    assertOfflineCachedBaseImage(docker(['image', 'inspect', BASE_IMAGE, '--format', '{{json .}}']));
    const imageIds = new Set();
    const metadata = {};
    for (const item of buildPlan) {
      phase = `${item.role}-source-integrity`;
      assertSourceMatchesCommittedBlobs(context, blobs);
      const checked = await verifyNpmCacacheIndex(path.dirname(cacheDirectory), entries);
      requireIt(checked.totalBytes === verified.totalBytes && checked.verified === 339,
        'npm cache changed before isolated image build');
      verifyOfflinePrismaEngineDirectory(enginesPath);
      phase = `${item.role}-image-build`;
      launchOfflineManualDockerBuild(item, docker);
      phase = `${item.role}-post-build-integrity`;
      assertSourceMatchesCommittedBlobs(context, blobs);
      const afterCache = await verifyNpmCacacheIndex(path.dirname(cacheDirectory), entries);
      requireIt(afterCache.totalBytes === verified.totalBytes && afterCache.verified === 339,
        'npm cache changed during isolated image build');
      verifyOfflinePrismaEngineDirectory(enginesPath);
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
      verifyWindowsTarThroughLinux({
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
      npmCacheLockSha256: lockSha256, npmCachePackagesVerified: 339,
      prismaEngineCommit: engines.engineCommit, prismaEngineTarget: engines.target,
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
    requireIt(process.argv.length === 10 && process.argv[2] === '--repository' &&
      process.argv[4] === '--staging-parent' && process.argv[6] === '--npm-cache-receipt' &&
      process.argv[8] === '--prisma-engine-dir',
    'usage: --repository <absolute-path> --staging-parent <absolute-path> --npm-cache-receipt <absolute-path> --prisma-engine-dir <absolute-path>');
    const revision = run('git', ['rev-parse', '--verify', 'HEAD'], { cwd: process.argv[3] }).trim();
    const result = await buildOfflineManualImages({ repositoryRoot: process.argv[3],
      stagingParent: process.argv[5], revision, npmCacheReceiptPath: process.argv[7],
      prismaEngineDirectory: process.argv[9] });
    process.stdout.write(JSON.stringify(result) + '\n');
  };
  runEntry().catch((error) => {
    const phase = /^Local manual image build failed closed at ([-a-z]+);/u.exec(error?.message ?? '')?.[1];
    process.stderr.write(`Manual local images NOT_READY${phase ? ` phase=${phase}` : ''}; no production authorization or deployment.\n`);
    process.exitCode = 1;
  });
}
