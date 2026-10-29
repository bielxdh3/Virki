import { constants } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyOfflineDockerSaveTar } from './lib/offline-docker-tar-verifier.mjs';

// Linux / WSL-only data check. The Windows Node file API has NO O_NOFOLLOW,
// so do not weaken the existing FD-bound TAR verifier to accept Windows paths.
// Never imports into Docker, signs a release, or authorizes deployment.
export async function verifyOfflineLocalTarOnLinux({ archivePath, imageId, revision,
  sha256, size, role } = {}) {
  if (process.platform !== 'linux' ||
      !Number.isInteger(constants.O_NOFOLLOW) ||
      typeof archivePath !== 'string' || !path.isAbsolute(archivePath) ||
      path.normalize(archivePath) !== archivePath ||
      !/^(runtime|migrator)$/u.test(role ?? '') ||
      !/^[a-f0-9]{40}$/u.test(revision ?? '') ||
      !/^sha256:[a-f0-9]{64}$/u.test(imageId ?? '') ||
      !/^[a-f0-9]{64}$/u.test(sha256 ?? '') ||
      !Number.isSafeInteger(size) || size < 1024 || size > 8 * 1024 ** 3) {
    throw Error('Linux local Docker TAR validation refused');
  }
  const verified = await verifyOfflineDockerSaveTar({ archivePath,
    expectedImageId: imageId, expectedRevision: revision,
    expectedArchiveSha256: sha256, expectedArchiveSizeBytes: size, role });
  return Object.freeze({ status: 'LOCAL_DOCKER_TAR_BYTES_VERIFIED_ONLY',
    ...verified, ownerSignatureVerified: false, dockerLoadAuthorized: false,
    transferAuthorized: false, deployAuthorized: false });
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const a = process.argv.slice(2);
    if (a.length !== 12 || a[0] !== '--archive' || a[2] !== '--image-id' ||
        a[4] !== '--revision' || a[6] !== '--sha256' || a[8] !== '--size' ||
        a[10] !== '--role') throw Error('Exact Linux verifier args required');
    const result = await verifyOfflineLocalTarOnLinux({
      archivePath: a[1], imageId: a[3], revision: a[5],
      sha256: a[7], size: Number(a[9]), role: a[11],
    });
    process.stdout.write(JSON.stringify(result) + '\n');
  } catch {
    process.stderr.write('Offline local Docker TAR NOT_VERIFIED; no release or deploy authority.\n');
    process.exitCode = 1;
  }
}
