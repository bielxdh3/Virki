// Conservative local/offline deployment budget. The inputs must be separately
// measured on the target host or pinned to verified bundle bytes; this pure
// arithmetic is NOT, by itself, a host identity or release authorization gate.
const GiB = 1024n ** 3n;
const MiB = 1024n ** 2n;
const MIN_RESERVE = 4n * GiB;
const MAX_VALUE = 8n * 1024n ** 4n;

function boundedBytes(value, label) {
  if (!Number.isSafeInteger(value) || value < 1 || BigInt(value) > MAX_VALUE) {
    throw new Error(`Offline release capacity rejected: ${label} missing or unsafe`);
  }
  return BigInt(value);
}

/**
 * Refuse to count any anticipated Docker layer sharing or archive compression.
 * Requires at least 4 GiB *remaining after* transfer, materialization and a
 * disposable DB backup/restore budget. The caller must sample filesystem and
 * database sizes again immediately before real host mutations.
 */
export function assessOfflineReleaseCapacity({
  freeBytes, sourceArchiveBytes, runtimeArchiveBytes, migratorArchiveBytes,
  runtimeExpandedBytes, migratorExpandedBytes, databaseBytes,
} = {}) {
  const free = boundedBytes(freeBytes, "host free bytes");
  const source = boundedBytes(sourceArchiveBytes, "source TAR bytes");
  const runtimeTar = boundedBytes(runtimeArchiveBytes, "runtime TAR bytes");
  const migratorTar = boundedBytes(migratorArchiveBytes, "migrator TAR bytes");
  const runtimeImage = boundedBytes(runtimeExpandedBytes, "runtime expanded image bytes");
  const migratorImage = boundedBytes(migratorExpandedBytes, "migrator expanded image bytes");
  const database = boundedBytes(databaseBytes, "host DB footprint bytes");

  // Three staged archives; Docker may unpack/copy each image more than once;
  // a backup, isolated restore and PostgreSQL WAL/storage overhead; plus reserve.
  const archiveStaging = source + runtimeTar + migratorTar;
  const dockerMaterialization = (runtimeImage + migratorImage) * 2n;
  const databaseSafety = database * 3n + 512n * MiB;
  const total = archiveStaging + dockerMaterialization + databaseSafety + MIN_RESERVE;
  return Object.freeze({
    ok: free >= total,
    availableBytes: free.toString(),
    requiredBytes: total.toString(),
    deficitBytes: free >= total ? "0" : (total - free).toString(),
    retainedReserveBytes: MIN_RESERVE.toString(),
    limitation: "Caller must independently measure source/image/DB sizes and target disk free bytes immediately before activation.",
  });
}

export function requireOfflineReleaseCapacity(input) {
  const result = assessOfflineReleaseCapacity(input);
  if (!result.ok) {
    throw new Error(`Offline release capacity rejected: insufficient target disk; deficit ${result.deficitBytes} bytes`);
  }
  return result;
}
