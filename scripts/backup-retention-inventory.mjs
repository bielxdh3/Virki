import { createHash } from "node:crypto";
import { constants, createReadStream } from "node:fs";
import { lstat, open, readFile, readdir, realpath, statfs } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const backupNamePattern = /^bielos-\d{8}-\d{6}-[a-f0-9]{6}\.dump$/u;
const markerName = ".bielos-migration-verification";
const minimumFreePercent = 15;

function parseMarker(contents) {
  const entries = contents.trimEnd().split("\n").map((line) => {
    const separator = line.indexOf("=");
    if (separator < 1) return null;
    return [line.slice(0, separator), line.slice(separator + 1)];
  });
  if (entries.some((entry) => !entry)) return null;
  const marker = Object.fromEntries(entries);
  if (
    entries.length !== 4 ||
    Object.keys(marker).length !== 4 ||
    !/^[0-9a-f]{40}$/u.test(marker.revision ?? "") ||
    !backupNamePattern.test(marker.backup_name ?? "") ||
    !/^[0-9a-f]{64}$/u.test(marker.backup_sha256 ?? "") ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/u.test(marker.verified_at ?? "") ||
    !Number.isFinite(Date.parse(marker.verified_at))
  ) return null;
  return marker;
}

async function sha256File(filePath) {
  if (!constants.O_NOFOLLOW) throw new Error("This platform cannot safely inspect backup files without following symlinks.");
  const handle = await open(filePath, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const openedStat = await handle.stat();
    if (!openedStat.isFile() || openedStat.nlink !== 1) throw new Error("Backup changed to an unsafe filesystem object during inventory.");
    const digest = createHash("sha256");
    for await (const chunk of createReadStream(filePath, { fd: handle.fd, autoClose: false })) digest.update(chunk);
    return digest.digest("hex");
  } finally {
    await handle.close();
  }
}

function normalizeDirectory(directory) {
  if (typeof directory !== "string" || directory.length === 0 || !path.isAbsolute(directory)) {
    throw new Error("Provide an explicit absolute backup inventory directory.");
  }
  return path.resolve(directory);
}

export async function inventoryBackupDirectory(directory, {
  now = Date.now(),
  getStatfs = statfs,
} = {}) {
  const absoluteDirectory = normalizeDirectory(directory);
  const directoryStat = await lstat(absoluteDirectory);
  if (!directoryStat.isDirectory() || directoryStat.isSymbolicLink()) {
    throw new Error("Backup inventory path must be a real directory, not a symlink.");
  }
  const canonicalDirectory = await realpath(absoluteDirectory);
  const fs = await getStatfs(canonicalDirectory);
  const totalBytes = Number(fs.blocks) * Number(fs.bsize);
  const availableBytes = Number(fs.bavail) * Number(fs.bsize);
  if (!Number.isFinite(totalBytes) || totalBytes <= 0 || !Number.isFinite(availableBytes) || availableBytes < 0) {
    throw new Error("Filesystem capacity could not be read safely.");
  }

  let marker;
  let markerStatus = "absent";
  const markerPath = path.join(canonicalDirectory, markerName);
  try {
    const markerStat = await lstat(markerPath);
    if (process.platform === "win32" || !markerStat.isFile() || markerStat.isSymbolicLink() || markerStat.nlink !== 1 || (markerStat.mode & 0o777) !== 0o600) {
      markerStatus = "unsafe";
    } else {
      marker = parseMarker(await readFile(markerPath, "utf8"));
      markerStatus = marker ? "present" : "malformed";
    }
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }

  const entries = await readdir(canonicalDirectory, { withFileTypes: true });
  const records = [];
  let markerBackupMatched = false;
  for (const entry of entries) {
    if (entry.name === markerName) continue;
    const filePath = path.join(canonicalDirectory, entry.name);
    if (entry.isSymbolicLink()) {
      records.push({ name: entry.name, classification: "symlink", action: "PRESERVE", bytes: null });
      continue;
    }
    let fileStat;
    try {
      fileStat = await lstat(filePath);
    } catch {
      records.push({ name: entry.name, classification: "unreadable", action: "PRESERVE", bytes: null });
      continue;
    }
    if (!fileStat.isFile() || fileStat.nlink !== 1) {
      records.push({ name: entry.name, classification: "unexpected_type_or_links", action: "PRESERVE", bytes: null });
      continue;
    }
    if (entry.name.includes(".partial") || entry.name.startsWith(".")) {
      records.push({ name: entry.name, classification: "partial_or_temporary", action: "PRESERVE", bytes: fileStat.size });
      continue;
    }
    if (!backupNamePattern.test(entry.name)) {
      records.push({ name: entry.name, classification: "unknown_file", action: "PRESERVE", bytes: fileStat.size });
      continue;
    }
    let classification = "backup_without_durable_verification";
    if (markerStatus === "present" && marker.backup_name === entry.name) {
      const digest = await sha256File(filePath);
      if (digest === marker.backup_sha256) {
        classification = "matches_current_verification_marker";
        markerBackupMatched = true;
      } else {
        classification = "verification_hash_mismatch";
      }
    }
    records.push({ name: entry.name, classification, action: "PRESERVE", bytes: fileStat.size });
  }
  if (markerStatus === "present" && !markerBackupMatched) markerStatus = "unmatched";
  const freePercent = (availableBytes / totalBytes) * 100;
  const inventory = {
    directory: canonicalDirectory,
    readOnly: true,
    deletionCapability: false,
    verificationMarker: {
      status: markerStatus,
      recordedAt: marker?.verified_at ?? null,
      currentForNextDeployment: Boolean(marker && markerStatus === "present" && markerBackupMatched && now - Date.parse(marker.verified_at) <= 86_400_000 && Date.parse(marker.verified_at) <= now + 300_000),
    },
    disk: {
      totalBytes,
      availableBytes,
      availablePercent: Number(freePercent.toFixed(2)),
      warningThresholdPercent: minimumFreePercent,
      pressureAlert: freePercent < minimumFreePercent,
    },
    retentionPlan: {
      plannedDeletions: [],
      preserveAllBecause: "No owner-approved retention policy or durable per-backup restore metadata exists.",
    },
    files: records,
  };
  return inventory;
}

function parseArguments(args) {
  if (args.length !== 2 || args[0] !== "--directory") {
    throw new Error("Usage: node scripts/backup-retention-inventory.mjs --directory <absolute-directory>");
  }
  return args[1];
}

function isMainModule() {
  return process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
}

if (isMainModule()) {
  try {
    const inventory = await inventoryBackupDirectory(parseArguments(process.argv.slice(2)));
    console.log(JSON.stringify(inventory, null, 2));
    if (inventory.disk.pressureAlert) process.exitCode = 2;
  } catch (error) {
    console.error(error instanceof Error ? error.message : "Backup inventory failed safely.");
    process.exitCode = 1;
  }
}
