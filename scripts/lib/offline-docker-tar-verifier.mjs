import { createHash } from "node:crypto";
import { constants, fstatSync, lstatSync, read as readFd } from "node:fs";
import { open } from "node:fs/promises";
import path from "node:path";

// Pure read-only inspection of single-image Docker-save classic and OCI hybrid
// TARs. Each OCI blob and the full index -> manifest -> config/layers descriptor
// graph must agree with content digests, sizes, and the Docker save manifest.
// Do not load/extract archives here. The caller must authenticate the expected
// image ID and TAR digest independently (e.g. through the owner-signed manifest).
const SOURCE = "https://github.com/bielxdh3/Virki";
const IMAGE_ID = /^sha256:[0-9a-f]{64}$/u;
const GIT_SHA = /^[0-9a-f]{40}$/u;
const ARCHIVE_SHA = /^[0-9a-f]{64}$/u;
const MAX_ARCHIVE = 8 * 1024 * 1024 * 1024;
const MAX_CONFIG = 4 * 1024 * 1024;
const MAX_MANIFEST = 1024 * 1024;
const MAX_AUXILIARY = 1024 * 1024;
const MAX_COLLECTED = 16 * 1024 * 1024;
const MAX_MEMBERS = 1024;
const MAX_LAYERS = 256;
const READ_BLOCK = 64 * 1024;
const DECODER = new TextDecoder("utf-8", { fatal: true });
const OCI_INDEX = "application/vnd.oci.image.index.v1+json";
const OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json";
const OCI_CONFIG = "application/vnd.oci.image.config.v1+json";
const OCI_LAYER = "application/vnd.oci.image.layer.v1.tar";
const OCI_BLOB = /^blobs\/sha256\/([0-9a-f]{64})$/u;

function refuse(reason) {
  throw new Error(`Offline Docker TAR rejected: ${reason}`);
}

function record(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactKeys(object, keys, label) {
  if (!record(object) || Object.keys(object).sort().join(",") !== [...keys].sort().join(",")) {
    refuse(`${label} has unexpected or missing fields`);
  }
}

// JSON.parse silently accepts repeated keys, including \u-escaped collisions.
// Parse strict JSON directly so names are unescaped before duplicate detection.
function strictJson(raw, label) {
  let source;
  try { source = DECODER.decode(raw); }
  catch { refuse(`${label} has invalid UTF-8`); }
  if (source.charCodeAt(0) === 0xfeff) refuse(`${label} has a BOM`);
  let pos = 0;
  let nodes = 0;
  const whitespace = () => {
    while (source[pos] === " " || source[pos] === "\n" ||
           source[pos] === "\r" || source[pos] === "\t") pos += 1;
  };
  function string() {
    if (source[pos] !== '"') refuse(`${label} expected a string`);
    const start = pos++;
    while (pos < source.length) {
      const char = source[pos++];
      if (char === '"') {
        try { return JSON.parse(source.slice(start, pos)); }
        catch { refuse(`${label} has an invalid JSON string`); }
      }
      if (char.charCodeAt(0) < 32) refuse(`${label} has a control byte in a string`);
      if (char === "\\") {
        const escape = source[pos++];
        if (escape === "u") {
          if (!/^[0-9a-fA-F]{4}$/u.test(source.slice(pos, pos + 4))) {
            refuse(`${label} has an invalid Unicode escape`);
          }
          pos += 4;
        } else if (!'"\\/bfnrt'.includes(escape ?? "")) {
          refuse(`${label} has an invalid JSON escape`);
        }
      }
    }
    refuse(`${label} has an unterminated string`);
  }
  function value(depth) {
    if (++nodes > 200000 || depth > 64) refuse(`${label} exceeds JSON complexity limits`);
    whitespace();
    if (source[pos] === '"') return string();
    if (source[pos] === "{") {
      pos += 1;
      const obj = Object.create(null);
      const keys = new Set();
      whitespace();
      if (source[pos] === "}") { pos += 1; return obj; }
      while (true) {
        whitespace();
        const key = string();
        if (keys.has(key)) refuse(`${label} has duplicate JSON keys`);
        keys.add(key);
        whitespace();
        if (source[pos++] !== ":") refuse(`${label} has an invalid object`);
        obj[key] = value(depth + 1);
        whitespace();
        const end = source[pos++];
        if (end === "}") return obj;
        if (end !== ",") refuse(`${label} has an invalid object separator`);
      }
    }
    if (source[pos] === "[") {
      pos += 1;
      const array = [];
      whitespace();
      if (source[pos] === "]") { pos += 1; return array; }
      while (true) {
        array.push(value(depth + 1));
        whitespace();
        const end = source[pos++];
        if (end === "]") return array;
        if (end !== ",") refuse(`${label} has an invalid array separator`);
      }
    }
    for (const [token, result] of [["true", true], ["false", false], ["null", null]]) {
      if (source.startsWith(token, pos)) { pos += token.length; return result; }
    }
    const match = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/u.exec(source.slice(pos));
    if (!match) refuse(`${label} has an invalid JSON value`);
    pos += match[0].length;
    const number = Number(match[0]);
    if (!Number.isFinite(number)) refuse(`${label} has a nonfinite number`);
    return number;
  }
  const parsed = value(0);
  whitespace();
  if (pos !== source.length) refuse(`${label} has trailing JSON data`);
  return parsed;
}

function tarAscii(header, start, length, label) {
  const bytes = header.subarray(start, start + length);
  const end = bytes.indexOf(0);
  const size = end === -1 ? length : end;
  if (end >= 0 && bytes.subarray(end).some((byte) => byte !== 0)) {
    refuse(`noncanonical ${label} TAR field`);
  }
  const value = bytes.subarray(0, size);
  if (value.some((byte) => byte < 32 || byte > 126)) refuse(`invalid ${label} TAR ASCII`);
  return value.toString("ascii");
}

function tarOctal(header, start, length, label) {
  const bytes = header.subarray(start, start + length);
  if (bytes[0] & 0x80) refuse(`binary ${label} TAR value forbidden`);
  const value = bytes.toString("ascii");
  if (!/^[ ]*[0-7]*[\0 ]*$/u.test(value)) refuse(`invalid ${label} TAR octal`);
  const digits = value.replace(/^[ ]*/u, "").replace(/[\0 ]*$/u, "");
  const parsed = digits ? Number.parseInt(digits, 8) : 0;
  if (!Number.isSafeInteger(parsed)) refuse(`oversized ${label} TAR value`);
  return parsed;
}

function safeMemberName(raw, isDirectory) {
  if (typeof raw !== "string" || !raw || raw.length > 255 ||
      raw.includes("\\") || raw.startsWith("/") || raw.includes("//") ||
      /[^a-zA-Z0-9_./-]/u.test(raw)) refuse("unsafe TAR member path");
  const normalized = isDirectory ? raw.replace(/\/$/u, "") : raw;
  const segments = normalized.split("/");
  if (segments.some((part) => !part || part === "." || part === "..") ||
      (!isDirectory && raw.endsWith("/"))) refuse("noncanonical TAR member path");
  return normalized;
}

function parseHeader(header) {
  if (header.toString("ascii", 257, 263) !== "ustar\0" ||
      header.toString("ascii", 263, 265) !== "00" ||
      header.subarray(500).some((byte) => byte !== 0)) refuse("unsupported TAR header format");
  const stored = tarOctal(header, 148, 8, "checksum");
  let actual = 0;
  for (let i = 0; i < 512; i += 1) actual += (i >= 148 && i < 156) ? 32 : header[i];
  if (stored !== actual) refuse("TAR checksum mismatch");
  const typeCode = header[156];
  if (typeCode !== 0 && typeCode !== 48 && typeCode !== 53) {
    refuse("symlinks, hardlinks, PAX, sparse and special TAR entries are forbidden");
  }
  const directory = typeCode === 53;
  const prefix = tarAscii(header, 345, 155, "prefix");
  const nameField = tarAscii(header, 0, 100, "name");
  const name = safeMemberName(prefix ? `${prefix}/${nameField}` : nameField, directory);
  if (tarAscii(header, 157, 100, "linkname") !== "" ||
      tarOctal(header, 108, 8, "uid") !== 0 ||
      tarOctal(header, 116, 8, "gid") !== 0 ||
      tarOctal(header, 329, 8, "devmajor") !== 0 ||
      tarOctal(header, 337, 8, "devminor") !== 0 ||
      !["", "root"].includes(tarAscii(header, 265, 32, "uname")) ||
      !["", "root"].includes(tarAscii(header, 297, 32, "gname"))) {
    refuse("unsafe TAR ownership or link metadata");
  }
  if (tarOctal(header, 100, 8, "mode") & ~0o777) {
    refuse("TAR member has special permission bits");
  }
  tarOctal(header, 136, 12, "mtime");
  const size = tarOctal(header, 124, 12, "size");
  if (directory && size !== 0) refuse("directory TAR member must be empty");
  return { name, directory, size };
}

function sameFile(a, b) {
  return ["dev", "ino", "mode", "nlink", "size", "mtimeNs", "ctimeNs"]
    .every((key) => a[key] === b[key]);
}

function ensureRegular(stat) {
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1n ||
      stat.size < 1024n || stat.size > BigInt(MAX_ARCHIVE) ||
      stat.size % 512n !== 0n) refuse("archive must be a bounded, aligned, single-link regular file");
}

function ensureNoAliases(filename) {
  let current = path.dirname(filename);
  while (true) {
    const meta = lstatSync(current, { bigint: true });
    if (!meta.isDirectory() || meta.isSymbolicLink()) refuse("unsafe archive directory ancestor");
    const parent = path.dirname(current);
    if (parent === current) return;
    current = parent;
  }
}

// Use the operating system's positional read on the caller's original FD.
// Never resolve or reopen a pathname from the FD-based entrypoint.
function readPinned(archiveFd, buffer, offset, length, position) {
  return new Promise((resolve, reject) => {
    readFd(archiveFd, buffer, offset, length, position, (error, bytesRead) => {
      if (error) reject(error);
      else resolve({ bytesRead });
    });
  });
}

function validateDockerConfig(raw, imageId, revision) {
  if (sha256(raw) !== imageId.slice(7)) refuse("config SHA-256 differs from expected image ID");
  const config = strictJson(raw, "image config");
  if (!record(config) || config.os !== "linux" || config.architecture !== "amd64" ||
      !record(config.config) || !record(config.config.Labels) ||
      config.config.Labels["org.opencontainers.image.source"] !== SOURCE ||
      config.config.Labels["org.opencontainers.image.revision"] !== revision) {
    refuse("image config platform or OCI provenance labels mismatch");
  }
  const user = config.config.User;
  // This release's Dockerfile explicitly runs both stages as node:node.
  // A mutable, empty, numeric root, or unknown named user is not acceptable.
  if (user !== "node:node") refuse("runtime/migrator image requires pinned nonroot user node:node");
  if (!record(config.rootfs) || config.rootfs.type !== "layers" ||
      !Array.isArray(config.rootfs.diff_ids) ||
      config.rootfs.diff_ids.length < 1 || config.rootfs.diff_ids.length > MAX_LAYERS ||
      config.rootfs.diff_ids.some((id) => !IMAGE_ID.test(id))) {
    refuse("image rootfs diff_ids are invalid");
  }
  return { user, diffIds: config.rootfs.diff_ids };
}

function validateManifest(raw, expectedImageId, layerHashes) {
  const manifest = strictJson(raw, "Docker save manifest");
  if (!Array.isArray(manifest) || manifest.length !== 1 ||
      !record(manifest[0])) refuse("archive must contain exactly one Docker image");
  const image = manifest[0];
  const configName = `${expectedImageId.slice(7)}.json`;
  if (Object.keys(image).sort().join(",") !== "Config,Layers,RepoTags" ||
      image.Config !== configName ||
      !(image.RepoTags === null || (Array.isArray(image.RepoTags) && image.RepoTags.length === 0)) ||
      !Array.isArray(image.Layers) || image.Layers.length < 1 ||
      image.Layers.length > MAX_LAYERS || image.Layers.length !== layerHashes.size) {
    refuse("Docker manifest has invalid config, repositories, or layer count");
  }
  const seen = new Set();
  for (const entry of image.Layers) {
    if (typeof entry !== "string" || !layerHashes.has(entry) || seen.has(entry)) {
      refuse("Docker manifest references duplicate or missing layer");
    }
    seen.add(entry);
  }
  return { configName, layers: image.Layers };
}

function ociDescriptor(object, mediaType, files, label, allowPlatform = false) {
  const keys = ["digest", "mediaType", "size"];
  if (allowPlatform && Object.hasOwn(object ?? {}, "platform")) keys.push("platform");
  exactKeys(object, keys, label);
  if (object.mediaType !== mediaType || !IMAGE_ID.test(object.digest) ||
      !Number.isSafeInteger(object.size) || object.size < 1) {
    refuse(`${label} unsupported media type, digest or length`);
  }
  const name = `blobs/sha256/${object.digest.slice(7)}`;
  const file = files.get(name);
  if (!file || file.size !== object.size || file.digest !== object.digest.slice(7)) {
    refuse(`${label} blob content or size does not match descriptor`);
  }
  if (allowPlatform && object.platform !== undefined) {
    exactKeys(object.platform, ["os", "architecture"], `${label} platform`);
    if (object.platform.os !== "linux" || object.platform.architecture !== "amd64") {
      refuse(`${label} platform differs from linux/amd64`);
    }
  }
  return { name, file };
}

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

/**
 * Independently verify the complete Docker-save archive and each layer's
 * uncompressed SHA-256 against its content-addressed image config. Uses one
 * pinned O_NOFOLLOW FD, absolute reads and bounded memory; never calls Docker.
 *
 * This authenticates content only relative to the caller's trusted expected
 * image ID + archive digest. It does not prove how the image was built, inspect
 * files *inside* layer tarballs, or grant deployment authorization. In particular
 * Docker image IDs are config digests, not registry manifest digests. The caller
 * must reverify before use and separately enforce host/owner policy.
 */
function validateExpectedIdentity({
  expectedImageId, expectedRevision, expectedArchiveSha256, expectedArchiveSizeBytes, role,
}) {
  if (!["runtime", "migrator"].includes(role) ||
      !IMAGE_ID.test(expectedImageId ?? "") ||
      !GIT_SHA.test(expectedRevision ?? "") ||
      !ARCHIVE_SHA.test(expectedArchiveSha256 ?? "") ||
      !Number.isSafeInteger(expectedArchiveSizeBytes) ||
      expectedArchiveSizeBytes < 1024 || expectedArchiveSizeBytes > MAX_ARCHIVE ||
      expectedArchiveSizeBytes % 512 !== 0) {
    refuse("invalid expected Docker archive identity");
  }
}

/**
 * Preview verifier for an already-open, caller-owned FileHandle.
 * It reads exclusively through fileHandle.fd, never opens the archive by
 * pathname, and leaves the handle open with its sequential cursor untouched.
 *
 * The caller must keep the handle open and exclusively owned until this promise
 * settles, pin the source/ownership policy, and prevent writes to the inode.
 * A content hash and before/after fstat reject observable mutations but cannot
 * make a concurrently writable inode into an atomic filesystem snapshot.
 * This result is content inspection, never a Docker load/deploy capability.
 */
export async function verifyOfflineDockerSaveTarFromHandle(request = {}) {
  if (!request || typeof request !== "object" || Array.isArray(request) ||
      Object.keys(request).sort().join(",") !== [
        "fileHandle", "expectedImageId", "expectedRevision", "expectedArchiveSha256",
        "expectedArchiveSizeBytes", "role",
      ].sort().join(",") ||
      !request.fileHandle || typeof request.fileHandle !== "object" ||
      typeof request.fileHandle.read !== "function" ||
      typeof request.fileHandle.stat !== "function" ||
      typeof request.fileHandle.close !== "function" ||
      !Number.isSafeInteger(request.fileHandle.fd) || request.fileHandle.fd < 0) {
    refuse("invalid caller-owned Docker archive FileHandle or expected identity fields");
  }
  validateExpectedIdentity(request);
  return verifyPinnedArchive(request.fileHandle.fd, request);
}

/**
 * Original pathname preview entrypoint. Keeps its no-follow path checks and
 * reuses the FD-bound parser after opening the file exactly once.
 */
export async function verifyOfflineDockerSaveTar({
  archivePath, expectedImageId, expectedRevision, expectedArchiveSha256,
  expectedArchiveSizeBytes, role,
} = {}) {
  const expected = {
    expectedImageId, expectedRevision, expectedArchiveSha256, expectedArchiveSizeBytes, role,
  };
  validateExpectedIdentity(expected);
  if (typeof archivePath !== "string" || archivePath.length > 4096 ||
      archivePath.includes("\0") || !path.isAbsolute(archivePath) ||
      path.normalize(archivePath) !== archivePath ||
      !Number.isInteger(constants.O_NOFOLLOW) || !Number.isInteger(constants.O_NONBLOCK)) {
    refuse("invalid Docker archive pathname or safe-file capabilities");
  }
  ensureNoAliases(archivePath);
  const pathBefore = lstatSync(archivePath, { bigint: true });
  ensureRegular(pathBefore);
  if (pathBefore.size !== BigInt(expectedArchiveSizeBytes)) refuse("archive length differs from expected");
  const handle = await open(archivePath, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    return await verifyPinnedArchive(handle.fd, expected, archivePath, pathBefore);
  } finally {
    await handle.close();
  }
}

async function verifyPinnedArchive(archiveFd, {
  expectedImageId, expectedRevision, expectedArchiveSha256, expectedArchiveSizeBytes, role,
}, archivePath, pathBefore) {
    const before = fstatSync(archiveFd, { bigint: true });
    ensureRegular(before);
    if (before.size !== BigInt(expectedArchiveSizeBytes)) refuse("archive length differs from expected");
    if (pathBefore && !sameFile(pathBefore, before)) refuse("archive path changed during opening");
    let offset = 0;
    const hasher = createHash("sha256");
    async function readExactly(length) {
      if (length > READ_BLOCK || offset + length > expectedArchiveSizeBytes) {
        refuse("TAR read exceeds pinned archive");
      }
      const buffer = Buffer.allocUnsafe(length);
      let read = 0;
      while (read < length) {
        const result = await readPinned(archiveFd, buffer, read, length - read, offset + read);
        if (result.bytesRead <= 0) refuse("unexpected end of Docker TAR");
        read += result.bytesRead;
      }
      offset += length;
      hasher.update(buffer);
      return buffer;
    }
    async function readMember(size, collect) {
      const digest = createHash("sha256");
      const chunks = [];
      const contentOffset = offset;
      for (let remain = size; remain > 0;) {
        const next = await readExactly(Math.min(remain, READ_BLOCK));
        digest.update(next);
        if (collect) chunks.push(next);
        remain -= next.length;
      }
      const padding = (512 - size % 512) % 512;
      if (padding && (await readExactly(padding)).some((byte) => byte !== 0)) {
        refuse("nonzero TAR padding");
      }
      return { digest: digest.digest("hex"), size, contentOffset,
        data: collect ? Buffer.concat(chunks) : null };
    }
    const files = new Map();
    const dirs = new Set();
    let collectedBytes = 0;
    let ended = false;
    while (offset + 512 <= expectedArchiveSizeBytes) {
      const header = await readExactly(512);
      if (header.every((byte) => byte === 0)) {
        if (offset + 512 > expectedArchiveSizeBytes ||
            (await readExactly(512)).some((byte) => byte !== 0)) {
          refuse("missing two-block TAR terminator");
        }
        while (offset < expectedArchiveSizeBytes) {
          if ((await readExactly(Math.min(READ_BLOCK, expectedArchiveSizeBytes - offset)))
            .some((byte) => byte !== 0)) refuse("nonzero TAR trailer");
        }
        ended = true;
        break;
      }
      if (files.size + dirs.size >= MAX_MEMBERS) refuse("too many TAR entries");
      const entry = parseHeader(header);
      if (files.has(entry.name) || dirs.has(entry.name)) refuse("duplicate Docker TAR member");
      if (entry.directory) {
        dirs.add(entry.name);
        continue;
      }
      const configName = `${expectedImageId.slice(7)}.json`;
      const isConfig = entry.name === configName;
      const isManifest = entry.name === "manifest.json";
      const isOciMetadata = entry.name === "index.json" || entry.name === "oci-layout";
      const isRepository = entry.name === "repositories";
      const isLayer = /^[a-f0-9]{64}\/layer\.tar$/u.test(entry.name);
      const isOciBlob = OCI_BLOB.test(entry.name);
      const isAux = /^[a-f0-9]{64}\/(?:VERSION|json)$/u.test(entry.name);
      if (!isConfig && !isManifest && !isOciMetadata &&
          !isRepository && !isLayer && !isOciBlob && !isAux) {
        refuse("unexpected member in Docker TAR");
      }
      const max = isConfig ? MAX_CONFIG : isManifest ? MAX_MANIFEST :
        (isLayer || isOciBlob ? MAX_ARCHIVE : MAX_AUXILIARY);
      if (entry.size > max || (isLayer && entry.size < 1024)) {
        refuse("unsafe Docker TAR member length");
      }
      if (!isLayer && !isOciBlob) {
        collectedBytes += entry.size;
        if (collectedBytes > MAX_COLLECTED) refuse("excessive collected Docker TAR metadata");
      }
      const result = await readMember(entry.size, !isLayer && !isOciBlob);
      if (isOciBlob && result.digest !== entry.name.slice("blobs/sha256/".length)) {
        refuse("OCI blob SHA-256 does not match its content-addressed path");
      }
      files.set(entry.name, result);
    }
    if (!ended || offset !== expectedArchiveSizeBytes) refuse("incomplete Docker TAR structure");
    const archiveSha256 = hasher.digest("hex");
    if (archiveSha256 !== expectedArchiveSha256) refuse("Docker TAR SHA-256 differs from trusted inventory");
    if (!sameFile(before, fstatSync(archiveFd, { bigint: true })) ||
        (archivePath && !sameFile(before, lstatSync(archivePath, { bigint: true })))) {
      refuse("Docker TAR changed during verification");
    }
    if (archivePath) ensureNoAliases(archivePath);
    const configName = `${expectedImageId.slice(7)}.json`;
    if (!files.has("manifest.json")) refuse("Docker save manifest missing");
    let config;
    let orderedLayerDigests;
    let allowedFiles;
    if (files.has("index.json") || files.has("oci-layout")) {
      if (!files.has("index.json") || !files.has("oci-layout")) {
        refuse("incomplete OCI layout");
      }
      // Metadata blobs are bounded and read by absolute offset from the pinned FD.
      const cached = new Map();
      let cachedBytes = 0;
      async function readOciMetadata(name, max) {
        const member = files.get(name);
        if (!member || member.size > max) refuse("OCI metadata is missing or oversized");
        if (cached.has(name)) return cached.get(name);
        cachedBytes += member.size;
        if (cachedBytes > MAX_COLLECTED) refuse("too much OCI metadata retained in memory");
        const buffer = Buffer.alloc(member.size);
        let received = 0;
        while (received < member.size) {
          const { bytesRead } = await readPinned(archiveFd, buffer, received,
            Math.min(READ_BLOCK, member.size - received), member.contentOffset + received);
          if (bytesRead <= 0) refuse("OCI metadata read truncated");
          received += bytesRead;
        }
        if (sha256(buffer) !== member.digest) refuse("OCI metadata mutated after initial read");
        cached.set(name, buffer);
        return buffer;
      }
      const index = strictJson(files.get("index.json").data, "OCI index");
      exactKeys(index, ["schemaVersion", "mediaType", "manifests"], "OCI index");
      if (index.schemaVersion !== 2 || index.mediaType !== OCI_INDEX ||
          !Array.isArray(index.manifests) || index.manifests.length !== 1) {
        refuse("OCI index must select exactly one image");
      }
      const selectedDescriptor = ociDescriptor(index.manifests[0], OCI_MANIFEST, files, "OCI manifest", true);
      const selectedManifest = await readOciMetadata(selectedDescriptor.name, MAX_MANIFEST);
      const manifest = strictJson(selectedManifest, "OCI image manifest");
      exactKeys(manifest, ["schemaVersion", "mediaType", "config", "layers"], "OCI image manifest");
      if (manifest.schemaVersion !== 2 || manifest.mediaType !== OCI_MANIFEST ||
          !Array.isArray(manifest.layers) || manifest.layers.length < 1 ||
          manifest.layers.length > MAX_LAYERS) refuse("unsupported OCI image manifest");
      const configDescriptor = ociDescriptor(manifest.config, OCI_CONFIG, files, "OCI config");
      const configPath = `blobs/sha256/${expectedImageId.slice(7)}`;
      if (configDescriptor.name !== configPath) refuse("OCI config not equal expected image ID");
      const configRaw = await readOciMetadata(configPath, MAX_CONFIG);
      config = validateDockerConfig(configRaw, expectedImageId, expectedRevision);
      const layers = manifest.layers.map((layer, i) =>
        ociDescriptor(layer, OCI_LAYER, files, `OCI layer ${i}`));
      orderedLayerDigests = layers.map((layer) => `sha256:${layer.file.digest}`);
      const referenced = new Set([selectedDescriptor.name, configPath]);
      for (const layer of layers) {
        if (referenced.has(layer.name)) refuse("duplicate OCI blob descriptor");
        referenced.add(layer.name);
      }
      const legacyNames = [...files.keys()].filter((name) => OCI_BLOB.test(name) && !referenced.has(name));
      // Docker Desktop 29 emits one extra content-addressed legacy metadata
      // JSON blob per layer. Its IDs form exactly one ancestry chain ending in
      // a final image metadata record. Unrelated blobs stay forbidden.
      if (legacyNames.length) {
        if (legacyNames.length !== layers.length) refuse("unreferenced OCI blobs do not match layer lineage");
        const metadata = [];
        const byId = new Map();
        for (const name of legacyNames) {
          const value = strictJson(await readOciMetadata(name, MAX_AUXILIARY), "Docker layer legacy metadata");
          if (!record(value) || !/^[a-f0-9]{64}$/u.test(value.id ?? "") ||
              (value.parent !== undefined && !/^[a-f0-9]{64}$/u.test(value.parent)) ||
              !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/u.test(value.created ?? "") ||
              value.os !== "linux" || !record(value.container_config) || byId.has(value.id)) {
            refuse("invalid Docker legacy layer metadata identity");
          }
          metadata.push({ name, value });
          byId.set(value.id, value);
        }
        const roots = metadata.filter(({ value }) => value.parent === undefined);
        const parentIds = new Set(metadata.map(({ value }) => value.parent).filter(Boolean));
        const leaves = metadata.filter(({ value }) => !parentIds.has(value.id));
        if (roots.length !== 1 || leaves.length !== 1 || parentIds.size !== metadata.length - 1) {
          refuse("Docker legacy layer ancestry is not a single chain");
        }
        const leaf = leaves[0].value;
        for (const { value } of metadata) {
          const expectedFields = ["id", "created", "container_config", "os"];
          if (value.parent !== undefined) expectedFields.push("parent");
          if (value === leaf) expectedFields.push("config", "architecture");
          exactKeys(value, expectedFields, "Docker legacy layer metadata");
          if (value !== leaf && (value.config !== undefined || value.architecture !== undefined)) {
            refuse("unexpected final image metadata on intermediate layer");
          }
        }
        if (leaf.architecture !== "amd64" || !record(leaf.config) ||
            leaf.config.User !== "node:node" || !record(leaf.config.Labels) ||
            leaf.config.Labels["org.opencontainers.image.revision"] !== expectedRevision ||
            leaf.config.Labels["org.opencontainers.image.source"] !== SOURCE) {
          refuse("Docker legacy final image identity differs from OCI config");
        }
        const visited = new Set();
        let current = leaf;
        while (current) {
          if (visited.has(current.id)) refuse("Docker legacy layer lineage cycle");
          visited.add(current.id);
          current = current.parent === undefined ? null : byId.get(current.parent);
          if (current === undefined) refuse("Docker legacy layer lineage missing parent");
        }
        if (visited.size !== metadata.length) refuse("Docker legacy layer lineage disconnected");
        for (const name of legacyNames) referenced.add(name);
      }
      const dockerManifest = strictJson(files.get("manifest.json").data, "Docker save manifest");
      if (!Array.isArray(dockerManifest) || dockerManifest.length !== 1) {
        refuse("Docker save must contain a single image");
      }
      const docker = dockerManifest[0];
      exactKeys(docker, ["Config", "RepoTags", "Layers", "LayerSources"], "Docker save OCI manifest");
      if (docker.Config !== configPath ||
          !(docker.RepoTags === null || (Array.isArray(docker.RepoTags) && docker.RepoTags.length === 0)) ||
          !Array.isArray(docker.Layers) || docker.Layers.length !== layers.length ||
          !record(docker.LayerSources) || Object.keys(docker.LayerSources).length !== layers.length) {
        refuse("Docker save manifest and OCI graph mismatch");
      }
      for (let i = 0; i < layers.length; i += 1) {
        if (docker.Layers[i] !== layers[i].name) refuse("Docker layer order mismatches OCI graph");
        const digest = orderedLayerDigests[i];
        exactKeys(docker.LayerSources[digest], ["digest", "mediaType", "size"], "Docker layer source");
        if (docker.LayerSources[digest].digest !== digest ||
            docker.LayerSources[digest].mediaType !== OCI_LAYER ||
            docker.LayerSources[digest].size !== layers[i].file.size) {
          refuse("Docker layer source descriptor mismatch");
        }
      }
      if (Object.keys(docker.LayerSources).some((key) => !orderedLayerDigests.includes(key))) {
        refuse("unrelated Docker layer source");
      }
      const layout = strictJson(files.get("oci-layout").data, "OCI layout");
      exactKeys(layout, ["imageLayoutVersion"], "OCI layout");
      if (layout.imageLayoutVersion !== "1.0.0") refuse("unsupported OCI layout");
      allowedFiles = new Set(["manifest.json", "oci-layout", "index.json", ...referenced]);
    } else {
      if (!files.has(configName)) refuse("image config missing");
      config = validateDockerConfig(files.get(configName).data, expectedImageId, expectedRevision);
      const layerHashes = new Map([...files].filter(([name]) =>
        /^[a-f0-9]{64}\/layer\.tar$/u.test(name))
        .map(([name, value]) => [name, value.digest]));
      const manifest = validateManifest(files.get("manifest.json").data, expectedImageId, layerHashes);
      orderedLayerDigests = manifest.layers.map((name) => `sha256:${layerHashes.get(name)}`);
      allowedFiles = new Set([configName, "manifest.json", ...manifest.layers]);
      for (const name of manifest.layers) {
        const directory = name.slice(0, -"/layer.tar".length);
        for (const suffix of ["json", "VERSION"]) allowedFiles.add(`${directory}/${suffix}`);
      }
    }
    if (orderedLayerDigests.length !== config.diffIds.length) {
      refuse("image layer count differs from config diff_ids");
    }
    for (let i = 0; i < orderedLayerDigests.length; i += 1) {
      if (orderedLayerDigests[i] !== config.diffIds[i]) {
        refuse("layer uncompressed SHA-256 differs from content-addressed config diff_id");
      }
    }
    if (files.has("repositories")) {
      const repositories = strictJson(files.get("repositories").data, "repositories");
      if (!record(repositories) || Object.keys(repositories).length !== 0) {
        refuse("Docker repository tags cannot be imported");
      }
      allowedFiles.add("repositories");
    }
    for (const [name, file] of files) {
      if (!allowedFiles.has(name)) refuse("unreferenced Docker TAR member");
      if (name.endsWith("/json")) strictJson(file.data, "layer metadata");
      if (name.endsWith("/VERSION") &&
          !/^1\.0\n?$/u.test(DECODER.decode(file.data))) {
        refuse("unexpected Docker layer VERSION");
      }
    }
    for (const directory of dirs) {
      if (![...allowedFiles].some((name) => name.startsWith(`${directory}/`))) {
        refuse("unreferenced Docker directory entry");
      }
    }
    if (!sameFile(before, fstatSync(archiveFd, { bigint: true })) ||
        (archivePath && !sameFile(before, lstatSync(archivePath, { bigint: true })))) {
      refuse("Docker TAR changed while validating OCI graph");
    }
    if (archivePath) ensureNoAliases(archivePath);
    return Object.freeze({
      role, imageId: expectedImageId, revision: expectedRevision, source: SOURCE,
      platform: "linux/amd64", user: config.user, archiveSha256,
      archiveSizeBytes: expectedArchiveSizeBytes, layerCount: orderedLayerDigests.length,
    });
}
