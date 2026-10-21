import { createHash } from "node:crypto";
import { constants, lstatSync } from "node:fs";
import { open } from "node:fs/promises";
import path from "node:path";

// Pure read-only inspection of the classic single-image Docker-save TAR format.
// Docker/Containerd OCI-layout save variants (index.json/oci-layout/blobs/) are
// intentionally unsupported until their separate descriptor graph is verified.
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

function refuse(reason) {
  throw new Error(`Offline Docker TAR rejected: ${reason}`);
}

function record(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
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

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

/**
 * Independently verify the complete classic Docker-save archive and each layer's
 * uncompressed SHA-256 against its content-addressed image config. Uses one
 * pinned O_NOFOLLOW FD, absolute reads and bounded memory; never calls Docker.
 *
 * This authenticates content only relative to the caller's trusted expected
 * image ID + archive digest. It does not prove how the image was built, inspect
 * files *inside* layer tarballs, or grant deployment authorization. In particular
 * Docker image IDs are config digests, not registry manifest digests. The caller
 * must reverify before use and separately enforce host/owner policy.
 */
export async function verifyOfflineDockerSaveTar({
  archivePath, expectedImageId, expectedRevision, expectedArchiveSha256,
  expectedArchiveSizeBytes, role,
} = {}) {
  if (!["runtime", "migrator"].includes(role) ||
      !IMAGE_ID.test(expectedImageId ?? "") ||
      !GIT_SHA.test(expectedRevision ?? "") ||
      !ARCHIVE_SHA.test(expectedArchiveSha256 ?? "") ||
      !Number.isSafeInteger(expectedArchiveSizeBytes) ||
      expectedArchiveSizeBytes < 1024 || expectedArchiveSizeBytes > MAX_ARCHIVE ||
      expectedArchiveSizeBytes % 512 !== 0 ||
      typeof archivePath !== "string" || archivePath.length > 4096 ||
      archivePath.includes("\0") || !path.isAbsolute(archivePath) ||
      path.normalize(archivePath) !== archivePath ||
      !Number.isInteger(constants.O_NOFOLLOW) || !Number.isInteger(constants.O_NONBLOCK)) {
    refuse("invalid expected Docker archive identity or safe-file capabilities");
  }
  ensureNoAliases(archivePath);
  const pathBefore = lstatSync(archivePath, { bigint: true });
  ensureRegular(pathBefore);
  if (pathBefore.size !== BigInt(expectedArchiveSizeBytes)) refuse("archive length differs from expected");
  const fd = await open(archivePath, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = await fd.stat({ bigint: true });
    ensureRegular(before);
    if (!sameFile(pathBefore, before)) refuse("archive path changed during opening");
    let offset = 0;
    const hasher = createHash("sha256");
    async function readExactly(length) {
      if (length > READ_BLOCK || offset + length > expectedArchiveSizeBytes) {
        refuse("TAR read exceeds pinned archive");
      }
      const buffer = Buffer.allocUnsafe(length);
      let read = 0;
      while (read < length) {
        const result = await fd.read(buffer, read, length - read, offset + read);
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
      return { digest: digest.digest("hex"), data: collect ? Buffer.concat(chunks) : null };
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
      const isRepository = entry.name === "repositories";
      const isLayer = /^[a-f0-9]{64}\/layer\.tar$/u.test(entry.name);
      const isAux = /^[a-f0-9]{64}\/(?:VERSION|json)$/u.test(entry.name);
      if (!isConfig && !isManifest && !isRepository && !isLayer && !isAux) {
        refuse("unexpected member in Docker TAR");
      }
      const max = isConfig ? MAX_CONFIG : isManifest ? MAX_MANIFEST :
        (isLayer ? MAX_ARCHIVE : MAX_AUXILIARY);
      if (entry.size > max || (isLayer && entry.size < 1024)) {
        refuse("unsafe Docker TAR member length");
      }
      if (!isLayer) {
        collectedBytes += entry.size;
        if (collectedBytes > MAX_COLLECTED) refuse("excessive collected Docker TAR metadata");
      }
      const result = await readMember(entry.size, !isLayer);
      files.set(entry.name, result);
    }
    if (!ended || offset !== expectedArchiveSizeBytes) refuse("incomplete Docker TAR structure");
    const archiveSha256 = hasher.digest("hex");
    if (archiveSha256 !== expectedArchiveSha256) refuse("Docker TAR SHA-256 differs from trusted inventory");
    if (!sameFile(before, await fd.stat({ bigint: true })) ||
        !sameFile(before, lstatSync(archivePath, { bigint: true }))) {
      refuse("Docker TAR changed during verification");
    }
    ensureNoAliases(archivePath);
    const configName = `${expectedImageId.slice(7)}.json`;
    if (!files.has(configName) || !files.has("manifest.json")) {
      refuse("image config or Docker manifest missing");
    }
    const config = validateDockerConfig(files.get(configName).data, expectedImageId, expectedRevision);
    const layerHashes = new Map([...files].filter(([name]) =>
      /^[a-f0-9]{64}\/layer\.tar$/u.test(name))
      .map(([name, value]) => [name, value.digest]));
    const manifest = validateManifest(files.get("manifest.json").data, expectedImageId, layerHashes);
    if (manifest.layers.length !== config.diffIds.length) refuse("image layer count differs from config diff_ids");
    for (let i = 0; i < manifest.layers.length; i += 1) {
      if (`sha256:${layerHashes.get(manifest.layers[i])}` !== config.diffIds[i]) {
        refuse("layer uncompressed SHA-256 differs from content-addressed config diff_id");
      }
    }
    const allowedFiles = new Set([configName, "manifest.json", ...manifest.layers]);
    if (files.has("repositories")) {
      const repositories = strictJson(files.get("repositories").data, "repositories");
      if (!record(repositories) || Object.keys(repositories).length !== 0) {
        refuse("Docker repository tags cannot be imported");
      }
      allowedFiles.add("repositories");
    }
    for (const name of manifest.layers) {
      if (name.endsWith("/layer.tar")) {
        const directory = name.slice(0, -"/layer.tar".length);
        for (const suffix of ["json", "VERSION"]) allowedFiles.add(`${directory}/${suffix}`);
      }
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
    return Object.freeze({
      role, imageId: expectedImageId, revision: expectedRevision, source: SOURCE,
      platform: "linux/amd64", user: config.user, archiveSha256,
      archiveSizeBytes: expectedArchiveSizeBytes, layerCount: manifest.layers.length,
    });
  } finally {
    await fd.close();
  }
}
