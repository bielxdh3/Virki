import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  linkSync, lstatSync, mkdirSync, mkdtempSync, renameSync, rmSync, symlinkSync,
  truncateSync, writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { inventoryOfflineArtifacts } from "./lib/offline-artifact-inventory.mjs";

const REVISION = "fbac177b91414ff8d047cef40cc9920d0ba882cd";
const SOURCE = "https://github.com/bielxdh3/Virki.git";
const OCI_SOURCE = "https://github.com/bielxdh3/Virki";
const digest = (value) => createHash("sha256").update(value).digest("hex");
const image = (role, hex) => ({
  role,
  imageId: `sha256:${hex.repeat(64)}`,
  sizeBytes: 18432,
  os: "linux",
  architecture: "amd64",
  labels: {
    "org.opencontainers.image.revision": REVISION,
    "org.opencontainers.image.source": OCI_SOURCE,
  },
});

function setup(t) {
  const artifactRoot = mkdtempSync(path.join(os.tmpdir(), "virki-offline-artifact-inventory-"));
  t.after(() => rmSync(artifactRoot, { recursive: true, force: true }));
  const paths = {
    sourceArchivePath: path.join(artifactRoot, "source.tar"),
    runtimeArchivePath: path.join(artifactRoot, "runtime.tar"),
    migratorArchivePath: path.join(artifactRoot, "migrator.tar"),
  };
  const contents = { source: Buffer.from("fixture source tar bytes"), runtime: Buffer.from("runtime tar fixture"), migrator: Buffer.from("migrator tar fixture") };
  writeFileSync(paths.sourceArchivePath, contents.source);
  writeFileSync(paths.runtimeArchivePath, contents.runtime);
  writeFileSync(paths.migratorArchivePath, contents.migrator);
  return {
    artifactRoot,
    ...paths,
    expectedRevision: REVISION,
    images: { runtime: image("runtime", "a"), migrator: image("migrator", "b") },
    contents,
  };
}

function input(fixture, overrides = {}) {
  const { contents: _contents, ...options } = fixture;
  return { ...options, ...overrides };
}

test("returns exact measured SHA256, byte sizes and checked image identities for three separate archives", async (t) => {
  const fixture = setup(t);
  const value = await inventoryOfflineArtifacts(input(fixture));
  assert.deepEqual(value, {
    source_sha: REVISION,
    repository: SOURCE,
    platform: "linux/amd64",
    source_archive_sha256: digest(fixture.contents.source),
    source_archive_size_bytes: fixture.contents.source.length,
    runtime_image: {
      archive_sha256: digest(fixture.contents.runtime),
      archive_size_bytes: fixture.contents.runtime.length,
      image_id: fixture.images.runtime.imageId,
    },
    migrator_image: {
      archive_sha256: digest(fixture.contents.migrator),
      archive_size_bytes: fixture.contents.migrator.length,
      image_id: fixture.images.migrator.imageId,
    },
  });
  assert.equal(Object.isFrozen(value), true);
  assert.equal(Object.isFrozen(value.runtime_image), true);
  assert.equal(Object.isFrozen(value.migrator_image), true);
  assert.equal(lstatSync(fixture.runtimeArchivePath).size, fixture.contents.runtime.length);
});

test("identical bytes are independently counted and hashed without trusting the archive's extension", async (t) => {
  const fixture = setup(t);
  writeFileSync(fixture.sourceArchivePath, Buffer.alloc(5 * 1024 * 1024 + 23, 0x7f));
  const inventory = await inventoryOfflineArtifacts(input(fixture));
  assert.equal(inventory.source_archive_size_bytes, 5 * 1024 * 1024 + 23);
  assert.equal(inventory.source_archive_sha256, digest(Buffer.alloc(5 * 1024 * 1024 + 23, 0x7f)));
});

test("rejects missing, empty and oversized files without allocating file-sized memory", async (t) => {
  const fixture = setup(t);
  rmSync(fixture.sourceArchivePath);
  await assert.rejects(inventoryOfflineArtifacts(input(fixture)));
  writeFileSync(fixture.sourceArchivePath, "");
  await assert.rejects(inventoryOfflineArtifacts(input(fixture)));
  writeFileSync(fixture.sourceArchivePath, "x");
  truncateSync(fixture.sourceArchivePath, 8 * 1024 * 1024 * 1024 + 1);
  await assert.rejects(inventoryOfflineArtifacts(input(fixture)));
});

test("refuses leaf symlinks, hardlinks and unsafe directory aliases", async (t) => {
  const fixture = setup(t);
  const aliased = path.join(fixture.artifactRoot, "aliased.tar");
  symlinkSync(fixture.runtimeArchivePath, aliased);
  await assert.rejects(inventoryOfflineArtifacts(input(fixture, { runtimeArchivePath: aliased })));
  rmSync(aliased);
  linkSync(fixture.runtimeArchivePath, aliased);
  await assert.rejects(inventoryOfflineArtifacts(input(fixture)));
  rmSync(aliased);
  const alternateRoot = `${fixture.artifactRoot}-alias`;
  symlinkSync(fixture.artifactRoot, alternateRoot, "dir");
  t.after(() => rmSync(alternateRoot, { force: true }));
  await assert.rejects(inventoryOfflineArtifacts(input(fixture, {
    artifactRoot: alternateRoot,
    runtimeArchivePath: path.join(alternateRoot, "runtime.tar"),
    sourceArchivePath: path.join(alternateRoot, "source.tar"),
    migratorArchivePath: path.join(alternateRoot, "migrator.tar"),
  })));

  const nested = path.join(fixture.artifactRoot, "nested");
  const actualRoot = path.join(nested, "releases");
  const alias = path.join(fixture.artifactRoot, "redirect");
  mkdirSync(actualRoot, { recursive: true });
  symlinkSync(nested, alias, "dir");
  const aliasRoot = path.join(alias, "releases");
  const mapped = {
    sourceArchivePath: path.join(aliasRoot, "source.tar"),
    runtimeArchivePath: path.join(aliasRoot, "runtime.tar"),
    migratorArchivePath: path.join(aliasRoot, "migrator.tar"),
  };
  for (const archivePath of Object.values(mapped)) writeFileSync(archivePath, "fixture");
  await assert.rejects(inventoryOfflineArtifacts(input(fixture, { artifactRoot: aliasRoot, ...mapped })));
});

test("refuses duplicate, nested, relative, traversal and other noncanonical paths", async (t) => {
  const fixture = setup(t);
  const root = fixture.artifactRoot;
  for (const overrides of [
    { runtimeArchivePath: fixture.sourceArchivePath },
    { runtimeArchivePath: "relative.tar" },
    { runtimeArchivePath: path.join(root, "..", "foreign.tar") },
    { runtimeArchivePath: `${root}${path.sep}..${path.sep}${path.basename(root)}${path.sep}runtime.tar` },
    { runtimeArchivePath: path.join(root, "inside", "runtime.tar") },
    { runtimeArchivePath: fixture.runtimeArchivePath.replace(/\.tar$/u, ".tgz") },
    { artifactRoot: "." },
    { artifactRoot: path.dirname(root) },
  ]) {
    await assert.rejects(inventoryOfflineArtifacts(input(fixture, overrides)));
  }
});

test("rejects mismatched Docker revision, source, role, architecture and invalid sizes", async (t) => {
  const fixture = setup(t);
  const change = (role, changes) => ({
    ...fixture.images,
    [role]: { ...fixture.images[role], ...changes },
  });
  for (const images of [
    change("runtime", { role: "migrator" }),
    change("runtime", { imageId: "sha256:INVALID" }),
    change("runtime", { sizeBytes: -1 }),
    change("runtime", { sizeBytes: 0 }),
    change("runtime", { sizeBytes: 1.25 }),
    change("runtime", { sizeBytes: Number.MAX_SAFE_INTEGER + 1 }),
    change("migrator", { os: "windows" }),
    change("migrator", { architecture: "arm64" }),
    change("migrator", { labels: { ...fixture.images.migrator.labels, "org.opencontainers.image.revision": "f".repeat(40) } }),
    change("migrator", { labels: { ...fixture.images.migrator.labels, "org.opencontainers.image.source": "https://example.invalid" } }),
    change("runtime", { labels: {} }),
  ]) {
    await assert.rejects(inventoryOfflineArtifacts(input(fixture, { images })));
  }
  await assert.rejects(inventoryOfflineArtifacts(input(fixture, { expectedRevision: "f".repeat(40) })));
  await assert.rejects(inventoryOfflineArtifacts(input(fixture, { expectedRevision: "invalid" })));
});

test("refuses a changed file path/inode while hashing rather than returning a success", async (t) => {
  const fixture = setup(t);
  const replacement = path.join(fixture.artifactRoot, "replacement.tar");
  writeFileSync(replacement, Buffer.alloc(16 * 1024 * 1024, 0x43));
  writeFileSync(fixture.runtimeArchivePath, Buffer.alloc(16 * 1024 * 1024, 0x42));
  let replaced = false;
  // An async reader should yield to the event loop while iterating bounded
  // chunks, letting this queued rename race occur during the two hash passes.
  const trigger = setTimeout(() => {
    try {
      renameSync(replacement, fixture.runtimeArchivePath);
      replaced = true;
    } catch { /* The race must still fail closed if the rename was denied. */ }
  }, 2);
  try {
    await assert.rejects(inventoryOfflineArtifacts(input(fixture)));
    assert.equal(replaced, true);
  } finally {
    clearTimeout(trigger);
  }
});
