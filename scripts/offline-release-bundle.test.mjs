import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { closeSync, fstatSync, mkdtempSync, mkdirSync, openSync, readFileSync,
  readdirSync, renameSync, rmSync, symlinkSync, writeFileSync, writeSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { prepareOfflineReleaseBundle, verifySourceTarAgainstGit } from "./lib/offline-release-bundle.mjs";
import { verifySourceTarFdAgainstGit } from "./lib/offline-source-tar-verifier.mjs";

const SOURCE = "https://github.com/bielxdh3/Virki.git";
const LABEL_SOURCE = "https://github.com/bielxdh3/Virki";
const EMPTY = createHash("sha256").update("").digest("hex");
const STAGES = ["tooling-policy-dependencies", "tooling-policy-tests", "chromium-dependencies",
  "production-hub-build", "runtime", "secrets-scan", "production-revision-tests",
  "backup-inventory-tests", "production-operations-tests", "public-site-tests",
  "unit-tests", "integration-tests", "browser-e2e", "lint", "typecheck",
  "prisma-validate", "build", "windows-ca-helper-tests", "worktree-diff-check"];
const IMAGE_IDS = { runtime: `sha256:${"a".repeat(64)}`, migrator: `sha256:${"b".repeat(64)}` };

function git(cwd, ...args) { return execFileSync("git", args, { cwd, encoding: "utf8" }).trim(); }
function manifest(revision) {
  const base = Date.parse("2026-10-21T14:00:00Z");
  return {
    runId: "e5f8bc3d5c", sourceBranch: "main", sourceHead: revision,
    startedUtc: new Date(base).toISOString(), finishedUtc: new Date(base + 300_000).toISOString(),
    nodeVersion: "v22.23.3", npmVersion: "10.9.9", stagedPatchSha256: EMPTY,
    workingTreePatchSha256: EMPTY, untrackedFiles: [],
    unitTestsFailureCount: 0, unitTestsFailures: [], integrationTestsFailureCount: 0,
    integrationTestsFailures: [], productionOperationsFailureCount: 0, productionOperationsFailures: [],
    dockerMutationJournal: "docker-mutations.jsonl", dockerMutationUncertain: false,
    dockerCleanupVerified: true, bootstrapVirginTestsLog: "bootstrap-virgin-tests.tap.log",
    bootstrapVirginTestsExitCode: 0,
    exitCode: 0, failedStages: [],
    stages: STAGES.map((name, i) => ({ name,
      startedUtc: new Date(base + i * 10_000 + 1_000).toISOString(),
      finishedUtc: new Date(base + i * 10_000 + 2_000).toISOString(), durationMs: 1000, exitCode: 0 })),
  };
}

function setup(t, { sha256 = false } = {}) {
  const root = mkdtempSync(path.join(os.tmpdir(), "virki-bundle-test-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const repositoryRoot = path.join(root, "repo");
  const stagingParent = path.join(root, "stages");
  mkdirSync(repositoryRoot);
  mkdirSync(stagingParent, { mode: 0o700 });
  git(repositoryRoot, "init", "-b", "main", ...(sha256 ? ["--object-format=sha256"] : []));
  // The test's archive must reflect Git's committed bytes, not system-wide
  // Windows CRLF checkout settings that change the synthetic README object.
  git(repositoryRoot, "config", "core.autocrlf", "false");
  git(repositoryRoot, "config", "user.email", "fixture@example.test");
  git(repositoryRoot, "config", "user.name", "Fixture");
  writeFileSync(path.join(repositoryRoot, "README.md"), "controlled fixture\n");
  git(repositoryRoot, "add", "README.md");
  git(repositoryRoot, "commit", "-m", "fixture");
  const revision = git(repositoryRoot, "rev-parse", "HEAD");
  git(repositoryRoot, "remote", "add", "origin", SOURCE);
  git(repositoryRoot, "update-ref", "refs/remotes/origin/main", revision);
  const ciManifestPath = path.join(root, "ci.json");
  writeFileSync(ciManifestPath, JSON.stringify(manifest(revision)));
  const payloadDir = path.join(root, "payload");
  mkdirSync(payloadDir);
  writeFileSync(path.join(payloadDir, "contents"), "standalone save fixture");
  const runLog = [];
  const runner = async (program, args, options = {}) => {
    runLog.push({ program, args: [...args] });
    if (program === "docker") {
      if (args[0] === "image" && args[1] === "inspect") {
        const role = Object.keys(IMAGE_IDS).find((value) => IMAGE_IDS[value] === args[2]);
        if (!role) throw new Error("image missing");
        return JSON.stringify([{
          Id: IMAGE_IDS[role], Size: 18432, Os: "linux", Architecture: "amd64",
          Config: { User: "node:node", Labels: {
            "org.opencontainers.image.revision": revision,
            "org.opencontainers.image.source": LABEL_SOURCE,
          } },
        }]);
      }
      if (args[0] === "save") {
        assert.deepEqual(args.slice(0, 2), ["save", "--output"]);
        execFileSync("tar", ["-cf", args[2], "-C", payloadDir, "contents"]);
        return "";
      }
      throw new Error(`unexpected Docker command ${args.join(" ")}`);
    }
    return execFileSync(program, args, { cwd: options.cwd, env: options.env, input: options.input,
      encoding: "utf8", maxBuffer: 2 * 1024 * 1024 });
  };
  const options = { repositoryRoot, revision, stagingParent, ciManifestPath, images: IMAGE_IDS, runner };
  return { root, revision, repositoryRoot, stagingParent, ciManifestPath, options, runLog };
}

function existingSource(t) {
  const f = setup(t);
  const filename = path.join(f.root, "existing-source.tar");
  execFileSync("git", ["archive", "--format=tar", `--output=${filename}`, f.revision],
    { cwd: f.repositoryRoot });
  const line = git(f.repositoryRoot, "ls-tree", "HEAD");
  const match = /^(100644|100755) blob ([0-9a-f]{40})\t(.+)$/u.exec(line);
  assert.ok(match);
  return { ...f, filename,
    objects: new Map([[match[3], { mode: match[1], type: "blob", id: match[2] }]]),
    timestamp: Number(git(f.repositoryRoot, "show", "-s", "--format=%ct", f.revision)) };
}

test("FD-bound source verifier reads the original inode after its filename is renamed", (t) => {
  const f = existingSource(t);
  const fd = openSync(f.filename, "r");
  t.after(() => closeSync(fd));
  const before = fstatSync(fd, { bigint: true });
  const contentHash = createHash("sha256").update(readFileSync(f.filename)).digest("hex");
  renameSync(f.filename, path.join(f.root, "renamed-source"));
  const result = verifySourceTarFdAgainstGit(fd, f.revision, f.objects, f.timestamp);
  assert.equal(result.sha256, contentHash);
  assert.equal(result.sizeBytes, Number(before.size));
});

test("FD-bound source verifier never reopens a filename replaced by a different TAR", (t) => {
  const f = existingSource(t);
  const original = readFileSync(f.filename);
  const fd = openSync(f.filename, "r");
  t.after(() => closeSync(fd));
  renameSync(f.filename, path.join(f.root, "pinned-source"));
  const changed = Buffer.from(original);
  const offset = changed.indexOf(Buffer.from("controlled fixture"));
  assert.ok(offset > 0);
  changed[offset] ^= 1;
  writeFileSync(f.filename, changed);
  assert.deepEqual(verifySourceTarFdAgainstGit(fd, f.revision, f.objects, f.timestamp), {
    sha256: createHash("sha256").update(original).digest("hex"), sizeBytes: original.length,
  });
  assert.throws(() => verifySourceTarAgainstGit(f.filename, f.revision, f.objects, f.timestamp),
    /blob content differs from Git/u);
});

test("FD-bound source verifier rejects in-place mutation after the fd was pinned", (t) => {
  const f = existingSource(t);
  const fd = openSync(f.filename, "r+");
  t.after(() => closeSync(fd));
  const before = fstatSync(fd, { bigint: true });
  const contents = readFileSync(f.filename);
  const offset = contents.indexOf(Buffer.from("controlled fixture"));
  assert.ok(offset > 0);
  writeSync(fd, Buffer.from("X"), 0, 1, offset);
  assert.throws(() => verifySourceTarFdAgainstGit(fd, f.revision, f.objects, f.timestamp, before),
    /changed|metadata/u);
  assert.throws(() => verifySourceTarFdAgainstGit(fd, f.revision, f.objects, f.timestamp),
    /blob content differs from Git/u);
});

test("builds exact HEAD tar and immutable-ID Docker save archives, returning measured inventory", async (t) => {
  const fixture = setup(t);
  const bundle = await prepareOfflineReleaseBundle(fixture.options);
  assert.equal(bundle.inventory.source_sha, fixture.revision);
  assert.equal(bundle.inventory.repository, SOURCE);
  assert.equal(bundle.inventory.platform, "linux/amd64");
  assert.equal(bundle.inventory.runtime_image.image_id, IMAGE_IDS.runtime);
  assert.equal(bundle.inventory.migrator_image.image_id, IMAGE_IDS.migrator);
  assert.equal(bundle.ciEvidence.stageCount, 19);
  assert.equal(bundle.inventory.source_archive_sha256,
    createHash("sha256").update(readFileSync(bundle.sourceArchivePath)).digest("hex"));
  assert.equal(readdirSync(bundle.directory).sort().join(","), "ci.json,migrator.tar,runtime.tar,source.tar");
  assert.equal(fixture.runLog.filter((call) => call.program === "docker" && call.args[0] === "save").length, 2);
  assert.ok(fixture.runLog.filter((call) => call.program === "docker" && call.args[0] === "save")
    .every((call) => Object.values(IMAGE_IDS).includes(call.args[3])));
});

test("manual bundle refuses fabricated 19-stage-only report without the separate virgin and Docker cleanup evidence", async (t) => {
  const fixture = setup(t);
  const incomplete = JSON.parse(readFileSync(fixture.ciManifestPath, "utf8"));
  for (const field of ["dockerMutationJournal", "dockerMutationUncertain", "dockerCleanupVerified", "bootstrapVirginTestsLog", "bootstrapVirginTestsExitCode"]) {
    delete incomplete[field];
  }
  writeFileSync(fixture.ciManifestPath, JSON.stringify(incomplete));
  await assert.rejects(prepareOfflineReleaseBundle(fixture.options), /virgin|bootstrap|Docker|offline/u);
  assert.deepEqual(readdirSync(fixture.stagingParent), []);
  assert.equal(fixture.runLog.some((call) => call.program === "docker"), false);
});

test("rejects dirty tracked, staged, untracked, wrong branch, shifted origin SHA and foreign remote", async (t) => {
  const f = setup(t);
  writeFileSync(path.join(f.repositoryRoot, "README.md"), "dirty");
  await assert.rejects(prepareOfflineReleaseBundle(f.options));
  git(f.repositoryRoot, "checkout", "--", "README.md");
  writeFileSync(path.join(f.repositoryRoot, "new.txt"), "untracked");
  await assert.rejects(prepareOfflineReleaseBundle(f.options));
  rmSync(path.join(f.repositoryRoot, "new.txt"));
  writeFileSync(path.join(f.repositoryRoot, "README.md"), "staged");
  git(f.repositoryRoot, "add", "README.md");
  await assert.rejects(prepareOfflineReleaseBundle(f.options));
  git(f.repositoryRoot, "reset", "--hard", "HEAD");
  git(f.repositoryRoot, "switch", "-c", "other");
  await assert.rejects(prepareOfflineReleaseBundle(f.options));
  git(f.repositoryRoot, "switch", "main");
  git(f.repositoryRoot, "update-ref", "refs/remotes/origin/main", "0".repeat(40));
  await assert.rejects(prepareOfflineReleaseBundle(f.options));
  git(f.repositoryRoot, "update-ref", "refs/remotes/origin/main", f.revision);
  git(f.repositoryRoot, "remote", "set-url", "origin", "https://example.test/foreign.git");
  await assert.rejects(prepareOfflineReleaseBundle(f.options));
  assert.deepEqual(readdirSync(f.stagingParent), []);
});

test("rejects missing image, changed revision/platform/user, partial archive and unexpected aliases; cleans owned staging", async (t) => {
  const f = setup(t);
  const base = f.options.runner;
  for (const variant of ["missing", "wrong-label", "wrong-platform", "root", "partial", "alias"]) {
    const runner = async (program, args, opts) => {
      if (program === "docker" && variant === "missing" && args[0] === "image") throw new Error("missing image");
      if (program === "docker" && args[0] === "image" && ["wrong-label", "wrong-platform", "root"].includes(variant)) {
        const values = JSON.parse(await base(program, args, opts));
        if (variant === "wrong-label") values[0].Config.Labels["org.opencontainers.image.revision"] = "f".repeat(40);
        if (variant === "wrong-platform") values[0].Architecture = "arm64";
        if (variant === "root") values[0].Config.User = "root";
        return JSON.stringify(values);
      }
      if (program === "docker" && variant === "partial" && args[0] === "save") {
        writeFileSync(args[2], "incomplete tar");
        return "";
      }
      if (program === "docker" && variant === "alias" && args[0] === "save") {
        assert.ok(Object.values(IMAGE_IDS).includes(args[3]));
        throw new Error("unexpected failure for alias test");
      }
      return base(program, args, opts);
    };
    await assert.rejects(prepareOfflineReleaseBundle({ ...f.options, runner }), variant);
    assert.deepEqual(readdirSync(f.stagingParent), []);
  }
});

test("rejects symlink output parent and unsafe source tree links, invalid CI and stale Git SHA", async (t) => {
  const f = setup(t);
  const symlink = path.join(f.root, "alias");
  symlinkSync(f.stagingParent, symlink, "dir");
  await assert.rejects(prepareOfflineReleaseBundle({ ...f.options, stagingParent: symlink }));
  writeFileSync(f.ciManifestPath, "{}");
  await assert.rejects(prepareOfflineReleaseBundle(f.options));
  writeFileSync(f.ciManifestPath, JSON.stringify(manifest(f.revision)));
  git(f.repositoryRoot, "config", "core.symlinks", "true");
  symlinkSync("README.md", path.join(f.repositoryRoot, "linked-file"));
  git(f.repositoryRoot, "add", "linked-file");
  git(f.repositoryRoot, "commit", "-m", "link");
  const linkedRevision = git(f.repositoryRoot, "rev-parse", "HEAD");
  git(f.repositoryRoot, "update-ref", "refs/remotes/origin/main", linkedRevision);
  writeFileSync(f.ciManifestPath, JSON.stringify(manifest(linkedRevision)));
  await assert.rejects(prepareOfflineReleaseBundle({ ...f.options, revision: linkedRevision }));
  assert.deepEqual(readdirSync(f.stagingParent), []);
});

test("rejects a valid but substituted source tar even if its paths are individually safe", async (t) => {
  const f = setup(t);
  const base = f.options.runner;
  const runner = async (program, args, options) => {
    const result = await base(program, args, options);
    if (program === "git" && args[0] === "archive") {
      const output = args.find((arg) => arg.startsWith("--output=")).slice("--output=".length);
      // Mutate only a member name in Git's canonical tar. GNU tar and BSD
      // tar encode optional numeric fields differently; generating a fresh
      // archive with the host tar can fail an earlier strict numeric gate.
      // This keeps every other header and Git's owner/time fields identical,
      // so a safe but untracked pathname must reach the missing-member gate.
      const archive = readFileSync(output);
      for (let offset = 0; offset + 512 <= archive.length;) {
        const header = archive.subarray(offset, offset + 512);
        if (header.every((byte) => byte === 0)) break;
        const kind = String.fromCharCode(header[156]);
        if (kind === "0" || kind === "\0") {
          assert.equal(header.toString("utf8", 0, 9), "README.md");
          header.fill(0, 0, 100);
          header.write("harmless.txt", 0, "utf8");
          header.fill(32, 148, 156);
          const checksum = header.reduce((total, byte) => total + byte, 0);
          header.write(`${checksum.toString(8).padStart(6, "0")}\0 `, 148, 8, "ascii");
          writeFileSync(output, archive);
          return result;
        }
        const size = parseInt(header.toString("ascii", 124, 136).replace(/\0.*/u, "").trim(), 8);
        assert.ok(Number.isSafeInteger(size));
        offset += 512 + Math.ceil(size / 512) * 512;
      }
      assert.fail("canonical Git archive had no regular source member");
    }
    return result;
  };
  await assert.rejects(prepareOfflineReleaseBundle({ ...f.options, runner }), /source tar contains a member missing from Git/);
  assert.deepEqual(readdirSync(f.stagingParent), []);
});

test("rejects valid tar with the exact Git member name but attacker-altered blob bytes", async (t) => {
  const f = setup(t);
  const base = f.options.runner;
  const replacement = path.join(f.root, "replacement");
  mkdirSync(replacement);
  writeFileSync(path.join(replacement, "README.md"), "ATTACKER CONTROLLED BYTES\n");
  const runner = async (program, args, opts) => {
    if (program === "git" && args[0] === "archive") {
      const output = args.find((part) => part.startsWith("--output=")).slice("--output=".length);
      execFileSync("tar", ["--format=ustar", "-cf", output, "-C", replacement, "README.md"]);
      return "";
    }
    return base(program, args, opts);
  };
  await assert.rejects(prepareOfflineReleaseBundle({ ...f.options, runner }), /blob|content|tar/u);
  assert.deepEqual(readdirSync(f.stagingParent), []);
});

test("rejects TAR headers that forge owner IDs, names, or extraction metadata", async (t) => {
  const f = setup(t);
  const base = f.options.runner;
  const rewriteNumber = (header, start, value) => {
    header.write(`${value.toString(8).padStart(7, "0")}\0`, start, 8, "ascii");
  };
  for (const variant of ["uid", "gid", "uname", "gname", "deviceMajor", "deviceMinor", "mtime"]) {
    const runner = async (program, args, opts) => {
      const result = await base(program, args, opts);
      if (program === "git" && args[0] === "archive") {
        const output = args.find((arg) => arg.startsWith("--output=")).slice("--output=".length);
        const tar = readFileSync(output);
        let offset = 0;
        while (offset < tar.length) {
          const header = tar.subarray(offset, offset + 512);
          const kind = String.fromCharCode(header[156]);
          if (kind === "0" || kind === "\0") {
            if (variant === "uid") rewriteNumber(header, 108, 1234);
            if (variant === "gid") rewriteNumber(header, 116, 1234);
            if (variant === "uname") { header.fill(0, 265, 297); header.write("attacker", 265); }
            if (variant === "gname") { header.fill(0, 297, 329); header.write("attacker", 297); }
            if (variant === "deviceMajor") rewriteNumber(header, 329, 1234);
            if (variant === "deviceMinor") rewriteNumber(header, 337, 1234);
            if (variant === "mtime") rewriteNumber(header, 136, 42);
            header.fill(32, 148, 156);
            const checksum = header.reduce((total, byte) => total + byte, 0);
            header.write(`${checksum.toString(8).padStart(6, "0")}\0 `, 148, 8, "ascii");
            writeFileSync(output, tar);
            return result;
          }
          const size = parseInt(header.toString("ascii", 124, 136).replace(/\0.*/u, "").trim(), 8);
          offset += 512 + Math.ceil(size / 512) * 512;
        }
        throw new Error("source tar regular header absent");
      }
      return result;
    };
    await assert.rejects(prepareOfflineReleaseBundle({ ...f.options, runner }), /owner|metadata|tar|mtime|time/iu, variant);
    assert.deepEqual(readdirSync(f.stagingParent), [], variant);
  }
});

test("Git's canonical ustar ownership and timestamp are stable in a real archive", (t) => {
  const f = setup(t);
  const archive = path.join(f.root, "real-source.tar");
  execFileSync("git", ["archive", "--format=tar", `--output=${archive}`, f.revision], { cwd: f.repositoryRoot });
  const tar = readFileSync(archive);
  let offset = 0;
  while (offset < tar.length) {
    const header = tar.subarray(offset, offset + 512);
    const kind = String.fromCharCode(header[156]);
    if (kind === "0" || kind === "\0") {
      const octal = (start, end) => parseInt(header.toString("ascii", start, end).replace(/\0.*/u, "").trim(), 8);
      const name = (start, end) => header.toString("utf8", start, end).replace(/\0.*$/u, "");
      assert.deepEqual({ uid: octal(108, 116), gid: octal(116, 124), uname: name(265, 297),
        gname: name(297, 329), major: octal(329, 337), minor: octal(337, 345),
        mtime: octal(136, 148) },
      { uid: 0, gid: 0, uname: "root", gname: "root", major: 0, minor: 0,
        mtime: Number(git(f.repositoryRoot, "show", "-s", "--format=%ct", f.revision)) });
      return;
    }
    const size = parseInt(header.toString("ascii", 124, 136).replace(/\0.*/u, "").trim(), 8);
    offset += 512 + Math.ceil(size / 512) * 512;
  }
  assert.fail("missing Git regular header");
});

test("rejects same-name source members with changed executable mode, duplicates, and PAX metadata", async (t) => {
  const f = setup(t);
  const base = f.options.runner;
  for (const variant of ["mode", "duplicate", "pax"]) {
    const runner = async (program, args, opts) => {
      if (program === "git" && args[0] === "archive") {
        const output = args.find((part) => part.startsWith("--output=")).slice("--output=".length);
        if (variant === "mode") {
          execFileSync("tar", ["--format=ustar", "--mode=0600", "-cf", output, "-C", f.repositoryRoot, "README.md"]);
        } else if (variant === "duplicate") {
          execFileSync("tar", ["--format=ustar", "-cf", output, "-C", f.repositoryRoot, "README.md", "README.md"]);
        } else {
          execFileSync("tar", ["--format=pax", "-cf", output, "-C", f.repositoryRoot, "README.md"]);
        }
        return "";
      }
      return base(program, args, opts);
    };
    await assert.rejects(prepareOfflineReleaseBundle({ ...f.options, runner }), variant);
    assert.deepEqual(readdirSync(f.stagingParent), []);
  }
});

test("accepts real Git archive with executable blob, directory, and long UTF-8 PAX path", async (t) => {
  const f = setup(t);
  const folder = "unicode-ç-".repeat(8);
  const filename = `build-${"a".repeat(62)}.sh`;
  mkdirSync(path.join(f.repositoryRoot, folder));
  writeFileSync(path.join(f.repositoryRoot, folder, filename), "#!/bin/sh\necho verified\n");
  git(f.repositoryRoot, "add", ".");
  git(f.repositoryRoot, "update-index", "--chmod=+x", `${folder}/${filename}`);
  git(f.repositoryRoot, "config", "core.filemode", "false");
  git(f.repositoryRoot, "commit", "-m", "nested executable and long path");
  const revision = git(f.repositoryRoot, "rev-parse", "HEAD");
  git(f.repositoryRoot, "update-ref", "refs/remotes/origin/main", revision);
  writeFileSync(f.ciManifestPath, JSON.stringify(manifest(revision)));
  const base = f.options.runner;
  const runner = async (program, args, opts) => {
    const output = await base(program, args, opts);
    if (program === "docker" && args[0] === "image") {
      const value = JSON.parse(output);
      value[0].Config.Labels["org.opencontainers.image.revision"] = revision;
      return JSON.stringify(value);
    }
    return output;
  };
  const bundle = await prepareOfflineReleaseBundle({ ...f.options, revision, runner });
  assert.equal(bundle.inventory.source_sha, revision);
  assert.ok(bundle.inventory.source_archive_size_bytes > 0);
});

test("authenticates a Git SHA-256 repository using 64-character blob object IDs", async (t) => {
  const f = setup(t, { sha256: true });
  const revision = git(f.repositoryRoot, "rev-parse", "HEAD");
  assert.match(revision, /^[0-9a-f]{64}$/u);
  const archive = path.join(f.root, "sha256.tar");
  execFileSync("git", ["archive", "--format=tar", `--output=${archive}`, revision], { cwd: f.repositoryRoot });
  const [entry] = git(f.repositoryRoot, "ls-tree", "-r", "HEAD").split("\n");
  const match = /^(100644|100755) blob ([0-9a-f]{64})\t(.+)$/u.exec(entry);
  assert.ok(match);
  assert.doesNotThrow(() => verifySourceTarAgainstGit(archive, revision, new Map([
    [match[3], { mode: match[1], type: "blob", id: match[2] }],
  ]), Number(git(f.repositoryRoot, "show", "-s", "--format=%ct", revision))));
  // Release policy currently requires a 40-hex commit even though the blob
  // verifier understands both object-hash formats.
  await assert.rejects(prepareOfflineReleaseBundle(f.options), /invalid release inputs/);
});

test("rejects export-ignore attributes from the committed SHA", async (t) => {
  const f = setup(t);
  writeFileSync(path.join(f.repositoryRoot, ".gitattributes"), "README.md export-ignore\n");
  git(f.repositoryRoot, "add", ".gitattributes");
  git(f.repositoryRoot, "commit", "-m", "export-ignore");
  const revision = git(f.repositoryRoot, "rev-parse", "HEAD");
  git(f.repositoryRoot, "update-ref", "refs/remotes/origin/main", revision);
  writeFileSync(f.ciManifestPath, JSON.stringify(manifest(revision)));
  await assert.rejects(prepareOfflineReleaseBundle({ ...f.options, revision }), /archive attributes/);
  assert.deepEqual(readdirSync(f.stagingParent), []);
});

test("rejects image identity changes between initial inspect and saved artifacts", async (t) => {
  const f = setup(t);
  const base = f.options.runner;
  let inspections = 0;
  const runner = async (program, args, options) => {
    const output = await base(program, args, options);
    if (program !== "docker" || args[0] !== "image") return output;
    inspections += 1;
    if (inspections <= 2) return output;
    const value = JSON.parse(output);
    value[0].Size += 1;
    return JSON.stringify(value);
  };
  await assert.rejects(prepareOfflineReleaseBundle({ ...f.options, runner }), /metadata shifted/);
  assert.deepEqual(readdirSync(f.stagingParent), []);
});
