import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, linkSync, mkdirSync, mkdtempSync, readFileSync,
  renameSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import {
  inspectUntrustedSourceGitForPreview, verifyInstalledTrustedSourceGit,
} from "./trusted-source-git.mjs";

const sha256 = (value) => createHash("sha256").update(value).digest("hex");
function git(args, options = {}) {
  return execFileSync("git", args, { encoding: "utf8", timeout: 10000,
    env: { ...process.env, GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_AUTHOR_DATE: "1700000000 +0000", GIT_COMMITTER_DATE: "1700000000 +0000" },
    ...options }).trim();
}

function fixture(t) {
  assert.equal(process.platform, "linux", "Run these tests in Linux Docker Node 22");
  assert.equal(process.getuid(), 0, "Run these tests as container root");
  const base = mkdtempSync("/var/lib/virki-source-proof-");
  chmodSync(base, 0o700);
  t.after(() => rmSync(base, { recursive: true, force: true }));
  const work = path.join(base, "builder");
  mkdirSync(work, { mode: 0o700 });
  git(["init", "-q", "-b", "main", work]);
  git(["-C", work, "config", "user.name", "Fixture"]);
  git(["-C", work, "config", "user.email", "fixture@example.invalid"]);
  mkdirSync(path.join(work, "bin"));
  writeFileSync(path.join(work, "README.md"), "trusted Git blob original\n");
  writeFileSync(path.join(work, "bin", "check.sh"), "#!/bin/sh\necho verified\n");
  git(["-C", work, "add", "."]);
  git(["-C", work, "update-index", "--chmod=+x", "bin/check.sh"]);
  git(["-C", work, "commit", "-qm", "approved source"]);
  const revision = git(["-C", work, "rev-parse", "HEAD"]);
  const trusted = path.join(base, "trusted.git");
  git(["init", "--bare", "-q", "-b", "main", trusted]);
  git(["-C", work, "push", "-q", trusted, "main:main"]);
  chmodSync(trusted, 0o700);
  const pin = path.join(base, "trusted-source.sha");
  writeFileSync(pin, `${revision}\n`, { mode: 0o600 });
  const candidate = path.join(base, "candidate");
  mkdirSync(candidate, { mode: 0o700 });
  const tar = path.join(candidate, "source.tar");
  git([`--git-dir=${trusted}`, "archive", "--format=tar", `--output=${tar}`, revision]);
  chmodSync(tar, 0o600);
  const bytes = readFileSync(tar);
  const fields = () => ({
    sourceArchivePath: tar,
    candidateSourceSha: revision,
    candidateArchiveSha256: sha256(readFileSync(tar)),
    candidateArchiveSizeBytes: readFileSync(tar).length,
    trustedGitDirectory: trusted,
    trustedShaPinPath: pin,
  });
  return { base, work, trusted, pin, candidate, tar, bytes, revision, fields };
}

test("independent root-installed SHA pin and Git blob tree verify a genuine source TAR", async (t) => {
  const f = fixture(t);
  const result = await inspectUntrustedSourceGitForPreview(f.fields());
  assert.equal(result.status, "INDEPENDENT_GIT_SOURCE_PREVIEW_ONLY");
  assert.equal(result.sourceSha, f.revision);
  assert.equal(result.archiveSha256, sha256(f.bytes));
  assert.equal(result.deployAuthorized, false);
  assert.equal(Object.hasOwn(result, "acceptanceToken"), false);
  assert.equal(Object.isFrozen(result), true);
});

test("internally matching claimed signed TAR digest cannot mask altered source blob", async (t) => {
  const f = fixture(t);
  const altered = Buffer.from(f.bytes);
  const at = altered.indexOf(Buffer.from("trusted Git blob original"));
  assert.ok(at > 0);
  altered[at] ^= 1;
  writeFileSync(f.tar, altered);
  assert.equal(f.fields().candidateArchiveSha256, sha256(altered));
  await assert.rejects(inspectUntrustedSourceGitForPreview(f.fields()), /blob content differs|refused/u);
});

test("candidate revision and internally consistent archive never substitute host SHA pin", async (t) => {
  const f = fixture(t);
  writeFileSync(path.join(f.work, "README.md"), "untrusted changed source\n");
  git(["-C", f.work, "add", "."]);
  git(["-C", f.work, "commit", "-qm", "unauthorized tree"]);
  const foreign = git(["-C", f.work, "rev-parse", "HEAD"]);
  git(["-C", f.work, "push", "-q", f.trusted, "main:main"]);
  git([`--git-dir=${f.trusted}`, "archive", "--format=tar", `--output=${f.tar}`, foreign]);
  const changed = { ...f.fields(), candidateSourceSha: foreign };
  await assert.rejects(inspectUntrustedSourceGitForPreview(changed), /refused|pin/u);
  await assert.rejects(inspectUntrustedSourceGitForPreview(f.fields()), /refused|main|pin/u);
});

test("Git replacement refs and shallow repository are prohibited", async (t) => {
  const f = fixture(t);
  git(["-C", f.work, "commit", "--allow-empty", "-qm", "hostile substitution"]);
  const foreign = git(["-C", f.work, "rev-parse", "HEAD"]);
  git(["-C", f.work, "push", "-q", f.trusted, "HEAD:refs/heads/alternate"]);
  git([`--git-dir=${f.trusted}`, "replace", f.revision, foreign]);
  await assert.rejects(inspectUntrustedSourceGitForPreview(f.fields()), /refused|replace/u);
  git([`--git-dir=${f.trusted}`, "replace", "-d", f.revision]);
  const shallow = path.join(f.base, "shallow.git");
  git(["clone", "-q", "--bare", "--depth=1", `file://${f.trusted}`, shallow]);
  chmodSync(shallow, 0o700);
  await assert.rejects(inspectUntrustedSourceGitForPreview({
    ...f.fields(), trustedGitDirectory: shallow,
  }), /refused|shallow/u);
});

test("symlink aliases, linked tar, Git object store aliases and untrusted pin are refused", async (t) => {
  const f = fixture(t);
  const alias = path.join(f.base, "git-alias");
  symlinkSync(f.trusted, alias, "dir");
  await assert.rejects(inspectUntrustedSourceGitForPreview({
    ...f.fields(), trustedGitDirectory: alias,
  }), /refused|alias/u);
  const originalPin = path.join(f.base, "real-pin");
  renameSync(f.pin, originalPin);
  symlinkSync(originalPin, f.pin);
  await assert.rejects(inspectUntrustedSourceGitForPreview(f.fields()), /refused|alias/u);
  rmSync(f.pin);
  renameSync(originalPin, f.pin);
  const link = path.join(f.candidate, "linked-source.tar");
  linkSync(f.tar, link);
  await assert.rejects(inspectUntrustedSourceGitForPreview(f.fields()), /refused|link/u);
  rmSync(link);
  const originalObjectDir = path.join(f.base, "real-objects");
  renameSync(path.join(f.trusted, "objects"), originalObjectDir);
  symlinkSync(originalObjectDir, path.join(f.trusted, "objects"), "dir");
  await assert.rejects(inspectUntrustedSourceGitForPreview(f.fields()), /refused|alias/u);
});

test("untrusted Git environment, injected SHA flags, alternates and missing pin cannot authorize", async (t) => {
  const f = fixture(t);
  const old = process.env.GIT_OBJECT_DIRECTORY;
  process.env.GIT_OBJECT_DIRECTORY = path.join(f.base, "hostile-objects");
  try {
    assert.equal((await inspectUntrustedSourceGitForPreview(f.fields())).deployAuthorized, false);
  } finally {
    if (old === undefined) delete process.env.GIT_OBJECT_DIRECTORY;
    else process.env.GIT_OBJECT_DIRECTORY = old;
  }
  await assert.rejects(inspectUntrustedSourceGitForPreview({
    ...f.fields(), candidateSourceSha: "--help",
  }), /refused/u);
  writeFileSync(path.join(f.trusted, "objects", "info", "alternates"), `${f.work}/.git/objects\n`);
  await assert.rejects(inspectUntrustedSourceGitForPreview(f.fields()), /refused|alternate/u);
  rmSync(path.join(f.trusted, "objects", "info", "alternates"));
  rmSync(f.pin);
  await assert.rejects(inspectUntrustedSourceGitForPreview(f.fields()), /refused/u);
});

test("matching candidate digest cannot hide changed executable mode or canonical commit time", async (t) => {
  const f = fixture(t);
  for (const variant of ["mode", "mtime"]) {
    const altered = Buffer.from(f.bytes);
    const member = altered.indexOf(Buffer.from("README.md"));
    assert.ok(member >= 0);
    const start = Math.floor(member / 512) * 512;
    const offset = start + (variant === "mode" ? 100 : 136);
    const width = variant === "mode" ? 8 : 12;
    const old = Number.parseInt(altered.toString("ascii", offset, offset + width).replace(/\0.*$/u, ""), 8);
    const changed = variant === "mode" ? 0o755 : old + 1;
    altered.write(changed.toString(8).padStart(width - 1, "0") + "\0", offset, "ascii");
    altered.fill(32, start + 148, start + 156);
    const checksum = altered.subarray(start, start + 512).reduce((sum, byte) => sum + byte, 0);
    altered.write(checksum.toString(8).padStart(7, "0") + "\0", start + 148, "ascii");
    writeFileSync(f.tar, altered);
    await assert.rejects(inspectUntrustedSourceGitForPreview(f.fields()), /refused|mode|metadata|timestamp/u);
  }
});

test("partial clone remote config cannot trigger an implicit Git fetch", async (t) => {
  const f = fixture(t);
  git([`--git-dir=${f.trusted}`, "config", "remote.origin.url", "https://example.invalid/hostile.git"]);
  git([`--git-dir=${f.trusted}`, "config", "remote.origin.promisor", "true"]);
  await assert.rejects(inspectUntrustedSourceGitForPreview(f.fields()), /refused|remote/u);
});

test("pin located inside the candidate itself is not independent trust", async (t) => {
  const f = fixture(t);
  const forgedPin = path.join(f.candidate, "trusted-source.sha");
  renameSync(f.pin, forgedPin);
  await assert.rejects(inspectUntrustedSourceGitForPreview({
    ...f.fields(), trustedShaPinPath: forgedPin,
  }), /refused|independent/u);
});

test("protected installed entrypoint ignores caller trust fields and refuses this unprovisioned host", async (t) => {
  const f = fixture(t);
  await assert.rejects(verifyInstalledTrustedSourceGit({
    candidateDirectory: f.candidate,
    trustedGitDirectory: f.trusted,
    trustedShaPinPath: f.pin,
  }), /refused/u);
  await assert.rejects(verifyInstalledTrustedSourceGit({ candidateDirectory: f.candidate }), /refused/u);
});
