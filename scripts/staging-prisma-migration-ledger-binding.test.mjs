import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  existsSync,
  linkSync,
  chmodSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  symlinkSync,
  unlinkSync,
  writeFileSync
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { deflateSync } from "node:zlib";
import {
  GIT_COMMAND_TIMEOUT_MS,
  GIT_EXECUTABLE,
  gitBuffer,
  parseCommitTreeObjectId,
  parseWindowsGitInstallPath,
  verifyPrismaMigrationLedger,
  verifyRegularFileSnapshot
} from "./staging-prisma-migration-ledger-binding.mjs";

const scriptPath = fileURLToPath(new URL("./staging-prisma-migration-ledger-binding.mjs", import.meta.url));
const gitExecutable = GIT_EXECUTABLE;
const gitExecutableStat = lstatSync(gitExecutable, { bigint: true });
assert.ok(gitExecutableStat.isFile() && !gitExecutableStat.isSymbolicLink() &&
  (process.platform === "win32" || gitExecutableStat.nlink === 1n),
  "tests must use the pinned, regular system Git executable");
const verifierSource = readFileSync(scriptPath, "utf8");
assert.match(verifierSource, /HKLM\\\\SOFTWARE\\\\GitForWindows/u,
  "Windows Git must be resolved from the machine-wide installer registration");
assert.doesNotMatch(verifierSource, /process\.env\.ProgramFiles/u,
  "a caller-controlled ProgramFiles variable must not redirect the pinned executable");

function isolatedGitEnvironment(source = process.env) {
  const environment = Object.fromEntries(
    Object.entries(source).filter(([name]) => !/^GIT_/iu.test(name))
  );
  environment.GIT_NO_REPLACE_OBJECTS = "1";
  environment.GIT_NO_LAZY_FETCH = "1";
  environment.GIT_OPTIONAL_LOCKS = "0";
  environment.GIT_CONFIG_NOSYSTEM = "1";
  environment.GIT_CONFIG_GLOBAL = process.platform === "win32" ? "NUL" : "/dev/null";
  return environment;
}

function runGit(args, cwd, input, environment = process.env) {
  const result = spawnSync(gitExecutable, args, {
    cwd,
    input,
    encoding: "utf8",
    env: isolatedGitEnvironment(environment),
    windowsHide: true
  });
  assert.equal(result.error, undefined, result.error?.message);
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}

function createFixture({
  environment = process.env,
  attributes = "",
  autocrlf = false,
  objectFormat = "sha1",
  directoryPrefix = "virki-prisma-ledger-"
} = {}) {
  const projectRoot = mkdtempSync(path.join(os.tmpdir(), directoryPrefix));
  const migrationDirectory = path.join(projectRoot, "packages", "database", "prisma", "migrations");
  mkdirSync(migrationDirectory, { recursive: true });
  writeFileSync(path.join(migrationDirectory, "migration_lock.toml"), 'provider = "postgresql"\n');
  writeFileSync(path.join(projectRoot, ".gitignore"), "20261114130000_ignored/\n");
  if (attributes) writeFileSync(path.join(projectRoot, ".gitattributes"), attributes);
  const migrations = [
    ["0_init", "CREATE TABLE \"User\" (\"id\" TEXT PRIMARY KEY);\n"],
    ["20261114120000_example", "ALTER TABLE \"User\" ADD COLUMN \"active\" BOOLEAN NOT NULL DEFAULT true;\n"]
  ];
  const expected = migrations.map(([name, sql]) => {
    const directory = path.join(migrationDirectory, name);
    mkdirSync(directory);
    writeFileSync(path.join(directory, "migration.sql"), sql);
    return { name, checksum: createHash("sha256").update(Buffer.from(sql)).digest("hex") };
  });
  const ledgerText = expected.map(({ name, checksum }) => `${name}\t${checksum}\ttrue\tfalse`).join("\n") + "\n";
  const git = (args, input) => runGit(args, projectRoot, input, environment);
  git(["init", "-q", ...(objectFormat === "sha1" ? [] : [`--object-format=${objectFormat}`])]);
  git(["config", "core.autocrlf", String(autocrlf)]);
  git(["config", "user.name", "Virki migration-ledger test"]);
  git(["config", "user.email", "virki-migration-ledger-test@example.invalid"]);
  git(["add", ".gitignore", ...(attributes ? [".gitattributes"] : []), "packages/database/prisma/migrations"]);
  git(["commit", "-qm", "fixture committed migration inventory"]);
  const approvedSourceSha = git(["rev-parse", "HEAD"]);
  return { projectRoot, migrationDirectory, expected, ledgerText, approvedSourceSha, git };
}

function createCommitWithTree(fixture, treeObjectId, { duplicateTreeHeader = false } = {}) {
  const author = "Virki migration-ledger test <virki-migration-ledger-test@example.invalid> 0 +0000";
  const treeHeaders = duplicateTreeHeader
    ? `tree ${treeObjectId}\ntree ${treeObjectId}`
    : `tree ${treeObjectId}`;
  const commit = Buffer.from(
    `${treeHeaders}\nauthor ${author}\ncommitter ${author}\n\nmalformed tree fixture\n`,
    "utf8"
  );
  const commitObjectId = fixture.git(["hash-object", "--literally", "-t", "commit", "-w", "--stdin"], commit);
  fixture.git(["update-ref", "HEAD", commitObjectId]);
  return commitObjectId;
}

function hexLedgerRows(fixture) {
  return fixture.expected.map(({ name, checksum }) =>
    [Buffer.from(name, "utf8").toString("hex"),
      Buffer.from(checksum, "utf8").toString("hex"),
      "true", "false"].join("\t")).join("\n") + "\n";
}

test("Windows Git path is derived from HKLM registration and ignores ProgramFiles", () => {
  assert.equal(
    parseWindowsGitInstallPath("HKEY_LOCAL_MACHINE\\SOFTWARE\\GitForWindows\r\n    InstallPath    REG_SZ    D:\\PortableGit\r\n"),
    "D:\\PortableGit\\cmd\\git.exe"
  );
  assert.throws(() => parseWindowsGitInstallPath("InstallPath REG_EXPAND_SZ %ProgramFiles%\\Git"), {
    code: "UNTRUSTED_GIT_EXECUTABLE"
  });
  assert.throws(() => parseWindowsGitInstallPath("InstallPath REG_SZ \\\\\server\\share\\Git"), {
    code: "UNTRUSTED_GIT_EXECUTABLE"
  });
  assert.match(verifierSource, /GLOBALROOT\/SystemRoot\/System32\/reg\.exe/u);
  assert.match(verifierSource, /GIT_CONFIG_NOSYSTEM = "1"/u);
  assert.match(verifierSource, /GIT_CONFIG_GLOBAL = process\.platform === "win32" \? "NUL" : "\/dev\/null"/u);
});

test("approved checkout migration inventory is accepted only when raw file bytes match the complete ledger", () => {
  const fixture = createFixture();
  try {
    assert.ok(fixture.expected.length > 0, "the approved fixture must contain committed migrations");
    assert.equal(verifyPrismaMigrationLedger(fixture), true);

    const accepted = spawnSync(process.execPath, [scriptPath], {
      cwd: fixture.projectRoot,
      input: fixture.ledgerText,
      encoding: "utf8",
      env: { ...isolatedGitEnvironment(), VIRKI_STAGING_APPROVED_SOURCE_SHA: fixture.approvedSourceSha }
    });
    assert.equal(accepted.status, 0);
    assert.equal(accepted.stdout, "STAGING_PRISMA_MIGRATION_LEDGER=PASS\n");
    assert.equal(accepted.stderr, "");
  } finally {
    rmSync(fixture.projectRoot, { recursive: true, force: true });
  }
});

test("verifier accepts a legitimate linked worktree .git pointer file", () => {
  const fixture = createFixture();
  const linkedWorktree = `${fixture.projectRoot}-linked-worktree`;
  try {
    fixture.git(["worktree", "add", "--detach", linkedWorktree, fixture.approvedSourceSha]);
    const linkedMigrationDirectory = path.join(
      linkedWorktree, "packages", "database", "prisma", "migrations"
    );
    assert.equal(verifyPrismaMigrationLedger({
      migrationDirectory: linkedMigrationDirectory,
      ledgerText: fixture.ledgerText,
      approvedSourceSha: fixture.approvedSourceSha
    }), true);
  } finally {
    rmSync(linkedWorktree, { recursive: true, force: true });
    rmSync(fixture.projectRoot, { recursive: true, force: true });
  }
});

test("restored migration ledger must exactly match every committed migration name and checksum", () => {
  const fixture = createFixture();
  try {
    assert.equal(verifyPrismaMigrationLedger(fixture), true);
    assert.throws(() => verifyPrismaMigrationLedger({
      ...fixture,
      ledgerText: fixture.ledgerText.split("\n").slice(0, -2).join("\n") + "\n"
    }), { code: "MIGRATION_LEDGER_SET_MISMATCH" });
    assert.throws(() => verifyPrismaMigrationLedger({
      ...fixture,
      ledgerText: fixture.ledgerText.replace(fixture.expected[0].checksum, "a".repeat(64))
    }), { code: "MIGRATION_LEDGER_CHECKSUM_MISMATCH" });
  } finally {
    rmSync(fixture.projectRoot, { recursive: true, force: true });
  }
});

test("restored migration ledger rejects duplicate, extra, unfinished, and rolled-back rows", () => {
  const fixture = createFixture();
  try {
    const first = fixture.ledgerText.split("\n")[0];
    assert.throws(() => verifyPrismaMigrationLedger({
      ...fixture,
      ledgerText: `${fixture.ledgerText}${first}\n`
    }), { code: "INVALID_MIGRATION_LEDGER_STATE" });
    assert.throws(() => verifyPrismaMigrationLedger({
      ...fixture,
      ledgerText: `${fixture.ledgerText}20261115000000_unexpected\t${"b".repeat(64)}\ttrue\tfalse\n`
    }), { code: "MIGRATION_LEDGER_SET_MISMATCH" });
    assert.throws(() => verifyPrismaMigrationLedger({
      ...fixture,
      ledgerText: fixture.ledgerText.replace("\ttrue\tfalse", "\tfalse\tfalse")
    }), { code: "INVALID_MIGRATION_LEDGER_STATE" });
    assert.throws(() => verifyPrismaMigrationLedger({
      ...fixture,
      ledgerText: fixture.ledgerText.replace("\ttrue\tfalse", "\ttrue\ttrue")
    }), { code: "INVALID_MIGRATION_LEDGER_STATE" });
  } finally {
    rmSync(fixture.projectRoot, { recursive: true, force: true });
  }
});

test("migration inventory rejects ignored untracked directories and dirty committed SQL", () => {
  const fixture = createFixture();
  try {
    const ignoredDirectory = path.join(fixture.migrationDirectory, "20261114130000_ignored");
    mkdirSync(ignoredDirectory);
    writeFileSync(path.join(ignoredDirectory, "migration.sql"), "SELECT 1;\n");
    assert.throws(() => verifyPrismaMigrationLedger(fixture), { code: "UNTRACKED_MIGRATION_ENTRY" });

    rmSync(ignoredDirectory, { recursive: true, force: true });
    const committedSql = path.join(fixture.migrationDirectory, fixture.expected[0].name, "migration.sql");
    writeFileSync(committedSql, `${readFileSync(committedSql, "utf8")}-- modified after approved commit\n`);
    assert.throws(() => verifyPrismaMigrationLedger(fixture), { code: "MIGRATION_SOURCE_TREE_MISMATCH" });
  } finally {
    rmSync(fixture.projectRoot, { recursive: true, force: true });
  }
});

function shellQuote(value) {
  const normalized = process.platform === "win32" ? value.replaceAll("\\", "/") : value;
  return `'${normalized.replaceAll("'", "'\\''")}'`;
}

test("raw-byte verification defeats a clean filter combined with assume-unchanged", () => {
  const fixture = createFixture({
    attributes: "packages/database/prisma/migrations/**/migration.sql filter=strip-sleep\n",
    directoryPrefix: process.platform === "win32"
      ? "virki-prisma-quote-' space-$tick-"
      : "virki-prisma-quote-' space-$tick-"
  });
  try {
    const relativePath = "packages/database/prisma/migrations/0_init/migration.sql";
    const sqlPath = path.join(fixture.migrationDirectory, "0_init", "migration.sql");
    const original = readFileSync(sqlPath);
    const filterScript = path.join(fixture.projectRoot, ".git", "strip-sleep-filter.mjs");
    if (process.platform !== "win32") {
      assert.equal(shellQuote("/tmp/with\\backslash"), "'/tmp/with\\backslash'");
    }
    writeFileSync(filterScript,
      'import { readFileSync } from "node:fs";\n' +
      'const input = readFileSync(0, "utf8");\n' +
      'process.stdout.write(input.replace(/^SELECT pg_sleep\\(1000\\);\\r?\\n?/gmu, ""));\n');
    fixture.git(["config", "filter.strip-sleep.clean", `${shellQuote(process.execPath)} ${shellQuote(filterScript)}`]);
    fixture.git(["config", "filter.strip-sleep.required", "true"]);
    fixture.git(["update-index", "--assume-unchanged", relativePath]);

    const attack = Buffer.concat([original, Buffer.from("SELECT pg_sleep(1000);\n")]);
    writeFileSync(sqlPath, attack);
    assert.equal(fixture.git(["status", "--porcelain"]), "",
      "assume-unchanged must hide the modified migration from ordinary status checks");

    const committedBlob = fixture.git(["rev-parse", `${fixture.approvedSourceSha}:${relativePath}`]);
    const filteredHash = fixture.git(["hash-object", `--path=${relativePath}`, "--stdin"], attack);
    const rawHash = fixture.git(["hash-object", "--no-filters", "--stdin"], attack);
    assert.equal(filteredHash, committedBlob, "the clean filter must reproduce the vulnerable accepted object ID");
    assert.notEqual(rawHash, committedBlob, "the raw bytes must differ from the approved blob");
    assert.throws(() => verifyPrismaMigrationLedger(fixture), { code: "MIGRATION_SOURCE_TREE_MISMATCH" });
  } finally {
    rmSync(fixture.projectRoot, { recursive: true, force: true });
  }
});

test("raw-byte verification rejects CRLF checkout conversion even when Git's clean filter matches", () => {
  const fixture = createFixture({
    attributes: "packages/database/prisma/migrations/**/migration.sql text\n",
    autocrlf: true
  });
  try {
    const relativePath = "packages/database/prisma/migrations/0_init/migration.sql";
    const sqlPath = path.join(fixture.migrationDirectory, "0_init", "migration.sql");
    const original = readFileSync(sqlPath, "utf8");
    const crlf = Buffer.from(original.replaceAll("\n", "\r\n"), "utf8");
    fixture.git(["update-index", "--assume-unchanged", relativePath]);
    writeFileSync(sqlPath, crlf);

    const committedBlob = fixture.git(["rev-parse", `${fixture.approvedSourceSha}:${relativePath}`]);
    const filteredHash = fixture.git(["hash-object", `--path=${relativePath}`, "--stdin"], crlf);
    const rawHash = fixture.git(["hash-object", "--no-filters", "--stdin"], crlf);
    assert.equal(filteredHash, committedBlob, "Git's text normalization must reproduce the committed blob");
    assert.notEqual(rawHash, committedBlob, "the checked-out CRLF bytes must not be mistaken for committed LF bytes");
    assert.throws(() => verifyPrismaMigrationLedger(fixture), { code: "MIGRATION_SOURCE_TREE_MISMATCH" });
  } finally {
    rmSync(fixture.projectRoot, { recursive: true, force: true });
  }
});

test("skip-worktree cannot hide changed migration bytes from the verifier", () => {
  const fixture = createFixture();
  try {
    const relativePath = "packages/database/prisma/migrations/0_init/migration.sql";
    const sqlPath = path.join(fixture.migrationDirectory, "0_init", "migration.sql");
    fixture.git(["update-index", "--skip-worktree", relativePath]);
    writeFileSync(sqlPath, "DROP TABLE \"User\";\n");
    assert.equal(fixture.git(["status", "--porcelain"]), "",
      "skip-worktree must hide the modified migration from ordinary status checks");
    assert.throws(() => verifyPrismaMigrationLedger(fixture), { code: "MIGRATION_SOURCE_TREE_MISMATCH" });
  } finally {
    rmSync(fixture.projectRoot, { recursive: true, force: true });
  }
});

test("approved commit tree replacement refs cannot substitute migration SQL", () => {
  const fixture = createFixture();
  try {
    const relativePath = "packages/database/prisma/migrations/0_init/migration.sql";
    const sqlPath = path.join(fixture.migrationDirectory, "0_init", "migration.sql");
    const approvedTree = fixture.git(["rev-parse", `${fixture.approvedSourceSha}^{tree}`]);
    const replacementSql = "DROP TABLE \"User\";\n";
    writeFileSync(sqlPath, replacementSql);
    fixture.git(["add", relativePath]);
    const replacementTree = fixture.git(["write-tree"]);
    fixture.git(["replace", approvedTree, replacementTree]);

    assert.equal(fixture.git(["rev-parse", "HEAD"]), fixture.approvedSourceSha,
      "the approved commit identity must remain unchanged during the tree-replacement attack");
    assert.equal(fixture.git(["rev-parse", `${fixture.approvedSourceSha}^{commit}`]), fixture.approvedSourceSha);
    assert.ok(fixture.git(["replace", "-l"]).split("\n").includes(approvedTree));

    const replacementLedger = fixture.expected.map(({ name, checksum }) => ({
      name,
      checksum: name === "0_init" ? createHash("sha256").update(replacementSql).digest("hex") : checksum
    })).map(({ name, checksum }) => `${name}\t${checksum}\ttrue\tfalse`).join("\n") + "\n";
    assert.throws(() => verifyPrismaMigrationLedger({ ...fixture, ledgerText: replacementLedger }), {
      code: "MIGRATION_SOURCE_TREE_MISMATCH"
    });
  } finally {
    rmSync(fixture.projectRoot, { recursive: true, force: true });
  }
});

test("verifier rejects duplicate names and non-canonical ordering in hash-valid Git trees", () => {
  for (const attack of ["duplicate", "unsorted", "prefix-unsorted"]) {
    const fixture = createFixture();
    try {
      const packageTree = Buffer.from(fixture.git([
        "rev-parse", `${fixture.approvedSourceSha}:packages`
      ]), "hex");
      let malformedTree;
      if (attack === "duplicate") {
        const entry = Buffer.concat([Buffer.from("40000 packages\0", "utf8"), packageTree]);
        malformedTree = Buffer.concat([entry, entry]);
      } else {
        const gitignoreBlob = Buffer.from(fixture.git([
          "rev-parse", `${fixture.approvedSourceSha}:.gitignore`
        ]), "hex");
        const packagesEntry = Buffer.concat([Buffer.from("40000 packages\0", "utf8"), packageTree]);
        const secondName = attack === "prefix-unsorted" ? "packages.data" : ".gitignore";
        const secondEntry = Buffer.concat([Buffer.from(`100644 ${secondName}\0`, "utf8"), gitignoreBlob]);
        malformedTree = Buffer.concat([packagesEntry, secondEntry]);
      }
      const treeObjectId = fixture.git(["hash-object", "--literally", "-t", "tree", "-w", "--stdin"], malformedTree);
      const approvedSourceSha = createCommitWithTree(fixture, treeObjectId);
      assert.throws(() => verifyPrismaMigrationLedger({ ...fixture, approvedSourceSha }), {
        code: "INVALID_MIGRATION_GIT_TREE"
      }, `${attack} tree entries must not be interpreted using a first-match lookup`);
    } finally {
      rmSync(fixture.projectRoot, { recursive: true, force: true });
    }
  }
});

test("verifier accepts Git base_name_compare ordering when a file shares a directory prefix", () => {
  const fixture = createFixture();
  try {
    const packageTree = Buffer.from(fixture.git([
      "rev-parse", `${fixture.approvedSourceSha}:packages`
    ]), "hex");
    const gitignoreBlob = Buffer.from(fixture.git([
      "rev-parse", `${fixture.approvedSourceSha}:.gitignore`
    ]), "hex");
    // Git sorts "packages.data" before the directory "packages/": the
    // directory's virtual terminator is '/', while a file terminates at NUL.
    const fileEntry = Buffer.concat([Buffer.from("100644 packages.data\0", "utf8"), gitignoreBlob]);
    const directoryEntry = Buffer.concat([Buffer.from("40000 packages\0", "utf8"), packageTree]);
    const rootTree = fixture.git(["hash-object", "--literally", "-t", "tree", "-w", "--stdin"],
      Buffer.concat([fileEntry, directoryEntry]));
    const approvedSourceSha = createCommitWithTree(fixture, rootTree);
    assert.equal(verifyPrismaMigrationLedger({ ...fixture, approvedSourceSha }), true);
  } finally {
    rmSync(fixture.projectRoot, { recursive: true, force: true });
  }
});

test("verifier rejects duplicate commit tree headers even when the commit object hashes correctly", () => {
  const fixture = createFixture();
  try {
    const rootTree = fixture.git(["rev-parse", `${fixture.approvedSourceSha}^{tree}`]);
    const approvedSourceSha = createCommitWithTree(fixture, rootTree, { duplicateTreeHeader: true });
    assert.throws(() => verifyPrismaMigrationLedger({ ...fixture, approvedSourceSha }), {
      code: "INVALID_MIGRATION_GIT_TREE"
    });
  } finally {
    rmSync(fixture.projectRoot, { recursive: true, force: true });
  }
});

test("commit parser permits signed-header continuations but rejects malformed core-header ordering", () => {
  const fixture = createFixture();
  try {
    const original = fixture.git(["cat-file", "commit", fixture.approvedSourceSha]);
    const originalHeaders = original.split("\n\n", 1)[0];
    const signedCommit = fixture.git(["hash-object", "--literally", "-t", "commit", "-w", "--stdin"],
      Buffer.from(`${originalHeaders}\ngpgsig -----BEGIN PGP SIGNATURE-----\n aGVsbG8=\n -----END PGP SIGNATURE-----\n\n`, "utf8"));
    fixture.git(["update-ref", "HEAD", signedCommit]);
    assert.equal(verifyPrismaMigrationLedger({ ...fixture, approvedSourceSha: signedCommit }), true);

    const tree = fixture.git(["rev-parse", `${fixture.approvedSourceSha}^{tree}`]);
    const author = "author Virki <virki@example.invalid> 1700000000 +0000";
    const committer = "committer Virki <virki@example.invalid> 1700000000 +0000";
    const malformedCommits = [
      `tree ${tree}\nparent not-an-object-id\n${author}\n${committer}\n\n`,
      `tree ${tree}\n${author}\n parent-continuation-is-invalid\n${committer}\n\n`,
      `tree ${tree}\n${author}\n${committer}\nparent ${"a".repeat(40)}\n\n`
    ];
    for (const content of malformedCommits) {
      // Git refuses to update HEAD to structurally bad commits. Exercise the
      // independent parser directly so a HEAD mismatch cannot falsely pass.
      assert.throws(() => parseCommitTreeObjectId(Buffer.from(content, "utf8"), 20), {
        code: "INVALID_MIGRATION_GIT_TREE"
      });
    }
  } finally {
    rmSync(fixture.projectRoot, { recursive: true, force: true });
  }
});

test("fixture Git operations and verifier CLI ignore ambient Git repository/index/object/config redirection", () => {
  const foreignRoot = mkdtempSync(path.join(os.tmpdir(), "virki-prisma-foreign-git-"));
  let fixture;
  try {
    runGit(["init", "-q"], foreignRoot);
    if (process.platform !== "win32") {
      const fakeGit = path.join(foreignRoot, "git");
      writeFileSync(fakeGit, "#!/bin/sh\nexit 97\n");
      chmodSync(fakeGit, 0o700);
    }
    const hostileEnvironment = {
      ...process.env,
      ...(process.platform === "win32" ? {} : { PATH: `${foreignRoot}${path.delimiter}${process.env.PATH ?? ""}` }),
      GIT_DIR: path.join(foreignRoot, ".git"),
      GIT_WORK_TREE: foreignRoot,
      GIT_INDEX_FILE: path.join(foreignRoot, ".git", "index"),
      GIT_COMMON_DIR: path.join(foreignRoot, ".git"),
      GIT_OBJECT_DIRECTORY: path.join(foreignRoot, ".git", "objects"),
      GIT_ALTERNATE_OBJECT_DIRECTORIES: path.join(foreignRoot, ".git", "objects"),
      GIT_CONFIG: path.join(foreignRoot, "hostile.gitconfig"),
      GIT_CONFIG_COUNT: "1",
      GIT_CONFIG_KEY_0: "core.bare",
      GIT_CONFIG_VALUE_0: "true",
      GIT_NO_REPLACE_OBJECTS: "0",
      GIT_NO_LAZY_FETCH: "0",
      ProgramFiles: "",
      ...(process.platform === "win32" ? {
        WINDIR: foreignRoot
      } : {})
    };
    fixture = createFixture({ environment: hostileEnvironment });
    if (process.platform === "win32") {
      const relativeGitDirectory = path.join(fixture.projectRoot, "Git", "cmd");
      mkdirSync(relativeGitDirectory, { recursive: true });
      writeFileSync(path.join(relativeGitDirectory, "git.exe"), "not a Windows executable");
    }

    const accepted = spawnSync(process.execPath, [scriptPath], {
      cwd: fixture.projectRoot,
      input: fixture.ledgerText,
      encoding: "utf8",
      env: {
        ...hostileEnvironment,
        VIRKI_STAGING_APPROVED_SOURCE_SHA: fixture.approvedSourceSha
      }
    });
    assert.equal(accepted.status, 0);
    assert.equal(accepted.stdout, "STAGING_PRISMA_MIGRATION_LEDGER=PASS\n");
    assert.equal(accepted.stderr, "");
  } finally {
    if (fixture) rmSync(fixture.projectRoot, { recursive: true, force: true });
    rmSync(foreignRoot, { recursive: true, force: true });
  }
});

test("verifier rejects alternate and promisor object stores", () => {
  const alternateFixture = createFixture();
  try {
    const objectDirectory = alternateFixture.git([
      "rev-parse", "--path-format=absolute", "--git-path", "objects"
    ]);
    const infoDirectory = path.join(objectDirectory, "info");
    mkdirSync(infoDirectory, { recursive: true });
    writeFileSync(path.join(infoDirectory, "alternates"), `${objectDirectory}\n`);
    assert.throws(() => verifyPrismaMigrationLedger(alternateFixture), {
      code: "UNTRUSTED_GIT_OBJECT_STORE"
    });
  } finally {
    rmSync(alternateFixture.projectRoot, { recursive: true, force: true });
  }

  const promisorFixture = createFixture();
  try {
    promisorFixture.git(["config", "extensions.partialClone", "origin"]);
    assert.throws(() => verifyPrismaMigrationLedger(promisorFixture), {
      code: "UNTRUSTED_GIT_OBJECT_STORE"
    });
  } finally {
    rmSync(promisorFixture.projectRoot, { recursive: true, force: true });
  }
});

test("verifier rejects promisor markers, HTTP alternates, promisor remotes, and shallow object stores", () => {
  const promisorMarkerFixture = createFixture();
  try {
    const objectDirectory = promisorMarkerFixture.git([
      "rev-parse", "--path-format=absolute", "--git-path", "objects"
    ]);
    const packDirectory = path.join(objectDirectory, "pack");
    mkdirSync(packDirectory, { recursive: true });
    writeFileSync(path.join(packDirectory, "pack-test.promisor"), "");
    assert.throws(() => verifyPrismaMigrationLedger(promisorMarkerFixture), {
      code: "UNTRUSTED_GIT_OBJECT_STORE"
    });
  } finally {
    rmSync(promisorMarkerFixture.projectRoot, { recursive: true, force: true });
  }

  const httpAlternateFixture = createFixture();
  try {
    const objectDirectory = httpAlternateFixture.git([
      "rev-parse", "--path-format=absolute", "--git-path", "objects"
    ]);
    const infoDirectory = path.join(objectDirectory, "info");
    mkdirSync(infoDirectory, { recursive: true });
    writeFileSync(path.join(infoDirectory, "http-alternates"), "https://objects.example.invalid/\n");
    assert.throws(() => verifyPrismaMigrationLedger(httpAlternateFixture), {
      code: "UNTRUSTED_GIT_OBJECT_STORE"
    });
  } finally {
    rmSync(httpAlternateFixture.projectRoot, { recursive: true, force: true });
  }

  const promisorRemoteFixture = createFixture();
  try {
    promisorRemoteFixture.git(["config", "remote.origin.promisor", "true"]);
    assert.throws(() => verifyPrismaMigrationLedger(promisorRemoteFixture), {
      code: "UNTRUSTED_GIT_OBJECT_STORE"
    });
  } finally {
    rmSync(promisorRemoteFixture.projectRoot, { recursive: true, force: true });
  }

  const shallowFixture = createFixture();
  try {
    writeFileSync(path.join(shallowFixture.projectRoot, ".git", "shallow"), `${shallowFixture.approvedSourceSha}\n`);
    assert.throws(() => verifyPrismaMigrationLedger(shallowFixture), {
      code: "UNTRUSTED_GIT_OBJECT_STORE"
    });
  } finally {
    rmSync(shallowFixture.projectRoot, { recursive: true, force: true });
  }
});

test("verifier rejects a loose Git blob whose compressed bytes do not match its object ID", () => {
  const fixture = createFixture();
  try {
    const relativePath = "packages/database/prisma/migrations/0_init/migration.sql";
    const blobObjectId = fixture.git(["rev-parse", `${fixture.approvedSourceSha}:${relativePath}`]);
    const objectDirectory = fixture.git([
      "rev-parse", "--path-format=absolute", "--git-path", "objects"
    ]);
    const looseObjectPath = path.join(objectDirectory, blobObjectId.slice(0, 2), blobObjectId.slice(2));
    const replacement = Buffer.from('DROP TABLE "User";\n', "utf8");
    const header = Buffer.from(`blob ${replacement.length}\0`, "utf8");
    chmodSync(looseObjectPath, 0o600);
    writeFileSync(looseObjectPath, deflateSync(Buffer.concat([header, replacement])));

    const catFile = spawnSync(gitExecutable, ["cat-file", "blob", blobObjectId], {
      cwd: fixture.projectRoot,
      encoding: null,
      env: isolatedGitEnvironment(),
      windowsHide: true
    });
    assert.equal(catFile.status, 0, catFile.stderr,
      "the fixture must prove Git returns the substituted loose-object bytes under the approved OID");
    assert.deepEqual(catFile.stdout, replacement,
      "the fixture should reproduce Git returning substituted loose-object bytes under the approved OID");
    assert.throws(() => verifyPrismaMigrationLedger(fixture), {
      code: "UNTRUSTED_GIT_OBJECT_STORE"
    });
  } finally {
    rmSync(fixture.projectRoot, { recursive: true, force: true });
  }
});

test("verifier accepts a valid SHA-256 repository and rejects SHA-1-length approval there", () => {
  const fixture = createFixture({ objectFormat: "sha256" });
  try {
    assert.equal(fixture.git(["rev-parse", "--show-object-format"]), "sha256");
    assert.equal(fixture.approvedSourceSha.length, 64);
    assert.equal(verifyPrismaMigrationLedger(fixture), true);
    assert.throws(() => verifyPrismaMigrationLedger({
      ...fixture,
      approvedSourceSha: fixture.approvedSourceSha.slice(0, 40)
    }), { code: "INVALID_APPROVED_SOURCE_SHA" });
  } finally {
    rmSync(fixture.projectRoot, { recursive: true, force: true });
  }
});

test("verifier rejects nested loose-object fanout directories for SHA-1 and SHA-256", () => {
  for (const objectFormat of ["sha1", "sha256"]) {
    const fixture = createFixture({ objectFormat });
    try {
      const objectId = fixture.git([
        "rev-parse", `${fixture.approvedSourceSha}:packages/database/prisma/migrations/0_init/migration.sql`
      ]);
      const objectDirectory = fixture.git([
        "rev-parse", "--path-format=absolute", "--git-path", "objects"
      ]);
      const nestedFanout = path.join(objectDirectory, objectId.slice(0, 2), "ab");
      mkdirSync(nestedFanout);
      writeFileSync(path.join(nestedFanout, "not-a-loose-object"), "unreferenced ODB leaf");
      assert.throws(() => verifyPrismaMigrationLedger(fixture), {
        code: "UNTRUSTED_GIT_OBJECT_STORE"
      });
    } finally {
      rmSync(fixture.projectRoot, { recursive: true, force: true });
    }
  }
});

test("unreferenced loose-object fanout cannot make the scanner unbounded", () => {
  const fixture = createFixture();
  try {
    const objectDirectory = fixture.git([
      "rev-parse", "--path-format=absolute", "--git-path", "objects"
    ]);
    const fanout = path.join(objectDirectory, "ff");
    mkdirSync(fanout, { recursive: true });
    for (let index = 0; index <= 8_192; index += 1) {
      writeFileSync(path.join(fanout, index.toString(16).padStart(38, "0")), "");
    }
    assert.throws(() => verifyPrismaMigrationLedger(fixture), {
      code: "UNTRUSTED_GIT_OBJECT_STORE"
    });
  } finally {
    rmSync(fixture.projectRoot, { recursive: true, force: true });
  }
});

test("verifier accepts legitimate packed ODB and multi-pack-index layouts", () => {
  for (const objectFormat of ["sha1", "sha256"]) {
    const fixture = createFixture({ objectFormat });
    try {
      fixture.git(["repack", "-ad"]);
      fixture.git(["multi-pack-index", "write"]);
      const objectDirectory = fixture.git([
        "rev-parse", "--path-format=absolute", "--git-path", "objects"
      ]);
      const packDirectory = path.join(objectDirectory, "pack");
      const expectedLength = objectFormat === "sha1" ? 40 : 64;
      assert.ok(readdirSync(packDirectory).some((name) =>
        new RegExp(`^pack-[a-f0-9]{${expectedLength}}\\.pack$`, "u").test(name)));
      assert.ok(existsSync(path.join(packDirectory, "multi-pack-index")));
      assert.equal(verifyPrismaMigrationLedger(fixture), true);
    } finally {
      rmSync(fixture.projectRoot, { recursive: true, force: true });
    }
  }
});

test("verifier accepts a valid split commit-graph for SHA-1 and SHA-256", () => {
  for (const objectFormat of ["sha1", "sha256"]) {
    const fixture = createFixture({ objectFormat });
    try {
      fixture.git(["commit-graph", "write", "--reachable", "--split"]);
      const objectDirectory = fixture.git([
        "rev-parse", "--path-format=absolute", "--git-path", "objects"
      ]);
      const graphDirectory = path.join(objectDirectory, "info", "commit-graphs");
      assert.ok(existsSync(path.join(graphDirectory, "commit-graph-chain")));
      assert.ok(readdirSync(graphDirectory).some((name) =>
        new RegExp(`^graph-[a-f0-9]{${objectFormat === "sha1" ? 40 : 64}}\\.graph$`, "u").test(name)));
      assert.equal(verifyPrismaMigrationLedger(fixture), true);
    } finally {
      rmSync(fixture.projectRoot, { recursive: true, force: true });
    }
  }
});

test("verifier rejects split commit-graph filenames with a non-canonical OID length", () => {
  for (const objectFormat of ["sha1", "sha256"]) {
    const fixture = createFixture({ objectFormat });
    try {
      const objectDirectory = fixture.git([
        "rev-parse", "--path-format=absolute", "--git-path", "objects"
      ]);
      const graphDirectory = path.join(objectDirectory, "info", "commit-graphs");
      mkdirSync(graphDirectory, { recursive: true });
      writeFileSync(path.join(graphDirectory,
        `graph-${"a".repeat(objectFormat === "sha1" ? 39 : 63)}.graph`), "invalid graph");
      assert.throws(() => verifyPrismaMigrationLedger(fixture), {
        code: "UNTRUSTED_GIT_OBJECT_STORE"
      });
    } finally {
      rmSync(fixture.projectRoot, { recursive: true, force: true });
    }
  }
});

test("split commit-graph data must match its canonical checksum in both object formats", () => {
  for (const objectFormat of ["sha1", "sha256"]) {
    const fixture = createFixture({ objectFormat });
    try {
      fixture.git(["commit-graph", "write", "--reachable", "--split"]);
      const objectDirectory = fixture.git([
        "rev-parse", "--path-format=absolute", "--git-path", "objects"
      ]);
      const graphDirectory = path.join(objectDirectory, "info", "commit-graphs");
      const graphFile = path.join(graphDirectory, readdirSync(graphDirectory)
        .find((name) => name.endsWith(".graph")));
      const corrupt = readFileSync(graphFile);
      corrupt[corrupt.length - 1] ^= 0xff;
      chmodSync(graphFile, 0o600);
      writeFileSync(graphFile, corrupt);
      assert.throws(() => verifyPrismaMigrationLedger(fixture), {
        code: "UNTRUSTED_GIT_OBJECT_STORE"
      });
    } finally {
      rmSync(fixture.projectRoot, { recursive: true, force: true });
    }
  }
});

test("verifier rejects uppercase promisor markers in a pack directory", () => {
  const fixture = createFixture();
  try {
    const objectDirectory = fixture.git([
      "rev-parse", "--path-format=absolute", "--git-path", "objects"
    ]);
    const packDirectory = path.join(objectDirectory, "pack");
    mkdirSync(packDirectory, { recursive: true });
    writeFileSync(path.join(packDirectory, `pack-${"a".repeat(40)}.PROMISOR`), "");
    assert.throws(() => verifyPrismaMigrationLedger(fixture), {
      code: "UNTRUSTED_GIT_OBJECT_STORE"
    });
  } finally {
    rmSync(fixture.projectRoot, { recursive: true, force: true });
  }
});

test("SHA-256 hash-valid malformed tree and duplicate commit headers are rejected", () => {
  const treeFixture = createFixture({ objectFormat: "sha256" });
  try {
    const packageTree = Buffer.from(treeFixture.git([
      "rev-parse", `${treeFixture.approvedSourceSha}:packages`
    ]), "hex");
    const entry = Buffer.concat([Buffer.from("40000 packages\0", "utf8"), packageTree]);
    const malformedTree = treeFixture.git(["hash-object", "--literally", "-t", "tree", "-w", "--stdin"],
      Buffer.concat([entry, entry]));
    const approvedSourceSha = createCommitWithTree(treeFixture, malformedTree);
    assert.throws(() => verifyPrismaMigrationLedger({ ...treeFixture, approvedSourceSha }), {
      code: "INVALID_MIGRATION_GIT_TREE"
    });
  } finally {
    rmSync(treeFixture.projectRoot, { recursive: true, force: true });
  }

  const commitFixture = createFixture({ objectFormat: "sha256" });
  try {
    const rootTree = commitFixture.git(["rev-parse", `${commitFixture.approvedSourceSha}^{tree}`]);
    const approvedSourceSha = createCommitWithTree(commitFixture, rootTree, { duplicateTreeHeader: true });
    assert.throws(() => verifyPrismaMigrationLedger({ ...commitFixture, approvedSourceSha }), {
      code: "INVALID_MIGRATION_GIT_TREE"
    });
  } finally {
    rmSync(commitFixture.projectRoot, { recursive: true, force: true });
  }
});

test("SHA-256 loose-object bytes are rehashed instead of trusting Git's object lookup", () => {
  const fixture = createFixture({ objectFormat: "sha256" });
  try {
    const relativePath = "packages/database/prisma/migrations/0_init/migration.sql";
    const objectId = fixture.git(["rev-parse", `${fixture.approvedSourceSha}:${relativePath}`]);
    const objectDirectory = fixture.git([
      "rev-parse", "--path-format=absolute", "--git-path", "objects"
    ]);
    const looseObjectPath = path.join(objectDirectory, objectId.slice(0, 2), objectId.slice(2));
    const replacement = Buffer.from('DROP TABLE "User";\n', "utf8");
    const header = Buffer.from(`blob ${replacement.length}\0`, "utf8");
    chmodSync(looseObjectPath, 0o600);
    writeFileSync(looseObjectPath, deflateSync(Buffer.concat([header, replacement])));
    const catFile = spawnSync(gitExecutable, ["cat-file", "blob", objectId], {
      cwd: fixture.projectRoot,
      encoding: null,
      env: isolatedGitEnvironment(),
      windowsHide: true
    });
    assert.equal(catFile.status, 0, catFile.stderr,
      "Git must return the substituted bytes so the verifier's independent SHA-256 check is exercised");
    assert.deepEqual(catFile.stdout, replacement);
    assert.throws(() => verifyPrismaMigrationLedger(fixture), {
      code: "UNTRUSTED_GIT_OBJECT_STORE"
    });
  } finally {
    rmSync(fixture.projectRoot, { recursive: true, force: true });
  }
});

test("leaf-file identity snapshots detect replacement after the initial read", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "virki-object-leaf-snapshot-"));
  try {
    const filePath = path.join(directory, "loose-object");
    writeFileSync(filePath, "original object bytes");
    const snapshot = { path: filePath, stat: lstatSync(filePath, { bigint: true }) };
    writeFileSync(filePath, "replacement object bytes");
    assert.throws(() => verifyRegularFileSnapshot(snapshot), {
      code: "UNTRUSTED_GIT_OBJECT_STORE"
    });
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("leaf-file snapshots reject atomic path replacement with identical content", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "virki-object-atomic-swap-"));
  try {
    const filePath = path.join(directory, "loose-object");
    const original = Buffer.from("identical Git object content");
    writeFileSync(filePath, original);
    const snapshot = { path: filePath, stat: lstatSync(filePath, { bigint: true }) };
    renameSync(filePath, path.join(directory, "previous-object"));
    writeFileSync(filePath, original);
    assert.deepEqual(readFileSync(filePath), original);
    assert.throws(() => verifyRegularFileSnapshot(snapshot), {
      code: "UNTRUSTED_GIT_OBJECT_STORE"
    });
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("Git cat-file on a FIFO is bounded by the command timeout", (t) => {
  if (process.platform === "win32") {
    t.skip("POSIX FIFO semantics are not available on Windows");
    return;
  }
  const fixture = createFixture();
  try {
    const objectId = fixture.git([
      "rev-parse", `${fixture.approvedSourceSha}:packages/database/prisma/migrations/0_init/migration.sql`
    ]);
    const objectDirectory = fixture.git([
      "rev-parse", "--path-format=absolute", "--git-path", "objects"
    ]);
    const looseObjectPath = path.join(objectDirectory, objectId.slice(0, 2), objectId.slice(2));
    unlinkSync(looseObjectPath);
    const fifo = spawnSync("/usr/bin/mkfifo", [looseObjectPath], { encoding: "utf8", windowsHide: true });
    if (fifo.error || fifo.status !== 0) {
      t.skip(`mkfifo unavailable: ${fifo.error?.message ?? fifo.stderr}`);
      return;
    }
    const startedAt = Date.now();
    assert.throws(() => gitBuffer(["cat-file", "blob", objectId], fixture.projectRoot, undefined, {
      timeoutMs: 300
    }), (error) => error.code === "MIGRATION_GIT_TREE_UNAVAILABLE" && error.cause?.code === "ETIMEDOUT");
    const elapsedMs = Date.now() - startedAt;
    assert.ok(elapsedMs >= 250 && elapsedMs < 3_000, `timeout should be bounded, observed ${elapsedMs}ms`);
    assert.equal(GIT_COMMAND_TIMEOUT_MS, 10_000, "production Git commands retain the 10-second timeout");
  } finally {
    rmSync(fixture.projectRoot, { recursive: true, force: true });
  }
});

test("verifier rejects symlinked Git object and pack directories", (t) => {
  const objectFixture = createFixture();
  try {
    const objectDirectory = objectFixture.git([
      "rev-parse", "--path-format=absolute", "--git-path", "objects"
    ]);
    const objectTarget = `${objectDirectory}-target`;
    renameSync(objectDirectory, objectTarget);
    try {
      symlinkSync(objectTarget, objectDirectory, process.platform === "win32" ? "junction" : "dir");
    } catch (error) {
      t.skip(`object-directory junction unavailable: ${error.code ?? error.message}`);
      return;
    }
    assert.throws(() => verifyPrismaMigrationLedger(objectFixture), {
      code: "UNTRUSTED_GIT_OBJECT_STORE"
    });
  } finally {
    rmSync(objectFixture.projectRoot, { recursive: true, force: true });
  }

  const packFixture = createFixture();
  try {
    const objectDirectory = packFixture.git([
      "rev-parse", "--path-format=absolute", "--git-path", "objects"
    ]);
    const packDirectory = path.join(objectDirectory, "pack");
    const packTarget = path.join(objectDirectory, "pack-target");
    mkdirSync(packDirectory, { recursive: true });
    renameSync(packDirectory, packTarget);
    try {
      symlinkSync(packTarget, packDirectory, process.platform === "win32" ? "junction" : "dir");
    } catch (error) {
      t.skip(`pack-directory junction unavailable: ${error.code ?? error.message}`);
      return;
    }
    assert.throws(() => verifyPrismaMigrationLedger(packFixture), {
      code: "UNTRUSTED_GIT_OBJECT_STORE"
    });
  } finally {
    rmSync(packFixture.projectRoot, { recursive: true, force: true });
  }
});

test("verifier rejects symlinked info and loose-object fanout directories", (t) => {
  const infoFixture = createFixture();
  try {
    const objectDirectory = infoFixture.git([
      "rev-parse", "--path-format=absolute", "--git-path", "objects"
    ]);
    const infoDirectory = path.join(objectDirectory, "info");
    const infoTarget = path.join(infoFixture.projectRoot, ".git", "info-target");
    renameSync(infoDirectory, infoTarget);
    try {
      symlinkSync(infoTarget, infoDirectory, process.platform === "win32" ? "junction" : "dir");
    } catch (error) {
      t.skip(`info-directory junction unavailable: ${error.code ?? error.message}`);
      return;
    }
    assert.throws(() => verifyPrismaMigrationLedger(infoFixture), {
      code: "UNTRUSTED_GIT_OBJECT_STORE"
    });
  } finally {
    rmSync(infoFixture.projectRoot, { recursive: true, force: true });
  }

  const fanoutFixture = createFixture();
  try {
    const blobObjectId = fanoutFixture.git([
      "rev-parse", `${fanoutFixture.approvedSourceSha}:packages/database/prisma/migrations/0_init/migration.sql`
    ]);
    const objectDirectory = fanoutFixture.git([
      "rev-parse", "--path-format=absolute", "--git-path", "objects"
    ]);
    const fanoutDirectory = path.join(objectDirectory, blobObjectId.slice(0, 2));
    const fanoutTarget = `${objectDirectory}-fanout-target`;
    renameSync(fanoutDirectory, fanoutTarget);
    try {
      symlinkSync(fanoutTarget, fanoutDirectory, process.platform === "win32" ? "junction" : "dir");
    } catch (error) {
      t.skip(`fanout-directory junction unavailable: ${error.code ?? error.message}`);
      return;
    }
    assert.throws(() => verifyPrismaMigrationLedger(fanoutFixture), {
      code: "UNTRUSTED_GIT_OBJECT_STORE"
    });
  } finally {
    rmSync(fanoutFixture.projectRoot, { recursive: true, force: true });
  }
});

test("verifier rejects a symlinked Git common directory", (t) => {
  const fixture = createFixture();
  try {
    const gitDirectory = path.join(fixture.projectRoot, ".git");
    const targetDirectory = path.join(fixture.projectRoot, ".git-target");
    renameSync(gitDirectory, targetDirectory);
    try {
      symlinkSync(targetDirectory, gitDirectory, process.platform === "win32" ? "junction" : "dir");
    } catch (error) {
      t.skip(`common-directory junction unavailable: ${error.code ?? error.message}`);
      return;
    }
    assert.throws(() => verifyPrismaMigrationLedger(fixture), {
      code: "UNTRUSTED_GIT_OBJECT_STORE"
    });
  } finally {
    rmSync(fixture.projectRoot, { recursive: true, force: true });
  }
});

test("verifier rejects hard-linked loose objects and pack files", (t) => {
  const looseFixture = createFixture();
  try {
    const blobObjectId = looseFixture.git([
      "rev-parse", `${looseFixture.approvedSourceSha}:packages/database/prisma/migrations/0_init/migration.sql`
    ]);
    const objectDirectory = looseFixture.git([
      "rev-parse", "--path-format=absolute", "--git-path", "objects"
    ]);
    const looseObject = path.join(objectDirectory, blobObjectId.slice(0, 2), blobObjectId.slice(2));
    const hardlink = path.join(looseFixture.projectRoot, "linked-loose-object");
    try {
      linkSync(looseObject, hardlink);
    } catch (error) {
      t.skip(`loose-object hard links unavailable: ${error.code ?? error.message}`);
      return;
    }
    assert.throws(() => verifyPrismaMigrationLedger(looseFixture), {
      code: "UNTRUSTED_GIT_OBJECT_STORE"
    });
  } finally {
    rmSync(looseFixture.projectRoot, { recursive: true, force: true });
  }

  const packFixture = createFixture();
  try {
    const objectDirectory = packFixture.git([
      "rev-parse", "--path-format=absolute", "--git-path", "objects"
    ]);
    const packDirectory = path.join(objectDirectory, "pack");
    mkdirSync(packDirectory, { recursive: true });
    const packFile = path.join(packDirectory, "pack-test.idx");
    const hardlink = path.join(packFixture.projectRoot, "linked-pack-index");
    writeFileSync(packFile, "untrusted pack-index fixture");
    try {
      linkSync(packFile, hardlink);
    } catch (error) {
      t.skip(`pack-file hard links unavailable: ${error.code ?? error.message}`);
      return;
    }
    assert.throws(() => verifyPrismaMigrationLedger(packFixture), {
      code: "UNTRUSTED_GIT_OBJECT_STORE"
    });
  } finally {
    rmSync(packFixture.projectRoot, { recursive: true, force: true });
  }
});

test("verifier rejects a symlinked individual migration directory", (t) => {
  const fixture = createFixture();
  try {
    const migrationPath = path.join(fixture.migrationDirectory, "0_init");
    const targetPath = path.join(fixture.projectRoot, ".git", "0_init-target");
    renameSync(migrationPath, targetPath);
    try {
      symlinkSync(targetPath, migrationPath, process.platform === "win32" ? "junction" : "dir");
    } catch (error) {
      t.skip(`migration-directory junction unavailable: ${error.code ?? error.message}`);
      return;
    }
    assert.throws(() => verifyPrismaMigrationLedger(fixture), {
      code: "INVALID_MIGRATION_DIRECTORY"
    });
  } finally {
    rmSync(fixture.projectRoot, { recursive: true, force: true });
  }
});

test("verifier rejects a symlink or junction in a migration directory parent", (t) => {
  const fixture = createFixture();
  try {
    const packagesDirectory = path.join(fixture.projectRoot, "packages");
    const originalParent = path.join(packagesDirectory, "database");
    const targetParent = path.join(packagesDirectory, "database-target");
    renameSync(originalParent, targetParent);
    try {
      symlinkSync(targetParent, originalParent, process.platform === "win32" ? "junction" : "dir");
    } catch (error) {
      t.skip(`directory symlink/junction unavailable: ${error.code ?? error.message}`);
      return;
    }
    assert.throws(() => verifyPrismaMigrationLedger(fixture), { code: "INVALID_MIGRATION_DIRECTORY" });
  } finally {
    rmSync(fixture.projectRoot, { recursive: true, force: true });
  }
});

test("verifier rejects hard-linked migration SQL files", (t) => {
  const fixture = createFixture();
  try {
    const sqlPath = path.join(fixture.migrationDirectory, "0_init", "migration.sql");
    const linkedPath = path.join(fixture.projectRoot, "linked-migration.sql");
    writeFileSync(linkedPath, readFileSync(sqlPath));
    unlinkSync(sqlPath);
    try {
      linkSync(linkedPath, sqlPath);
    } catch (error) {
      t.skip(`hard links unavailable: ${error.code ?? error.message}`);
      return;
    }
    assert.throws(() => verifyPrismaMigrationLedger(fixture), { code: "INVALID_MIGRATION_SQL_FILE" });
  } finally {
    rmSync(fixture.projectRoot, { recursive: true, force: true });
  }
});

test("approved source SHA must use the repository's full object-format length", () => {
  const fixture = createFixture();
  try {
    assert.throws(() => verifyPrismaMigrationLedger({
      ...fixture,
      approvedSourceSha: fixture.approvedSourceSha.slice(0, 39)
    }), { code: "MISSING_APPROVED_SOURCE_SHA" });
    assert.throws(() => verifyPrismaMigrationLedger({
      ...fixture,
      approvedSourceSha: fixture.approvedSourceSha.padEnd(64, "0")
    }), { code: "INVALID_APPROVED_SOURCE_SHA" });
  } finally {
    rmSync(fixture.projectRoot, { recursive: true, force: true });
  }
});

test("migration ledger CLI reads only the stdin ledger and emits a generic pass or block", () => {
  const fixture = createFixture();
  try {
    const accepted = spawnSync(process.execPath, [scriptPath], {
      cwd: fixture.projectRoot,
      input: fixture.ledgerText,
      encoding: "utf8",
      env: { ...isolatedGitEnvironment(), VIRKI_STAGING_APPROVED_SOURCE_SHA: fixture.approvedSourceSha }
    });
    assert.equal(accepted.status, 0);
    assert.equal(accepted.stdout, "STAGING_PRISMA_MIGRATION_LEDGER=PASS\n");
    assert.equal(accepted.stderr, "");

    const missingSourceShaEnvironment = isolatedGitEnvironment();
    delete missingSourceShaEnvironment.VIRKI_STAGING_APPROVED_SOURCE_SHA;
    const missingSourceSha = spawnSync(process.execPath, [scriptPath], {
      cwd: fixture.projectRoot,
      input: fixture.ledgerText,
      encoding: "utf8",
      env: missingSourceShaEnvironment
    });
    assert.equal(missingSourceSha.status, 1);
    assert.equal(missingSourceSha.stdout, "");
    assert.equal(missingSourceSha.stderr, "BLOCK:STAGING_PRISMA_MIGRATION_LEDGER\n");

    const rejected = spawnSync(process.execPath, [scriptPath], {
      cwd: fixture.projectRoot,
      input: "",
      encoding: "utf8",
      env: { ...isolatedGitEnvironment(), VIRKI_STAGING_APPROVED_SOURCE_SHA: fixture.approvedSourceSha }
    });
    assert.equal(rejected.status, 1);
    assert.equal(rejected.stdout, "");
    assert.equal(rejected.stderr, "BLOCK:STAGING_PRISMA_MIGRATION_LEDGER\n");
  } finally {
    rmSync(fixture.projectRoot, { recursive: true, force: true });
  }
});

test("hex-fields binds one physical database row to one ledger row in SHA-1 and SHA-256 checkouts", () => {
  for (const objectFormat of ["sha1", "sha256"]) {
    const fixture = createFixture({ objectFormat });
    try {
      const hexLedger = hexLedgerRows(fixture);
      assert.equal(verifyPrismaMigrationLedger({ ...fixture, ledgerText: hexLedger, hexFields: true }), true);
      const accepted = spawnSync(process.execPath, [scriptPath, "--hex-fields"], {
        cwd: fixture.projectRoot,
        input: hexLedger,
        encoding: "utf8",
        env: { ...isolatedGitEnvironment(), VIRKI_STAGING_APPROVED_SOURCE_SHA: fixture.approvedSourceSha }
      });
      assert.equal(accepted.status, 0, accepted.stderr);
      assert.equal(accepted.stdout, "STAGING_PRISMA_MIGRATION_LEDGER=PASS\n");
      assert.equal(accepted.stderr, "");
      const unencoded = spawnSync(process.execPath, [scriptPath, "--hex-fields"], {
        cwd: fixture.projectRoot,
        input: fixture.ledgerText,
        encoding: "utf8",
        env: { ...isolatedGitEnvironment(), VIRKI_STAGING_APPROVED_SOURCE_SHA: fixture.approvedSourceSha }
      });
      assert.equal(unencoded.status, 1);
      assert.equal(unencoded.stdout, "");
      assert.equal(unencoded.stderr, "BLOCK:STAGING_PRISMA_MIGRATION_LEDGER\n");
    } finally {
      rmSync(fixture.projectRoot, { recursive: true, force: true });
    }
  }
});

test("hex-fields rejects row-forging via embedded tabs and newlines in migration_name", () => {
  const fixture = createFixture();
  try {
    const [first, second] = fixture.expected;
    // One *physical* PostgreSQL row can forge two logical TSV rows when the
    // untrusted migration_name contains separators. This is why the rollback
    // SQL MUST encode both text fields before concatenating them.
    const hostileName = `${first.name}\t${first.checksum}\ttrue\tfalse\n${second.name}`;
    assert.ok(Buffer.byteLength(hostileName) <= 255);
    const legacyForged = `${hostileName}\t${second.checksum}\ttrue\tfalse\n`;
    assert.equal(legacyForged, fixture.ledgerText,
      "the legacy TSV transport is ambiguous for a single hostile DB row");
    const hexForged = `${Buffer.from(hostileName).toString("hex")}\t${Buffer.from(second.checksum).toString("hex")}\ttrue\tfalse\n`;
    assert.equal(hexForged.split("\n").length, 2, "hex encoding retains exactly one physical output row");
    assert.throws(() => verifyPrismaMigrationLedger({
      ...fixture, ledgerText: hexForged, hexFields: true
    }), { code: "INVALID_MIGRATION_LEDGER_ROW" });
  } finally {
    rmSync(fixture.projectRoot, { recursive: true, force: true });
  }
});

test("hex-fields rejects malformed encodings, null-output rows, and extra blank records", () => {
  const fixture = createFixture();
  try {
    const valid = hexLedgerRows(fixture);
    const [firstName, firstChecksum] = valid.split("\n")[0].split("\t");
    const invalidRows = [
      `${firstName.toUpperCase()}\t${firstChecksum}\ttrue\tfalse\n`,
      `ff\t${firstChecksum}\ttrue\tfalse\n`,
      `0\t${firstChecksum}\ttrue\tfalse\n`,
      `0a\t${firstChecksum}\ttrue\tfalse\n`,
      `${firstName}\t\ttrue\tfalse\n`,
      `${firstName}\t${firstChecksum}\ttrue\tfalse\n\n`,
      `\n${firstName}\t${firstChecksum}\ttrue\tfalse\n`,
      `\r\n${firstName}\t${firstChecksum}\ttrue\tfalse\n`
    ];
    for (const invalid of invalidRows) {
      assert.throws(() => verifyPrismaMigrationLedger({
        ...fixture, ledgerText: invalid, hexFields: true
      }), { code: "INVALID_MIGRATION_LEDGER_ROW" });
    }
    const forbiddenCliFlag = spawnSync(process.execPath, [scriptPath, "--not-hex-fields"], {
      cwd: fixture.projectRoot,
      input: valid,
      encoding: "utf8",
      env: { ...isolatedGitEnvironment(), VIRKI_STAGING_APPROVED_SOURCE_SHA: fixture.approvedSourceSha }
    });
    assert.equal(forbiddenCliFlag.status, 1);
    assert.equal(forbiddenCliFlag.stderr, "BLOCK:STAGING_PRISMA_MIGRATION_LEDGER\n");
  } finally {
    rmSync(fixture.projectRoot, { recursive: true, force: true });
  }
});
