import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const MAX_TEXT_FILE_BYTES = 1024 * 1024;
const scannerPath = fileURLToPath(new URL("./secret-scan.mjs", import.meta.url));

test("secret scan fails closed on oversized NUL-free text without printing its contents", () => {
  const repository = mkdtempSync(path.join(tmpdir(), "virki-secret-scan-"));
  const credentialField = ["pass", "word"].join("") + "=";
  const syntheticValue = ["local", "fixture", "value", "0123456789abcdef"].join("-");

  try {
    execFileSync("git", ["init", "--quiet"], { cwd: repository });
    const prefix = Buffer.from(`${credentialField}${syntheticValue}\n`, "utf8");
    const content = Buffer.concat([prefix, Buffer.alloc(MAX_TEXT_FILE_BYTES + 1 - prefix.length, 0x61)]);
    writeFileSync(path.join(repository, "large-source.txt"), content);
    execFileSync("git", ["add", "large-source.txt"], { cwd: repository });

    const result = spawnSync(process.execPath, [scannerPath], { cwd: repository, encoding: "utf8" });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /large-source\.txt:1 oversized-text-file/u);
    assert.equal(`${result.stdout}${result.stderr}`.includes(syntheticValue), false);
  } finally {
    rmSync(repository, { recursive: true, force: true });
  }
});

test("exact-revision secret scan blocks credential paths and secret assignments without printing values", () => {
  const repository = mkdtempSync(path.join(tmpdir(), "virki-secret-revision-"));
  const value = ["test-fixture", "0123456789abcdef", "fedcba9876543210"].join("-");

  try {
    execFileSync("git", ["init", "--quiet"], { cwd: repository });
    writeFileSync(path.join(repository, "settings.json"), JSON.stringify({ access_token: value }));
    for (const [filePath, content] of [
      [".aws/credentials", "fixture only\n"],
      ["secrets/id_ed25519", "fixture only\n"],
      ["keys/signing.pem.gz", "fixture only\n"],
      ["keys/signing.pem.gz.gz", "fixture only\n"],
      ["keys/id_ed25519.gz", "fixture only\n"],
      ["keys/id_ed25519.gz.gz", "fixture only\n"],
      ["logs/app.log.1.gz", "fixture only\n"],
      ["database/prod.sqlite-journal", "fixture only\n"],
      ["backup/prod-20261003", "fixture only\n"],
      ["certs/private.der", Buffer.from([0x30, 0x00, 0x2a])],
      ["opaque.bin", Buffer.concat([Buffer.from([0xff, 0x00]), Buffer.from(JSON.stringify({ access_token: value }), "ascii")])],
      ["opaque-utf16le.bin", Buffer.from(JSON.stringify({ client_secret: value }), "utf16le")],
      ["opaque-utf16be.bin", Buffer.from(JSON.stringify({ client_secret: value }), "utf16le").swap16()],
    ]) {
      const absolutePath = path.join(repository, filePath);
      mkdirSync(path.dirname(absolutePath), { recursive: true });
      writeFileSync(absolutePath, content);
    }
    execFileSync("git", ["-c", "core.autocrlf=false", "add", "."], { cwd: repository });
    execFileSync("git", ["-c", "user.name=Secret Scan Test", "-c", "user.email=secret-scan@example.invalid", "commit", "--quiet", "-m", "fixture"], { cwd: repository });
    const revision = execFileSync("git", ["rev-parse", "HEAD"], { cwd: repository, encoding: "utf8" }).trim();

    const result = spawnSync(process.execPath, [scannerPath, "--revision", revision], { cwd: repository, encoding: "utf8" });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /settings\.json:\d+ generic-secret-assignment/u);
    assert.match(result.stderr, /\.aws\/credentials:1 aws-credentials/u);
    assert.match(result.stderr, /secrets\/id_ed25519:1 private-key-file/u);
    assert.match(result.stderr, /keys\/signing\.pem\.gz:1 private-key-file/u);
    assert.match(result.stderr, /keys\/signing\.pem\.gz\.gz:1 private-key-file/u);
    assert.match(result.stderr, /keys\/id_ed25519\.gz:1 private-key-file/u);
    assert.match(result.stderr, /keys\/id_ed25519\.gz\.gz:1 private-key-file/u);
    assert.match(result.stderr, /logs\/app\.log\.1\.gz:1 application-log/u);
    assert.match(result.stderr, /database\/prod\.sqlite-journal:1 database-dump/u);
    assert.match(result.stderr, /backup\/prod-20261003:1 sensitive-export-directory/u);
    assert.match(result.stderr, /certs\/private\.der:1 private-key-file/u);
    assert.match(result.stderr, /opaque\.bin:1 generic-secret-assignment/u);
    assert.match(result.stderr, /opaque-utf16le\.bin:1 generic-secret-assignment/u);
    assert.match(result.stderr, /opaque-utf16be\.bin:1 generic-secret-assignment/u);
    assert.equal(`${result.stdout}${result.stderr}`.includes(value), false);
  } finally {
    rmSync(repository, { recursive: true, force: true });
  }
});

test("exact-revision secret scan accepts safe tracked files and migration SQL", () => {
  const repository = mkdtempSync(path.join(tmpdir(), "virki-secret-revision-safe-"));

  try {
    execFileSync("git", ["init", "--quiet"], { cwd: repository });
    writeFileSync(path.join(repository, "README.md"), "Safe source fixture.\n");
    const backupSentinelPath = path.join(repository, "infra", "backups", ".gitkeep");
    mkdirSync(path.dirname(backupSentinelPath), { recursive: true });
    writeFileSync(backupSentinelPath, "");
    const migrationPath = path.join(repository, "packages", "database", "prisma", "migrations", "20261001000000_fixture", "migration.sql");
    mkdirSync(path.dirname(migrationPath), { recursive: true });
    writeFileSync(migrationPath, "CREATE TABLE fixture (id TEXT PRIMARY KEY);\n");
    execFileSync("git", ["-c", "core.autocrlf=false", "add", "."], { cwd: repository });
    execFileSync("git", ["-c", "user.name=Secret Scan Test", "-c", "user.email=secret-scan@example.invalid", "commit", "--quiet", "-m", "fixture"], { cwd: repository });
    const revision = execFileSync("git", ["rev-parse", "HEAD"], { cwd: repository, encoding: "utf8" }).trim();

    const result = spawnSync(process.execPath, [scannerPath, "--revision", revision], { cwd: repository, encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /Secret scan passed/u);
  } finally {
    rmSync(repository, { recursive: true, force: true });
  }
});


test("scanner covers prefixed keys in tracked formats and every credential URL on a line", () => {
  const repository = mkdtempSync(path.join(tmpdir(), "virki-secret-names-"));
  const value = ["synthetic", "scanner", "fixture", "0123456789abcdef"].join("-");
  try {
    execFileSync("git", ["init", "--quiet"], { cwd: repository });
    for (const [file, content] of [
      ["config.json", JSON.stringify({ PROD_API_KEY: value, VIRKI_HASH_SECRET: value })],
      ["settings.yml", `VIRKI_SIGNING_KEY: ${value}`],
      ["settings.toml", `encryption_key = "${value}"`],
      ["settings.ts", `export const PROD_API_KEY = "${value}";`],
      ["urls.md", `postgresql://test:placeholder@localhost/a postgresql://test:${value}@localhost/b`],
    ]) writeFileSync(path.join(repository, file), content);
    writeFileSync(path.join(repository, "safe.ts"), 'const PROD_API_KEY = process.env.PROD_API_KEY;\n');
    writeFileSync(path.join(repository, ".env.example"), 'POSTGRES_PASSWORD=change-me-in-your-local-env\nPROD_API_KEY=replace-with-local-secret\n');
    execFileSync("git", ["add", "."], { cwd: repository });
    const result = spawnSync(process.execPath, [scannerPath], { cwd: repository, encoding: "utf8" });
    assert.equal(result.status, 1);
    for (const file of ["config.json", "settings.yml", "settings.toml", "settings.ts", "urls.md"]) assert.ok(result.stderr.includes(`${file}:1`), file);
    assert.equal(result.stderr.includes(value), false);
    assert.equal(result.stderr.includes("safe.ts:"), false);
    assert.equal(result.stderr.includes(".env.example:"), false);
  } finally { rmSync(repository, { recursive: true, force: true }); }
});

test("scanner blocks template-literal and multiline credentials plus private JWKs without printing values", () => {
  const repository = mkdtempSync(path.join(tmpdir(), "virki-secret-modern-formats-"));
  const templateValue = ["synthetic", "template", "credential", "0123456789abcdef"].join("-");
  const multilineValue = ["synthetic", "multiline", "credential", "0123456789abcdef"].join("-");
  const jwkValue = ["synthetic", "jwk", "private", "0123456789abcdef"].join("-");

  try {
    execFileSync("git", ["init", "--quiet"], { cwd: repository });
    writeFileSync(path.join(repository, "settings.ts"), `export const APP_SECRET = \`${templateValue}\`;\nconst apiKey =\n  "${multilineValue}";\n`);
    writeFileSync(path.join(repository, "private-jwk.json"), JSON.stringify({
      kty: "EC",
      crv: "P-256",
      x: "public-coordinate-fixture",
      y: "public-coordinate-fixture",
      d: jwkValue
    }));
    writeFileSync(path.join(repository, "public-jwk.json"), JSON.stringify({
      kty: "EC",
      crv: "P-256",
      x: "public-coordinate-fixture",
      y: "public-coordinate-fixture"
    }));
    execFileSync("git", ["add", "."], { cwd: repository });

    const result = spawnSync(process.execPath, [scannerPath], { cwd: repository, encoding: "utf8" });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /settings\.ts:1 application-key-assignment/u);
    assert.match(result.stderr, /settings\.ts:2 (?:generic-secret-assignment|multiline-secret-assignment)/u);
    assert.match(result.stderr, /private-jwk\.json:1 private-jwk/u);
    assert.doesNotMatch(result.stderr, /public-jwk\.json:/u);
    for (const value of [templateValue, multilineValue, jwkValue]) {
      assert.equal(`${result.stdout}${result.stderr}`.includes(value), false);
    }
  } finally {
    rmSync(repository, { recursive: true, force: true });
  }
});
