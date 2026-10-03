import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const MAX_TEXT_FILE_BYTES = 1024 * 1024;
const scannerPath = fileURLToPath(new URL("./secret-scan.mjs", import.meta.url));

test("secret scan fails closed on oversized NUL-free text without printing its contents", () => {
  const repository = mkdtempSync(path.join(tmpdir(), "bielos-secret-scan-"));
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
