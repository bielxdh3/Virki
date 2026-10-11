import assert from "node:assert/strict";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { downloadGhcrEvidence, evidenceDigestFromRunLog, evidenceTag } from "./lib/ghcr-evidence.mjs";

const revision = "0123456789abcdef0123456789abcdef01234567";
const containerId = "f".repeat(64);
const validPackage = JSON.stringify({ visibility: "private", owner: { login: "bielxdh3" }, repository: { full_name: "bielxdh3/Virki" } });
const digest = `sha256:${"a".repeat(64)}`;
const logProof = (kind, sha = revision, runId = 67890, suppliedDigest = digest) => {
  const step = kind === "codeql" ? "Store reviewed CodeQL SARIF in private GHCR evidence" : "Store exact-run image digests in private GHCR evidence";
  return `Analyze JavaScript / TypeScript\t${step}\t2026-10-11T04:00:00Z VIRKI_EVIDENCE_DIGEST revision=${sha} run=${runId} kind=${kind} platform=${kind === "codeql" ? "none" : "linux/amd64"} digest=${suppliedDigest}\n`;
};

function fixture(mode = "valid", kind = "codeql") {
  const calls = [];
  const execute = (command, args, options) => {
    calls.push({ command, args, env: options.env ? "isolated" : "none" });
    if (command === "gh") {
      if (args[1] === "token") return { status: 0, stdout: "DUMMY-TEST-TOKEN" };
      if (args[0] === "run") return { status: 0, stdout: mode === "missing-log" ? "unrelated" : logProof(kind, mode === "wrong-log-sha" ? "f".repeat(40) : revision) };
      return { status: 0, stdout: mode === "public" ? JSON.stringify({ ...JSON.parse(validPackage), visibility: "public" }) : validPackage };
    }
    if (args[0] === "login") {
      assert.ok(options.env?.DOCKER_CONFIG?.includes("virki-private-evidence-"));
      assert.equal(options.input, "DUMMY-TEST-TOKEN\n");
      return { status: mode === "login-failed" ? 1 : 0, stdout: "" };
    }
    if (args[0] === "pull") return { status: mode === "pull-failed" ? 1 : 0, stdout: "" };
    if (args[0] === "image") {
      const fields = ["https://github.com/bielxdh3/Virki", revision, "67890", kind, kind === "codeql" ? "none" : "linux/amd64", "linux/amd64"];
      if (mode === "foreign-run") fields[2] = "67891";
      if (mode === "wrong-arch") fields[5] = "linux/arm64";
      return { status: 0, stdout: fields.join("|") };
    }
    if (args[0] === "create") return { status: 0, stdout: containerId };
    if (args[0] === "cp") {
      const directory = args.at(-1);
      mkdirSync(directory);
      const name = kind === "codeql" ? "report.sarif" : "virki-production-images.manifest";
      if (mode === "empty") return { status: 0, stdout: "" };
      if (mode === "symlink") { writeFileSync(path.join(directory, "other"), "outside"); return { status: 0, stdout: "" }; }
      writeFileSync(path.join(directory, name), "{}\n");
      return { status: 0, stdout: "" };
    }
    if (args[0] === "rm") return { status: 0, stdout: "" };
    throw new Error(`Unexpected command: ${command} ${args.join(" ")}`);
  };
  return { calls, execute };
}

test("private OCI evidence requires exact SHA, run, kind and architecture", () => {
  assert.equal(evidenceTag(revision, 67890, "codeql"), `${revision}-67890-codeql`);
  assert.equal(evidenceDigestFromRunLog(logProof("codeql"), { revision, runId: 67890, kind: "codeql" }), digest);
  assert.equal(evidenceDigestFromRunLog(logProof("codeql").replace("Store reviewed CodeQL SARIF in private GHCR evidence", "UNKNOWN STEP"), { revision, runId: 67890, kind: "codeql" }), digest);
  assert.equal(evidenceDigestFromRunLog(logProof("images"), { revision, runId: 67890, kind: "images", platform: "amd64" }), digest);
  for (const malicious of ["", logProof("codeql", "f".repeat(40)), logProof("codeql") + logProof("codeql")]) {
    assert.throws(() => evidenceDigestFromRunLog(malicious, { revision, runId: 67890, kind: "codeql" }));
  }
  assert.equal(evidenceTag(revision, 67890, "images", "amd64"), `${revision}-67890-images-amd64`);
  for (const values of [
    [revision, -1, "codeql", ""], [revision, 0, "codeql", ""],
    [revision, 67890, "images", ""], [revision, 67890, "codeql", "arm64"],
    ["wrong", 67890, "codeql", ""], [revision, 67890, "other", ""],
  ]) assert.throws(() => evidenceTag(...values));
});

for (const kind of ["codeql", "images"]) {
  test(`pulls ${kind} from private GHCR by run-scoped tag without executing image`, () => {
    const { calls, execute } = fixture("valid", kind);
    const proof = downloadGhcrEvidence({ revision, runId: 67890, kind, platform: kind === "codeql" ? "" : "amd64", execute, repositoryRoot: "/repo" });
    try {
      assert.ok(existsSync(proof.contents));
      assert.ok(readFileSync(path.join(proof.contents, kind === "codeql" ? "report.sarif" : "virki-production-images.manifest"), "utf8"));
      assert.ok(calls.some((call) => call.command === "docker" && call.args[0] === "pull"));
      assert.ok(calls.some((call) => call.command === "docker" && call.args[0] === "rm"));
      assert.ok(!calls.some((call) => call.command === "docker" && call.args[0] === "run"));
      assert.ok(!existsSync(path.join(proof.directory, "auth")), "Credential cache must be removed before return.");
    } finally {
      rmSync(proof.directory, { recursive: true, force: true });
    }
  });
}

for (const mode of ["public", "missing-log", "wrong-log-sha", "login-failed", "pull-failed", "foreign-run", "wrong-arch", "empty", "symlink"]) {
  test(`GHCR ${mode} fails closed without persistent credentials or unsafe execution`, () => {
    const { calls, execute } = fixture(mode);
    assert.throws(() => downloadGhcrEvidence({ revision, runId: 67890, kind: "codeql", execute, repositoryRoot: "/repo" }));
    assert.ok(!calls.some((call) => call.command === "docker" && call.args[0] === "run"));
    if (mode === "public") assert.ok(!calls.some((call) => call.command === "docker"));
  });
}
