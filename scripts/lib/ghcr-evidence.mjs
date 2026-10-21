import { lstatSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { CANONICAL_VIRKI_REPOSITORY, normalizeRevision, ProductionRevisionError } from "./production-revision.mjs";

const PACKAGE = "ghcr.io/bielxdh3/virki-evidence";
const SOURCE = "https://github.com/bielxdh3/Virki";

// GitHub's private GHCR API and registry require a classic read:packages PAT.
// Unattended deployment must not reuse its fine-grained repository/Actions
// read-only token for package access, or require a broad classic repo scope.
export function selectGhcrReadCredential(env = process.env) {
  const dedicated = env.VIRKI_GHCR_READ_TOKEN;
  if (dedicated !== undefined && (typeof dedicated !== "string" ||
      dedicated.length === 0 || /\s/u.test(dedicated))) {
    throw new ProductionRevisionError("COMMAND_FAILED");
  }
  if (env.VIRKI_AUTOMATED_DEPLOY_ENABLED === "true" && !dedicated) {
    throw new ProductionRevisionError("COMMAND_FAILED");
  }
  return dedicated
    ? { token: dedicated, apiOptions: { env: { ...env, GH_TOKEN: dedicated } } }
    : { token: null, apiOptions: {} };
}

export function evidenceDigestFromRunLog(log, { revision, runId, kind, platform = "" }) {
  evidenceTag(revision, runId, kind, platform);
  if (typeof log !== "string" || log.length > 60 * 1024 * 1024) throw new ProductionRevisionError("COMMAND_FAILED");
  const step = kind === "codeql" ? "Store reviewed CodeQL SARIF in private GHCR evidence" : "Store exact-run image digests in private GHCR evidence";
  const expectedPlatform = platform ? `linux/${platform}` : "none";
  const matches = [];
  for (const line of log.split("\n")) {
    const columns = line.split("\t");
    // gh run --log currently labels some runner steps as UNKNOWN STEP.
    if (columns.length < 3 || (columns[1] !== step && columns[1] !== "UNKNOWN STEP")) continue;
    const found = /\bVIRKI_EVIDENCE_DIGEST revision=([0-9a-f]{40}) run=([1-9][0-9]*) kind=(codeql|images) platform=(none|linux\/(?:amd64|arm64)) digest=(sha256:[0-9a-f]{64})(?:\s|$)/u.exec(columns.slice(2).join("\t"));
    if (found) {
      if (found[1] !== revision || found[2] !== String(runId) || found[3] !== kind) {
        throw new ProductionRevisionError("COMMAND_FAILED");
      }
      // The successful image job has both architecture proofs in the same run log.
      if (found[4] !== expectedPlatform && kind === "images" && ["linux/amd64", "linux/arm64"].includes(found[4])) continue;
      if (found[4] !== expectedPlatform) throw new ProductionRevisionError("COMMAND_FAILED");
      matches.push(found[5]);
    }
  }
  if (matches.length !== 1) throw new ProductionRevisionError("COMMAND_FAILED");
  return matches[0];
}

export function evidenceTag(revision, runId, kind, platform = "") {
  const sha = normalizeRevision(revision);
  if (!Number.isSafeInteger(runId) || runId <= 0 || !["codeql", "images"].includes(kind)
    || (kind === "codeql" && platform !== "") || (kind === "images" && !["amd64", "arm64"].includes(platform))) {
    throw new ProductionRevisionError("COMMAND_FAILED");
  }
  return `${sha}-${runId}-${kind}${platform ? `-${platform}` : ""}`;
}

// Reads only from a stopped OCI image. The image is never executed.
export function downloadGhcrEvidence({ revision, runId, logRunId = runId, kind, platform = "", execute, repositoryRoot }) {
  const tag = evidenceTag(revision, runId, kind, platform);
  if (!Number.isSafeInteger(logRunId) || logRunId <= 0) throw new ProductionRevisionError("COMMAND_FAILED");
  const directory = mkdtempSync(path.join(os.tmpdir(), "virki-private-evidence-"));
  const authDir = path.join(directory, "auth");
  const evidenceDir = path.join(directory, "contents");
  let reference;
  const options = { cwd: repositoryRoot };
  let containerId;
  let proof;
  let cleanupFailed;
  const run = (command, args, extra = {}) => {
    const result = execute(command, args, { ...options, ...extra });
    if (result?.status !== 0) throw new ProductionRevisionError("COMMAND_FAILED");
    return result.stdout?.trim() ?? "";
  };
  try {
    const registry = selectGhcrReadCredential();
    const response = run("gh", ["api", "users/bielxdh3/packages/container/virki-evidence"], registry.apiOptions);
    const pkg = JSON.parse(response);
    if (pkg.visibility !== "private" || pkg.owner?.login !== "bielxdh3"
      || pkg.repository?.full_name !== CANONICAL_VIRKI_REPOSITORY) throw new ProductionRevisionError("COMMAND_FAILED");
    const log = run("gh", ["run", "view", String(logRunId), "--repo", CANONICAL_VIRKI_REPOSITORY, "--log"]);
    const digest = evidenceDigestFromRunLog(log, { revision, runId, kind, platform });
    reference = `${PACKAGE}@${digest}`;
    const token = registry.token ?? run("gh", ["auth", "token"]);
    if (!token) throw new ProductionRevisionError("COMMAND_FAILED");
    const fs = { ...process.env, DOCKER_CONFIG: authDir };
    const docker = (args, extra = {}) => run("docker", args, { ...extra, env: fs });
    docker(["login", "ghcr.io", "--username", "bielxdh3", "--password-stdin"], { input: `${token}\n` });
    docker(["pull", reference]);
    const fields = docker(["image", "inspect", reference, "--format", '{{index .Config.Labels "org.opencontainers.image.source"}}|{{index .Config.Labels "org.opencontainers.image.revision"}}|{{index .Config.Labels "virki.evidence.run-id"}}|{{index .Config.Labels "virki.evidence.kind"}}|{{index .Config.Labels "virki.evidence.platform"}}|{{.Os}}/{{.Architecture}}']).split("|");
    if (fields.length !== 6 || fields[0] !== SOURCE || fields[1] !== revision || fields[2] !== String(runId)
      || fields[3] !== kind || fields[4] !== (platform ? `linux/${platform}` : "none")
      || fields[5] !== (kind === "images" ? `linux/${platform}` : "linux/amd64")) {
      throw new ProductionRevisionError("COMMAND_FAILED");
    }
    const id = docker(["create", "--entrypoint", "/never-execute", reference]);
    if (!/^[0-9a-f]{64}$/u.test(id)) throw new ProductionRevisionError("COMMAND_FAILED");
    containerId = id;
    docker(["cp", `${id}:/evidence/.`, evidenceDir]);
    const entries = readdirSync(evidenceDir, { withFileTypes: true });
    if (entries.length === 0 || entries.some((entry) => !entry.isFile()
      || !((kind === "codeql" && entry.name.endsWith(".sarif")) || (kind === "images" && entry.name === "virki-production-images.manifest")))) {
      throw new ProductionRevisionError("COMMAND_FAILED");
    }
    for (const entry of entries) {
      const metadata = lstatSync(path.join(evidenceDir, entry.name));
      if (!metadata.isFile() || metadata.size === 0 || metadata.size > 20 * 1024 * 1024) throw new ProductionRevisionError("COMMAND_FAILED");
    }
    if (kind === "images" && entries.length !== 1) throw new ProductionRevisionError("COMMAND_FAILED");
    const final = JSON.parse(run("gh", ["api", "users/bielxdh3/packages/container/virki-evidence"], registry.apiOptions));
    if (final.visibility !== "private" || final.repository?.full_name !== CANONICAL_VIRKI_REPOSITORY) {
      throw new ProductionRevisionError("COMMAND_FAILED");
    }
    proof = { directory, contents: evidenceDir, reference, tag };
  } catch {
    rmSync(directory, { recursive: true, force: true });
    throw new ProductionRevisionError("COMMAND_FAILED");
  } finally {
    const cleanup = containerId
      ? execute("docker", ["rm", "-v", containerId], { ...options, env: { ...process.env, DOCKER_CONFIG: authDir } })
      : { status: 0 };
    // Remove cached registry credentials even after successful retrieval.
    rmSync(authDir, { recursive: true, force: true });
    cleanupFailed = cleanup?.status !== 0;
  }
  if (cleanupFailed) {
    rmSync(directory, { recursive: true, force: true });
    throw new ProductionRevisionError("COMMAND_FAILED");
  }
  return proof;
}
