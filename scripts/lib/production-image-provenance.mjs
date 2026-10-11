import { ProductionRevisionError } from "./production-revision.mjs";

// Fail closed on any foreign CI run, revision, platform, or additional manifest content.
export function verifyImageProvenance(contents, { revision, runId, platform }) {
  const sha = /^[0-9a-f]{40}$/u;
  const digest = /^sha256:[0-9a-f]{64}$/u;
  if (!sha.test(revision) || !Number.isSafeInteger(runId) || runId <= 0 ||
      !["linux/amd64", "linux/arm64"].includes(platform) ||
      typeof contents !== "string" || contents.length > 512 || !/^[\x20-\x7e\n]+$/u.test(contents)) {
    throw new ProductionRevisionError("COMMAND_FAILED", "Untrusted GHCR provenance evidence.");
  }
  const lines = contents.split("\n");
  if (lines.length !== 6 || lines[5] !== "" ||
      lines[0] !== `revision=${revision}` || lines[1] !== `run_id=${runId}` ||
      lines[2] !== `platform=${platform}` ||
      !lines[3].startsWith("runtime_digest=") || !digest.test(lines[3].slice(15)) ||
      !lines[4].startsWith("migrator_digest=") || !digest.test(lines[4].slice(16))) {
    throw new ProductionRevisionError("COMMAND_FAILED", "GHCR provenance does not match the accepted CI run.");
  }
  return { runtimeDigest: lines[3].slice(15), migratorDigest: lines[4].slice(16) };
}
