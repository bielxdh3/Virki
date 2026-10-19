import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const revisionPattern = /^[a-f0-9]{40}$/iu;

export function verifyRemoteMainHead(expectedSha, execute = execFileSync) {
  if (typeof expectedSha !== "string" || !revisionPattern.test(expectedSha)) {
    throw new TypeError("Invalid production source revision.");
  }

  const output = execute("git", ["ls-remote", "origin", "refs/heads/main"], { encoding: "utf8" });
  const match = String(output).trim().match(/^([a-f0-9]{40})\s+refs\/heads\/main$/iu);
  if (!match || match[1].toLowerCase() !== expectedSha.toLowerCase()) {
    throw new Error("origin/main changed after approval preflight or could not be verified.");
  }

  return match[1].toLowerCase();
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    verifyRemoteMainHead(process.argv[2]);
  } catch {
    console.error("::error::origin/main changed after approval preflight or could not be verified.");
    process.exitCode = 1;
  }
}
