import { spawnSync } from "node:child_process";
import path from "node:path";

export const REVISION_LABEL = "org.opencontainers.image.revision";
export const PRODUCTION_SERVICES = [
  "public-site",
  "hub",
  "intake",
  "session-cleanup",
  "email-worker",
];

const ERROR_MESSAGES = Object.freeze({
  REVISION_MISSING: "Revision is required.",
  REVISION_INVALID: "Revision is invalid.",
  COMMAND_FAILED: "Production command failed.",
  SOURCE_ROOT_MISMATCH: "Repository root mismatch.",
  SOURCE_DIRTY_TRACKED: "Working tree has tracked changes.",
  SOURCE_DIRTY_STAGED: "Working tree has staged changes.",
  SOURCE_DIRTY_UNTRACKED: "Working tree has untracked files.",
  SOURCE_BRANCH_MISMATCH: "Active branch is not main.",
  SOURCE_REMOTE_MISMATCH: "Local and origin revisions do not match.",
  ARGUMENT_INVALID: "Production command arguments are invalid.",
  REMOTE_REQUIRED: "Production commands must target the canonical remote server.",
});

export class ProductionRevisionError extends Error {
  constructor(code) {
    super(ERROR_MESSAGES[code] ?? ERROR_MESSAGES.COMMAND_FAILED);
    this.name = "ProductionRevisionError";
    this.code = code;
  }
}

export function normalizeRevision(value) {
  if (typeof value !== "string" || value.length === 0) {
    throw new ProductionRevisionError("REVISION_MISSING");
  }

  if (!/^[0-9a-fA-F]{40}$/.test(value)) {
    throw new ProductionRevisionError("REVISION_INVALID");
  }

  return value.toLowerCase();
}

export function runCommand(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd,
    env: options.env,
    encoding: "utf8",
    shell: false,
    windowsHide: true,
    maxBuffer: 64 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  });

  if (result.error) {
    return { status: 1, stdout: "" };
  }

  return {
    status: Number.isInteger(result.status) ? result.status : 1,
    stdout: result.stdout ?? "",
  };
}

function requireSuccess(result) {
  if (result.status !== 0) {
    throw new ProductionRevisionError("COMMAND_FAILED");
  }

  return result.stdout.trim();
}

function pathsMatch(left, right) {
  const normalizedLeft = path.resolve(left);
  const normalizedRight = path.resolve(right);

  if (process.platform === "win32") {
    return normalizedLeft.toLowerCase() === normalizedRight.toLowerCase();
  }

  return normalizedLeft === normalizedRight;
}

export function inspectProductionSource({ repositoryRoot, execute = runCommand }) {
  const git = (args) => execute("git", args, { cwd: repositoryRoot });
  const resolvedRoot = requireSuccess(git(["rev-parse", "--show-toplevel"]));

  if (!pathsMatch(resolvedRoot, repositoryRoot)) {
    throw new ProductionRevisionError("SOURCE_ROOT_MISMATCH");
  }

  const branch = requireSuccess(git(["branch", "--show-current"]));
  if (branch !== "main") {
    throw new ProductionRevisionError("SOURCE_BRANCH_MISMATCH");
  }

  const staged = git(["diff", "--cached", "--quiet", "--ignore-submodules", "--"]);
  if (staged.status === 1) {
    throw new ProductionRevisionError("SOURCE_DIRTY_STAGED");
  }
  requireSuccess(staged);

  const tracked = git(["diff", "--quiet", "--ignore-submodules", "--"]);
  if (tracked.status === 1) {
    throw new ProductionRevisionError("SOURCE_DIRTY_TRACKED");
  }
  requireSuccess(tracked);

  const untracked = requireSuccess(
    git(["ls-files", "--others", "--exclude-standard"]),
  );
  if (untracked.length > 0) {
    throw new ProductionRevisionError("SOURCE_DIRTY_UNTRACKED");
  }

  const revision = normalizeRevision(
    requireSuccess(git(["rev-parse", "--verify", "HEAD"])),
  );
  const remoteRevision = normalizeRevision(
    requireSuccess(git(["rev-parse", "--verify", "refs/remotes/origin/main"])),
  );

  if (revision !== remoteRevision) {
    throw new ProductionRevisionError("SOURCE_REMOTE_MISMATCH");
  }

  return { branch, revision };
}
