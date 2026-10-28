import { spawnSync } from "node:child_process";
import path from "node:path";

export const REVISION_LABEL = "org.opencontainers.image.revision";
export const CANONICAL_VIRKI_REPOSITORY = "bielxdh3/Virki";
export const CANONICAL_VIRKI_REMOTE = `https://github.com/${CANONICAL_VIRKI_REPOSITORY}.git`;
export const PRODUCTION_SERVICES = [
  "public-site",
  "hub",
  "oidc-issuer",
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
  SOURCE_REPOSITORY_MISMATCH: "Origin is not the canonical Virki repository.",
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
    input: options.input,
    encoding: "utf8",
    shell: false,
    windowsHide: true,
    maxBuffer: 64 * 1024 * 1024,
    stdio: options.interactive ? "inherit" : options.input === undefined ? ["ignore", "pipe", "pipe"] : ["pipe", "pipe", "pipe"],
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

export function inspectProductionSource({ repositoryRoot, execute = runCommand, canonicalRemoteUrl = CANONICAL_VIRKI_REMOTE, expectedRevision }) {
  const gitEnvironment = { ...process.env, GIT_NO_REPLACE_OBJECTS: "1" };
  const git = (args) => execute("git", args, { cwd: repositoryRoot, env: gitEnvironment });
  const resolvedRoot = requireSuccess(git(["rev-parse", "--show-toplevel"]));

  if (!pathsMatch(resolvedRoot, repositoryRoot)) {
    throw new ProductionRevisionError("SOURCE_ROOT_MISMATCH");
  }

  const branch = requireSuccess(git(["branch", "--show-current"]));
  if (branch !== "main") {
    throw new ProductionRevisionError("SOURCE_BRANCH_MISMATCH");
  }

  const originUrl = requireSuccess(git(["remote", "get-url", "origin"]));
  if (originUrl !== canonicalRemoteUrl) {
    throw new ProductionRevisionError("SOURCE_REPOSITORY_MISMATCH");
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
  // A post-deploy health read is pinned to the approved release; main may have advanced.
  if (expectedRevision !== undefined) {
    if (revision !== normalizeRevision(expectedRevision)) throw new ProductionRevisionError("SOURCE_REMOTE_MISMATCH");
    return { branch, revision };
  }
  const remoteMain = requireSuccess(
    git(["ls-remote", "--exit-code", "--refs", "origin", "refs/heads/main"]),
  ).split(/\s+/u);
  if (remoteMain[1] !== "refs/heads/main") {
    throw new ProductionRevisionError("SOURCE_REMOTE_MISMATCH");
  }
  const remoteRevision = normalizeRevision(remoteMain[0]);

  if (revision !== remoteRevision) {
    throw new ProductionRevisionError("SOURCE_REMOTE_MISMATCH");
  }

  return { branch, revision };
}

// Signed offline releases cannot consult GitHub. The independently signed
// accepted SHA is authoritative; the cached tracking ref is a consistency
// check, not a substitute for the owner signature or trusted native host.
export function inspectOfflineProductionSource({
  repositoryRoot, expectedRevision, execute = runCommand,
  canonicalRemoteUrl = CANONICAL_VIRKI_REMOTE,
}) {
  const source = inspectProductionSource({
    repositoryRoot, expectedRevision: normalizeRevision(expectedRevision),
    execute, canonicalRemoteUrl,
  });
  const tracked = requireSuccess(execute("git", [
    "rev-parse", "--verify", "refs/remotes/origin/main^{commit}",
  ], {
    cwd: repositoryRoot, env: { ...process.env, GIT_NO_REPLACE_OBJECTS: "1" },
  }));
  if (normalizeRevision(tracked) !== source.revision) {
    throw new ProductionRevisionError("SOURCE_REMOTE_MISMATCH");
  }
  return source;
}
