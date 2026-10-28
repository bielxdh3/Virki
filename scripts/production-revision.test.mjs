import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  inspectOfflineProductionSource,
  inspectProductionSource,
  normalizeRevision,
  ProductionRevisionError,
  PRODUCTION_SERVICES,
} from "./lib/production-revision.mjs";
import {
  parseProductionCommand,
  runProductionCommand,
} from "./production-compose.mjs";
import {
  parseVerifierArguments,
  verifyServiceRevisions,
} from "./verify-production-revision.mjs";

const validRevision = "0123456789abcdef0123456789abcdef01234567";
function expectCode(callback, code) {
  assert.throws(callback, (error) => {
    assert.ok(error instanceof ProductionRevisionError);
    assert.equal(error.code, code);
    return true;
  });
}

test("accepts full SHA values and normalizes uppercase", () => {
  assert.equal(normalizeRevision(validRevision), validRevision);
  assert.equal(normalizeRevision(validRevision.toUpperCase()), validRevision);
});

test("rejects missing, short, long, non-hex, whitespace, newline, and shell-like revisions", () => {
  expectCode(() => normalizeRevision(), "REVISION_MISSING");
  expectCode(() => normalizeRevision(""), "REVISION_MISSING");
  expectCode(() => normalizeRevision(validRevision.slice(0, 7)), "REVISION_INVALID");
  expectCode(() => normalizeRevision(validRevision.slice(0, 39)), "REVISION_INVALID");
  expectCode(() => normalizeRevision(`${validRevision}0`), "REVISION_INVALID");
  expectCode(
    () => normalizeRevision(`${validRevision.slice(0, 39)}g`),
    "REVISION_INVALID",
  );
  expectCode(() => normalizeRevision(` ${validRevision}`), "REVISION_INVALID");
  expectCode(() => normalizeRevision(`${validRevision}\n`), "REVISION_INVALID");
  expectCode(() => normalizeRevision(`${validRevision};echo`), "REVISION_INVALID");
  expectCode(() => normalizeRevision(`sha:${validRevision}`), "REVISION_INVALID");
});

test("production command and verifier parsers enforce bounded allowlists", () => {
  for (const command of ["up", "restart", "verify", "config"]) {
    assert.equal(parseProductionCommand([command]), command);
  }
  expectCode(() => parseProductionCommand(["down"]), "ARGUMENT_INVALID");
  expectCode(() => parseProductionCommand(["up", "--verbose"]), "ARGUMENT_INVALID");

  assert.deepEqual(parseVerifierArguments([]), { expectedRevision: null });
  assert.deepEqual(parseVerifierArguments(["--expected", validRevision]), {
    expectedRevision: validRevision,
  });
  assert.deepEqual(parseVerifierArguments([`--expected=${validRevision}`]), {
    expectedRevision: validRevision,
  });
  expectCode(() => parseVerifierArguments(["--revision", validRevision]), "ARGUMENT_INVALID");
});

test("legacy local production wrapper refuses to run on the development PC", () => {
  expectCode(() => runProductionCommand(["up"]), "REMOTE_REQUIRED");
});

function git(cwd, ...args) {
  return execFileSync("git", args, {
    cwd,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
}

function createTestRepository() {
  const root = mkdtempSync(path.join(os.tmpdir(), "virki-revision-"));
  const remote = path.join(root, "remote.git");
  const work = path.join(root, "work");

  git(root, "init", "--bare", remote);
  git(root, "init", work);
  git(work, "config", "user.email", "test@example.invalid");
  git(work, "config", "user.name", "Virki Test");
  writeFileSync(path.join(work, "tracked.txt"), "initial\n");
  git(work, "add", "tracked.txt");
  git(work, "commit", "-m", "initial");
  git(work, "branch", "-M", "main");
  git(work, "remote", "add", "origin", remote);
  git(work, "push", "-u", "origin", "main");

  return { root, remote, work };
}

function withTestRepository(callback) {
  const repository = createTestRepository();
  try {
    callback(repository.work, repository.remote);
  } finally {
    rmSync(repository.root, { recursive: true, force: true });
  }
}

test("clean source inspection accepts a clean main matching the canonical remote", () => {
  withTestRepository((work, remote) => {
    const state = inspectProductionSource({ repositoryRoot: work, canonicalRemoteUrl: remote });
    assert.equal(state.branch, "main");
    assert.match(state.revision, /^[0-9a-f]{40}$/u);
  });
});

test("source inspection ignores Git replacement refs for the accepted revision", () => {
  withTestRepository((work, remote) => {
    const original = git(work, "rev-parse", "HEAD");
    writeFileSync(path.join(work, "tracked.txt"), "replacement\n");
    git(work, "add", "tracked.txt");
    git(work, "commit", "-m", "replacement object");
    const replacement = git(work, "rev-parse", "HEAD");
    git(work, "reset", "--hard", original);
    git(work, "update-ref", "refs/replace/" + original, replacement);

    assert.equal(git(work, "show", original + ":tracked.txt"), "replacement");
    const state = inspectProductionSource({ repositoryRoot: work, canonicalRemoteUrl: remote });
    assert.equal(state.revision, original);
  });
});

test("source inspection rejects a fork or alternate origin before trusting its main", () => {
  withTestRepository((work) => {
    expectCode(
      () => inspectProductionSource({ repositoryRoot: work }),
      "SOURCE_REPOSITORY_MISMATCH",
    );
  });
});

test("source inspection reports tracked, staged, and untracked dirty categories", () => {
  withTestRepository((work, remote) => {
    writeFileSync(path.join(work, "tracked.txt"), "changed\n");
    expectCode(
      () => inspectProductionSource({ repositoryRoot: work, canonicalRemoteUrl: remote }),
      "SOURCE_DIRTY_TRACKED",
    );
  });

  withTestRepository((work, remote) => {
    writeFileSync(path.join(work, "tracked.txt"), "staged\n");
    git(work, "add", "tracked.txt");
    expectCode(
      () => inspectProductionSource({ repositoryRoot: work, canonicalRemoteUrl: remote }),
      "SOURCE_DIRTY_STAGED",
    );
  });

  withTestRepository((work, remote) => {
    writeFileSync(path.join(work, "untracked.txt"), "untracked\n");
    expectCode(
      () => inspectProductionSource({ repositoryRoot: work, canonicalRemoteUrl: remote }),
      "SOURCE_DIRTY_UNTRACKED",
    );
  });
});

test("source inspection rejects branch and local/remote revision mismatches", () => {
  withTestRepository((work, remote) => {
    git(work, "switch", "-c", "other");
    expectCode(
      () => inspectProductionSource({ repositoryRoot: work, canonicalRemoteUrl: remote }),
      "SOURCE_BRANCH_MISMATCH",
    );
  });

  withTestRepository((work, remote) => {
    writeFileSync(path.join(work, "tracked.txt"), "new commit\n");
    git(work, "add", "tracked.txt");
    git(work, "commit", "-m", "local only");
    expectCode(
      () => inspectProductionSource({ repositoryRoot: work, canonicalRemoteUrl: remote }),
      "SOURCE_REMOTE_MISMATCH",
    );
  });
});

test("offline signed source inspection works without GitHub while requiring cached origin/main and the signed SHA", () => {
  withTestRepository((work, remote) => {
    const revision = git(work, "rev-parse", "HEAD");
    const tracked = git(work, "rev-parse", "refs/remotes/origin/main");
    assert.equal(revision, tracked);
    // Simulate GitHub being unavailable: remove the transport endpoint while
    // preserving the clean, canonical local checkout and its tracking ref.
    rmSync(remote, { recursive: true, force: true });
    const result = inspectOfflineProductionSource({
      repositoryRoot: work,
      canonicalRemoteUrl: remote,
      expectedRevision: revision,
    });
    assert.deepEqual(result, { branch: "main", revision });
    expectCode(() => inspectProductionSource({ repositoryRoot: work, canonicalRemoteUrl: remote }),
      "COMMAND_FAILED");
    expectCode(() => inspectOfflineProductionSource({
      repositoryRoot: work, canonicalRemoteUrl: remote, expectedRevision: "f".repeat(40),
    }), "SOURCE_REMOTE_MISMATCH");

    writeFileSync(path.join(work, "tracked.txt"), "local only\n");
    git(work, "add", "tracked.txt");
    git(work, "commit", "-m", "unpublished");
    expectCode(() => inspectOfflineProductionSource({
      repositoryRoot: work, canonicalRemoteUrl: remote, expectedRevision: git(work, "rev-parse", "HEAD"),
    }), "SOURCE_REMOTE_MISMATCH");
  });
});

test("offline source inspection refuses missing cached origin/main, a dirty checkout or a foreign origin", () => {
  withTestRepository((work, remote) => {
    const revision = git(work, "rev-parse", "HEAD");
    git(work, "update-ref", "-d", "refs/remotes/origin/main");
    expectCode(() => inspectOfflineProductionSource({
      repositoryRoot: work, canonicalRemoteUrl: remote, expectedRevision: revision,
    }), "COMMAND_FAILED");
  });
  withTestRepository((work, remote) => {
    const revision = git(work, "rev-parse", "HEAD");
    writeFileSync(path.join(work, "tracked.txt"), "dirty\n");
    expectCode(() => inspectOfflineProductionSource({
      repositoryRoot: work, canonicalRemoteUrl: remote, expectedRevision: revision,
    }), "SOURCE_DIRTY_TRACKED");
  });
  withTestRepository((work) => {
    const revision = git(work, "rev-parse", "HEAD");
    expectCode(() => inspectOfflineProductionSource({
      repositoryRoot: work, expectedRevision: revision,
    }), "SOURCE_REPOSITORY_MISMATCH");
  });
});

function fakeDocker(labels = {}, missingServices = []) {
  return (command, args) => {
    assert.equal(command, "docker");
    if (args.includes("ps")) {
      const service = args.at(-1);
      return {
        status: 0,
        stdout: missingServices.includes(service) ? "" : `container-${service}\n`,
      };
    }

    if (args[0] === "inspect") {
      const service = args.at(-1).replace("container-", "");
      return { status: 0, stdout: `${labels[service] ?? ""}\n` };
    }

    return { status: 1, stdout: "" };
  };
}

test("revision verifier accepts an all-service match", () => {
  const labels = Object.fromEntries(
    PRODUCTION_SERVICES.map((service) => [service, validRevision]),
  );
  const result = verifyServiceRevisions({
    expectedRevision: validRevision,
    execute: fakeDocker(labels),
  });

  assert.equal(result.ok, true);
  assert.equal(result.lines.at(-1), "production revision verified");
  for (const service of PRODUCTION_SERVICES) {
    assert.ok(result.lines.includes(`${service}: match`));
  }
});

test("revision verifier safely categorizes missing, malformed, absent, and mismatched labels", () => {
  const unexpectedRevision = "f".repeat(40);
  const result = verifyServiceRevisions({
    expectedRevision: validRevision,
    execute: fakeDocker(
      {
        "public-site": "",
        hub: "not-a-revision",
        "oidc-issuer": "not-a-revision",
        "session-cleanup": unexpectedRevision,
        "email-worker": unexpectedRevision,
      },
      [],
    ),
  });

  assert.equal(result.ok, false);
  assert.ok(result.lines.includes("public-site: label missing"));
  assert.ok(result.lines.includes("hub: label malformed"));
  assert.ok(result.lines.includes("oidc-issuer: label malformed"));
  assert.ok(result.lines.includes("session-cleanup: mismatch"));
  assert.ok(result.lines.includes("email-worker: mismatch"));
  assert.equal(result.lines.join("\n").includes(unexpectedRevision), false);

  const absent = verifyServiceRevisions({
    expectedRevision: validRevision,
    execute: fakeDocker({}, ["hub"]),
  });
  assert.equal(absent.ok, false);
  assert.ok(absent.lines.includes("hub: missing"));
});
