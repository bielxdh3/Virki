import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { verifyRemoteMainHead } from "./production-main-head-check.mjs";

const revision = "0123456789abcdef0123456789abcdef01234567";
const repositoryRoot = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const approvalWorkflow = readFileSync(path.join(repositoryRoot, ".github", "workflows", "approve-production.yml"), "utf8");

test("a main advance after preflight blocks approval pointer publication", () => {
  const observations = [
    `${revision}\trefs/heads/main\n`,
    `${"f".repeat(40)}\trefs/heads/main\n`,
  ];
  const execute = (command, args) => {
    assert.equal(command, "git");
    assert.deepEqual(args, ["ls-remote", "origin", "refs/heads/main"]);
    return observations.shift();
  };

  assert.equal(verifyRemoteMainHead(revision, execute), revision);
  assert.throws(() => verifyRemoteMainHead(revision, execute), /main changed after approval preflight/u);
});

test("the final exact-main check runs before any approval-pointer mutation", () => {
  const publishStep = approvalWorkflow.slice(approvalWorkflow.indexOf("- name: Publish approved revision pointer only"));
  const headCheck = publishStep.indexOf('node scripts/production-main-head-check.mjs "$TARGET_SHA"');
  const firstMutation = publishStep.indexOf("gh api --method POST");
  const contentsMutation = publishStep.indexOf('gh api --method PUT "repos/$GITHUB_REPOSITORY/contents/production.json"');

  assert.ok(headCheck >= 0);
  assert.ok(firstMutation > headCheck);
  assert.ok(contentsMutation > headCheck);
});
