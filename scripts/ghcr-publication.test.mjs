import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import test from "node:test";

// Exercise the actual workflow Bash step without a registry or Docker daemon.
const workflow = readFileSync(new URL("../.github/workflows/ci.yml", import.meta.url), "utf8");
const step = workflow.indexOf("      - name: Publish tested private GHCR images and record exact manifest digests\n");
const begin = workflow.indexOf("        run: |\n", step) + "        run: |\n".length;
const end = workflow.indexOf("\n      - name:", begin);
assert.ok(step >= 0 && begin > step && end > begin, "CI publishing step must be found in the actual workflow.");
const publication = workflow.slice(begin, end).split("\n").map((line) => line.startsWith("          ") ? line.slice(10) : line).join("\n");
const sha = "0123456789abcdef0123456789abcdef01234567";
const command = process.platform === "win32" ? "ssh" : "bash";
const args = process.platform === "win32"
  ? ["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=8", "servidor", "bash -s"]
  : ["-s"];

function simulate(mode) {
  const runner = String.raw`#!/usr/bin/env bash
set -Eeuo pipefail
GHCR_USERNAME=fixture-user
GHCR_PASSWORD=fixture-token-not-real
GH_TOKEN=fixture-token-not-real
EXPECTED_ARCH=amd64
ACCEPTED_SHA=${sha}
ACCEPTED_RUN_ID=42
RUNNER_TEMP=$(mktemp -d)
trap 'rm -rf -- "$RUNNER_TEMP"' EXIT
trace="$RUNNER_TEMP/calls"
touch "$trace"
gh() {
  printf 'gh %s\n' "$*" >> "$trace"
  [[ '${mode}' != private-missing ]] || return 1
  if [[ '${mode}' == public-package ]]; then printf 'public\n'; else printf 'private\n'; fi
}
docker() {
  printf 'docker %s\n' "$*" >> "$trace"
  case "$1" in
    login) [[ "$*" == *'--password-stdin'* ]] || return 1; cat >/dev/null ;;
    tag) return 0 ;;
    push)
      [[ '${mode}' != denied-push || "$*" != *virki-migrator* ]] || return 1
      if [[ '${mode}' == broken-digest && "$*" == *virki-migrator* ]]; then
        printf 'pushed: digest: sha256:untrusted size: 1\n'
      elif [[ "$*" == *virki-runtime* ]]; then
        printf 'pushed: digest: sha256:${"a".repeat(64)} size: 123\n'
      else
        printf 'pushed: digest: sha256:${"b".repeat(64)} size: 123\n'
      fi ;;
    *) return 1 ;;
  esac
}
` + String.raw`
set +e
(
` + publication + String.raw`
) >"$RUNNER_TEMP/workflow-stdout" 2>"$RUNNER_TEMP/workflow-stderr"
result=$?
set -e
printf 'RESULT=%s\n' "$result"
printf 'PUSHES=%s\n' "$(grep -c '^docker push' "$trace" || :)"
printf 'LOGINS=%s\n' "$(grep -c '^docker login' "$trace" || :)"
printf 'MANIFEST=%s\n' "$([[ -f "$RUNNER_TEMP/virki-production-images.manifest" ]] && echo yes || echo no)"
if [[ -f "$RUNNER_TEMP/virki-production-images.manifest" ]]; then
  cat "$RUNNER_TEMP/virki-production-images.manifest"
fi
if grep -Fq 'fixture-token-not-real' "$RUNNER_TEMP/workflow-stderr" "$RUNNER_TEMP/workflow-stdout"; then exit 55; fi
`;
  const executed = spawnSync(command, args, { input: runner, encoding: "utf8", timeout: 20_000 });
  assert.equal(executed.status, 0, `Isolated GHCR workflow simulation failed: ${executed.stderr}`);
  return Object.fromEntries(executed.stdout.trim().split("\n").map((line) => {
    const at = line.indexOf("=");
    return [line.slice(0, at), line.slice(at + 1)];
  }));
}

test("CI publisher only emits SHA/run/platform-bound private GHCR digests", () => {
  assert.deepEqual(simulate("success"), {
    RESULT: "0", PUSHES: "2", LOGINS: "1", MANIFEST: "yes",
    revision: sha, run_id: "42", platform: "linux/amd64",
    runtime_digest: `sha256:${"a".repeat(64)}`,
    migrator_digest: `sha256:${"b".repeat(64)}`,
  });
});

for (const mode of ["public-package", "private-missing", "denied-push", "broken-digest"]) {
  test(`CI publisher ${mode} fails closed without usable provenance`, () => {
    const actual = simulate(mode);
    assert.notEqual(actual.RESULT, "0");
    assert.equal(actual.MANIFEST, "no");
    if (["public-package", "private-missing"].includes(mode)) {
      assert.equal(actual.PUSHES, "0", "Never push to an unverified or public package.");
      assert.equal(actual.LOGINS, "0");
    }
  });
}
