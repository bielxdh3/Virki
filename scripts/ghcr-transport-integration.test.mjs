import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import test from "node:test";

const source = readFileSync(new URL("./production-server.sh", import.meta.url), "utf8");
const start = source.indexOf("verify_image_manifest() {");
const end = source.indexOf("\ncompose_args() {", start);
assert.ok(start >= 0 && end > start, "The test must exercise actual production image transport functions.");
const functions = source.slice(start, end);
// Windows Git Bash cannot enforce POSIX mode 0600 reliably; use the native Linux
// SSH test host. Docker is a shell mock: this never touches running services.
const command = process.platform === "win32" ? "ssh" : "bash";
const args = process.platform === "win32"
  ? ["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=8", "servidor", "bash -s"]
  : ["-s"];
const sha = "0123456789abcdef0123456789abcdef01234567";
const digestA = "a".repeat(64);
const digestB = "b".repeat(64);

function exerciseTransport(mode) {
  const script = String.raw`#!/usr/bin/env bash
set -Eeuo pipefail
revision=${sha}
image_id=0123456789abcdef01234567
root=$(mktemp -d)
trap 'rm -rf -- "$root"' EXIT
temp_dir="$root/.deploy-tmp"
mkdir -m 700 -- "$temp_dir"
printf 'fake-disposable-test-token' > "$root/.ghcr-read-token"
chmod 600 -- "$root/.ghcr-read-token"
cat > "$temp_dir/images-$revision-$image_id.manifest" <<'MANIFEST'
revision=${sha}
run_id=42
platform=linux/amd64
runtime_digest=sha256:${digestA}
migrator_digest=sha256:${digestB}
MANIFEST
if [[ '${mode}' == invalid-manifest ]]; then
  printf 'extra=untrusted\n' >> "$temp_dir/images-$revision-$image_id.manifest"
fi
image_hash=$(sha256sum "$temp_dir/images-$revision-$image_id.manifest" | cut -d' ' -f1)
trace="$root/calls"
touch "$trace"
docker() {
  local command="$1 $2"
  printf '%s\n' "$*" >> "$trace"
  case "$command" in
    'login ghcr.io')
      [[ "$*" == *'--password-stdin'* && "$DOCKER_CONFIG" == "$temp_dir"/.ghcr-auth.* ]] || return 1
      cat >/dev/null
      printf 'test-only' > "$DOCKER_CONFIG/config.json"
      [[ '${mode}' != deny-login ]] ;;
    'pull ghcr.io/'*)
      [[ '${mode}' != deny-migrator || "$*" != *virki-migrator* ]] ;;
    'image inspect')
      if [[ '${mode}' == mismatched-label && "$*" == *virki-migrator* ]]; then
        printf 'wrong-revision|https://github.com/bielxdh3/Virki|linux/amd64\n'
      elif [[ '${mode}' == mismatched-platform && "$*" == *virki-migrator* ]]; then
        printf '%s|https://github.com/bielxdh3/Virki|linux/arm64\n' "$revision"
      else
        printf '%s|https://github.com/bielxdh3/Virki|linux/amd64\n' "$revision"
      fi ;;
    'image tag') return 0 ;;
    *) return 1 ;;
  esac
}
fail() { printf '%s\n' "$1" >&2; exit 1; }
` + "\n" + functions + String.raw`
set +e
(load_production_images) >/dev/null 2>"$root/failure"
result=$?
set -e
printf 'RESULT=%s\n' "$result"
printf 'PULLS=%s\n' "$(grep -c '^pull ' "$trace" || :)"
printf 'TAGS=%s\n' "$(grep -c '^image tag ' "$trace" || :)"
printf 'LOGIN=%s\n' "$(grep -c '^login ghcr.io ' "$trace" || :)"
printf 'MANIFEST=%s\n' "$([[ -f "$temp_dir/images-$revision-$image_id.manifest" ]] && echo retained || echo consumed)"
printf 'AUTH_TEMP=%s\n' "$(find "$temp_dir" -maxdepth 1 -name '.ghcr-auth.*' | wc -l | tr -d ' ')"
if grep -Fq 'fake-disposable-test-token' "$root/failure"; then exit 55; fi
`;
  const result = spawnSync(command, args, { input: script, encoding: "utf8", timeout: 15_000 });
  assert.equal(result.status, 0, `GHCR isolated test harness failed: ${result.error?.code ?? result.stderr}`);
  return Object.fromEntries(result.stdout.trim().split("\n").map((line) => line.split("=")));
}

for (const [mode, outcome] of Object.entries({
  success: { RESULT: "0", PULLS: "2", TAGS: "2", LOGIN: "1", MANIFEST: "consumed", AUTH_TEMP: "0" },
  "invalid-manifest": { RESULT: "1", PULLS: "0", TAGS: "0", LOGIN: "0", MANIFEST: "retained", AUTH_TEMP: "0" },
  "deny-login": { RESULT: "1", PULLS: "0", TAGS: "0", LOGIN: "1", MANIFEST: "retained", AUTH_TEMP: "0" },
  "deny-migrator": { RESULT: "1", PULLS: "2", TAGS: "0", LOGIN: "1", MANIFEST: "retained", AUTH_TEMP: "0" },
  "mismatched-label": { RESULT: "1", PULLS: "2", TAGS: "0", LOGIN: "1", MANIFEST: "retained", AUTH_TEMP: "0" },
  "mismatched-platform": { RESULT: "1", PULLS: "2", TAGS: "0", LOGIN: "1", MANIFEST: "retained", AUTH_TEMP: "0" }
})) {
  test(`private GHCR transport ${mode}, rejects partial tags and erases temporary authentication`, () => {
    assert.deepEqual(exerciseTransport(mode), outcome);
  });
}
