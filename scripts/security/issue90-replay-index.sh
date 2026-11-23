#!/usr/bin/env bash
# Offline V23–V49 integrity replay. Uses a temporary Git index only; never
# checks out, resets, cleans, commits, or changes the caller's worktree/index.
set -euo pipefail

if [[ $# -ne 1 ]]; then
  printf 'Usage: bash scripts/security/issue90-replay-index.sh /path/to/pinned/buildkit-git\n' >&2
  exit 2
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
buildkit="$(cd "$1" && pwd)"
manifest="$root/docs/security/experiments/issue90-review-patches.sha256"
expected=(
  7eb9bfebb607c6795138b50d9bd9453b87c09b3d
  d4b9e014f42deaa152bc7e3be3175080f1ddb271
  b0bcf49bf41ece17080aeba5a4f218f0cb165fb1
  1b0ad7d10b0ef7413a2a72b6bdff5c8b90f51d2f
  932758801e6c0b47d3eceaef7aca96b1c5734e87
  c7234b862c991a940c3047f05a6f2752d7fd1e6f
  9607e2d13c28168f2f00a9370737b622b080ccc9
  c8f6df12b47ef2540bf2553ac5a9ecc9ce892971
  c8d30aca6c0df02cd49b5746d414194496fa72ff
  fcecd3d1c3d9810bb3060310f822fcb7f6da5305
  8f1537fd0132eeb12108a7faed4657ad019c8b41
  a411d348f5946769f97a7c28dc169abc7b374384
  4da0f43bfcdad770f4a1bf5786ec6df79f6f4a97
  ba02b937798adb90eed08d17196f9aca91b13721
  fcaf997a3f72c64904a04fd5c240db44773f0b13
  86064bbbfdd3c6ebd9dfc6afc3bcd61938bfa10d
  0acbf322c771b6c00a2803438fda77ac82c81a40
  50d92e619251b1b4a889f9c6f6d7489ce2a56f6f
  bd76aa00d4a62fa04523f4be26692de11dfb229d
  b6231f822efcd8f0be7956c93e189a30418c51b4
  5c732ac1f0873141eacfc88cc2f222f543fd4d6d
  a3e5add39cd2ac188314ba4b79294a391cc7fc4c
  7952e6dc2599b447fa97b86dda77e27416de8c7e
  4e8440c77a86e009685717e86194bb4e6a83ff81
  5de9120c20a35c8b0dee8a85e47973471759c315
  d63d46e43eedca0203cf555611b27c3cf03c49d0
  c02dad283db232bba7f02128e88697feeea6dffa
)

test -f "$manifest"
cd "$root"
sha256sum --check "$manifest"
test "$(wc -l < "$manifest")" -eq "${#expected[@]}"
git -C "$buildkit" cat-file -e 'f5b59a1f2fb25a0cb7072c398cab9aed7835da4e^{tree}'
index="$(mktemp "${TMPDIR:-/tmp}/virki-issue90-index.XXXXXX")"
trap 'rm -f "$index"' EXIT
export GIT_INDEX_FILE="$index"
git -C "$buildkit" read-tree f5b59a1f2fb25a0cb7072c398cab9aed7835da4e

i=0
while read -r digest patch; do
  # Windows worktrees may check out the text manifest with CRLF even though
  # the binary-sensitive .patch files retain their exact pinned LF bytes.
  patch="${patch%$'\r'}"
  [[ $patch == docs/security/experiments/*.patch ]] || exit 2
  git -C "$buildkit" apply --cached --check "$root/$patch"
  git -C "$buildkit" apply --cached "$root/$patch"
  actual="$(git -C "$buildkit" write-tree)"
  if [[ "$actual" != "${expected[$i]}" ]]; then
    printf 'Issue90 patch %d tree mismatch: %s\n' "$((i + 1))" "$actual" >&2
    exit 1
  fi
  printf 'V%d: %s OK\n' "$((i + 23))" "$actual"
  i=$((i + 1))
done < "$manifest"
test "$i" -eq 27
printf 'ISSUE90_REPLAY_V23_TO_V49=PASS\n'
