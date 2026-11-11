#!/usr/bin/env bash
# Keep Playwright arguments as execve argv. Windows PowerShell 5.1 strips the
# embedded quotes from a Bash -lc command passed through docker.exe, turning
# a spaced --grep value into multiple unquoted shell words.
set -o pipefail
node scripts/e2e/run-e2e.mjs "$@" 2>&1 | node scripts/e2e/redact-browser-e2e-log.mjs > /tmp/browser-e2e.log
status=$?
cat /tmp/browser-e2e.log
exit $status
