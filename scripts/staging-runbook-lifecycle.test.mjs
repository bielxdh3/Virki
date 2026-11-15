import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, mkdtempSync, mkdirSync, chmodSync, rmSync, existsSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { rootCertificates } from "node:tls";
import { fileURLToPath } from "node:url";
import test from "node:test";

// The full shell lifecycle contract is Linux-only. Windows CI still discovers
// the suite but reports explicit skips; the Linux runner executes all cases.
const testBash = process.platform === "win32" ? test.skip : test;

const root = fileURLToPath(new URL("../", import.meta.url));
// Checkout may have CRLF on Windows; copied Bash code blocks use LF on Linux.
const runbook = readFileSync(path.join(root, "docs/security/pr118-staging-operator-runbook-20261114.md"), "utf8").replace(/\r\n/g, "\n");
const start = runbook.indexOf("hub_cleanup_armed=0\n");
const end = runbook.indexOf("hub_abort() {", start);
assert.ok(start > 0 && end > start, "protected shell cleanup block must exist");
const lifecycle = runbook.slice(start, end);

const bash = process.env.BASH_FOR_STAGING_TEST ?? "/bin/bash";

function simulate({ hub, worker, operation, failDocker = "" }) {
  const tmp = mkdtempSync(path.join(tmpdir(), "virki-runbook-test-"));
  const log = path.join(tmp, "mock-docker.log");
  const script = `set -euo pipefail
    docker() {
      printf '%s\\n' "$*" >> "$MOCK_DOCKER_LOG";
      if [[ "$MOCK_FAIL_DOCKER" == "worker" && "$*" == *"stop --timeout 60 email-worker"* ]]; then return 77; fi
      if [[ "$MOCK_FAIL_DOCKER" == "hub" && "$*" == *"stop --timeout 60 hub"* ]]; then return 78; fi
    }
    ctx=mock-context; project=mock-worker; profile=mock-profile; file=mock-worker.yml
    hub_project=mock-hub; hub_file=mock-hub.yml
    ${lifecycle}
    hub_cleanup_armed=${hub ? 1 : 0}
    worker_cleanup_armed=${worker ? 1 : 0}
    ${operation}
  `;
  try {
    const result = spawnSync(bash, ["--noprofile", "--norc", "-c", script], {
      env: { PATH: "/usr/bin:/bin", MOCK_DOCKER_LOG: log, MOCK_FAIL_DOCKER: failDocker },
      encoding: "utf8",
      timeout: 5000,
    });
    assert.ifError(result.error);
    const calls = existsSync(log) ? readFileSync(log, "utf8").trim().split("\n") : [];
    return { result, calls };
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

testBash("unexpected successful exit is BLOCK and stops worker before Hub", () => {
  const { result, calls } = simulate({ hub: true, worker: true, operation: "exit 0" });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /BLOCK: staging shell exited/);
  assert.equal(calls.length, 2);
  assert.match(calls[0], /--project-name mock-worker.*stop --timeout 60 email-worker/);
  assert.match(calls[1], /--project-name mock-hub.*stop --timeout 60 hub/);
});

testBash("Hub-only failure preserves failure code and stops only Hub", () => {
  const { result, calls } = simulate({ hub: true, worker: false, operation: "exit 7" });
  assert.equal(result.status, 7);
  assert.equal(calls.length, 1);
  assert.match(calls[0], /--project-name mock-hub.*stop --timeout 60 hub/);
});

testBash("normal exit after independently verified stops does not stop services", () => {
  const { result, calls } = simulate({ hub: false, worker: false, operation: "exit 0" });
  assert.equal(result.status, 0);
  assert.equal(calls.length, 0);
});

testBash("TERM preserves abnormal status and triggers ordered cleanup", () => {
  const { result, calls } = simulate({ hub: true, worker: true, operation: "kill -TERM \"$BASHPID\"" });
  assert.equal(result.status, 143);
  assert.equal(calls.length, 2);
  assert.match(calls[0], /stop --timeout 60 email-worker/);
  assert.match(calls[1], /stop --timeout 60 hub/);
});

testBash("a failed worker stop never skips Hub stop or reports a successful shutdown", () => {
  const { result, calls } = simulate({
    hub: true, worker: true, operation: "exit 0", failDocker: "worker",
  });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /BLOCK/);
  assert.equal(calls.length, 2);
  assert.match(calls[0], /stop --timeout 60 email-worker/);
  assert.match(calls[1], /stop --timeout 60 hub/);
});

testBash("worker is armed before up and disarmed only after physical stopped checks", () => {
  assert.match(runbook, /worker_cleanup_armed=1\nif ! docker[\s\S]*?up --no-deps --pull never --detach email-worker/);
  const stop = runbook.indexOf('After the single approved OTP window, stop the worker:');
  const disarm = runbook.indexOf('worker_cleanup_armed=0', stop);
  assert.ok(stop > 0 && disarm > stop);
  for (const required of ['"$stopped_state" != "exited"', '"$stopped_restart" != "no"',
    '"$stopped_restarts" != "${VIRKI_STAGING_WORKER_INITIAL_RESTART_COUNT:-0}"',
    '"$all_running_workers"']) {
    assert.ok(runbook.indexOf(required, stop) < disarm && runbook.indexOf(required, stop) > stop, required);
  }
  const hubDisarm = runbook.indexOf('hub_cleanup_armed=0', disarm);
  assert.ok(hubDisarm > disarm);
  assert.match(runbook.slice(disarm, hubDisarm), /stopped_hub_restart.*no/);
  assert.match(runbook.slice(hubDisarm, hubDisarm + 85), /trap - EXIT INT TERM HUP/);
  assert.match(runbook, /abort_worker\(\) \{\n  printf /);
});

testBash("both staging and rollback compare IPv6 addresses canonically, without DNS", () => {
  const helpers = [...runbook.matchAll(/same_ip_address\(\) \{([\s\S]*?)\n\}/g)];
  assert.equal(helpers.length, 2, "the operator and rollback shells are separate");
  for (const match of helpers) {
    const helper = `same_ip_address() {${match[1]}\n}`;
    for (const [left, right, expected] of [
      ["2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1", 0],
      ["2001:db8::1", "2001:db8::2", 1],
      ["127.0.0.1", "127.0.0.1", 0],
      ["127.0.0.1", "::1", 1],
      ["example.com", "example.com", 1],
    ]) {
      const sh = `node_bin="${process.execPath.replaceAll('"', '\\"')}"\n${helper}\nsame_ip_address "$1" "$2"\n`;
      const result = spawnSync(bash, ["-c", sh, "--", left, right], {
        encoding: "utf8", timeout: 5000,
      });
      assert.ifError(result.error);
      assert.equal(result.status === 0 ? 0 : 1, expected, `${left} vs ${right}: ${result.stderr}`);
    }
  }
});

testBash("the rollback requires a physically stopped worker and uses unambiguous migration encoding", () => {
  const rollback = runbook.slice(runbook.indexOf("## 4. Physical rollback"));
  const stopCheck = rollback.indexOf('rollback_worker_state="$(docker');
  const hubStop = rollback.indexOf('stop --timeout 60 hub');
  assert.ok(stopCheck > 0 && hubStop > stopCheck);
  assert.match(rollback.slice(stopCheck, hubStop), /exited\|no\|/);
  assert.match(rollback, /--command "ALTER DATABASE \\"\$VIRKI_STAGING_RESTORE_DB\\" OWNER TO virki_migrator"/);
  assert.doesNotMatch(rollback, /ALTER DATABASE :\\"database_name\\"/);
  assert.match(rollback, /encode\(convert_to\(migration_name, 'UTF8'\), 'hex'\)/);
  assert.match(rollback, /encode\(convert_to\(checksum, 'UTF8'\), 'hex'\)/);
  assert.match(rollback, /staging-prisma-migration-ledger-binding\.mjs --hex-fields/);
  assert.equal((runbook.match(/negative_host="\$\{negative_host\/\/:\/\\\\:\}"/g) ?? []).length, 2);
});

testBash("operator and rollback must attest raw committed helper bytes instead of trusting git status", () => {
  assert.equal((runbook.match(/for source_file in \\/g) ?? []).length, 2);
  assert.equal((runbook.match(/for git_name in "\$\{!GIT_@\}"/g) ?? []).length, 2);
  assert.equal((runbook.match(/GIT_NO_REPLACE_OBJECTS=1 \/usr\/bin\/git hash-object --no-filters/g) ?? []).length, 2);
  assert.equal((runbook.match(/GIT_NO_REPLACE_OBJECTS=1 \/usr\/bin\/git rev-parse --verify/g) ?? []).length, 2);
  for (const filename of ["scripts/staging-prisma-migration-ledger-binding.mjs",
    "scripts/staging-pgpass-bootstrap-binding.mjs", "scripts/staging-toolchain-preflight.mjs",
    "docs/security/pr118-staging-operator-runbook-20261114.md"]) {
    assert.equal(runbook.split(filename).length >= 3, true, filename);
  }
});

testBash("git assume-unchanged hides a modified source from status but not raw OID comparison", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "virki-git-assume-"));
  const git = "/usr/bin/git";
  const env = { PATH: "/usr/bin:/bin", HOME: dir, GIT_CONFIG_NOSYSTEM: "1" };
  const call = (...args) => {
    const result = spawnSync(git, args, { cwd: dir, env, encoding: "utf8", timeout: 5000 });
    assert.ifError(result.error);
    assert.equal(result.status, 0, result.stderr);
    return result.stdout.trim();
  };
  try {
    call("init", "-q");
    writeFileSync(path.join(dir, "operator.mjs"), "console.log('safe');\n");
    call("add", "operator.mjs");
    call("-c", "user.email=fixture@example.test", "-c", "user.name=Fixture", "commit", "-qm", "baseline");
    writeFileSync(path.join(dir, "operator.mjs"), "console.log('hostile');\n");
    call("update-index", "--assume-unchanged", "operator.mjs");
    assert.equal(call("status", "--porcelain"), "", "status may wrongly appear clean");
    const committed = call("rev-parse", "--verify", "HEAD:operator.mjs");
    const actual = call("hash-object", "--no-filters", "--", "operator.mjs");
    assert.notEqual(actual, committed, "raw content integrity must deny the hidden modification");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

testBash("operator and rollback service-file checks accept CRLF but pin the exact approved CA", () => {
  const checks = [...runbook.matchAll(/require_service_tls\(\) \{([\s\S]*?)\n\}/g)];
  assert.equal(checks.length, 2);
  const dir = mkdtempSync(path.join(tmpdir(), "virki-crlf-hba-"));
  const filename = path.join(dir, "pg_service.conf");
  try {
    for (const match of checks) {
      const shell = `set -eu
        PGSERVICEFILE="$1"
        ca_file="/approved/db/ca.crt"
        require_service_tls() {${match[1]}
        }
        require_service_tls virki-staging-worker
      `;
      const base = [
        "[virki-staging-worker]", "host=db.example.test", "port=5432",
        "dbname=virki_stage", "user=virki_email_worker", "sslmode=verify-full",
        "sslrootcert=/approved/db/ca.crt",
      ];
      for (const [lines, expected] of [
        [base, 0],
        [[...base.slice(0, -1), "sslrootcert=/untrusted/ca.crt"], 1],
        [[...base, "sslrootcert=/approved/db/ca.crt"], 1],
      ]) {
        writeFileSync(filename, lines.join("\r\n") + "\r\n");
        const result = spawnSync(bash, ["-c", shell, "--", filename], {
          encoding: "utf8", timeout: 5000,
        });
        assert.ifError(result.error);
        assert.equal(result.status === 0 ? 0 : 1, expected, result.stderr);
      }
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

testBash("OCI CA inspection never executes image binaries and fails shut on bytes, volume, create/copy/cleanup errors", () => {
  const match = runbook.match(/verify_staging_prisma_image_ca\(\) \(([\s\S]*?)\n\)/u);
  assert.ok(match, "non-executing worker/Hub CA gate must exist");
  assert.ok(runbook.includes('verify_staging_prisma_image_ca "$image"'));
  assert.ok(runbook.includes('verify_staging_prisma_image_ca "$hub_image"'));
  assert.match(match[1], /docker --context "\$ctx" create/u);
  assert.match(match[1], /docker --context "\$ctx" cp/u);
  assert.match(match[1], /docker --context "\$ctx" rm --force/u);
  assert.match(match[1], /scripts\/staging-prisma-ca-archive-proof\.mjs/u);
  assert.doesNotMatch(match[1], /docker --context "\$ctx" (?:run|exec|start)/u);

  const dir = mkdtempSync(path.join(tmpdir(), "virki-ca-archive-mock-"));
  const caDir = path.join(dir, "ca");
  const caFile = path.join(caDir, "staging-db-root.pem");
  const archive = path.join(dir, "ca.tar");
  const dockerLog = path.join(dir, "docker.log");
  const createdFlag = path.join(dir, "created.flag");
  const nonceFile = path.join(dir, "nonce.txt");
  const pollCounter = path.join(dir, "poll-count.txt");
  try {
    mkdirSync(caDir);
    chmodSync(caDir, 0o755);
    const pem = rootCertificates[0].trimEnd() + "\n";
    writeFileSync(caFile, pem, { mode: 0o444 });
    chmodSync(caFile, 0o444);
    const approved = createHash("sha256").update(pem).digest("hex");
    const tar = spawnSync("/usr/bin/tar", [
      "--format=ustar", "--owner=0", "--group=0", "-C", dir, "-cf", archive, "ca"
    ], { encoding: "utf8", timeout: 5000 });
    assert.ifError(tar.error);
    assert.equal(tar.status, 0, tar.stderr);
    for (const [caseName, caDigest, volume, failure, expected] of [
      ["accepted", approved, "null", "", "PASS"],
      ["wrong-hash", "a".repeat(64), "null", "", "BLOCK"],
      ["volumes", approved, "{}", "", "BLOCK"],
      ["create", approved, "null", "create", "BLOCK"],
      ["create-timeout", approved, "null", "timeout-create", "BLOCK"],
      ["uncertain-create", approved, "null", "uncertain", "BLOCK"],
      ["orphan-after-create-error", approved, "null", "orphan", "BLOCK"],
      ["late-orphan-after-first-empty-inventory", approved, "null", "late", "BLOCK"],
      ["inventory-failure-after-create", approved, "null", "inventory", "BLOCK"],
      ["invalid-id", approved, "null", "id", "BLOCK"],
      ["ownership-mismatch", approved, "null", "label", "BLOCK"],
      ["name-collision", approved, "null", "collision", "BLOCK"],
      ["copy", approved, "null", "cp", "BLOCK"],
      ["remove", approved, "null", "rm", "BLOCK"],
    ]) {
      writeFileSync(dockerLog, "");
      writeFileSync(createdFlag, failure === "collision" ? "1" : "");
      writeFileSync(nonceFile, "");
      writeFileSync(pollCounter, "0");
      const shell = `set -euo pipefail
        ctx=mock
        node_bin="${process.execPath.replaceAll('"', '\\"')}"
        VIRKI_STAGING_APPROVED_SOURCE_SHA="${"0".repeat(40)}"
        VIRKI_STAGING_APPROVED_DB_CA_SHA256="$MOCK_CA_DIGEST"
        timeout() {
          [[ "$1" == "--kill-after=5s" ]] || return 9
          shift 2
          "$@"
        }
        sleep() { [[ "$1" == "1" ]]; }
        docker() {
          printf '%s\\n' "$*" >> "$MOCK_DOCKER_LOG"
          if [[ "$*" == *"image inspect"* ]]; then printf '%s\\n' "$MOCK_VOLUME"; return; fi
          if [[ "$*" == *" ps -aq "* ]]; then
            counter="$(cat "$MOCK_POLL_COUNTER")"
            counter=$((counter + 1))
            printf '%s' "$counter" > "$MOCK_POLL_COUNTER"
            if [[ "$MOCK_FAIL" == "inventory" && "$counter" -ge "2" ]]; then return 124; fi
            if [[ "$MOCK_FAIL" == "late" && "$counter" == "2" ]]; then return 0; fi
            [[ -s "$MOCK_CREATED" ]] && printf '%064d\\n' 0
            return 0
          fi
          if [[ "$*" == *" create "* ]]; then
            [[ "$MOCK_FAIL" != "create" && "$MOCK_FAIL" != "uncertain" ]] || return 8
            for value in "$@"; do
              if [[ "$value" == org.virki.staging.ca-inspection-nonce=* ]]; then
                printf '%s' "$value" | cut -d= -f2 > "$MOCK_NONCE_FILE"
              fi
            done
            printf '1' > "$MOCK_CREATED"
            if [[ "$MOCK_FAIL" == "timeout-create" ]]; then return 124; fi
            [[ "$MOCK_FAIL" != "orphan" && "$MOCK_FAIL" != "late" ]] || return 8
            if [[ "$MOCK_FAIL" == "id" ]]; then printf '%s\\n' '--help'; return; fi
            printf '%064d\\n' 0
            return
          fi
          if [[ "$*" == *" container inspect "* ]]; then
            nonce="$(cat "$MOCK_NONCE_FILE")"
            [[ "$MOCK_FAIL" != "label" ]] || nonce="not-the-current-inspection"
            if [[ "$*" == *"{{.Id}}|"* ]]; then
              printf '%064d|%s\\n' 0 "$nonce"
            else
              printf '%s\\n' "$nonce"
            fi
            return
          fi
          if [[ "$*" == *" cp "* ]]; then
            [[ "$MOCK_FAIL" != "cp" ]] || return 8
            cat "$MOCK_TAR"
            return
          fi
          if [[ "$*" == *" rm --force "* ]]; then
            [[ "$MOCK_FAIL" != "rm" ]] || return 8
            : > "$MOCK_CREATED"
            return
          fi
          return 9
        }
        verify_staging_prisma_image_ca() (${match[1]}
        )
        if verify_staging_prisma_image_ca "approved@sha256:mock"; then
          printf 'PASS\\n'
        else
          printf 'BLOCK\\n'
        fi
      `;
      const result = spawnSync(bash, ["-c", shell], {
        encoding: "utf8", timeout: 10000,
        env: { PATH: "/usr/bin:/bin", MOCK_CA_DIGEST: caDigest,
          MOCK_VOLUME: volume, MOCK_FAIL: failure, MOCK_TAR: archive,
          MOCK_DOCKER_LOG: dockerLog, MOCK_CREATED: createdFlag,
          MOCK_NONCE_FILE: nonceFile, MOCK_POLL_COUNTER: pollCounter }
      });
      assert.ifError(result.error);
      assert.equal(result.status, 0, `${caseName}: ${result.stderr}`);
      assert.equal(result.stdout.trim(), expected, caseName);
      const calls = readFileSync(dockerLog, "utf8");
      assert.doesNotMatch(calls, /\b(?:run|exec|start)\b/u);
      if (!["volumes", "create", "uncertain-create", "inventory-failure-after-create", "name-collision", "ownership-mismatch"].includes(caseName)) {
        assert.match(calls, /rm --force/u, `${caseName} must attempt cleanup`);
      }
      if (["accepted", "wrong-hash", "orphan-after-create-error", "create-timeout", "invalid-id", "copy"].includes(caseName)) {
        assert.equal(readFileSync(createdFlag, "utf8"), "", `${caseName} must leave no orphan`);
      }
      if (caseName === "ownership-mismatch") {
        assert.equal(readFileSync(createdFlag, "utf8"), "1", "never remove a container with an alien label");
      }
      if (caseName === "late-orphan-after-first-empty-inventory") {
        assert.equal(readFileSync(createdFlag, "utf8"), "", "late daemon create must be observed and cleaned");
        assert.ok(Number(readFileSync(pollCounter, "utf8")) >= 3, "cleanup rechecks an empty first lookup");
      }
      if (caseName === "uncertain-create") {
        assert.match(result.stderr, /create outcome unknown/u,
          "unknown create status must stay an explicit manual-reconciliation BLOCK");
      }
      if (caseName === "inventory-failure-after-create") {
        assert.match(result.stderr, /inventory unavailable/u, "daemon inventory errors must fail closed");
        assert.equal(readFileSync(createdFlag, "utf8"), "1",
          "unverifiable resource requires manual reconciliation, never a false cleanup PASS");
      }
      if (caseName === "name-collision") {
        assert.doesNotMatch(calls, / create /u, "a pre-existing container must never be replaced");
      }
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

testBash("all runbook shell fences pass bash -n (no execution)", () => {
  const fences = [...runbook.matchAll(/```sh\r?\n([\s\S]*?)\r?\n```/g)];
  assert.ok(fences.length >= 5);
  for (const [index, fence] of fences.entries()) {
    const result = spawnSync(bash, ["-n"], { input: fence[1] + "\n", encoding: "utf8", timeout: 5000 });
    assert.equal(result.status, 0, `sh fence ${index + 1}: ${result.stderr}; last lines: ${fence[1].split("\n").slice(-15).join(" | ")}`);
  }
});
