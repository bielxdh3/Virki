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
const ledger = readFileSync(path.join(root, "docs/security/pr118-segregated-staging-execution-ledger-20261114.md"), "utf8").replace(/\r\n/g, "\n");
const start = runbook.indexOf("hub_cleanup_armed=0\n");
const end = runbook.indexOf("hub_abort() {", start);
assert.ok(start > 0 && end > start, "protected shell cleanup block must exist");
const lifecycle = runbook.slice(start, end);

const bash = "/bin/bash";

test("staging handoff reflects implemented isolated RPs and the complete signed preflight contract", () => {
  assert.doesNotMatch(ledger, /current code hardcodes USER RP ID/u);
  assert.doesNotMatch(ledger, /a dedicated staging RP\/origin implementation .* required/u);
  assert.match(ledger, /VIRKI_STAGING_PASSKEY_RP_ENABLED=true/u);
  assert.match(ledger, /separately approved passkey-enabled staging procedure/u);
  const gate1 = ledger.slice(ledger.indexOf("## Gate 1 —"), ledger.indexOf("## Gate 2 —"));
  assert.match(gate1, /signed_staging_runtime_preflight/u);
  assert.match(gate1, /13 mandatory `--runtime-\*` bindings/u);
  assert.match(runbook, /signed_staging_runtime_preflight\(\) \{/u);
  assert.doesNotMatch(gate1, /Run `node scripts\/staging-otp-preflight\.mjs` with the two signed JSON declarations/u);
  const signedGate = gate1.indexOf("signed_staging_runtime_preflight");
  const startupInstruction = gate1.indexOf("7. Only after the signed preflight has passed");
  assert.ok(signedGate > 0 && startupInstruction > signedGate,
    "Hub activation must follow rather than precede the signed Gate-1 preflight");
  assert.match(gate1.slice(0, signedGate), /Do not start the Hub before step 6/u);
});

test("staging worker URL rejects loopback and host gateways inside its own network namespace", () => {
  const start = runbook.indexOf("  const url = new URL(process.env.VIRKI_STAGING_EMAIL_WORKER_DATABASE_URL);");
  const end = runbook.indexOf("')\"", start);
  assert.ok(start > 0 && end > start, "worker URL parser must remain embedded in the runbook");
  const parse = runbook.slice(start, end);
  const base = (host) => {
    const url = new URL(`postgresql://virki_email_worker@${host}:55492/stage_mfa_20261117?sslmode=require&sslaccept=strict&sslcert=%2Fapp%2Fca%2Fstaging-db-root.pem`);
    url.password = "placeholder";
    return url.href;
  };
  const run = (host) => spawnSync(process.execPath, ["-e", parse], {
    env: { PATH: process.env.PATH, VIRKI_STAGING_EMAIL_WORKER_DATABASE_URL: base(host) },
    encoding: "utf8", timeout: 5000
  });
  const accepted = run("pg18-stage.internal");
  assert.equal(accepted.status, 0, accepted.stderr);
  assert.equal(accepted.stdout, "pg18-stage.internal|55492|stage_mfa_20261117|virki_email_worker");
  for (const host of ["127.0.0.1", "127.0.0.2", "127.1", "0x7f000001", "localhost", "localhost.", "localhost%2e", "db.localhost", "0.0.0.0", "0", "[::1]", "[::]", "[::ffff:7f00:1]", "host.docker.internal", "gateway.docker.internal", "host.containers.internal"]) {
    const rejected = run(host);
    assert.notEqual(rejected.status, 0, `worker must reject ${host} from its isolated namespace`);
  }
});

test("public Hub-to-DB and worker-to-DB live binding remains a mandatory independent witness", () => {
  const hubWitness = runbook.indexOf("**Mandatory published-route and database-binding witness — NO-GO until observed.**");
  const browser = runbook.indexOf("Keep the Hub running for the approved browser window.", hubWitness);
  const workerSection = runbook.indexOf("## 3. Explicit attended worker window", browser);
  const workerWitness = runbook.indexOf("Reconfirm the published HTTPS-to-Hub-to-", workerSection);
  const workerActivation = runbook.indexOf("worker_cleanup_armed=1", workerWitness);
  assert.ok(hubWitness > 0 && browser > hubWitness && workerSection > browser &&
    workerWitness > workerSection && workerActivation > workerWitness,
  "live route and DB observations must be required before the browser and worker windows");
  assert.match(runbook.slice(hubWitness, browser), /actual published Hub PostgreSQL session/u);
  assert.match(runbook.slice(hubWitness, browser), /stage_pr130/u);
  assert.match(runbook.slice(workerWitness, workerActivation), /non-loopback endpoint/u);
  assert.match(runbook.slice(workerWitness, workerActivation), /mandatory NO-GO/u);
});

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
  assert.match(runbook, /abort_worker\(\) \{\n {2}printf /);
});

testBash("Hub startup waits for bounded real health before inspecting the final healthy state", () => {
  const startup = runbook.slice(runbook.indexOf("hub_cleanup_armed=1"), runbook.indexOf("STAGING_HUB_RUNTIME_ISOLATION=PASS"));
  assert.match(startup, /up --no-deps --pull never --wait --wait-timeout 120 hub/u);
  assert.match(startup, /\[\[ "\$hub_health" == "healthy" \]\] \|\| hub_abort/u);
});

testBash("signed staging runtime assertions bind measured identities before Hub startup and again before worker", () => {
  const definition = runbook.indexOf("signed_staging_runtime_preflight() {");
  const firstCall = runbook.indexOf("signed_staging_runtime_preflight ||", definition);
  const hubStartup = runbook.indexOf("hub_cleanup_armed=1", firstCall);
  const secondCall = runbook.indexOf("signed_staging_runtime_preflight ||", hubStartup);
  const workerStartup = runbook.indexOf("worker_cleanup_armed=1", secondCall);
  assert.ok(definition > 0 && firstCall > definition && hubStartup > firstCall &&
    secondCall > hubStartup && workerStartup > secondCall,
  "a fresh signed comparison must precede each staging activation");
  const body = runbook.slice(definition, firstCall);
  for (const flag of ["worker-oci-digest", "hub-oci-digest", "worker-compose-project",
    "hub-compose-project", "hub-compose-file-sha256", "network-id", "db-name",
    "resource-policy-id", "resource-policy-evidence-ref", "worker-memory-bytes",
    "worker-cpu-nano", "worker-pids-limit", "worker-interval-ms"]) {
    assert.ok(body.includes(`--runtime-${flag}`), `signed preflight must bind ${flag}`);
  }
});

testBash("worker activation rechecks empty project/service inventories and original healthy Hub immediately before up", () => {
  const workerSection = runbook.indexOf("## 3. Explicit attended worker window");
  const guardStart = runbook.indexOf("late_worker_context_guard() {", workerSection);
  const guardCall = runbook.indexOf("late_worker_context_guard || abort_worker", guardStart);
  const up = runbook.indexOf("worker_cleanup_armed=1", guardCall);
  assert.ok(workerSection > 0 && guardStart > workerSection && guardCall > guardStart && up > guardCall);
  const guard = runbook.slice(guardStart, guardCall);
  for (const must of [
    'label=com.docker.compose.project=$project',
    'label=com.docker.compose.service=email-worker',
    'label=com.docker.compose.project=$hub_project',
    'label=com.docker.compose.service=hub',
    'docker --context "$ctx" compose --project-name "$hub_project"',
    'docker --context "$ctx" inspect "$hub_id"',
    '$c.State.Status == "running"',
    '$c.State.Health.Status == "healthy"',
    '$c.HostConfig.RestartPolicy.Name == "no"',
    '$c.RestartCount == $initial_restarts',
    '$c.Config.Labels["com.docker.compose.project"] == $hub_project',
    '$c.Config.Labels["com.docker.compose.service"] == "hub"',
    '$c.NetworkSettings.Networks[$network].NetworkID == $network_id'
  ]) assert.ok(guard.includes(must), `missing late pre-up guard ${must}`);
});

testBash("worker late pre-up control flow blocks newly appeared containers and propagates jq failure", () => {
  const start = runbook.indexOf("late_worker_context_guard() {");
  const end = runbook.indexOf("late_worker_context_guard || abort_worker", start);
  assert.ok(start > 0 && end > start);
  const guard = runbook.slice(start, end);
  for (const [mode, expected] of [["clean", 0], ["worker-appeared", 17], ["hub-replaced", 17], ["lookup-failed", 17], ["hub-unhealthy", 17]]) {
    const script = `set -euo pipefail
      ctx=mock-context; project=mock-worker; hub_project=mock-hub; hub_file=mock-hub.yml
      network=mock-network; network_id=mock-network-id
      hub_image=mock-image; hub_image_id=mock-image-id
      hub_id=$(printf 'a%.0s' {1..64}); hub_initial_restarts=0
      docker() {
        printf 'docker mock call: %s\\n' "$*" >&2
        case "$*" in
          *"ps -aq --filter label=com.docker.compose.project=mock-worker"*)
            [[ "$MODE" == "lookup-failed" ]] && return 87
            [[ "$MODE" == "worker-appeared" ]] && printf 'rogue-worker\\n'
            return 0;;
          *"ps -aq --filter label=com.docker.compose.service=email-worker"*) return 0;;
          *"volume ls -q --filter label=com.docker.compose.project="*|*"network ls -q --filter label=com.docker.compose.project="*) return 0;;
          *"ps -aq --filter label=com.docker.compose.project=mock-hub"*)
            [[ "$MODE" == "hub-replaced" ]] && { printf 'wrong-hub\\n'; return 0; }
            printf '%s\\n' "$hub_id";;
          *"ps -aq --filter label=com.docker.compose.service=hub"*) printf '%s\\n' "$hub_id";;
          *"compose --project-name mock-hub -f mock-hub.yml ps -q hub"*) printf '%s\\n' "$hub_id";;
          *"inspect $hub_id"*)
            # Large valid JSON makes a non-draining mock consumer SIGPIPE under pipefail.
            printf '[%*s{}%*s]\\n' 65536 '' 65536 '';;
          *) printf 'unexpected docker mock invocation: %s\\n' "$*" >&2; return 87;;
        esac
      }
      jq() {
        printf 'jq mock mode=%s args=%s\\n' "$MODE" "$*" >&2
        # A real jq consumes the producer's stdin; drain it to avoid a false
        # pipefail/SIGPIPE from this mock when Docker writes a large inspect.
        if ! cat >/dev/null; then return 1; fi
        [[ "$MODE" != "hub-unhealthy" ]]
      }
      ${guard}
      if late_worker_context_guard; then exit 0; else exit 17; fi`;
    const result = spawnSync(bash, ["--noprofile", "--norc", "-c", script], {
      env: { PATH: "/usr/bin:/bin", MODE: mode }, encoding: "utf8", timeout: 5000
    });
    assert.ifError(result.error);
    assert.equal(result.status, expected, `${mode}: stdout=${result.stdout}; stderr=${result.stderr}`);
  }
});

testBash("worker late pre-up inspect predicate rejects mutated Docker fields with real jq", t => {
  const jq = spawnSync("jq", ["--version"], { encoding: "utf8", timeout: 5000 });
  if (jq.status !== 0) {
    // The pinned local WSL tooling has no jq binary and must not download one.
    // GitHub-hosted Ubuntu executes this mandatory semantic fixture with jq.
    if (process.env.CI === "true") assert.fail("hosted Linux guard fixture requires preinstalled jq");
    t.skip("jq is not installed in this offline WSL environment; control-flow mock still runs");
    return;
  }
  const start = runbook.indexOf("late_worker_context_guard() {");
  const end = runbook.indexOf("late_worker_context_guard || abort_worker", start);
  assert.ok(start > 0 && end > start);
  const guard = runbook.slice(start, end);
  const hubId = "a".repeat(64);
  const secretSentinel = "VIRKI_TEST_SECRET_SENTINEL=fixture-only-never-print";
  const valid = {
    Id: hubId,
    State: { Status: "running", Health: { Status: "healthy" } },
    HostConfig: { RestartPolicy: { Name: "no" }, NetworkMode: "mock-network" },
    RestartCount: 0,
    Config: { Image: "mock-image", Env: [secretSentinel], Labels: { "com.docker.compose.project": "mock-hub", "com.docker.compose.service": "hub" } },
    Image: "mock-image-id",
    NetworkSettings: { Networks: { "mock-network": { NetworkID: "mock-network-id" } } }
  };
  const cases = [
    ["valid", null, 0],
    ["replaced ID", c => { c.Id = "b".repeat(64); }, 17],
    ["stopped", c => { c.State.Status = "exited"; }, 17],
    ["unhealthy", c => { c.State.Health.Status = "unhealthy"; }, 17],
    ["restart policy", c => { c.HostConfig.RestartPolicy.Name = "always"; }, 17],
    ["restarted", c => { c.RestartCount = 1; }, 17],
    ["unexpected image ref", c => { c.Config.Image = "another-image"; }, 17],
    ["unexpected image ID", c => { c.Image = "another-id"; }, 17],
    ["wrong project", c => { c.Config.Labels["com.docker.compose.project"] = "other"; }, 17],
    ["wrong service", c => { c.Config.Labels["com.docker.compose.service"] = "other"; }, 17],
    ["extra network", c => { c.NetworkSettings.Networks.extra = { NetworkID: "extra-id" }; }, 17],
    ["network ID", c => { c.NetworkSettings.Networks["mock-network"].NetworkID = "other-id"; }, 17],
    ["network mode", c => { c.HostConfig.NetworkMode = "host"; }, 17],
    ["inspect missing", c => { delete c.State.Health; }, 17],
    ["inspect fails", null, 17]
  ];
  for (const [name, mutate, expected] of cases) {
    const fixture = structuredClone(valid);
    if (mutate) mutate(fixture);
    const script = `set -euo pipefail
      ctx=mock-context; project=mock-worker; hub_project=mock-hub; hub_file=mock-hub.yml
      network=mock-network; network_id=mock-network-id; hub_image=mock-image; hub_image_id=mock-image-id
      hub_id=$(printf 'a%.0s' {1..64}); hub_initial_restarts=0
      docker() {
        case "$*" in
          *"ps -aq --filter label=com.docker.compose.project=mock-worker"*|*"ps -aq --filter label=com.docker.compose.service=email-worker"*|*"volume ls -q"*|*"network ls -q"*) return 0;;
          *"ps -aq --filter label=com.docker.compose.project=mock-hub"*|*"ps -aq --filter label=com.docker.compose.service=hub"*|*"compose --project-name mock-hub -f mock-hub.yml ps -q hub"*) printf '%s\\n' "$hub_id";;
          *"inspect $hub_id"*)
            [[ "$MOCK_INSPECT_FAIL" == "yes" ]] && return 88
            printf '%s\\n' "$HUB_FIXTURE";;
          *) return 87;;
        esac
      }
      ${guard}
      if late_worker_context_guard; then exit 0; else exit 17; fi`;
    const result = spawnSync(bash, ["--noprofile", "--norc", "-c", script], {
      env: { PATH: process.env.PATH, HUB_FIXTURE: JSON.stringify([fixture]), MOCK_INSPECT_FAIL: name === "inspect fails" ? "yes" : "no" },
      encoding: "utf8", timeout: 5000
    });
    assert.ifError(result.error);
    assert.equal(result.status, expected, `${name}: ${result.stderr}`);
    const output = `${result.stdout}\n${result.stderr}`;
    assert.doesNotMatch(output, /DATABASE_URL|SECRET|PASSWORD/u, "inspect output must remain private");
    assert.ok(!output.includes(secretSentinel), "synthetic container environment must never be emitted");
  }
});

testBash("both negative SCRAM probes reject chmod and entropy errors inside an ||-guarded subshell", () => {
  const probes = [...runbook.matchAll(/remote_scram_probe\(\) \{([\s\S]*?)\n\}/gu)];
  assert.equal(probes.length, 2, "operator and rollback use separate probes");
  for (const match of probes) {
    for (const fault of ["chmod", "od"]) {
      const script = `set -euo pipefail
        umask 077
        service_dir="$(mktemp -d)"
        trap 'rm -rf -- "$service_dir"' EXIT
        VIRKI_STAGING_APPROVED_DB_HOST=db.example.test
        VIRKI_STAGING_APPROVED_DB_PORT=5432
        VIRKI_STAGING_APPROVED_DB_SERVER_ADDR=127.0.0.1
        staging_db_client_addr=127.0.0.1
        same_ip_address() { return 0; }
        psql() {
          if [[ "$*" == *"select 1"* ]]; then
            printf 'password authentication failed for user \\"virki_runtime\\"\\n' >&2
            return 3
          fi
          printf '127.0.0.1|5432|virki_stage|virki_runtime|virki_runtime|true|127.0.0.1\\n'
        }
        ${fault}() { return 33; }
        remote_scram_probe() {${match[1]}
        }
        if remote_scram_probe virki-staging-hub virki_stage virki_runtime; then
          exit 0
        else
          exit 17
        fi
      `;
      const result = spawnSync(bash, ["--noprofile", "--norc", "-c", script], { encoding: "utf8", timeout: 5000 });
      assert.ifError(result.error);
      assert.equal(result.status, 17, `${fault} failure must BLOCK both probes: ${result.stderr}`);
    }
  }
});

testBash("Hub Compose and runtime environment reject unexpected keys, duplicates and staging passkey opt-in", () => {
  const compose = runbook.slice(runbook.indexOf('if ! hub_config="$(docker'),
    runbook.indexOf("STAGING_HUB_ISOLATION_PREFLIGHT=PASS"));
  const runtime = runbook.slice(runbook.indexOf("if ! { printf '%s\\n' \"$hub_config\""),
    runbook.indexOf("STAGING_HUB_RUNTIME_ISOLATION=PASS"));
  assert.ok(runtime.length > 100, "runtime image, Compose and container inspection must be explicit");
  assert.match(compose, /hub_allowed_env_keys/u);
  assert.match(compose, /VIRKI_STAGING_PASSKEY_RP_ENABLED/u);
  assert.match(runtime, /\$allowed_env_keys/u);
  assert.match(runtime, /\$runtime_env_keys/u);
  assert.match(runtime, /VIRKI_STAGING_PASSKEY_RP_ENABLED/u);
  assert.match(runtime, /unique/u);
  assert.match(runtime, /docker --context "\$ctx" image inspect "\$hub_image"/u);
  assert.match(runtime, /\$compose_env \| to_entries/u);
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
          if [[ "$*" == *"image inspect"* ]]; then printf '%s\\n' "$MOCK_VOLUME"; return 0; fi
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
            if [[ "$MOCK_FAIL" == "id" ]]; then printf '%s\\n' '--help'; return 0; fi
            printf '%064d\\n' 0
            return 0
          fi
          if [[ "$*" == *" container inspect "* ]]; then
            nonce="$(cat "$MOCK_NONCE_FILE")"
            [[ "$MOCK_FAIL" != "label" ]] || nonce="not-the-current-inspection"
            if [[ "$*" == *"{{.Id}}|"* ]]; then
              printf '%064d|%s\\n' 0 "$nonce"
            else
              printf '%s\\n' "$nonce"
            fi
            return 0
          fi
          if [[ "$*" == *" cp "* ]]; then
            [[ "$MOCK_FAIL" != "cp" ]] || return 8
            cat "$MOCK_TAR"
            return 0
          fi
          if [[ "$*" == *" rm --force "* ]]; then
            [[ "$MOCK_FAIL" != "rm" ]] || return 8
            : > "$MOCK_CREATED"
            return 0
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
      const mockDockerBody = shell.split("docker() {")[1]?.split("\n        verify_staging_prisma_image_ca()")[0];
      assert.ok(mockDockerBody, "the disposable Docker mock must remain present");
      assert.doesNotMatch(mockDockerBody, /\breturn(?=\s*(?:;|\n|\}))/u,
        "successful mock branches require explicit return 0, including during EXIT cleanup");
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
