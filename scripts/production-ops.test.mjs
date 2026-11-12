import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import "./production-migration-guard.test.mjs";
import { fileURLToPath } from "node:url";
import { deployProduction } from "./deploy-production.mjs";
import { isValidProductionConfig } from "./lib/production-config.mjs";
import { DOCKER_SCRIPT, runAcceptedProductionPreflight, runProductionPreflight } from "./production-preflight.mjs";

const revision = "0123456789abcdef0123456789abcdef01234567";
const linuxKernelRelease = process.platform === "linux"
  ? readFileSync("/proc/sys/kernel/osrelease", "utf8").toLowerCase()
  : "";
const makeEvidence = (data = provenanceFixture, type = "file") => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "virki-test-image-evidence-"));
  const contents = path.join(directory, "contents");
  mkdirSync(contents);
  const file = path.join(contents, "virki-production-images.manifest");
  if (type === "directory") mkdirSync(file);
  else if (type === "symlink") symlinkSync(secretScannerPath, file);
  else writeFileSync(file, data);
  return { directory, contents, file };
};

const provenanceFixture = `revision=${revision}\nrun_id=54321\nplatform=linux/amd64\nruntime_digest=sha256:${"a".repeat(64)}\nmigrator_digest=sha256:${"b".repeat(64)}\n`;
const nativeLinuxHostSkip = process.platform !== "linux"
  ? "Requires a Linux shell."
  : /microsoft|wsl/u.test(linuxKernelRelease)
    ? "Production host checks reject WSL kernels; native Linux is required."
    : false;
const config = {
  sshAlias: "test-production",
  host: "production.example.invalid",
  port: "2222",
  root: "/srv/virki",
};
const preflightScript = readFileSync(new URL("./production-preflight.mjs", import.meta.url), "utf8");
const serverScript = readFileSync(new URL("./production-server.sh", import.meta.url), "utf8");
const migrationRunnerSource = readFileSync(new URL("../packages/database/scripts/prisma-migrate.mjs", import.meta.url), "utf8");
const migrationRunnerPath = fileURLToPath(new URL("../packages/database/scripts/prisma-migrate.mjs", import.meta.url));
const deploymentScript = readFileSync(new URL("./deploy-production.mjs", import.meta.url), "utf8");
const backupRestoreScript = readFileSync(new URL("./backup-restore-validation.mjs", import.meta.url), "utf8");
const secretScannerPath = fileURLToPath(new URL("./secret-scan.mjs", import.meta.url));
const secretScannerSource = readFileSync(secretScannerPath, "utf8");
const isSecretScanCommand = (command, args) => command === process.execPath && path.basename(args[0] ?? "") === "secret-scan.mjs" && args[1] === "--revision";

test("native Linux preflight requires eight stable probes, the marker, and Docker", async () => {
  let remoteCalls = 0;
  const result = await runProductionPreflight({
    config,
    sleep: async () => {},
    execute: (command, args, options) => {
      assert.equal(command, "ssh");
      if (args[0] === "-G") {
        return { status: 0, stdout: `user deploy\nhostname ${config.host}\nport ${config.port}\n` };
      }
      remoteCalls += 1;
      assert.ok(args.at(-1).startsWith("bash -s -- "));
      if (remoteCalls <= 8) {
        assert.ok(options.input.includes("protocol=2"));
        assert.ok(options.input.includes("*microsoft*"));
        return { status: 0, stdout: "VIRKI_PROBE_ID=host\nVIRKI_PROBE_WD=/srv/virki\nVIRKI_PROBE_PLATFORM=linux-native\nVIRKI_PROBE_MARKER=valid\n" };
      }
      return { status: 0, stdout: "VIRKI_DOCKER_VERSION=29\nVIRKI_DOCKER_INFO=29\nVIRKI_COMPOSE_VERSION=2\nVIRKI_PLATFORM=linux/amd64\nVIRKI_FLOCK=available\nVIRKI_DISK_FREE_GB=100\nVIRKI_DEMANAGE_COUNT=2\n" };
    },
  });

  assert.equal(result.status, 0);
  assert.equal(result.platform, "linux/amd64");
  assert.equal(remoteCalls, 9);
  assert.ok(result.lines.some((line) => line.includes("8/8")));
  assert.ok(result.lines.every((line) => !line.includes(config.host)));
  assert.equal(isValidProductionConfig({ ...config, root: "C:\\Virki" }), false);
});

test("Docker preflight fails closed when container-name visibility is unavailable", { skip: process.platform !== "linux" }, () => {
  const temporaryDirectory = mkdtempSync(path.join(os.tmpdir(), "virki-docker-preflight-"));
  const binDirectory = path.join(temporaryDirectory, "bin");
  const root = path.join(temporaryDirectory, "root");
  try {
    mkdirSync(binDirectory);
    mkdirSync(root);
    const docker = path.join(binDirectory, "docker");
    writeFileSync(docker, `#!/bin/sh
if [ "$1" = version ]; then printf '29.8.1\\n'; exit 0; fi
if [ "$1" = compose ]; then printf '5.5.1\\n'; exit 0; fi
if [ "$1" = info ]; then
  case "$3" in
    '{{.ServerVersion}}') printf '29.8.1\\n' ;;
    '{{.OSType}}') printf 'linux\\n' ;;
    '{{.Architecture}}') printf 'x86_64\\n' ;;
    *) exit 2 ;;
  esac
  exit 0
fi
if [ "$1" = ps ]; then exit 42; fi
exit 2
`);
    chmodSync(docker, 0o700);

    const result = spawnSync("bash", ["-s", "--", "docker", root], {
      encoding: "utf8",
      input: DOCKER_SCRIPT,
      env: { ...process.env, PATH: `${binDirectory}${path.delimiter}${process.env.PATH ?? ""}` },
    });

    assert.notEqual(result.status, 0);
    assert.doesNotMatch(result.stdout ?? "", /VIRKI_DEMANAGE_COUNT=0/u);
  } finally {
    rmSync(temporaryDirectory, { recursive: true, force: true });
  }
});

test("standalone preflight binds host contact to the exact accepted source gate", async () => {
  const calls = [];
  const result = await runAcceptedProductionPreflight({
    config,
    sourceExecute: () => ({ status: 0, stdout: "" }),
    inspectSource: ({ repositoryRoot }) => {
      calls.push("source");
      assert.equal(path.isAbsolute(repositoryRoot), true);
      assert.equal(existsSync(path.join(repositoryRoot, "package.json")), true);
      return { branch: "main", revision };
    },
    verifyCi: ({ revision: observed }) => {
      calls.push("gate:" + observed);
      return { ok: true, lines: ["exact static-analysis gate passed"] };
    },
    preflight: async ({ config: observed }) => {
      calls.push("preflight");
      assert.deepEqual(observed, config);
      return { status: 0, lines: ["native host checks passed"] };
    }
  });
  assert.deepEqual(calls, ["source", "gate:" + revision, "preflight"]);
  assert.equal(result.status, 0);
  assert.deepEqual(result.lines, ["exact static-analysis gate passed", "native host checks passed"]);
});

test("standalone preflight blocks before SSH when exact-SHA release evidence is unavailable", async () => {
  let preflightCalls = 0;
  const result = await runAcceptedProductionPreflight({
    config,
    inspectSource: () => ({ branch: "main", revision }),
    verifyCi: () => ({ ok: false, lines: ["exact-SHA SARIF evidence unavailable"] }),
    preflight: async () => {
      preflightCalls += 1;
      return { status: 0, lines: [] };
    }
  });
  assert.equal(result.status, 1);
  assert.deepEqual(result.lines, ["exact-SHA SARIF evidence unavailable"]);
  assert.equal(preflightCalls, 0);
});

test("preflight stops at a missing native host marker without trying Docker", async () => {
  let remoteCalls = 0;
  const result = await runProductionPreflight({
    config,
    sleep: async () => {},
    execute: (command, args) => {
      if (args[0] === "-G") return { status: 0, stdout: `user deploy\nhostname ${config.host}\nport ${config.port}\n` };
      remoteCalls += 1;
      return { status: 1, stdout: "VIRKI_PROBE_FAILURE=MARKER_METADATA_INVALID\n" };
    },
  });
  assert.equal(result.status, 1);
  assert.equal(remoteCalls, 1);
  assert.ok(result.lines[0].includes("production host marker is missing or has unsafe metadata"));
});

test("preflight reports a sanitized remote host-check category", async () => {
  const result = await runProductionPreflight({
    config,
    sleep: async () => {},
    execute: (command, args) => {
      if (args[0] === "-G") return { status: 0, stdout: `user deploy\nhostname ${config.host}\nport ${config.port}\n` };
      return {
        status: 1,
        stdout: "VIRKI_PROBE_FAILURE=PROTECTED_ENV_METADATA_INVALID:.env\n",
        stderr: "private-value=must-not-be-returned",
      };
    },
  });

  assert.equal(result.status, 1);
  assert.deepEqual(result.lines, ["SSH preflight failed on probe 1; protected production environment file .env has unsafe ownership or permissions."]);
  assert.doesNotMatch(result.lines.join(" "), /private-value|must-not-be-returned/u);
});

test("preflight treats inherited remote category names as unknown", async () => {
  const result = await runProductionPreflight({
    config,
    sleep: async () => {},
    execute: (command, args) => {
      if (args[0] === "-G") return { status: 0, stdout: `user deploy\nhostname ${config.host}\nport ${config.port}\n` };
      return { status: 1, stdout: "VIRKI_PROBE_FAILURE=toString\n", stderr: "" };
    },
  });

  assert.equal(result.status, 1);
  assert.deepEqual(result.lines, ["SSH preflight failed on probe 1; SSH transport or remote probe did not return a verifiable result."]);
});

test("preflight identifies strict host-key rejection without returning SSH diagnostics", async () => {
  const result = await runProductionPreflight({
    config,
    sleep: async () => {},
    execute: (command, args) => {
      if (args[0] === "-G") return { status: 0, stdout: `user deploy\nhostname ${config.host}\nport ${config.port}\n` };
      return { status: 255, stdout: "", stderr: "Host key verification failed. private-value=must-not-be-returned" };
    },
  });

  assert.equal(result.status, 1);
  assert.deepEqual(result.lines, ["SSH preflight failed on probe 1; strict host-key verification rejected the SSH target."]);
  assert.doesNotMatch(result.lines.join(" "), /private-value|must-not-be-returned/u);
});

test("native shell probe emits the sanitized protected environment metadata category", { skip: nativeLinuxHostSkip }, async () => {
  const temporaryDirectory = mkdtempSync(path.join(os.tmpdir(), "virki-native-probe-"));
  const root = path.join(temporaryDirectory, "root");
  try {
    mkdirSync(root, { mode: 0o700 });
    for (const name of [".deploy-tmp", "releases", "backups"]) mkdirSync(path.join(root, name), { mode: 0o700 });
    const hostname = spawnSync("hostname", ["-s"], { encoding: "utf8" }).stdout.trim();
    const marker = path.join(root, ".virki-production-host");
    writeFileSync(marker, `role=production\nprotocol=2\nhostname=${hostname}\npath=${root}\n`, { mode: 0o600 });
    chmodSync(marker, 0o600);
    for (const name of [".env", ".env.oidc", ".env.oidc-data", ".ghcr-read-token"]) {
      const file = path.join(root, name);
      writeFileSync(file, "placeholder=must-not-be-returned\n", { mode: name === ".env.oidc-data" ? 0o644 : 0o600 });
      chmodSync(file, name === ".env.oidc-data" ? 0o644 : 0o600);
    }

    const runProbe = () => runProductionPreflight({
      config: { ...config, root },
      sleep: async () => {},
      execute: (command, args, options = {}) => {
        if (args[0] === "-G") return { status: 0, stdout: `user deploy\nhostname ${config.host}\nport ${config.port}\n` };
        const probe = spawnSync("bash", ["-s", "--", "probe", root], { encoding: "utf8", input: options.input });
        return { status: Number.isInteger(probe.status) ? probe.status : 1, stdout: probe.stdout ?? "", stderr: probe.stderr ?? "" };
      },
    });

    const unsafeMetadata = await runProbe();
    assert.equal(unsafeMetadata.status, 1);
    assert.deepEqual(unsafeMetadata.lines, ["SSH preflight failed on probe 1; protected production environment file .env.oidc-data has unsafe ownership or permissions."]);
    assert.doesNotMatch(unsafeMetadata.lines.join(" "), /placeholder|must-not-be-returned/u);

    rmSync(path.join(root, ".env.oidc-data"));
    const missingFile = await runProbe();
    assert.equal(missingFile.status, 1);
    assert.deepEqual(missingFile.lines, ["SSH preflight failed on probe 1; protected production environment file .env.oidc-data is missing or is not a regular file."]);
    assert.doesNotMatch(missingFile.lines.join(" "), /placeholder|must-not-be-returned/u);
  } finally {
    rmSync(temporaryDirectory, { recursive: true, force: true });
  }
});

test("preflight fails closed when the host cannot serialize state-changing operations", async () => {
  let remoteCalls = 0;
  const result = await runProductionPreflight({
    config,
    sleep: async () => {},
    execute: (command, args) => {
      if (args[0] === "-G") return { status: 0, stdout: `user deploy\nhostname ${config.host}\nport ${config.port}\n` };
      remoteCalls += 1;
      if (remoteCalls <= 8) {
        return { status: 0, stdout: "VIRKI_PROBE_ID=host\nVIRKI_PROBE_WD=/srv/virki\nVIRKI_PROBE_PLATFORM=linux-native\nVIRKI_PROBE_MARKER=valid\n" };
      }
      return { status: 0, stdout: "VIRKI_DOCKER_VERSION=29\nVIRKI_DOCKER_INFO=29\nVIRKI_COMPOSE_VERSION=2\nVIRKI_PLATFORM=linux/amd64\nVIRKI_DISK_FREE_GB=100\nVIRKI_DEMANAGE_COUNT=2\n" };
    },
  });
  assert.equal(result.status, 1);
  assert.equal(remoteCalls, 9);
  assert.ok(result.lines.at(-1).includes("locking"));
});

test("Linux source lifecycle keeps host identity pre-provisioned and secrets remote-only", () => {
  assert.match(serverScript, /grep -Fxq 'protocol=2' "\$marker_path"/u);
  assert.doesNotMatch(serverScript, /printf .{0,100}role=production.{0,100}protocol=2|Set-Content.*virki-production-host/u);
  assert.match(serverScript, /ln -s "\$root\/.env" "\$stage\/.env"/u);
  assert.match(serverScript, /ln -s "\$root\/.env\.oidc" "\$stage\/.env\.oidc"/u);
  assert.match(serverScript, /ln -s "\$root\/.env\.oidc-data" "\$stage\/.env\.oidc-data"/u);
  assert.match(preflightScript, /for name in .env .env\.oidc .env\.oidc-data/u);
  assert.match(serverScript, /Remote production secret files are missing or have unsafe permissions/u);
  assert.match(serverScript, /run_clone_migrations/u);
  assert.match(serverScript, /source_dir=\$release/u);
  assert.match(serverScript, /assert_active_source/u);
  assert.match(serverScript, /activate_source/u);
  assert.match(serverScript, /compose up --detach --force-recreate "\$\{application_services\[@\]\}"/u);
  assert.match(serverScript, /prisma:migrate:status --workspace @virki\/database/u);
  assert.match(serverScript, /encrypted recovery outbox payload or delivery-attempt metadata/u);
  assert.match(serverScript, /docker rm --force --volumes "\$container_id"/u);
  assert.doesNotMatch(serverScript.replace(/^cleanup_clone\(\) \{[\s\S]*?^\}/mu, ""), /\bcompose[^\n]*\bdown\b|docker volume (?:rm|prune)|docker system prune|prisma db push|powershell/i);
  assert.match(serverScript, /readonly lock_path="\$root\/\.virki-operations\.lock"/u);
  assert.match(serverScript, /flock -n "\$state_lock_fd"/u);
  assert.match(serverScript, /state_changing_actions='[^']*install-source cleanup-deploy-staging first-install first-install-recovery first-admin-rescue-prepare first-admin-rescue stage first-admin-bootstrap deploy start restart start-tunnel stop maintenance-on maintenance-off backup-verify audit-cleanup sessions-cleanup/u);
  assert.match(serverScript, /tar --list --verbose --quoting-style=c --file "\$archive"/u);
  assert.match(serverScript, /local role_script="\$release\/infra\/postgres-init\/10-virki-database-roles\.sh"[\s\S]*?chmod 644 -- "\$role_script"[\s\S]*?stat -c '%a' -- "\$role_script"/u);
  assert.match(serverScript, /Source archive contains a link or unsupported filesystem entry/u);
  assert.match(serverScript, /find "\$stage" -type l -print -quit/u);
  assert.match(serverScript, /current .virki-release .virki-production-host/u);
  const cleanupDispatch = serverScript.indexOf('if [[ "$action" == cleanup-deploy-staging ]]; then');
  assert.ok(cleanupDispatch >= 0);
  assert.match(serverScript.slice(cleanupDispatch), /verify_cleanup_target \|\| fail[\s\S]*?acquire_state_lock[\s\S]*?cleanup_deploy_staging "\$revision" "\$archive_id"/u);
  const dispatch = serverScript.indexOf('if [[ "$action" == first-install ]]; then\n  trap \'cleanup_failed_first_install "$?"\' EXIT\nelif [[ "$action" == install-source || "$action" == deploy ]]; then\n  trap \'cleanup_failed_deploy "$?"\' EXIT\nfi');
  assert.ok(dispatch >= 0);
  assert.ok(serverScript.slice(dispatch).includes([
    'if [[ "$action" == first-install ]]; then',
    '  trap \'cleanup_failed_first_install "$?"\' EXIT',
    'elif [[ "$action" == install-source || "$action" == deploy ]]; then',
    '  trap \'cleanup_failed_deploy "$?"\' EXIT',
    "fi",
    "verify_host",
  ].join("\n")));
  const stateLock = serverScript.indexOf('if [[ "$state_changing_actions" == *" $action "* ]]; then acquire_state_lock; fi', dispatch);
  const stagingCleanup = serverScript.slice(serverScript.indexOf("cleanup_deploy_staging() {"), serverScript.indexOf("\ncleanup_failed_deploy() {"));
  assert.match(stagingCleanup, /source-\$expected_revision-\$staging_id\.tar[\s\S]*?images-\$expected_revision-\$staging_id\.manifest[\s\S]*?\[\[ -f "\$path" && ! -L "\$path" \]\][\s\S]*?\(\(cleanup_failed == 0\)\)/u);
  assert.match(serverScript, /cleanup_failed_deploy\(\)[\s\S]*?cleanup_deploy_staging "\$revision" "\$archive_id"[\s\S]*?Deployment staging cleanup could not be confirmed/u);
  assert.match(serverScript, /if \[\[ "\$action" == cleanup-deploy-staging \]\]; then[\s\S]*?cleanup_deploy_staging "\$revision" "\$archive_id"/u);
  assert.match(deploymentScript, /cleanupAfterFailure\(error, source\.revision, archiveId, sourceCode, config, execute\)/u);
  assert.equal((deploymentScript.match(/cleanupAfterFailure\(error, source\.revision, archiveId, sourceCode, config, execute\)/gu) ?? []).length, 2);
  const deployStage = serverScript.indexOf('if [[ "$action" == deploy || "$action" == first-install || "$action" == first-install-recovery ]]; then\n  if [[ "$action" == first-install ]]; then verify_fresh_install_target; fi\n  if [[ "$action" == first-install-recovery ]]; then verify_first_install_recovery_target; fi\n  load_production_images\n  install_source\nfi', stateLock);
  const imageValidation = serverScript.indexOf("load_production_images", deployStage);
  const sourceInstall = serverScript.indexOf("install_source", imageValidation);
  const acceptedRevision = serverScript.indexOf("verify_revision", deployStage);
  const backupValidation = serverScript.indexOf("create_verified_backup", acceptedRevision);
  const verifyHost = serverScript.indexOf("verify_host", dispatch);
  assert.ok(dispatch < verifyHost && verifyHost < stateLock && stateLock < deployStage && deployStage < imageValidation && imageValidation < sourceInstall && sourceInstall < acceptedRevision && acceptedRevision < backupValidation);
  assert.match(preflightScript, /command -v flock/u);
  assert.doesNotMatch(preflightScript, /New-Item|Set-Content|writeFileSync|mkdir -p/u);
  assert.match(preflightScript, /stat -c '%u' -- "\$file".*id -u/u);
  assert.match(preflightScript, /stat -c '%a' -- "\$root".*700/u);
  assert.match(preflightScript, /stat -c '%a' -- "\$marker".*600/u);
});

test("native Linux role initialization scripts remain LF-only after Windows checkout", () => {
  const attributes = readFileSync(new URL("../.gitattributes", import.meta.url), "utf8");
  assert.match(attributes, /^\*\.sh text eol=lf$/mu);
  for (const relative of [
    "../infra/postgres-init/10-virki-database-roles.sh",
    "./e2e/20-virki-e2e-runtime-test-role.sh",
    "./production-server.sh",
  ]) {
    const source = readFileSync(new URL(relative, import.meta.url), "utf8");
    assert.ok(source.startsWith("#!"), `${relative} needs an executable shebang`);
    assert.ok(!source.includes("\r"), `${relative} cannot contain CRLF for Docker/Linux execution`);
  }
});

test("private GHCR transport requires CI-run-bound exact digests and isolates the pull credential", () => {
  const transport = serverScript.slice(serverScript.indexOf("verify_image_manifest() {"), serverScript.indexOf("\ncompose_args() {"));
  assert.match(transport, /sha256sum[\s\S]*?\$image_hash/u);
  assert.match(transport, /run_id=\[1-9\]/u);
  assert.ok(transport.includes("^runtime_digest=sha256:[0-9a-f]{64}$"));
  assert.ok(transport.includes("^migrator_digest=sha256:[0-9a-f]{64}$"));
  assert.match(transport, /\.ghcr-read-token[\s\S]*?stat -c '%a'[\s\S]*?== 600/u);
  assert.match(transport, /mktemp -d[\s\S]*?DOCKER_CONFIG[\s\S]*?--password-stdin < "\$token"/u);
  assert.match(transport, /docker pull "\$image@\$digest"/u);
  assert.match(transport, /org\.opencontainers\.image\.revision[\s\S]*?org\.opencontainers\.image\.source/u);
  assert.match(transport, /docker image tag "ghcr\.io\/bielxdh3\/virki-runtime@[\s\S]*?" "virki-production-ci:/u);
  assert.match(transport, /docker image tag "ghcr\.io\/bielxdh3\/virki-migrator@[\s\S]*?" "virki-migrator-ci:/u);
  assert.doesNotMatch(transport, /docker build|docker load|--password=|docker system prune/u);
  assert.match(preflightScript, /for name in \.env \.env\.oidc \.env\.oidc-data \.ghcr-read-token/u);
});

test("backup verification isolates its EXIT cleanup trap from the production maintenance trap", () => {
  const backup = serverScript.slice(serverScript.indexOf("create_verified_backup() {"), serverScript.indexOf("\nrun_first_install_recovery_clone_migrations() {"));
  assert.match(backup, /create_verified_backup\(\) \{\n(?:[ ]{2}#[^\n]*\n)*[ ]{2}\(\n/u);
  assert.match(backup, /trap - EXIT[\s\S]*?\n[ ]{2}\)\n\}/u);
  assert.match(serverScript, /[ ]{2}deploy\)\n[\s\S]*?maintenance_on\n[ ]{4}create_verified_backup\n[ ]{4}apply_production_migrations/u);
});

test("first install tolerates its own staged revision without allowing unrelated releases", () => {
  const check = serverScript.slice(serverScript.indexOf("verify_fresh_install_target() {"), serverScript.indexOf("\nverify_empty_first_install_recovery_database() {"));
  assert.match(check, /"\$source_marker_present" == true && "\$entry" == "\$release_dir\/\$revision" && -d "\$entry" && ! -L "\$entry"/u);
  assert.match(check, /\[\[ "\$source_marker_present" == false \]\] \|\| verify_revision/u);
});

test("first-install recovery recognizes the extension provisioned before Prisma migration", () => {
  const recoveryStart = serverScript.indexOf("verify_empty_first_install_recovery_database() {");
  assert.ok(recoveryStart >= 0);
  const recoveryEnd = serverScript.indexOf("\nverify_first_install_recovery_has_no_application_rows() {", recoveryStart);
  const recovery = serverScript.slice(recoveryStart, recoveryEnd);
  assert.match(recovery, /extname NOT IN \('plpgsql', 'pgcrypto'\)/u);
  assert.match(recovery, /WHEN NOT EXISTS \([\s\S]*?namespace\.nspname = 'public'[\s\S]*?THEN 'empty-partial'/u);
});

test("audit maintenance is restricted to the protected cleanup function and configured policy", () => {
  const roleInitializer = readFileSync(new URL("../infra/postgres-init/10-virki-database-roles.sh", import.meta.url), "utf8");
  const migration = readFileSync(new URL("../packages/database/prisma/migrations/20261019120000_runtime_audit_write_boundary/migration.sql", import.meta.url), "utf8");
  const compose = readFileSync(new URL("../infra/docker-compose.prod.yml", import.meta.url), "utf8");
  const contractStart = serverScript.indexOf("verify_first_install_role_contract() {");
  const contractEnd = serverScript.indexOf("\napply_first_install_database_roles() {", contractStart);
  const contract = serverScript.slice(contractStart, contractEnd);
  const recoveryStart = serverScript.indexOf("verify_empty_first_install_recovery_database() {");
  const recoveryEnd = serverScript.indexOf("\nverify_first_install_recovery_has_no_application_rows() {", recoveryStart);
  const recovery = serverScript.slice(recoveryStart, recoveryEnd);

  assert.match(roleInitializer, /AUDIT_LOG_RETENTION_DAYS=\$\{AUDIT_LOG_RETENTION_DAYS:-180\}/u);
  assert.match(roleInitializer, /CREATE TABLE IF NOT EXISTS virki_security\.audit_retention_policy/u);
  assert.match(roleInitializer, /ON CONFLICT \(singleton\) DO UPDATE SET retention_days = EXCLUDED\.retention_days/u);
  assert.doesNotMatch(roleInitializer, /GRANT INSERT \([^\n]*\) ON TABLE public\."AuditLog" TO virki_audit_maintenance/u);
  assert.match(migration, /CREATE OR REPLACE FUNCTION virki_security\.delete_expired_audit_logs\(\)/u);
  assert.match(migration, /FROM virki_security\.audit_retention_policy/u);
  assert.match(migration, /AUTH_AUDIT_LOG_CLEANUP/u);
  assert.match(compose, /AUDIT_LOG_RETENTION_DAYS: \$\{AUDIT_LOG_RETENTION_DAYS:-180\}/u);
  assert.match(compose, /MIGRATION_DATABASE_URL:[\s\S]*?AUDIT_LOG_RETENTION_DAYS: \$\{AUDIT_LOG_RETENTION_DAYS:-180\}/u);
  assert.match(migrationRunnerSource, /readAuditRetentionDays\(process\.env\.AUDIT_LOG_RETENTION_DAYS\)/u);
  assert.match(migrationRunnerSource, /command === "deploy" && exitCode === 0[\s\S]*?SET retention_days = \$\{auditRetentionDays\}[\s\S]*?Virki audit retention policy could not be reconciled/u);
  assert.match(contract, /NOT has_any_column_privilege\('virki_audit_maintenance', 'public\.\\"AuditLog\\"', 'INSERT'\)/u);
  assert.match(contract, /retention_days = \$audit_retention_days/u);
  assert.match(serverScript, /configured_audit_retention_days\(\)[\s\S]*?AUDIT_LOG_RETENTION_DAYS[\s\S]*?retention_days >= 1 && retention_days <= 3650/u);
  assert.match(contract, /delete_expired_audit_logs\(\)'/u);
  assert.match(recovery, /policy\.relname = 'audit_retention_policy'/u);
  assert.match(recovery, /routine\.proconfig IS DISTINCT FROM ARRAY\['search_path=pg_catalog'\]/u);
});

test("GHCR temporary Docker configuration cleanup removes generated subdirectories", () => {
  const pull = serverScript.slice(serverScript.indexOf("load_production_images() {"), serverScript.indexOf("\ncompose_args() {"));
  assert.match(pull, /trap 'rm -rf -- "\$auth_dir"' EXIT/u);
});

test("disposable backup-restore validation uses its own source directory and aborts on restore errors", () => {
  assert.match(backupRestoreScript, /fileURLToPath\(import\.meta\.url\)/u);
  assert.doesNotMatch(backupRestoreScript, /repositoryRoot = process\.cwd\(\)/u);
  assert.match(backupRestoreScript, /"pg_restore", "--exit-on-error", "--clean"/u);
});

test("archive path screening normalizes Windows separators before every sensitive check", () => {
  const check = deploymentScript.slice(deploymentScript.indexOf("function isSensitiveArchivePath(entry) {"), deploymentScript.indexOf("\nfunction requireSuccess("));
  assert.match(check, /const segments = normalizedEntry\.split\("\/"\)/u);
  assert.doesNotMatch(check, /\.test\(entry\)/u);
});

test("issuer discovery health checks do not mistake JSON response bodies for HTTP headers", () => {
  const check = serverScript.slice(serverScript.indexOf("assert_production_response_headers() {"), serverScript.indexOf("\ndatabase_query() {"));
  assert.match(check, /headers=\$\{headers%%\$'\\r\\n\\r\\n'\*\}/u);
  assert.match(check, /headers=\$\{headers%%\$'\\n\\n'\*\}/u);
});

test("first install requires an empty isolated Virki target and leaves legacy and Tunnel state untouched", () => {
  const firstInstall = serverScript.slice(serverScript.indexOf("  first-install)\n"), serverScript.indexOf("  stage)\n"));
  assert.match(serverScript, /verify_fresh_install_target\(\)[\s\S]*?current_link[\s\S]*?first_install_path[\s\S]*?project_containers[\s\S]*?project_volumes[\s\S]*?project_networks/u);
  assert.match(serverScript, /first_install_volume='virki-prod_virki_postgres_data'/u);
  assert.match(firstInstall, /compose up --detach postgres/u);
  assert.match(firstInstall, /compose --profile migration run --rm --no-deps migrate/u);
  assert.match(firstInstall, /run_migration_status[\s\S]*?verify_migration_schema[\s\S]*?verify_first_install_role_contract/u);
  assert.match(firstInstall, /activate_source[\s\S]*?write_first_install_marker/u);
  assert.doesNotMatch(firstInstall, /maintenance_on|create_verified_backup|cloudflared/u);
  assert.match(serverScript, /cleanup_failed_first_install\(\)[\s\S]*?compose stop postgres[\s\S]*?new Virki database volume was preserved/u);
  assert.match(serverScript, /Virki staging requires its Cloudflare Tunnel connector to remain stopped/u);
});

test("first install reconciles roles and proves migrator TCP login before Prisma migrations", () => {
  const firstInstall = serverScript.slice(serverScript.indexOf("  first-install)\n"), serverScript.indexOf("  first-install-recovery)\n"));
  const probe = serverScript.slice(serverScript.indexOf("migrator_network_authentication_result() {"), serverScript.indexOf("\nreport_first_install_migrator_pre_reconcile_state() {"));
  assert.match(firstInstall, /apply_first_install_database_roles[\s\S]*?verify_migrator_tcp_authentication[\s\S]*?compose --profile migration run --rm --no-deps migrate/u);
  assert.match(probe, /compose --profile migration run --rm --no-deps --entrypoint node migrate --input-type=module/u);
  assert.match(probe, /MIGRATION_DATABASE_URL[\s\S]*?SELECT current_user AS role/u);
  assert.match(probe, /url\.hostname !== "postgres"[\s\S]*?url\.port !== "5432"[\s\S]*?url\.pathname !== "\/virki"/u);
  assert.match(probe, /current_database\(\) AS database[\s\S]*?rows\[0\]\.database === "virki"/u);
  assert.match(probe, /AUTH=FAIL:TARGET_MISMATCH/u);
  assert.match(serverScript, /\[\[ "\$result" == AUTH=PASS \]\]/u);
  assert.doesNotMatch(probe, /127\.0\.0\.1|PGPASSWORD/u);
});

test("partial first-install recovery is typed, exact-resource-only, and checkpointed", () => {
  const recovery = serverScript.slice(serverScript.indexOf("  first-install-recovery)\n"), serverScript.indexOf("  stage)\n"));
  const guard = serverScript.slice(serverScript.indexOf("verify_first_install_recovery_target() {"), serverScript.indexOf("\nverify_first_install_marker() {"));
  const projectGuard = serverScript.slice(serverScript.indexOf("verify_first_install_recovery_project() {"), serverScript.indexOf("\nverify_first_install_recovery_release() {"));
  const databaseGuard = serverScript.slice(serverScript.indexOf("verify_empty_first_install_recovery_database() {"), serverScript.indexOf("\nverify_first_install_recovery_has_no_application_rows() {"));
  const backup = serverScript.slice(serverScript.indexOf("create_first_install_recovery_backup() {"), serverScript.indexOf("\nassert_backup_verified() {"));
  assert.match(serverScript, /allowed_actions='[^']*first-install-recovery/u);
  assert.match(serverScript, /state_changing_actions='[^']*first-install-recovery/u);
  assert.match(guard, /exact retained partial-install source markers/u);
  assert.match(guard, /completion marker already exists/u);
  assert.match(guard, /unexpected hidden entry/u);
  assert.match(guard, /phase=\(prepared\|database-verified\)/u);
  assert.match(guard, /verify_first_install_recovery_project "\$recovery_prior_revision" "\$revision"[\s\S]*?verify_source_archive[\s\S]*?verify_image_manifest[\s\S]*?write_first_install_recovery_marker prepared/u);
  assert.match(guard, /\[\[ "\$current_target" == "\$release_dir\/\$revision" \]\]/u);
  assert.match(guard, /current\)[\s\S]*?\[\[ "\$progress_present" == true && "\$accepted_release_present" == true \]\]/u);
  assert.match(serverScript, /first_install_volume='virki-prod_virki_postgres_data'/u);
  assert.match(projectGuard, /com\.docker\.compose\.project[\s\S]*?\$first_install_volume[\s\S]*?another container uses the Virki network/u);
  assert.match(databaseGuard, /current_database\(\) <> 'virki'[\s\S]*?datname NOT IN[\s\S]*?migrated-candidate/u);
  assert.match(serverScript, /has_column_privilege[\s\S]*?createdAt[\s\S]*?virki_audit_log_created_at_guard[\s\S]*?timestamp_policy/u);
  assert.match(serverScript, /runtime_test\.rolname = 'virki_runtime_test'[\s\S]*?has_function_privilege\(runtime_test\.oid/u);
  assert.match(databaseGuard, /routine\.proname NOT IN \('delete_expired_audit_logs', 'enforce_audit_log_timestamp'\)[\s\S]*?routine\.prosecdef OR pg_get_function_result\(routine\.oid\) IS DISTINCT FROM 'trigger'[\s\S]*?CASE WHEN to_regclass\('public\."AuditLog"'\) IS NULL THEN 0 ELSE 2 END/u);
  assert.match(databaseGuard, /virki_audit_log_created_at_guard[\s\S]*?tgfoid = 'virki_security\.enforce_audit_log_timestamp\(\)'::regprocedure/u);
  assert.match(recovery, /elif \[\[ "\$recovery_database_state" == migrated-candidate \]\]; then[\s\S]*?assert_backup_verified[\s\S]*?Recovery found migrations applied before the prior checkpoint/u);
  assert.match(recovery, /apply_first_install_database_roles[\s\S]*?verify_migrator_tcp_authentication[\s\S]*?if \[\[ "\$recovery_database_state" == empty-partial \]\]; then[\s\S]*?compose --profile migration run/u);
  assert.match(recovery, /verify_empty_first_install_recovery_database[\s\S]*?report_first_install_migrator_pre_reconcile_state[\s\S]*?apply_first_install_database_roles/u);
  assert.match(recovery, /verify_first_install_recovery_has_no_application_rows[\s\S]*?write_first_install_recovery_marker database-verified/u);
  assert.match(backup, /pg_dump[^\n]*--format=custom[\s\S]*?docker network create --internal[\s\S]*?pg_restore --exit-on-error/u);
  assert.doesNotMatch(recovery + backup, /docker volume rm|docker volume prune|compose (?:down|rm)|--volumes/u);
});

test("first-install recovery is a main-SHA CI-gated production mutation", async () => {
  const calls = [];
  const result = await deployProduction({
    action: "first-install-recovery",
    config,
    inspectSource: () => {
      calls.push("source");
      return { branch: "main", revision };
    },
    verifyCi: ({ revision: observed }) => {
      calls.push(`ci:${observed}`);
      return { ok: false, lines: ["exact SHA gate blocked"] };
    },
    preflight: async () => assert.fail("Recovery preflight must not run before exact-SHA CI is green."),
    execute: () => assert.fail("Recovery must not contact production before exact-SHA CI is green."),
  });
  assert.deepEqual(calls, ["source", `ci:${revision}`]);
  assert.deepEqual(result, { status: 1, lines: ["exact SHA gate blocked"] });
  assert.match(deploymentScript, /first-install-recovery/u);
  assert.match(deploymentScript, /downloadProductionImages/u);
  assert.match(deploymentScript, /runRemoteScript\(action, source\.revision/u);
});

test("Linux first-install shell guard accepts only a pristine Virki target before image or database work", { skip: nativeLinuxHostSkip }, async (suite) => {
  const rootDirectory = mkdtempSync(path.join(os.tmpdir(), "virki-first-install-guard-"));
  const scriptPath = fileURLToPath(new URL("./production-server.sh", import.meta.url));
  const host = spawnSync("hostname", ["-s"], { encoding: "utf8" });
  assert.equal(host.status, 0);

  function fixture(mode = "empty", configure = () => {}) {
    const root = path.join(rootDirectory, `${mode}-${Math.random().toString(16).slice(2)}`);
    const temp = path.join(root, ".deploy-tmp");
    const releases = path.join(root, "releases");
    const backups = path.join(root, "backups");
    mkdirSync(temp, { recursive: true, mode: 0o700 });
    mkdirSync(releases, { mode: 0o700 });
    mkdirSync(backups, { mode: 0o700 });
    chmodSync(root, 0o700);
    const marker = ["role=production", "protocol=2", `hostname=${host.stdout.trim()}`, `path=${root}`, ""].join("\n");
    writeFileSync(path.join(root, ".virki-production-host"), marker, { mode: 0o600 });
    for (const name of [".env", ".env.oidc", ".env.oidc-data"]) writeFileSync(path.join(root, name), "", { mode: 0o600 });
    configure({ root, temp, releases, backups });

    const bin = path.join(rootDirectory, `bin-${mode}-${Math.random().toString(16).slice(2)}`);
    mkdirSync(bin, { mode: 0o700 });
    const callsPath = path.join(rootDirectory, `docker-${mode}-${Math.random().toString(16).slice(2)}.txt`);
    const dockerScript = [
      "#!/bin/sh",
      "set -eu",
      'printf \'%s\\n\' "$*" >> "$DOCKER_CALLS_FILE"',
      'if [ "$VIRKI_TEST_DOCKER_MODE" = recovery ]; then',
      '  case "$1" in',
      '    ps) case "$*" in *"label=com.docker.compose.project=virki-prod"*) printf "%s\\n" "$VIRKI_TEST_CONTAINER_ID" ;; *"volume=virki-prod_virki_postgres_data"*) if [ "$VIRKI_TEST_DOCKER_VARIANT" = consumer ]; then printf "%s\\n" "$VIRKI_TEST_OTHER_CONTAINER_ID"; fi; printf "%s\\n" "$VIRKI_TEST_CONTAINER_ID" ;; *) exit 2 ;; esac ;;',
      '    inspect) case "$3" in *".Config.Image"*) if [ "$VIRKI_TEST_DOCKER_VARIANT" = project ]; then printf "virki-other|postgres|postgres:17-alpine@sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24|exited|0|false\\n"; else printf "virki-prod|postgres|postgres:17-alpine@sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24|exited|0|false\\n"; fi ;; "{{len .Mounts}}") printf "2\\n" ;; *".Mounts"*) printf "bind||%s/releases/%s/infra/postgres-init/10-virki-database-roles.sh|/docker-entrypoint-initdb.d/10-virki-database-roles.sh|false;volume|virki-prod_virki_postgres_data|/var/lib/docker/volumes/virki-prod_virki_postgres_data/_data|/var/lib/postgresql/data|true;\\n" "$VIRKI_TEST_ROOT" "$VIRKI_TEST_PRIOR_REVISION" ;; *) exit 2 ;; esac ;;',
      '    volume) if [ "$VIRKI_TEST_DOCKER_VARIANT" = volume-label ]; then printf "virki-prod_virki_postgres_data|virki-other|virki_postgres_data\\n"; else printf "virki-prod_virki_postgres_data|virki-prod|virki_postgres_data\\n"; fi ;;',
      '    network) case "$4" in *".Containers"*) if [ "$VIRKI_TEST_DOCKER_VARIANT" = network-member ]; then printf "virki-prod-postgres-1|unexpected-service|\\n"; fi ;; *) if [ "$VIRKI_TEST_DOCKER_VARIANT" = network-label ]; then printf "virki-prod_default|virki-other\\n"; else printf "virki-prod_default|virki-prod\\n"; fi ;; esac ;;',
      '    *) exit 2 ;;',
      '  esac',
      '  exit 0',
      'fi',
      'if [ "$VIRKI_TEST_DOCKER_MODE" = container ] && [ "$1" = ps ]; then printf \'existing-container\\n\'; fi',
      'if [ "$VIRKI_TEST_DOCKER_MODE" = volume ] && [ "$1" = volume ]; then printf \'virki-prod_virki_postgres_data\\n\'; fi',
      'if [ "$VIRKI_TEST_DOCKER_MODE" = network ] && [ "$1" = network ]; then printf \'virki-prod_default\\n\'; fi',
    ].join("\n") + "\n";
    const dockerPath = path.join(bin, "docker");
    writeFileSync(dockerPath, dockerScript, { mode: 0o700 });
    chmodSync(dockerPath, 0o700);
    return { root, temp, releases, backups, bin, callsPath };
  }

  function runFirstInstall(target, dockerMode = "empty") {
    const result = spawnSync("bash", [
      scriptPath,
      "first-install",
      target.root,
      revision,
      "a".repeat(64),
      "b".repeat(24),
      "c".repeat(64),
      "d".repeat(24),
    ], {
      cwd: rootDirectory,
      encoding: "utf8",
      env: {
        ...process.env,
        PATH: `${target.bin}${path.delimiter}${process.env.PATH ?? ""}`,
        DOCKER_CALLS_FILE: target.callsPath,
        VIRKI_TEST_DOCKER_MODE: dockerMode,
      },
      timeout: 10_000,
    });
    return {
      status: result.status,
      output: `${result.stdout ?? ""}${result.stderr ?? ""}`,
      dockerCalls: existsSync(target.callsPath) ? readFileSync(target.callsPath, "utf8").trim().split(/\r?\n/u).filter(Boolean) : [],
    };
  }

  function runRecovery(target, dockerVariant = "valid") {
    const result = spawnSync("bash", [
      scriptPath,
      "first-install-recovery",
      target.root,
      revision,
      "a".repeat(64),
      "b".repeat(24),
      "c".repeat(64),
      "d".repeat(24),
    ], {
      cwd: rootDirectory,
      encoding: "utf8",
      env: {
        ...process.env,
        PATH: `${target.bin}${path.delimiter}${process.env.PATH ?? ""}`,
        DOCKER_CALLS_FILE: target.callsPath,
        VIRKI_TEST_DOCKER_MODE: "recovery",
        VIRKI_TEST_DOCKER_VARIANT: dockerVariant,
        VIRKI_TEST_CONTAINER_ID: "a".repeat(64),
        VIRKI_TEST_OTHER_CONTAINER_ID: "b".repeat(64),
        VIRKI_TEST_ROOT: target.root,
        VIRKI_TEST_PRIOR_REVISION: target.priorRevision ?? "e".repeat(40),
      },
      timeout: 10_000,
    });
    return {
      status: result.status,
      output: `${result.stdout ?? ""}${result.stderr ?? ""}`,
      dockerCalls: existsSync(target.callsPath) ? readFileSync(target.callsPath, "utf8").trim().split(/\r?\n/u).filter(Boolean) : [],
    };
  }

  function partialRecoveryFixture(mode, configure = () => {}) {
    const priorRevision = "e".repeat(40);
    const priorArchiveHash = "1".repeat(64);
    const acceptedArchiveHash = "a".repeat(64);
    const target = fixture(mode, ({ root, releases, backups }) => {
      const priorRelease = path.join(releases, priorRevision);
      mkdirSync(priorRelease, { mode: 0o700 });
      writeFileSync(path.join(priorRelease, ".virki-release"), `revision=${priorRevision}\narchive_sha256=${priorArchiveHash}\n`, { mode: 0o600 });
      for (const name of [".env", ".env.oidc", ".env.oidc-data"]) symlinkSync(path.join(root, name), path.join(priorRelease, name));
      writeFileSync(path.join(root, ".virki-source-state"), [
        `revision=${priorRevision}`,
        "source=verified-archive",
        "branch=main",
        "clean=true",
        "ci=success",
        `archive_sha256=${priorArchiveHash}`,
        "",
      ].join("\n"), { mode: 0o600 });
      writeFileSync(path.join(root, ".virki-deploy-revision"), `${priorRevision}\n`, { mode: 0o600 });
      writeFileSync(path.join(root, ".virki-first-install-recovery"), [
        `prior_revision=${priorRevision}`,
        `revision=${revision}`,
        `archive_sha256=${acceptedArchiveHash}`,
        "phase=prepared",
        "",
      ].join("\n"), { mode: 0o600 });
      configure({ root, releases, backups, priorRevision, priorArchiveHash, acceptedArchiveHash });
    });
    return { ...target, priorRevision, priorArchiveHash, acceptedArchiveHash };
  }

  try {
    await suite.test("recovery refuses a root without retained install source markers before Docker access", () => {
      const target = fixture("recovery-missing-source");
      const result = runRecovery(target);
      assert.equal(result.status, 1);
      assert.match(result.output, /exact retained partial-install source markers/u);
      assert.deepEqual(result.dockerCalls, []);
      assert.equal(existsSync(path.join(target.root, ".virki-first-install-recovery")), false);
    });

    await suite.test("recovery refuses unverified backup files before inspecting or starting PostgreSQL", () => {
      const target = partialRecoveryFixture("recovery-backup", ({ backups }) => writeFileSync(path.join(backups, "unclassified.dump"), "fixture", { mode: 0o600 }));
      const checkpoint = readFileSync(path.join(target.root, ".virki-first-install-recovery"), "utf8");
      const result = runRecovery(target);
      assert.equal(result.status, 1);
      assert.match(result.output, /backup directory contains unverified artifacts/u);
      assert.deepEqual(result.dockerCalls, []);
      assert.equal(readFileSync(path.join(target.root, ".virki-first-install-recovery"), "utf8"), checkpoint);
    });

    await suite.test("recovery accepts one current verified backup and rejects every other backup entry", () => {
      const backupName = "virki-20261010-120000-abcdef.dump";
      const target = partialRecoveryFixture("recovery-verified-backup", ({ root, backups }) => {
        writeFileSync(path.join(backups, backupName), "", { mode: 0o600 });
        writeFileSync(path.join(root, ".virki-migration-verification"), [
          `revision=${revision}`,
          `backup_name=${backupName}`,
          "backup_sha256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          `verified_at=${new Date().toISOString()}`,
          "",
        ].join("\n"), { mode: 0o600 });
      });
      const result = runRecovery(target);
      assert.equal(result.status, 1);
      assert.match(result.output, /Verified the exact retained partial first-install target/u);
      assert.match(result.output, /Verified GHCR provenance manifest is missing or unsafe/u);
      assert.ok(result.dockerCalls.some((call) => call.includes(".Config.Image")));

      writeFileSync(path.join(target.backups, "extra.dump"), "unexpected", { mode: 0o600 });
      writeFileSync(target.callsPath, "", { mode: 0o600 });
      const contaminated = runRecovery(target);
      assert.equal(contaminated.status, 1);
      assert.match(contaminated.output, /backup directory contains unverified artifacts/u);
      assert.deepEqual(contaminated.dockerCalls, []);
    });

    await suite.test("recovery accepts the pinned PostgreSQL image reference and safely repeats a prepared checkpoint", () => {
      const target = partialRecoveryFixture("recovery-valid");
      const checkpointPath = path.join(target.root, ".virki-first-install-recovery");
      const checkpoint = readFileSync(checkpointPath, "utf8");
      for (let attempt = 0; attempt < 2; attempt += 1) {
        const result = runRecovery(target);
        assert.equal(result.status, 1);
        assert.match(result.output, /Verified the exact retained partial first-install target/u);
        assert.match(result.output, /Verified GHCR provenance manifest is missing or unsafe/u);
        assert.ok(result.dockerCalls.some((call) => call.includes(".Config.Image")));
        assert.equal(readFileSync(checkpointPath, "utf8"), checkpoint);
      }
    });

    for (const [variant, reason] of [
      ["project", /identity or stopped state does not match/u],
      ["consumer", /another container uses the PostgreSQL volume/u],
      ["volume-label", /volume labels do not match/u],
      ["network-label", /network labels do not match/u],
      ["network-member", /another container uses the Virki network/u],
    ]) {
      await suite.test(`recovery refuses ${variant} identity collisions before image or database work`, () => {
        const target = partialRecoveryFixture(`recovery-${variant}`);
        const result = runRecovery(target, variant);
        assert.equal(result.status, 1);
        assert.match(result.output, reason);
        assert.ok(!result.output.includes("Verified GHCR provenance manifest is missing or unsafe"));
        assert.ok(!result.dockerCalls.some((call) => call.includes("compose up")));
      });
    }

    await suite.test("recovery refuses a checkpoint bound to a different accepted SHA before Docker access", () => {
      const target = partialRecoveryFixture("recovery-sha");
      const checkpointPath = path.join(target.root, ".virki-first-install-recovery");
      writeFileSync(checkpointPath, readFileSync(checkpointPath, "utf8").replace(`revision=${revision}`, `revision=${"f".repeat(40)}`), { mode: 0o600 });
      const result = runRecovery(target);
      assert.equal(result.status, 1);
      assert.match(result.output, /does not match the accepted recovery source/u);
      assert.deepEqual(result.dockerCalls, []);
    });

    await suite.test("recovery refuses a symlinked production root before Docker access", () => {
      const target = partialRecoveryFixture("recovery-root-symlink");
      const alias = path.join(rootDirectory, "recovery-root-alias");
      symlinkSync(target.root, alias, "dir");
      const result = runRecovery({ ...target, root: alias });
      assert.equal(result.status, 1);
      assert.match(result.output, /Pre-provisioned production root does not match/u);
      assert.deepEqual(result.dockerCalls, []);
    });

    await suite.test("recovery refuses an unexpected release symlink before Docker access", () => {
      const target = partialRecoveryFixture("recovery-release-symlink");
      symlinkSync(path.join(target.root, ".env"), path.join(target.releases, "unexpected-release-link"));
      const result = runRecovery(target);
      assert.equal(result.status, 1);
      assert.match(result.output, /release directory contains a non-directory entry/u);
      assert.deepEqual(result.dockerCalls, []);
    });

    await suite.test("pristine root passes all collision checks before missing-image failure", () => {
      const target = fixture();
      const result = runFirstInstall(target);
      assert.equal(result.status, 1);
      assert.match(result.output, /Verified GHCR provenance manifest is missing or unsafe/u);
      assert.deepEqual(result.dockerCalls.map((call) => call.split(" ")[0]), ["ps", "volume", "network"]);
      assert.ok(!result.dockerCalls.some((call) => call.includes("compose up")));
    });

    await suite.test("active source link blocks without Docker calls", () => {
      const target = fixture("current", ({ root, releases }) => {
        mkdirSync(path.join(releases, revision));
        symlinkSync(`releases/${revision}`, path.join(root, "current"));
      });
      const result = runFirstInstall(target);
      assert.equal(result.status, 1);
      assert.match(result.output, /current release is already active/u);
      assert.deepEqual(result.dockerCalls, []);
    });

    await suite.test("an unrelated pre-existing release directory blocks before Docker work", () => {
      const target = fixture("release", ({ releases }) => mkdirSync(path.join(releases, revision)));
      const result = runFirstInstall(target);
      assert.equal(result.status, 1);
      assert.match(result.output, /First install refused because an unrelated release already exists\./u);
      assert.deepEqual(result.dockerCalls, []);
    });

    await suite.test("partial source metadata blocks without Docker calls", () => {
      const target = fixture("partial", ({ root }) => writeFileSync(path.join(root, ".virki-source-state"), "partial\n", { mode: 0o600 }));
      const result = runFirstInstall(target);
      assert.equal(result.status, 1);
      assert.match(result.output, /source state is incomplete/u);
      assert.deepEqual(result.dockerCalls, []);
    });

    await suite.test("retained backup blocks before loading images", () => {
      const target = fixture("backup", ({ backups }) => writeFileSync(path.join(backups, "retained.dump"), "fixture", { mode: 0o600 }));
      const result = runFirstInstall(target);
      assert.equal(result.status, 1);
      assert.match(result.output, /backup directory is not empty/u);
      assert.deepEqual(result.dockerCalls, []);
    });

    for (const collision of ["container", "volume", "network"]) {
      await suite.test(`${collision} collision blocks before loading images`, () => {
        const target = fixture(collision);
        const result = runFirstInstall(target, collision);
        assert.equal(result.status, 1);
        assert.match(result.output, new RegExp(`${collision === "container" ? "project containers" : collision === "volume" ? "PostgreSQL volume" : "project network"} already exist`, "u"));
        assert.ok(!result.output.includes("Verified GHCR provenance manifest is missing or unsafe"));
        assert.ok(!result.dockerCalls.some((call) => call.includes("compose up")));
      });
    }
  } finally {
    rmSync(rootDirectory, { recursive: true, force: true });
  }
});

test("Virki staging is private, bounded, loopback-only, and does not start Tunnel", () => {
  const stage = serverScript.slice(serverScript.indexOf("  stage)\n"), serverScript.indexOf("  first-admin-bootstrap)\n"));
  assert.match(stage, /verify_first_install_marker[\s\S]*?verify_first_install_volume[\s\S]*?assert_tunnel_stopped[\s\S]*?assert_staging_ports_available/u);
  assert.match(stage, /export PUBLIC_SITE_PORT=13000[\s\S]*?export HUB_PORT=13001/u);
  assert.match(serverScript, /readonly staging_application_services=\(public-site hub oidc-issuer session-cleanup\)/u);
  assert.match(stage, /assert_staging_mail_worker_stopped[\s\S]*?compose up --detach "\$\{staging_application_services\[@\]\}"[\s\S]*?assert_revisions "\$\{staging_application_services\[@\]\}"[\s\S]*?assert_loopback_ports[\s\S]*?assert_health[\s\S]*?assert_staging_mail_worker_stopped/u);
  assert.doesNotMatch(stage, /compose up --detach "\$\{application_services\[@\]\}"/u);
  assert.doesNotMatch(stage, /compose up[^\n]*cloudflared/u);
  const workerGate = serverScript.slice(serverScript.indexOf("assert_staging_mail_worker_stopped() {"), serverScript.indexOf("stop_stage_after_failure() {"));
  assert.match(workerGate, /compose ps --all --quiet email-worker/u);
  assert.match(workerGate, /docker inspect --format [^\n]*\.State\.Status[^\n]*\.State\.Running[^\n]*\.State\.Restarting/u);
  assert.match(workerGate, /virki-prod\|email-worker\|created\|false\|false/u);
  assert.match(workerGate, /virki-prod\|email-worker\|exited\|false\|false/u);
  assert.doesNotMatch(workerGate, /--status running/u,
    "checking running containers alone would miss a restart-policy worker in a restarting state");
  assert.doesNotMatch(workerGate, /compose (?:up|start|run|stop) /u,
    "worker readiness inspection must not mutate the worker");
  assert.ok(serverScript.includes('"127.0.0.1:$expected_port"'));
  const stageCleanup = serverScript.slice(serverScript.indexOf("stop_stage_after_failure() {"), serverScript.indexOf("is_valid_dns_hostname() {"));
  assert.match(stageCleanup, /compose stop "\$\{staging_application_services\[@\]\}"/u);
  assert.doesNotMatch(stageCleanup, /compose stop "\$\{application_services\[@\]\}"/u,
    "failed staging cannot stop a worker it never started or owned");
  assert.doesNotMatch(stageCleanup, /compose stop (?:postgres|cloudflared)/u);
  assert.doesNotMatch(stageCleanup, /cloudflared/u);
});

test("staging worker guard rejects actual running/restarting/unknown container states without touching Docker", {
  skip: !existsSync(process.platform === "win32" ? "C:\\Program Files\\Git\\bin\\bash.exe" : "/bin/bash")
    ? "An isolated Bash parser is required to exercise the worker guard with stubbed commands."
    : false
}, () => {
  const bashExecutable = process.platform === "win32" ? "C:\\Program Files\\Git\\bin\\bash.exe" : "/bin/bash";
  const start = serverScript.indexOf("assert_staging_mail_worker_stopped() {");
  const end = serverScript.indexOf("\n}\n", start);
  assert.ok(start >= 0 && end > start, "the exact source function must be extracted");
  const sourceFunction = serverScript.slice(start, end + 3);
  const fixture = `set -euo pipefail
compose() {
  [[ "$*" == 'ps --all --quiet email-worker' ]] || exit 98
  [[ "\${STUB_COMPOSE_FAIL:-0}" == 0 ]] || return 1
  printf '%s\\n' "\${STUB_WORKER_IDS:-}"
}
docker() {
  [[ "$1" == inspect && "$2" == --format && "$#" == 4 ]] || exit 98
  [[ "\${STUB_DOCKER_FAIL:-0}" == 0 ]] || return 1
  if [[ "$4" == worker-safe ]]; then
    printf '%s\\n' 'virki-prod|email-worker|exited|false|false'
  else
    printf '%s\\n' "\${STUB_DOCKER_IDENTITY:-}"
  fi
}
fail() { printf '%s\\n' 'worker-gate-rejected' >&2; exit 79; }
${sourceFunction}
assert_staging_mail_worker_stopped
`;
  const check = (env, expectedStatus) => {
    const child = spawnSync(bashExecutable, ["--noprofile", "--norc", "-s"], {
      input: fixture,
      encoding: "utf8",
      timeout: 5_000,
      windowsHide: true,
      env: { ...process.env, PATH: "/__virki_no_external_commands__", ...env }
    });
    assert.equal(child.error, undefined, String(child.error));
    assert.equal(child.status, expectedStatus, `unexpected worker-guard result: ${child.stderr}`);
  };
  check({}, 0);
  check({ STUB_WORKER_IDS: "worker-safe" }, 0);
  check({ STUB_WORKER_IDS: "worker-unknown", STUB_DOCKER_IDENTITY: "virki-prod|email-worker|created|false|false" }, 0);
  for (const state of [
    "virki-prod|email-worker|running|true|false",
    "virki-prod|email-worker|restarting|true|true",
    "virki-prod|email-worker|paused|true|false",
    "virki-prod|email-worker|dead|false|false",
    "another-project|email-worker|exited|false|false",
    "virki-prod|hub|exited|false|false",
    "garbage"
  ]) check({ STUB_WORKER_IDS: "worker-unknown", STUB_DOCKER_IDENTITY: state }, 79);
  check({ STUB_WORKER_IDS: "worker-safe\nworker-unknown", STUB_DOCKER_IDENTITY: "virki-prod|email-worker|restarting|false|true" }, 79);
  check({ STUB_WORKER_IDS: "worker-unknown", STUB_DOCKER_FAIL: "1" }, 79);
  check({ STUB_COMPOSE_FAIL: "1" }, 79);
});

test("production Compose uses the exact loaded runtime and migration image tags", () => {
  assert.match(serverScript, /--project-directory "\$source_dir\/infra"/u);
  const compose = readFileSync(new URL("../infra/docker-compose.prod.yml", import.meta.url), "utf8");
  assert.match(compose, /image: \$\{VIRKI_PRODUCTION_IMAGE:\?/u);
  assert.match(compose, /image: \$\{VIRKI_MIGRATOR_IMAGE:\?/u);
  assert.match(compose, /pull_policy: never/u);
  assert.doesNotMatch(compose, /^\s+build:/mu);
  assert.match(serverScript, /export VIRKI_PRODUCTION_IMAGE="virki-production-ci:\$revision"/u);
  assert.match(serverScript, /export VIRKI_MIGRATOR_IMAGE="virki-migrator-ci:\$revision"/u);
});

test("routed services start only after app checks, and failure cleanup preserves PostgreSQL", () => {
  const resumeStart = serverScript.indexOf("resume_services() {");
  const resumeEnd = serverScript.indexOf("\ninstall_source() {", resumeStart);
  const resume = serverScript.slice(resumeStart, resumeEnd);
  const resumeBackupVerification = resume.indexOf("assert_backup_verified");
  const resumeMigrationStatus = resume.indexOf("run_migration_status");
  const resumeSchemaValidation = resume.indexOf("verify_migration_schema", resumeMigrationStatus);
  const resumeSourceActivation = resume.indexOf("activate_source", resumeSchemaValidation);
  assert.ok(resumeBackupVerification >= 0 && resumeBackupVerification < resumeMigrationStatus, "maintenance-off must prove a fresh exact-revision backup before source activation");
  assert.ok(resumeMigrationStatus >= 0 && resumeSchemaValidation > resumeMigrationStatus && resumeSourceActivation > resumeSchemaValidation);
  const resumeAppStart = resume.indexOf('compose up --detach --force-recreate "${application_services[@]}"');
  const resumeRevision = resume.indexOf("assert_revisions", resumeAppStart);
  const resumePorts = resume.indexOf("assert_loopback_ports", resumeRevision);
  const resumeHealth = resume.indexOf("assert_health", resumePorts);
  const resumeTunnel = resume.indexOf("compose up --detach cloudflared", resumeHealth);
  const resumeTrapClear = resume.indexOf("trap - EXIT", resumeTunnel);
  assert.ok(resumeAppStart >= 0 && resumeRevision > resumeAppStart && resumePorts > resumeRevision && resumeHealth > resumePorts && resumeTunnel > resumeHealth && resumeTrapClear > resumeTunnel);
  assert.match(resume, /trap 'stop_routed_services' EXIT/u);

  const startAt = serverScript.indexOf("  start)\n");
  const restartAt = serverScript.indexOf("  restart)\n", startAt);
  const start = serverScript.slice(startAt, restartAt);
  assert.match(serverScript, /assert_no_maintenance\(\) \{\n {2}\[\[ ! -e "\$maintenance_path" && ! -L "\$maintenance_path" \]\]/u);
  assert.ok(start.indexOf("assert_no_maintenance") >= 0 && start.indexOf("assert_no_maintenance") < start.indexOf("compose up --detach postgres"));
  assert.ok(start.indexOf("assert_active_source") < start.indexOf("trap 'stop_routed_services' EXIT"));
  const startApp = start.indexOf('compose up --detach "${application_services[@]}"');
  const startRevision = start.indexOf("assert_revisions", startApp);
  const startPorts = start.indexOf("assert_loopback_ports", startRevision);
  const startHealth = start.indexOf("assert_health", startPorts);
  const startTunnel = start.indexOf("compose up --detach cloudflared", startHealth);
  assert.ok(startApp >= 0 && startRevision > startApp && startPorts > startRevision && startHealth > startPorts && startTunnel > startHealth);

  const restartEnd = serverScript.indexOf("  start-tunnel)\n", restartAt);
  const restart = serverScript.slice(restartAt, restartEnd);
  assert.ok(restart.indexOf("assert_no_maintenance") >= 0 && restart.indexOf("assert_no_maintenance") < restart.indexOf("compose up --detach postgres"));
  const restartApp = restart.indexOf('compose up --detach --force-recreate "${application_services[@]}"');
  const restartHealth = restart.indexOf("assert_health", restartApp);
  const restartTunnel = restart.indexOf("compose up --detach cloudflared", restartHealth);
  assert.ok(restartApp >= 0 && restartHealth > restartApp && restartTunnel > restartHealth);

  const tunnelAt = restartEnd;
  const stopAt = serverScript.indexOf("  stop)\n", tunnelAt);
  const tunnelActions = serverScript.slice(tunnelAt, stopAt);
  assert.ok(tunnelActions.indexOf("assert_no_maintenance") >= 0 && tunnelActions.indexOf("assert_no_maintenance") < tunnelActions.indexOf("compose stop cloudflared"));

  const stopServicesAt = serverScript.indexOf("stop_routed_services() {");
  const stopServicesEnd = serverScript.indexOf("\nstop_tunnel_on_failure()", stopServicesAt);
  const stopServices = serverScript.slice(stopServicesAt, stopServicesEnd);
  assert.match(stopServices, /for service in cloudflared "\$\{application_services\[@\]\}"/u);
  assert.doesNotMatch(stopServices, /postgres/u);
  assert.match(serverScript, /maintenance_on\(\)[\s\S]*?trap 'stop_routed_services' EXIT[\s\S]*?compose stop cloudflared[\s\S]*?compose stop "\$\{application_services\[@\]\}"/u);
});

test("sessions cleanup runs as a configured one-shot service during maintenance", () => {
  const start = serverScript.indexOf("  sessions-cleanup)\n");
  const end = serverScript.indexOf("  config)\n", start);
  const action = serverScript.slice(start, end);
  const compose = readFileSync(new URL("../infra/docker-compose.prod.yml", import.meta.url), "utf8");
  const worker = compose.slice(compose.indexOf("  session-cleanup:"), compose.indexOf("\n  audit-maintenance:", compose.indexOf("  session-cleanup:")));
  assert.match(action, /compose run --rm --no-deps session-cleanup npm run sessions:cleanup --workspace @virki\/auth/u);
  assert.doesNotMatch(action, /compose exec[^\n]*\bhub\b/u);
  assert.match(worker, /DATABASE_URL: \$\{DATABASE_URL/u);
  assert.match(worker, /SESSION_CLEANUP_INTERVAL_SECONDS: \$\{SESSION_CLEANUP_INTERVAL_SECONDS/u);
  assert.match(worker, /AUDIT_LOG_RETENTION_DAYS: \$\{AUDIT_LOG_RETENTION_DAYS/u);
});

test("restore clone and migration runner use an isolated password-protected internal network", () => {
  assert.match(serverScript, /docker network create --internal --label "virki\.restore\.operation=\$isolation_id" "\$db_network"/u);
  assert.match(serverScript, /local -x POSTGRES_USER=virki_bootstrap POSTGRES_PASSWORD="\$bootstrap_password" VIRKI_RUNTIME_DB_PASSWORD="\$runtime_password" VIRKI_MIGRATOR_DB_PASSWORD="\$migrator_password" VIRKI_AUDIT_MAINTENANCE_DB_PASSWORD="\$audit_maintenance_password"[\s\S]*?--env POSTGRES_PASSWORD/u);
  assert.match(serverScript, /bootstrap_password=\$\(od -An -N32 -tx1 \/dev\/urandom/u);
  assert.match(serverScript, /runtime_password=\$\(od -An -N32 -tx1 \/dev\/urandom/u);
  assert.match(serverScript, /migrator_password=\$\(od -An -N32 -tx1 \/dev\/urandom/u);
  assert.match(serverScript, /audit_maintenance_password=\$\(od -An -N32 -tx1 \/dev\/urandom/u);
  assert.match(serverScript, /\$bootstrap_password" != "\$runtime_password" && "\$bootstrap_password" != "\$migrator_password" && "\$runtime_password" != "\$migrator_password" && "\$audit_maintenance_password" != "\$bootstrap_password" && "\$audit_maintenance_password" != "\$runtime_password" && "\$audit_maintenance_password" != "\$migrator_password/u);
  assert.match(serverScript, /--env VIRKI_RUNTIME_DB_PASSWORD --env VIRKI_MIGRATOR_DB_PASSWORD --env VIRKI_AUDIT_MAINTENANCE_DB_PASSWORD/u);
  assert.match(serverScript, /services:[\s\S]*?migrate:[\s\S]*?networks:[\s\S]*?- restore/u);
  assert.match(serverScript, /external: true[\s\S]*?name: %s/u);
  assert.match(serverScript, /compose_with_override "\$override" --profile migration run --rm --no-deps --name "\$migration_container" --label "virki\.restore\.operation=\$isolation_id"/u);
  assert.doesNotMatch(serverScript, /POSTGRES_HOST_AUTH_METHOD=trust/u);

  assert.match(serverScript, /verify_clone_cleanup\(\)[\s\S]*?docker ps --all --filter "label=virki\.restore\.operation=\$isolation_id"[\s\S]*?docker network ls --filter "label=virki\.restore\.operation=\$isolation_id"/u);
  const backup = serverScript.slice(serverScript.indexOf("create_verified_backup() {"), serverScript.indexOf("\nassert_backup_verified() {"));
  assert.doesNotMatch(backup, /virki-prod_default/u);
  const cloneCleanup = serverScript.slice(serverScript.indexOf("cleanup_clone() {"), serverScript.indexOf("\nverify_clone_cleanup() {"));
  assert.match(cloneCleanup, /docker ps --all --quiet --filter "label=virki\.restore\.operation=\$isolation_id"[\s\S]*?docker rm --force --volumes "\$container_id"[\s\S]*?docker network rm "\$network_id"[\s\S]*?return "\$cleanup_failed"/u);
  assert.match(cloneCleanup, /docker volume ls --filter "label=virki\.restore\.operation=\$isolation_id"[\s\S]*?docker volume inspect --format '\{\{index \.Labels "virki\.restore\.operation"\}\}' "\$volume_name"[\s\S]*?if \[\[ "\$volume_name" != "virki-restore-data-\$isolation_id" \|\| "\$owned" != "\$isolation_id" \]\]; then\s+printf[^\n]+\s+cleanup_failed=1\s+continue\s+fi\s+docker volume rm "\$volume_name"/u);
  assert.equal((cloneCleanup.match(/docker volume rm\b/gu) ?? []).length, 1);
  assert.doesNotMatch(cloneCleanup, /\bcompose[^\n]*\bdown\b|docker volume prune|docker system prune|prisma db push|powershell/iu);
  assert.doesNotMatch(cloneCleanup, /\|\| true/u);
  assert.match(backup, /docker exec --interactive --user postgres "\$container" pg_restore[^\n]*< "\$partial_backup_path" >\/dev\/null/u);
  assert.doesNotMatch(backup, /docker cp/u);
  const cleanupHandler = serverScript.slice(serverScript.indexOf("cleanup_failed_backup_verification() {"), serverScript.indexOf("\ncreate_verified_backup() {"));
  assert.match(cleanupHandler, /cleanup_clone "\$isolation_id" "\$override"[\s\S]*?verify_clone_cleanup "\$isolation_id" "\$override"[\s\S]*?rm -f -- "\$partial_backup_path" "\$verification_tmp"[\s\S]*?if \[\[ "\$backup_verified" != true \]\]; then[\s\S]*?rm -f -- "\$backup_path" "\$verification_path"/u);
  assert.doesNotMatch(cleanupHandler, /\|\| true/u);
  const trap = backup.indexOf("trap 'cleanup_failed_backup_verification");
  const dump = backup.indexOf('> "$partial_backup_path"');
  assert.ok(trap >= 0 && dump > trap);
  assert.match(backup, /trap 'cleanup_failed_backup_verification "\$\?" "\$isolation_id" "\$override" "\$backup_path" "\$partial_backup_path" "\$verification_tmp" "\$backup_verified" "\$verification_path"' EXIT/u);
  const cleanup = backup.indexOf('cleanup_clone "$isolation_id" "$override"', backup.indexOf("before_recovery"));
  const verifyCleanup = backup.indexOf('verify_clone_cleanup "$isolation_id" "$override"', cleanup);
  const promoteBackup = backup.indexOf('mv -- "$partial_backup_path" "$backup_path"', verifyCleanup);
  const markerWrite = backup.indexOf('> "$verification_tmp"', promoteBackup);
  const confirmBackup = backup.indexOf("backup_verified=true", markerWrite);
  const clearTrap = backup.indexOf("trap - EXIT", confirmBackup);
  assert.ok(cleanup >= 0 && verifyCleanup > cleanup && promoteBackup > verifyCleanup && markerWrite > promoteBackup && confirmBackup > markerWrite && clearTrap > confirmBackup);
  const deployAt = serverScript.indexOf("  deploy)\n");
  const startAt = serverScript.indexOf("  start)\n", deployAt);
  const deploy = serverScript.slice(deployAt, startAt);
  assert.ok(deploy.indexOf("maintenance_on") < deploy.indexOf("create_verified_backup"));
  assert.ok(deploy.indexOf("create_verified_backup") < deploy.indexOf("apply_production_migrations"));
});

test("production migration reconciles only exact baseline histories and verifies the resulting schema", () => {
  const historyStart = serverScript.indexOf("current_migration_names() {");
  const historyEnd = serverScript.indexOf("\nidentity_snapshot_sql=", historyStart);
  const history = serverScript.slice(historyStart, historyEnd);
  const normalizerStart = history.indexOf("normalize_migration_history() {");
  const pruneStart = history.indexOf("prune_legacy_migration_history() {");
  const normalizer = history.slice(normalizerStart, history.indexOf("\nverify_migration_schema()", normalizerStart));
  const prune = history.slice(pruneStart, history.indexOf("\nnormalize_migration_history()", pruneStart));

  for (const migration of [
    "20260624190000_initial_schema",
    "20260624203000_add_login_rate_limit",
    "20260625160000_add_gymforge_foundation",
    "20260625173000_add_gymforge_competition_assignments",
    "20260714100000_add_gymforge_score_corrections",
    "20260801090000_identity_access_foundation",
    "20260801100000_add_intake_dedupe_controls",
    "20260801110000_add_partial_application_state",
    "20260801120000_account_security_verification",
    "20260801130000_administrative_elevation",
    "20260801140000_security_ui_keys",
    "20260802090000_restrict_intake_database_access",
    "20260802100000_fix_intake_security_functions",
    "20260805120000_add_remembered_browser_grant",
    "20260922090000_total_identity_security_rebaseline",
  ]) assert.ok(serverScript.includes(migration), `Expected the exact legacy allowlist to include ${migration}.`);

  assert.match(history, /count\(DISTINCT "migration_name"\)/u);
  assert.match(history, /"migration_name" IS NULL OR "migration_name" NOT IN/u);
  assert.match(history, /"finished_at" IS NULL AND "rolled_back_at" IS NULL/u);
  assert.match(normalizer, /15\|15\|0\|0\|15\|0\|1\|14\|0/u);
  assert.match(normalizer, /16\|16\|0\|0\|16\|1\|1\|14\|0/u);
  assert.match(normalizer, /migration_history_is_clean_baseline/u);
  const prefixStart = history.indexOf("migration_history_is_current_prefix() {");
  const prefixEnd = history.indexOf("\nrun_migration_prisma()", prefixStart);
  const prefix = history.slice(prefixStart, prefixEnd);
  assert.match(prefix, /prefix\+=\("\$current_name"\)/u);
  assert.match(prefix, /expected=\$\(migration_history_name_set "\$\{prefix\[@\]\}"\)/u);
  assert.match(prefix, /"\$history_names" == "\$expected"/u);
  assert.match(normalizer, /migration_history_is_current_prefix "\$names" "\$\{current_names\[@\]\}" \|\| fail 'Production migration history skips a committed migration\.'/u);
  const resolve = normalizer.indexOf('resolve-baseline');
  const exactResolvedState = normalizer.indexOf("state" , resolve);
  const guardedPrune = prune.indexOf("actual_names <> '$expected_names'");
  const deleteRows = prune.indexOf('DELETE FROM "_prisma_migrations" WHERE "migration_name" <> \'0_init\'');
  assert.ok(resolve >= 0 && exactResolvedState > resolve && guardedPrune >= 0 && deleteRows > guardedPrune);
  assert.match(normalizer, /run_migration_prisma .* resolve-baseline/u);
  assert.match(prune, /clone_migration_query "\$container" "\$sql"/u);
  assert.match(prune, /PGPASSWORD="\$VIRKI_MIGRATOR_DB_PASSWORD" psql --host 127\.0\.0\.1 -U virki_migrator/u);
  assert.doesNotMatch(prune, /database_query "\$sql"|\$POSTGRES_USER/u);
  assert.ok(prune.includes("DO \\$virki\\$"));
  assert.match(prune, /"finished_at" IS NULL OR "rolled_back_at" IS NOT NULL/u);

  const cloneStart = serverScript.indexOf("run_clone_migrations() {");
  const cloneEnd = serverScript.indexOf("\ncleanup_clone()", cloneStart);
  const clone = serverScript.slice(cloneStart, cloneEnd);
  assert.ok(clone.indexOf("normalize_migration_history") < clone.indexOf('migrate\n'));
  assert.ok(clone.indexOf('migrate\n') < clone.indexOf('migrate npm run prisma:migrate:status'));
  assert.ok(clone.indexOf('migrate npm run prisma:migrate:status') < clone.indexOf("verify_migration_schema"));

  const applyStart = serverScript.indexOf("apply_production_migrations() {");
  const applyEnd = serverScript.indexOf("\nassert_no_maintenance()", applyStart);
  const apply = serverScript.slice(applyStart, applyEnd);
  assert.ok(apply.indexOf("assert_backup_verified") < apply.indexOf("normalize_migration_history"));
  assert.ok(apply.indexOf("assert_backup_verified") < apply.indexOf("compose up --detach --force-recreate postgres"));
  assert.ok(apply.indexOf("compose up --detach --force-recreate postgres") < apply.indexOf("pg_isready"));
  assert.ok(apply.indexOf("pg_isready") < apply.indexOf("10-virki-database-roles.sh"));
  assert.ok(apply.indexOf("10-virki-database-roles.sh") < apply.indexOf("compose --profile migration run --rm --no-deps migrate"));
  assert.doesNotMatch(apply, /compose (?:down|rm)[\s\S]*?postgres|--volumes/u);
  assert.ok(apply.indexOf("normalize_migration_history") < apply.indexOf("compose --profile migration run --rm --no-deps migrate"));
  assert.ok(apply.indexOf("compose --profile migration run --rm --no-deps migrate") < apply.indexOf("run_migration_status"));
  assert.ok(apply.indexOf("run_migration_status") < apply.indexOf("verify_migration_schema"));
  assert.ok(apply.indexOf("verify_migration_schema") < apply.indexOf("verify_first_install_role_contract"));
  assert.match(history, /run_migration_prisma .* verify-schema/u);
  assert.match(migrationRunnerSource, /\["verify-schema", \["migrate", "diff", "--from-schema-datasource", schemaPath, "--to-schema-datamodel", schemaPath, "--exit-code"\]\]/u);
});

test("recovery snapshots account for the intended legacy-key migration and retain full outbox state", () => {
  const snapshotStart = serverScript.indexOf("recovery_snapshot_sql() {");
  const snapshotEnd = serverScript.indexOf("\nrecovery_snapshot() {", snapshotStart);
  assert.ok(snapshotStart >= 0 && snapshotEnd > snapshotStart);
  const snapshotSql = serverScript.slice(snapshotStart, snapshotEnd);
  assert.match(snapshotSql, /local recovery_key_expression='"idempotencyKey"'/u);
  assert.match(snapshotSql, /snapshot_phase" == before_migrations/u);
  assert.match(snapshotSql, /~ \('\^account-recovery:/u);
  assert.match(snapshotSql, /CASE WHEN .*account-recovery:\[A-Za-z0-9_-\]\{32\}.*chr\(36\).*account-recovery-migrated:.*id.*ELSE .*idempotencyKey.*END/u);
  assert.match(snapshotSql, /snapshot_phase" != after_migrations/u);

  const messageProjection = snapshotSql.slice(snapshotSql.indexOf("'messages'"), snapshotSql.indexOf("'attempts'"));
  assert.match(messageProjection, /to_jsonb\(message\)->>'pendingSmtpHeaderMessageId'/u,
    "Snapshot must preserve the in-flight ID across sender rotation and tolerate the pre-migration schema");
  for (const field of [
    '"id"', '"kind"', '"recipientEmail"', '"locale"', '"payload"', '"status"', '"attemptCount"',
    '"availableAt"', '"sentAt"', '"terminalFailedAt"', '"createdAt"', '"updatedAt"',
  ]) {
    assert.ok(messageProjection.includes(field), `Recovery snapshots must preserve the ${field} field.`);
  }
  const attemptProjection = snapshotSql.slice(snapshotSql.indexOf("'attempts'"));
  assert.match(attemptProjection, /to_jsonb\(attempt\)->>'smtpHeaderMessageId'/u,
    "Snapshot must preserve SMTP Message-ID when present without referencing a column absent before migration");

  assert.match(serverScript, /before_recovery=\$\(recovery_snapshot "\$container" before_migrations\)/u);
  assert.match(serverScript, /after_recovery=\$\(recovery_snapshot "\$container" after_migrations\)/u);
  assert.match(serverScript, /before_recovery=\$\(recovery_snapshot "" before_migrations\)/u);
  assert.match(serverScript, /after_recovery=\$\(recovery_snapshot "" after_migrations\)/u);
});

test("rollback snapshot includes every outbox kind and corresponding delivery attempt", { skip: process.platform === "win32" ? "Requires Bash for the production SQL renderer." : false }, () => {
  const start = serverScript.indexOf("recovery_snapshot_sql() {");
  const end = serverScript.indexOf("\nrecovery_snapshot() {", start);
  assert.ok(start >= 0 && end > start);
  const renderer = serverScript.slice(start, end);
  for (const phase of ["before_migrations", "after_migrations"]) {
    const result = spawnSync("bash", ["-c", `set -euo pipefail\nfail() { exit 81; }\n${renderer}\nrecovery_snapshot_sql "$1"`, "virki-rollback-sql-test", phase], { encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr);
    const sql = result.stdout;
    assert.match(sql, /FROM "EmailOutboxMessage" AS message/u);
    assert.match(sql, /FROM "EmailDeliveryAttempt" AS attempt\s+JOIN "EmailOutboxMessage" AS message ON message\."id" = attempt\."messageId"/u);
    assert.doesNotMatch(sql, /WHERE\s+(?:message\.)?"kind"/u,
      "Rollback must retain ADMIN verification, mailbox rebind, notifications and all other email kinds, not just recovery email");
    assert.match(sql, /to_jsonb\(message\)->>'pendingSmtpHeaderMessageId'/u);
    assert.match(sql, /processingLeaseExpiresAt/u,
      "Rollback must attest worker ownership leases, not just SMTP header IDs and message status.");
    assert.match(sql, /to_jsonb\(attempt\)->>'smtpHeaderMessageId'/u);
    if (phase === "before_migrations") {
      assert.match(sql, /CASE WHEN "kind"::text = 'ACCOUNT_RECOVERY' AND "idempotencyKey" ~/u,
        "Legacy idempotency normalization must never rewrite another email kind merely because its key shares the recovery prefix.");
      assert.match(sql, /to_jsonb\(message\) \? 'processingLeaseExpiresAt'/u,
        "Only a source schema without lease column may normalize the historical PROCESSING backfill.");
    }
  }
});

test("disposable rollback restore rehearsal includes ADMIN verification and both mailbox rebind message kinds", () => {
  for (const kind of ["ACCOUNT_RECOVERY", "ADMIN_EMAIL_VERIFICATION", "RECOVERY_EMAIL_REBIND", "RECOVERY_EMAIL_REBIND_NOTICE"]) {
    assert.ok(backupRestoreScript.includes(`kind: "${kind}"`), `Backup fixture must seed ${kind}.`);
  }
  assert.match(backupRestoreScript, /assert\.deepEqual\(restoredOutbox, sourceOutbox/u,
    "The physical restore rehearsal must compare entire message and attempt inventories.");
  assert.match(backupRestoreScript, /processingLeaseExpiresAt: new Date\(/u,
    "Physical backup/restore must include a PROCESSING message with a retained lease expiry.");
});

test("non-whitespace backup sentinel content blocks preflight and transfer", async () => {
  let archivePath;
  let preflightCalled = false;
  await assert.rejects(deployProduction({
    action: "install",
    config,
    inspectSource: () => ({ branch: "main", revision }),
    verifyCi: () => ({ ok: true, lines: [] }),
    preflight: async () => {
      preflightCalled = true;
      return { status: 0, lines: [] };
    },
    execute: (command, args, options = {}) => {
      if (command === "git") assert.equal(options.env?.GIT_NO_REPLACE_OBJECTS, "1");
      if (command === "git" && args[0] === "archive") {
        archivePath = args.find((value) => value.startsWith("--output=")).slice("--output=".length);
        writeFileSync(archivePath, "tracked source archive");
        return { status: 0, stdout: "" };
      }
      if (command === "git" && args[0] === "ls-tree") {
        return { status: 0, stdout: `100644 blob ${revision}\tinfra/backups/.gitkeep\0` };
      }
      if (command === "git" && args[0] === "cat-file" && args[1] === "-s") return { status: 0, stdout: "15\n" };
      if (command === "git" && args[0] === "cat-file" && args[1] === "blob") return { status: 0, stdout: "not a sentinel\n" };
      assert.fail(`Unexpected command: ${command} ${args.join(" ")}`);
    },
  }), /Production command failed/u);
  assert.equal(preflightCalled, false);
  assert.equal(existsSync(path.dirname(archivePath)), false);
});

test("deployment accepts a one-byte LF backup sentinel and transfers exact-SHA GHCR provenance", async () => {
  const sequence = [];
  let archivePath;
  let imageArchivePath;
  let archiveId;
  const result = await deployProduction({
    action: "deploy",
    config,
    inspectSource: () => {
      sequence.push("source");
      return { branch: "main", revision };
    },
    verifyCi: () => {
      sequence.push("ci");
      return { ok: true, runId: 54321, lines: [] };
    },
    preflight: async () => {
      sequence.push("preflight");
      return { status: 0, platform: "linux/amd64", lines: ["preflight ok"] };
    },
    retrieveEvidence: () => {
      sequence.push("ghcr:evidence");
      const evidence = makeEvidence();
      imageArchivePath = evidence.file;
      return evidence;
    },
    execute: (command, args, options = {}) => {
      sequence.push(command === "ssh" ? "ssh" : isSecretScanCommand(command, args) ? "secret-scan" : command === "git" && args[0] === "show" && args[1] === revision + ":scripts/secret-scan.mjs" ? "scanner-source" : `${command}:${args[0]}`);
      if (command === "git") assert.equal(options.env?.GIT_NO_REPLACE_OBJECTS, "1");
      if (command === "git" && args[0] === "archive") {
        archivePath = args.find((value) => value.startsWith("--output=")).slice("--output=".length);
        writeFileSync(archivePath, "tracked source archive");
        return { status: 0, stdout: "" };
      }
      if (command === "git" && args[0] === "ls-tree") {
        return {
          status: 0,
          stdout: [
            `100644 blob ${revision}\tREADME.md`,
            `100644 blob ${revision}\t.env.example`,
            `100644 blob ${revision}\tscripts/production-server.sh`,
            `040000 tree ${revision}\tinfra/backups`,
            `100644 blob ${revision}\tinfra/backups/.gitkeep`,
            `100644 blob ${revision}\tpackages/database/prisma/migrations/20261001000000_security_polish/migration.sql`,
          ].join("\0") + "\0",
        };
      }
      if (command === "git" && args[0] === "check-attr") {
        const attributes = [];
        for (const sourcePath of options.input.split("\0").filter(Boolean)) {
          attributes.push(sourcePath, "export-ignore", "unspecified", sourcePath, "export-subst", "unspecified");
        }
        return { status: 0, stdout: attributes.join("\0") + "\0" };
      }
      if (command === "git" && args[0] === "cat-file" && args[1] === "-s") return { status: 0, stdout: "1\n" };
      if (command === "git" && args[0] === "cat-file" && args[1] === "blob") return { status: 0, stdout: "\n" };
      if (command === "git" && args[0] === "show") return { status: 0, stdout: args[1] === `${revision}:scripts/secret-scan.mjs` ? secretScannerSource : serverScript };
      if (command === "tar") return { status: 0, stdout: "README.md\n.env.example\nscripts/production-server.sh\ninfra/backups/\ninfra/backups/.gitkeep\npackages/database/prisma/migrations/20261001000000_security_polish/migration.sql\n" };
      if (isSecretScanCommand(command, args)) {
        assert.equal(args[1], "--revision");
        assert.equal(args[2], revision);
        return { status: 0, stdout: "Secret scan passed.\n" };
      }

      if (command === "scp") {
        if (args.at(-2) === archivePath) {
          const remotePath = args.at(-1).split(":").at(-1);
          const match = remotePath.match(new RegExp(`source-${revision}-([a-f0-9]{24})\\.tar$`, "u"));
          assert.ok(match);
          archiveId = match[1];
        } else {
          assert.equal(args.at(-2), imageArchivePath);
          const remotePath = args.at(-1).split(":").at(-1);
          assert.match(remotePath, new RegExp(`images-${revision}-${archiveId}\\.manifest$`, "u"));
        }
        assert.equal(args.some((value) => value.endsWith("/.env")), false);
        return { status: 0, stdout: "" };
      }
      if (command === "ssh") {
        assert.ok(options.input.includes("verify_host"));
        const remoteCommand = args.at(-1);
        assert.match(remoteCommand, new RegExp(`^bash -s -- deploy ${config.root} ${revision} `, "u"));
        const remoteArguments = remoteCommand.split(" ");
        assert.match(remoteArguments.at(-4), /^[a-f0-9]{64}$/u);
        assert.equal(remoteArguments.at(-3), archiveId);
        assert.match(remoteArguments.at(-2), /^[a-f0-9]{64}$/u);
        assert.equal(remoteArguments.at(-1), archiveId);
        return { status: 0, stdout: "stage or deployment complete\n" };
      }
      assert.fail(`Unexpected command: ${command}`);
    },
  });

  assert.equal(result.status, 0);
  assert.deepEqual(sequence.slice(0, 10), ["source", "ci", "git:archive", "git:ls-tree", "git:cat-file", "git:cat-file", "git:check-attr", "tar:-tf", "scanner-source", "secret-scan"]);
  assert.ok(sequence.indexOf("preflight") < sequence.indexOf("ghcr:evidence"));
  assert.ok(sequence.indexOf("ghcr:evidence") < sequence.findIndex((item) => item.startsWith("scp:")));
  assert.equal(sequence.filter((item) => item.startsWith("scp:")).length, 2);
  assert.equal(sequence.filter((item) => item === "ssh").length, 1);
  assert.equal(existsSync(path.dirname(archivePath)), false);
  assert.equal(existsSync(path.dirname(imageArchivePath)), false);
});

test("deployment rejects nonregular, symlinked, and oversized GHCR artifact entries before remote copy", async (suite) => {
  for (const entryKind of ["directory", "oversized", ...(process.platform === "linux" ? ["symlink"] : [])]) {
    await suite.test(entryKind, async () => {
      let stagingTouched = false;
      let artifactDirectory;
      await assert.rejects(deployProduction({
        action: "deploy",
        config,
        inspectSource: () => ({ branch: "main", revision }),
        verifyCi: () => ({ ok: true, runId: 54321, lines: [] }),
        preflight: async () => ({ status: 0, platform: "linux/amd64", lines: [] }),
        retrieveEvidence: () => {
          const evidence = makeEvidence(entryKind === "oversized" ? provenanceFixture.padEnd(513, "x") : provenanceFixture, entryKind);
          artifactDirectory = evidence.directory;
          return evidence;
        },
        execute: (command, args) => {
          if (command === "git" && args[0] === "archive") {
            writeFileSync(args.find((arg) => arg.startsWith("--output=")).slice(9), "archive");
            return { status: 0, stdout: "" };
          }
          if (command === "git" && args[0] === "ls-tree") {
            return { status: 0, stdout: `100644 blob ${revision}\tREADME.md\0` };
          }
          if (command === "git" && args[0] === "check-attr") {
            return { status: 0, stdout: "README.md\0export-ignore\0unspecified\0README.md\0export-subst\0unspecified\0" };
          }
          if (command === "git" && args[0] === "show") return { status: 0, stdout: args[1] === `${revision}:scripts/secret-scan.mjs` ? secretScannerSource : serverScript };
          if (command === "tar") return { status: 0, stdout: "README.md\n" };
          if (isSecretScanCommand(command, args)) return { status: 0, stdout: "Secret scan passed.\n" };

          if (command === "ssh" || command === "scp") {
            stagingTouched = true;
            return { status: 1, stdout: "" };
          }
          assert.fail(`Unexpected command: ${command}`);
        }
      }));
      assert.equal(stagingTouched, false, "Untrusted artifact must never be transferred to production.");
      assert.equal(existsSync(artifactDirectory), false, "Local artifact staging must be removed on failure.");
    });
  }
});

test("first-install uses the exact-SHA CI GHCR provenance and invokes only the guarded fresh-install action", async () => {
  const calls = [];
  let sourceArchivePath;
  let imageArchivePath;
  let stagingId;
  const sourcePaths = [
    "README.md",
    "scripts/production-server.sh",
    "scripts/secret-scan.mjs",
    "infra/docker-compose.prod.yml",
    "infra/docker-compose.cloudflare.yml",
    "infra/postgres-init/10-virki-database-roles.sh",
  ];
  const result = await deployProduction({
    action: "first-install",
    config,
    inspectSource: () => ({ branch: "main", revision }),
    verifyCi: () => ({ ok: true, runId: 54321, lines: ["exact SHA image gate passed"] }),
    preflight: async () => {
      calls.push("preflight");
      return { status: 0, platform: "linux/amd64", lines: ["preflight passed"] };
    },
    retrieveEvidence: () => {
      calls.push("ghcr:evidence");
      const evidence = makeEvidence();
      imageArchivePath = evidence.file;
      return evidence;
    },
    execute: (command, args, options = {}) => {
      calls.push(command === "ssh" ? "ssh" : `${command}:${args[0]}`);
      if (command === "git" && args[0] === "archive") {
        sourceArchivePath = args.find((value) => value.startsWith("--output=")).slice("--output=".length);
        writeFileSync(sourceArchivePath, "verified source archive");
        return { status: 0, stdout: "" };
      }
      if (command === "git" && args[0] === "ls-tree") {
        return { status: 0, stdout: sourcePaths.map((entry) => `100644 blob ${revision}\t${entry}`).join("\0") + "\0" };
      }
      if (command === "git" && args[0] === "check-attr") {
        const fields = options.input.split("\0").filter(Boolean).flatMap((entry) => [entry, "export-ignore", "unspecified", entry, "export-subst", "unspecified"]);
        return { status: 0, stdout: fields.join("\0") + "\0" };
      }
      if (command === "git" && args[0] === "show") return { status: 0, stdout: args[1] === `${revision}:scripts/secret-scan.mjs` ? secretScannerSource : serverScript };
      if (command === "tar") return { status: 0, stdout: `${sourcePaths.join("\n")}\n` };
      if (isSecretScanCommand(command, args)) return { status: 0, stdout: "Secret scan passed.\n" };

      if (command === "scp") {
        if (args.at(-2) === sourceArchivePath) {
          stagingId = args.at(-1).match(new RegExp(`source-${revision}-([a-f0-9]{24})\\.tar$`, "u"))?.[1];
          assert.ok(stagingId);
        } else {
          assert.equal(args.at(-2), imageArchivePath);
          assert.match(args.at(-1), new RegExp(`images-${revision}-${stagingId}\\.manifest$`, "u"));
        }
        return { status: 0, stdout: "" };
      }
      if (command === "ssh") {
        assert.ok(options.input.includes("verify_fresh_install_target"));
        assert.match(args.at(-1), new RegExp(`^bash -s -- first-install ${config.root} ${revision} `, "u"));
        assert.equal(args.at(-1).split(" ").at(-3), stagingId);
        return { status: 0, stdout: "fresh database initialized\n" };
      }
      assert.fail(`Unexpected first-install command: ${command}`);
    },
  });

  assert.equal(result.status, 0);
  assert.ok(calls.indexOf("preflight") < calls.indexOf("ghcr:evidence"));
  assert.ok(calls.indexOf("ghcr:evidence") < calls.findIndex((call) => call === "ssh"));
  assert.equal(calls.filter((call) => call === "ssh").length, 1);
  assert.equal(existsSync(path.dirname(sourceArchivePath)), false);
  assert.equal(existsSync(path.dirname(imageArchivePath)), false);
});

test("failed transfers and remote deploys invoke cleanup for only their unique staging paths", async (suite) => {
  for (const failureStage of ["image-transfer", "remote-deploy"]) {
    await suite.test(failureStage, async () => {
      let archivePath;
      let imageArchivePath;
      let archiveId;
      const calls = [];
      await assert.rejects(deployProduction({
        action: "deploy",
        config,
        inspectSource: () => ({ branch: "main", revision }),
        verifyCi: () => ({ ok: true, runId: 54321, lines: [] }),
        preflight: async () => ({ status: 0, platform: "linux/amd64", lines: [] }),
        retrieveEvidence: () => {
          const evidence = makeEvidence();
          imageArchivePath = evidence.file;
          return evidence;
        },
        execute: (command, args, options = {}) => {
          calls.push({ command, args });
          if (command === "git" && args[0] === "archive") {
            archivePath = args.find((value) => value.startsWith("--output=")).slice("--output=".length);
            writeFileSync(archivePath, "tracked source archive");
            return { status: 0, stdout: "" };
          }
          if (command === "git" && args[0] === "ls-tree") {
            return { status: 0, stdout: `100644 blob ${revision}\tREADME.md\0` };
          }
          if (command === "git" && args[0] === "check-attr") {
            return { status: 0, stdout: "README.md\0export-ignore\0unspecified\0README.md\0export-subst\0unspecified\0" };
          }
          if (command === "git" && args[0] === "show") return { status: 0, stdout: args[1] === `${revision}:scripts/secret-scan.mjs` ? secretScannerSource : serverScript };
          if (command === "tar") return { status: 0, stdout: "README.md\n" };
          if (isSecretScanCommand(command, args)) return { status: 0, stdout: "Secret scan passed.\n" };

          if (command === "scp") {
            if (args.at(-2) === archivePath) {
              const remotePath = args.at(-1).split(":").at(-1);
              archiveId = remotePath.match(new RegExp(`source-${revision}-([a-f0-9]{24})\\.tar$`, "u"))?.[1];
              assert.ok(archiveId);
              return { status: 0, stdout: "" };
            }
            assert.equal(args.at(-2), imageArchivePath);
            assert.match(args.at(-1), new RegExp(`images-${revision}-${archiveId}\\.manifest$`, "u"));
            return { status: failureStage === "image-transfer" ? 1 : 0, stdout: "" };
          }
          if (command === "ssh") {
            const remoteCommand = args.at(-1);
            if (remoteCommand.startsWith("bash -s -- cleanup-deploy-staging ")) {
              assert.equal(remoteCommand, `bash -s -- cleanup-deploy-staging ${config.root} ${revision} ${archiveId}`);
              assert.ok(options.input.includes("cleanup_deploy_staging"));
              return { status: 0, stdout: "staging removed\n" };
            }
            assert.equal(failureStage, "remote-deploy");
            assert.ok(remoteCommand.startsWith(`bash -s -- deploy ${config.root} ${revision} `));
            return { status: 1, stdout: "" };
          }
          assert.fail(`Unexpected command: ${command}`);
        },
      }), /Production command failed/u);
      const sshCalls = calls.filter((call) => call.command === "ssh");
      assert.equal(sshCalls.at(-1).args.at(-1), `bash -s -- cleanup-deploy-staging ${config.root} ${revision} ${archiveId}`);
      assert.equal(sshCalls.length, failureStage === "image-transfer" ? 1 : 2);
      assert.equal(existsSync(path.dirname(archivePath)), false);
      assert.equal(existsSync(path.dirname(imageArchivePath)), false);
    });
  }
});

test("sensitive files in the Git tree block transfer and production contact", async () => {
  for (const filePath of [
    "apps/.env",
    "apps/.env.staging",
    ".npmrc",
    "infra/cloudflare/account.json",
    "Infra/Cloudflare/account.JSON",
    "keys/client.key",
    "database/virki-dump.zip",
    "infra/backups/production.dump",
    "exports/production.dump.gz",
    "database/cache.sqlite-wal",
    "database/cache.sqlite-shm",
    "database/production.sqlite3.gz",
    "exports/snapshot.sql.zst",
    "exports/account-backup.tar.gz",
    "mail-attachments/account.mbox",
    ".aws/credentials",
    "secrets/id_ed25519",
    "logs/app.log.1",
    "logs/app.log.gz",
    "database/prod.sqlite-journal",
    "backup/prod-20261003",
    "certs/private.der",
    "keys/signing.pem.gz",
    "keys/signing.pem.gz.gz",
    "keys/id_ed25519.gz",
    "keys/id_ed25519.gz.gz",
  ]) {
    let productionContact = false;
    await assert.rejects(deployProduction({
      action: "install",
      config,
      inspectSource: () => ({ branch: "main", revision }),
      verifyCi: () => ({ ok: true, lines: [] }),
      preflight: async () => {
        productionContact = true;
        return { status: 0, lines: [] };
      },
      execute: (command, args, options = {}) => {
        if (command === "git") assert.equal(options.env?.GIT_NO_REPLACE_OBJECTS, "1");
        if (command === "git" && args[0] === "archive") {
          writeFileSync(args.find((value) => value.startsWith("--output=")).slice("--output=".length), "archive");
          return { status: 0, stdout: "" };
        }
        if (command === "git" && args[0] === "ls-tree") {
          return { status: 0, stdout: `100644 blob ${revision}\t${filePath}\0` };
        }
        if (command === "git" && args[0] === "show") return { status: 0, stdout: serverScript };
        if (command === "tar") return { status: 0, stdout: `${filePath}\n` };
        productionContact = true;
        return { status: 1, stdout: "" };
      },
    }), /Production command failed/u, filePath);
    assert.equal(productionContact, false, `${filePath} must not reach production preflight or transfer`);
  }
});

test("a failed exact-revision secret scan blocks preflight and transfer", async () => {
  let productionContact = false;
  await assert.rejects(deployProduction({
    action: "install",
    config,
    inspectSource: () => ({ branch: "main", revision }),
    verifyCi: () => ({ ok: true, lines: [] }),
    preflight: async () => {
      productionContact = true;
      return { status: 0, lines: [] };
    },
    execute: (command, args, options = {}) => {
      if (command === "git") assert.equal(options.env?.GIT_NO_REPLACE_OBJECTS, "1");
      if (command === "git" && args[0] === "archive") {
        writeFileSync(args.find((value) => value.startsWith("--output=")).slice("--output=".length), "archive");
        return { status: 0, stdout: "" };
      }
      if (command === "git" && args[0] === "ls-tree") return { status: 0, stdout: `100644 blob ${revision}\tREADME.md\0` };
      if (command === "git" && args[0] === "check-attr") return { status: 0, stdout: "README.md\0export-ignore\0unspecified\0README.md\0export-subst\0unspecified\0" };
      if (command === "git" && args[0] === "show") return { status: 0, stdout: args[1] === `${revision}:scripts/secret-scan.mjs` ? secretScannerSource : serverScript };
      if (command === "tar") return { status: 0, stdout: "README.md\n" };
      if (isSecretScanCommand(command, args)) {
        assert.equal(args[1], "--revision");
        assert.equal(args[2], revision);
        return { status: 1, stdout: "", stderr: "Secret scan failed.\n" };
      }
      productionContact = true;
      return { status: 1, stdout: "" };
    },
  }), /Production command failed/u);
  assert.equal(productionContact, false);
});

test("a release-marker symlink in the Git tree blocks transfer and production contact", async () => {
  let productionContact = false;
  await assert.rejects(deployProduction({
    action: "install",
    config,
    inspectSource: () => ({ branch: "main", revision }),
    verifyCi: () => ({ ok: true, lines: [] }),
    preflight: async () => {
      productionContact = true;
      return { status: 0, lines: [] };
    },
    execute: (command, args, options = {}) => {
      if (command === "git") assert.equal(options.env?.GIT_NO_REPLACE_OBJECTS, "1");
      if (command === "git" && args[0] === "archive") {
        writeFileSync(args.find((value) => value.startsWith("--output=")).slice("--output=".length), "archive");
        return { status: 0, stdout: "" };
      }
      if (command === "git" && args[0] === "ls-tree") {
        return { status: 0, stdout: "120000 blob " + revision + "\t.virki-release\0" };
      }
      if (command === "git" && args[0] === "show") return { status: 0, stdout: serverScript };
      productionContact = true;
      return { status: 1, stdout: "" };
    },
  }), /Production command failed/u);
  assert.equal(productionContact, false);
});

test("a directory-only Git export-ignore attribute blocks transfer and production contact", async () => {
  let productionContact = false;
  await assert.rejects(deployProduction({
    action: "install",
    config,
    inspectSource: () => ({ branch: "main", revision }),
    verifyCi: () => ({ ok: true, lines: [] }),
    preflight: async () => {
      productionContact = true;
      return { status: 0, lines: [] };
    },
    execute: (command, args, options = {}) => {
      if (command === "git") assert.equal(options.env?.GIT_NO_REPLACE_OBJECTS, "1");
      if (command === "git" && args[0] === "archive") {
        writeFileSync(args.find((value) => value.startsWith("--output=")).slice("--output=".length), "archive");
        return { status: 0, stdout: "" };
      }
      if (command === "git" && args[0] === "ls-tree") {
        assert.ok(args.includes("-t"));
        return {
          status: 0,
          stdout: "040000 tree " + revision + "\tapps\0"
            + "040000 tree " + revision + "\tapps/feature\0"
            + "100644 blob " + revision + "\tapps/feature/file.js\0",
        };
      }
      if (command === "git" && args[0] === "check-attr") {
        const attributes = [];
        for (const sourcePath of options.input.split("\0").filter(Boolean)) {
          attributes.push(
            sourcePath,
            "export-ignore",
            sourcePath === "apps/feature" ? "set" : "unspecified",
            sourcePath,
            "export-subst",
            "unspecified",
          );
        }
        return { status: 0, stdout: attributes.join("\0") + "\0" };
      }
      productionContact = true;
      return { status: 1, stdout: "" };
    },
  }), /Production command failed/u);
  assert.equal(productionContact, false);
});

test("production migration uses the protected Compose URL when no disposable override is supplied", () => {
  const migrationStart = serverScript.indexOf("run_migration_prisma() {");
  const migrationEnd = serverScript.indexOf("\nprune_legacy_migration_history() {", migrationStart);
  const migrationRunner = serverScript.slice(migrationStart, migrationEnd);
  assert.match(migrationRunner, /if \[\[ -n "\$database_url" \]\]; then[\s\S]*?local -x MIGRATION_DATABASE_URL="\$database_url"[\s\S]*?else\s+unset MIGRATION_DATABASE_URL/u);
  assert.doesNotMatch(migrationRunner, /local -x MIGRATION_DATABASE_URL="\$database_url"[\s\S]{0,80}compose /u);
  const pruneStart = serverScript.indexOf("prune_legacy_migration_history() {");
  const pruneEnd = serverScript.indexOf("\nnormalize_migration_history() {", pruneStart);
  const prune = serverScript.slice(pruneStart, pruneEnd);
  assert.match(prune, /clone_migration_query "\$container" "\$sql"[\s\S]*?else\s+compose exec -T postgres sh -lc 'PGPASSWORD="\$VIRKI_MIGRATOR_DB_PASSWORD" psql --host 127\.0\.0\.1 -U virki_migrator -d "\$POSTGRES_DB"/u);
  assert.doesNotMatch(prune, /compose exec -T -e MIGRATION_DATABASE_URL/u);
  assert.match(serverScript, /--health-cmd 'pg_isready -h 127\.0\.0\.1 -U virki_bootstrap -d virki_restore'/u);
});

test("production migration wrapper refuses schema development and db push commands before Prisma runs", () => {
  for (const command of ["dev", "push"]) {
    const result = spawnSync(process.execPath, [migrationRunnerPath, command], {
      env: {
        NODE_ENV: "production",
      },
      encoding: "utf8",
      windowsHide: true
    });
    assert.equal(result.status, 1, `${command} must be rejected in production.`);
    assert.match(result.stderr ?? "", /development schema commands are disabled in production/u);
  }
});

test("production health checks use validated configured hosts and the configured OIDC issuer", { skip: process.platform === "win32" ? "The local Windows bash launcher has no available WSL distribution; CI runs native Bash." : false }, () => {
  const validatorStart = serverScript.indexOf("is_valid_dns_hostname() {");
  const validatorEnd = serverScript.indexOf("\n}\n", validatorStart);
  const start = serverScript.indexOf("assert_health() {");
  const end = serverScript.indexOf("\n}\n", start);
  assert.ok(validatorStart >= 0 && validatorEnd > validatorStart);
  assert.ok(start >= 0 && end > start);
  const validator = serverScript.slice(validatorStart, validatorEnd + 2);
  const health = serverScript.slice(start, end);

  assert.match(health, /is_valid_dns_hostname "\$portal_hostname" && is_valid_dns_hostname "\$hub_hostname"/u);
  const hostnames = [
    "portal.biel.dev.br",
    "preview-1.example.test",
    "bad..example.com",
    "-bad.example.com",
    "bad-.example.com",
    `${"a".repeat(64)}.example.com`,
    `${"a.".repeat(126)}aa`,
    "valid.example.com\r\nInjected: yes",
  ];
  const bash = spawnSync("bash", ["-c", `${validator}\nfor hostname in "$@"; do if is_valid_dns_hostname "$hostname"; then printf 'Y\\n'; else printf 'N\\n'; fi; done`, "virki-hostname-test", ...hostnames], { encoding: "utf8" });
  assert.equal(bash.status, 0, bash.stderr);
  assert.deepEqual(bash.stdout.trim().split(/\r?\n/u), ["Y", "Y", "N", "N", "N", "N", "N", "N"]);
  assert.match(health, /VIRKI_PORTAL_HOSTNAME/u);
  assert.match(health, /VIRKI_HUB_HOSTNAME/u);
  assert.match(health, /VIRKI_OIDC_ISSUER/u);
  assert.match(health, /"https:\/\/\$portal_hostname"/u);
  assert.match(health, /Host: \$portal_hostname/u);
  assert.match(health, /Host: \$hub_hostname/u);
  assert.doesNotMatch(health, /portal\.biel\.dev\.br|hub\.biel\.dev\.br/u);
});

test("ADMIN health probes fail closed for the effective native or Access perimeter", { skip: process.platform === "win32" ? "Requires a Bash operator fixture; Linux CI runs it." : false }, () => {
  const validatorStart = serverScript.indexOf("is_valid_dns_hostname() {");
  const healthStart = serverScript.indexOf("assert_health() {");
  assert.ok(validatorStart >= 0 && healthStart >= 0);
  const validator = serverScript.slice(validatorStart, serverScript.indexOf("\n}\n", validatorStart) + 2);
  const health = serverScript.slice(healthStart, serverScript.indexOf("\n}\n", healthStart) + 2);
  const bashFixture = String.raw`
set -euo pipefail
fail() { printf 'DENIED:%s\n' "$1" >&2; exit 80; }
compose() {
  if [[ "$1" == port ]]; then
    if [[ "$2" == public-site ]]; then printf '127.0.0.1:13000'; return; fi
    if [[ "$2" == hub ]]; then printf '127.0.0.1:13001'; return; fi
  fi
  if [[ "$1" == exec ]]; then
    case "$*" in
      *VIRKI_PORTAL_HOSTNAME*) printf 'portal.example.test'; return ;;
      *VIRKI_HUB_HOSTNAME*) printf 'hub.example.test'; return ;;
      *VIRKI_OIDC_ISSUER*) printf 'https://portal.example.test'; return ;;
      *VIRKI_HUB_PERIMETER_MODE*) printf '%s' "$VIRKI_TEST_MODE"; return ;;
    esac
  fi
  fail 'Unexpected Compose invocation'
}
curl() {
  local args="$*"
  if [[ "$args" == *'/admin/accounts'* ]]; then
    [[ "$args" == *'cf-access-jwt-assertion: forged-staging-probe'* ]] || fail 'Missing forged assertion probe'
    printf 'HTTP/1.1 %s Test\r\nLocation: %s\r\n\r\n\nVIRKI_STATUS:%s' "$VIRKI_TEST_ADMIN_STATUS" "$VIRKI_TEST_REDIRECT" "$VIRKI_TEST_ADMIN_STATUS"
  elif [[ "$args" == *'/api/health'* ]]; then
    printf 'HTTP/1.1 200 OK\r\n\r\n\nVIRKI_STATUS:200'
  elif [[ "$args" == *'/.well-known/openid-configuration'* ]]; then
    printf 'HTTP/1.1 200 OK\r\n\r\n{"issuer":"https://portal.example.test","code_challenge_methods_supported":["S256"],"response_types_supported":["code"]}\nVIRKI_STATUS:200'
  else
    printf 'HTTP/1.1 200 OK\r\n\r\n\nVIRKI_STATUS:200'
  fi
}
assert_production_response_headers() { :; }
${validator}
${health}
assert_health
`;
  const expected = "https://hub.example.test/login?returnTo=%2Fadmin%2Faccounts";
  for (const { mode, status, location, allowed } of [
    { mode: "access", status: "403", location: "", allowed: true },
    { mode: "", status: "403", location: "", allowed: true },
    { mode: "not-native", status: "403", location: "", allowed: true },
    { mode: "native", status: "307", location: expected, allowed: true },
    { mode: "native", status: "403", location: "", allowed: false },
    { mode: "native", status: "302", location: expected, allowed: false },
    { mode: "native", status: "307", location: "", allowed: false },
    { mode: "access", status: "307", location: expected, allowed: false },
    { mode: "native", status: "307", location: "https://attacker.invalid/login?returnTo=%2Fadmin%2Faccounts", allowed: false },
    { mode: "native", status: "307", location: "https://hub.example.test/login?returnTo=%2Fadmin%2Fsecurity", allowed: false },
    { mode: "native", status: "307", location: `${expected}\r\nLocation: ${expected}`, allowed: false },
    { mode: "native", status: "307", location: `${expected}\r\n\r\nHTTP/1.1 403 Forbidden\r\nLocation: https://attacker.invalid`, allowed: false },
  ]) {
    const result = spawnSync("bash", ["-c", bashFixture], {
      encoding: "utf8",
      env: {
        PATH: process.env.PATH ?? "/usr/bin:/bin",
        VIRKI_TEST_MODE: mode,
        VIRKI_TEST_ADMIN_STATUS: status,
        VIRKI_TEST_REDIRECT: location,
      },
    });
    assert.equal(result.status === 0, allowed, `mode=${mode} status=${status} location=${location}: ${result.stderr}`);
  }
});

test("temporary dual-Codex task notes stay out of source and Docker archives", () => {
  const gitignore = readFileSync(new URL("../.gitignore", import.meta.url), "utf8");
  const dockerignore = readFileSync(new URL("../.dockerignore", import.meta.url), "utf8");
  assert.match(gitignore, /^\/\.dual-codex-task-\*\.md$/mu);
  assert.match(dockerignore, /^\/\.dual-codex-task-\*\.md$/mu);
});


test("restore-clone migration ledger reads use the migrator role, never runtime", () => {
  const namesStart = serverScript.indexOf("migration_history_names() {");
  const namesEnd = serverScript.indexOf("\nmigration_history_summary() {", namesStart);
  const summaryStart = namesEnd + 1;
  const summaryEnd = serverScript.indexOf("\nmigration_history_is_clean_baseline() {", summaryStart);
  assert.ok(namesStart >= 0 && namesEnd > namesStart && summaryEnd > summaryStart);
  const namesFunction = serverScript.slice(namesStart, namesEnd);
  const summaryFunction = serverScript.slice(summaryStart, summaryEnd);
  assert.match(namesFunction, /clone_migration_query "\$container" "\$sql"/u);
  assert.match(summaryFunction, /clone_migration_query "\$container" "\$sql"/u);
  assert.doesNotMatch(namesFunction, /clone_query "\$container" "\$sql"/u);
  assert.doesNotMatch(summaryFunction, /clone_query "\$container" "\$sql"/u);
});

test("database role initialization allows every Prisma model and enum after migration", () => {
  const roleInitializer = readFileSync(new URL("../infra/postgres-init/10-virki-database-roles.sh", import.meta.url), "utf8");
  const prismaSchema = readFileSync(new URL("../packages/database/prisma/schema.prisma", import.meta.url), "utf8");
  const allowedRelations = roleInitializer.match(/relation\.relname NOT IN \(([\s\S]*?)\)/u)?.[1] ?? "";
  const allowedTypes = roleInitializer.match(/type\.typname NOT IN \(([\s\S]*?)\)/u)?.[1] ?? "";
  const models = [...prismaSchema.matchAll(/^model\s+(\w+)\s+\{/gmu)].map((match) => match[1]);
  const enums = [...prismaSchema.matchAll(/^enum\s+(\w+)\s+\{/gmu)].map((match) => match[1]);

  for (const model of models) assert.ok(allowedRelations.includes(`'${model}'`), `Database role guard must allow Prisma model ${model}.`);
  for (const enumName of enums) assert.ok(allowedTypes.includes(`'${enumName}'`), `Database role guard must allow Prisma enum ${enumName}.`);
});
