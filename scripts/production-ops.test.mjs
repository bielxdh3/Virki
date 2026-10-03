import assert from "node:assert/strict";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { deployProduction } from "./deploy-production.mjs";
import { isValidProductionConfig } from "./lib/production-config.mjs";
import { runProductionPreflight } from "./production-preflight.mjs";

const revision = "0123456789abcdef0123456789abcdef01234567";
const config = {
  sshAlias: "test-production",
  host: "production.example.invalid",
  port: "2222",
  root: "/srv/bielos",
};
const preflightScript = readFileSync(new URL("./production-preflight.mjs", import.meta.url), "utf8");
const serverScript = readFileSync(new URL("./production-server.sh", import.meta.url), "utf8");
const deploymentScript = readFileSync(new URL("./deploy-production.mjs", import.meta.url), "utf8");

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
        return { status: 0, stdout: "BIELOS_PROBE_ID=host\nBIELOS_PROBE_WD=/srv/bielos\nBIELOS_PROBE_PLATFORM=linux-native\nBIELOS_PROBE_MARKER=valid\n" };
      }
      return { status: 0, stdout: "BIELOS_DOCKER_VERSION=29\nBIELOS_DOCKER_INFO=29\nBIELOS_COMPOSE_VERSION=2\nBIELOS_PLATFORM=linux/amd64\nBIELOS_FLOCK=available\nBIELOS_DISK_FREE_GB=100\nBIELOS_DEMANAGE_COUNT=2\n" };
    },
  });

  assert.equal(result.status, 0);
  assert.equal(result.platform, "linux/amd64");
  assert.equal(remoteCalls, 9);
  assert.ok(result.lines.some((line) => line.includes("8/8")));
  assert.ok(result.lines.every((line) => !line.includes(config.host)));
  assert.equal(isValidProductionConfig({ ...config, root: "C:\\BielOS" }), false);
});

test("preflight stops at a missing native host marker without trying Docker", async () => {
  let remoteCalls = 0;
  const result = await runProductionPreflight({
    config,
    sleep: async () => {},
    execute: (command, args) => {
      if (args[0] === "-G") return { status: 0, stdout: `user deploy\nhostname ${config.host}\nport ${config.port}\n` };
      remoteCalls += 1;
      return { status: 1, stdout: "" };
    },
  });
  assert.equal(result.status, 1);
  assert.equal(remoteCalls, 1);
  assert.ok(result.lines[0].includes("marker was not verified"));
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
        return { status: 0, stdout: "BIELOS_PROBE_ID=host\nBIELOS_PROBE_WD=/srv/bielos\nBIELOS_PROBE_PLATFORM=linux-native\nBIELOS_PROBE_MARKER=valid\n" };
      }
      return { status: 0, stdout: "BIELOS_DOCKER_VERSION=29\nBIELOS_DOCKER_INFO=29\nBIELOS_COMPOSE_VERSION=2\nBIELOS_PLATFORM=linux/amd64\nBIELOS_DISK_FREE_GB=100\nBIELOS_DEMANAGE_COUNT=2\n" };
    },
  });
  assert.equal(result.status, 1);
  assert.equal(remoteCalls, 9);
  assert.ok(result.lines.at(-1).includes("locking"));
});

test("Linux source lifecycle keeps host identity pre-provisioned and secrets remote-only", () => {
  assert.match(serverScript, /grep -Fxq 'protocol=2' "\$marker_path"/u);
  assert.doesNotMatch(serverScript, /printf .{0,100}role=production.{0,100}protocol=2|Set-Content.*bielos-production-host/u);
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
  assert.match(serverScript, /prisma migrate status/u);
  assert.match(serverScript, /encrypted recovery outbox payload or delivery-attempt metadata/u);
  assert.match(serverScript, /docker rm --force --volumes "\$container_id"/u);
  assert.doesNotMatch(serverScript, /\bcompose[^\n]*\bdown\b|docker volume rm|prisma db push|powershell/i);
  assert.match(serverScript, /readonly lock_path="\$root\/\.bielos-operations\.lock"/u);
  assert.match(serverScript, /flock -n "\$state_lock_fd"/u);
  assert.match(serverScript, /state_changing_actions='[^']*install-source cleanup-deploy-staging deploy start restart start-tunnel stop maintenance-on maintenance-off backup-verify audit-cleanup sessions-cleanup/u);
  assert.match(serverScript, /tar --list --verbose --quoting-style=c --file "\$archive"/u);
  assert.match(serverScript, /Source archive contains a link or unsupported filesystem entry/u);
  assert.match(serverScript, /find "\$stage" -type l -print -quit/u);
  assert.match(serverScript, /current .bielos-release .bielos-production-host/u);
  const cleanupDispatch = serverScript.indexOf('if [[ "$action" == cleanup-deploy-staging ]]; then');
  assert.ok(cleanupDispatch >= 0);
  assert.match(serverScript.slice(cleanupDispatch), /verify_cleanup_target \|\| fail[\s\S]*?acquire_state_lock[\s\S]*?cleanup_deploy_staging "\$revision" "\$archive_id"/u);
  const dispatch = serverScript.indexOf('if [[ "$action" == install-source || "$action" == deploy ]]; then\n  trap \'cleanup_failed_deploy "$?"\' EXIT\nfi');
  assert.ok(dispatch >= 0);
  assert.ok(serverScript.slice(dispatch).includes([
    'if [[ "$action" == install-source || "$action" == deploy ]]; then',
    '  trap \'cleanup_failed_deploy "$?"\' EXIT',
    "fi",
    "verify_host",
  ].join("\n")));
  const stateLock = serverScript.indexOf('if [[ "$state_changing_actions" == *" $action "* ]]; then acquire_state_lock; fi', dispatch);
  const stagingCleanup = serverScript.slice(serverScript.indexOf("cleanup_deploy_staging() {"), serverScript.indexOf("\ncleanup_failed_deploy() {"));
  assert.match(stagingCleanup, /source-\$expected_revision-\$staging_id\.tar[\s\S]*?images-\$expected_revision-\$staging_id\.tar\.gz[\s\S]*?\[\[ -f "\$path" && ! -L "\$path" \]\][\s\S]*?\(\(cleanup_failed == 0\)\)/u);
  assert.match(serverScript, /cleanup_failed_deploy\(\)[\s\S]*?cleanup_deploy_staging "\$revision" "\$archive_id"[\s\S]*?Deployment staging cleanup could not be confirmed/u);
  assert.match(serverScript, /if \[\[ "\$action" == cleanup-deploy-staging \]\]; then[\s\S]*?cleanup_deploy_staging "\$revision" "\$archive_id"/u);
  assert.match(deploymentScript, /cleanupAfterFailure\(error, source\.revision, archiveId, sourceCode, config, execute\)/u);
  assert.equal((deploymentScript.match(/cleanupAfterFailure\(error, source\.revision, archiveId, sourceCode, config, execute\)/gu) ?? []).length, 2);
  const deployStage = serverScript.indexOf('if [[ "$action" == deploy ]]; then\n  load_production_images\n  install_source\nfi', stateLock);
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

test("production Compose uses the exact loaded runtime and migration image tags", () => {
  assert.match(serverScript, /--project-directory "\$source_dir\/infra"/u);
  const compose = readFileSync(new URL("../infra/docker-compose.prod.yml", import.meta.url), "utf8");
  assert.match(compose, /image: \$\{BIELOS_PRODUCTION_IMAGE:\?/u);
  assert.match(compose, /image: \$\{BIELOS_MIGRATOR_IMAGE:\?/u);
  assert.match(compose, /pull_policy: never/u);
  assert.doesNotMatch(compose, /^\s+build:/mu);
  assert.match(serverScript, /export BIELOS_PRODUCTION_IMAGE="bielos-production-ci:\$revision"/u);
  assert.match(serverScript, /export BIELOS_MIGRATOR_IMAGE="bielos-migrator-ci:\$revision"/u);
});

test("routed services start only after app checks, and failure cleanup preserves PostgreSQL", () => {
  const resumeStart = serverScript.indexOf("resume_services() {");
  const resumeEnd = serverScript.indexOf("\ninstall_source() {", resumeStart);
  const resume = serverScript.slice(resumeStart, resumeEnd);
  const resumeMigrationStatus = resume.indexOf("run_migration_status");
  const resumeSchemaValidation = resume.indexOf("verify_migration_schema", resumeMigrationStatus);
  const resumeSourceActivation = resume.indexOf("activate_source", resumeSchemaValidation);
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

test("restore clone and migration runner use an isolated password-protected internal network", () => {
  assert.match(serverScript, /docker network create --internal --label "bielos\.restore\.operation=\$isolation_id" "\$db_network"/u);
  assert.match(serverScript, /local -x POSTGRES_PASSWORD="\$password"[\s\S]*?--env POSTGRES_PASSWORD/u);
  assert.match(serverScript, /password=\$\(od -An -N32 -tx1 \/dev\/urandom/u);
  assert.match(serverScript, /services:[\s\S]*?migrate:[\s\S]*?networks:[\s\S]*?- restore/u);
  assert.match(serverScript, /external: true[\s\S]*?name: %s/u);
  assert.match(serverScript, /compose_with_override "\$override" --profile migration run --rm --no-deps --name "\$migration_container" --label "bielos\.restore\.operation=\$isolation_id"/u);
  assert.doesNotMatch(serverScript, /bielos-prod_default|POSTGRES_HOST_AUTH_METHOD=trust/u);

  assert.match(serverScript, /verify_clone_cleanup\(\)[\s\S]*?docker ps --all --filter "label=bielos\.restore\.operation=\$isolation_id"[\s\S]*?docker network ls --filter "label=bielos\.restore\.operation=\$isolation_id"/u);
  const backup = serverScript.slice(serverScript.indexOf("create_verified_backup() {"), serverScript.indexOf("\nassert_backup_verified() {"));
  const cloneCleanup = serverScript.slice(serverScript.indexOf("cleanup_clone() {"), serverScript.indexOf("\nverify_clone_cleanup() {"));
  assert.match(cloneCleanup, /docker ps --all --quiet --filter "label=bielos\.restore\.operation=\$isolation_id"[\s\S]*?docker rm --force --volumes "\$container_id"[\s\S]*?docker network rm "\$network_id"[\s\S]*?return "\$cleanup_failed"/u);
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
  const resolve = normalizer.indexOf("migrate resolve --applied 0_init");
  const exactResolvedState = normalizer.indexOf("state" , resolve);
  const guardedPrune = prune.indexOf("actual_names <> '$expected_names'");
  const deleteRows = prune.indexOf('DELETE FROM "_prisma_migrations" WHERE "migration_name" <> \'0_init\'');
  assert.ok(resolve >= 0 && exactResolvedState > resolve && guardedPrune >= 0 && deleteRows > guardedPrune);
  assert.ok(prune.includes("DO \\$bielos\\$"));
  assert.match(prune, /"finished_at" IS NULL OR "rolled_back_at" IS NOT NULL/u);

  const cloneStart = serverScript.indexOf("run_clone_migrations() {");
  const cloneEnd = serverScript.indexOf("\ncleanup_clone()", cloneStart);
  const clone = serverScript.slice(cloneStart, cloneEnd);
  assert.ok(clone.indexOf("normalize_migration_history") < clone.indexOf('migrate\n'));
  assert.ok(clone.indexOf('migrate\n') < clone.indexOf('migrate npx prisma migrate status'));
  assert.ok(clone.indexOf('migrate npx prisma migrate status') < clone.indexOf("verify_migration_schema"));

  const applyStart = serverScript.indexOf("apply_production_migrations() {");
  const applyEnd = serverScript.indexOf("\nassert_no_maintenance()", applyStart);
  const apply = serverScript.slice(applyStart, applyEnd);
  assert.ok(apply.indexOf("assert_backup_verified") < apply.indexOf("normalize_migration_history"));
  assert.ok(apply.indexOf("normalize_migration_history") < apply.indexOf("compose --profile migration run --rm --no-deps migrate"));
  assert.ok(apply.indexOf("compose --profile migration run --rm --no-deps migrate") < apply.indexOf("run_migration_status"));
  assert.ok(apply.indexOf("run_migration_status") < apply.indexOf("verify_migration_schema"));
  assert.match(serverScript, /migrate diff --from-schema-datasource "\$migration_schema" --to-schema-datamodel "\$migration_schema" --exit-code/u);
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
  for (const field of [
    '"id"', '"kind"', '"recipientEmail"', '"locale"', '"payload"', '"status"', '"attemptCount"',
    '"availableAt"', '"sentAt"', '"terminalFailedAt"', '"createdAt"', '"updatedAt"',
  ]) {
    assert.ok(messageProjection.includes(field), `Recovery snapshots must preserve the ${field} field.`);
  }

  assert.match(serverScript, /before_recovery=\$\(recovery_snapshot "\$container" before_migrations\)/u);
  assert.match(serverScript, /after_recovery=\$\(recovery_snapshot "\$container" after_migrations\)/u);
  assert.match(serverScript, /before_recovery=\$\(recovery_snapshot "" before_migrations\)/u);
  assert.match(serverScript, /after_recovery=\$\(recovery_snapshot "" after_migrations\)/u);
});

test("deployment downloads the exact-SHA tested images after preflight and transfers both verified artifacts", async () => {
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
    execute: (command, args, options = {}) => {
      sequence.push(command === "ssh" ? "ssh" : `${command}:${args[0]}`);
      if (command === "git") assert.equal(options.env?.GIT_NO_REPLACE_OBJECTS, "1");
      if (command === "git" && args[0] === "archive") {
        archivePath = args.find((value) => value.startsWith("--output=")).slice("--output=".length);
        writeFileSync(archivePath, "tracked source archive");
        return { status: 0, stdout: "" };
      }
      if (command === "git" && args[0] === "ls-tree") {
        return {
          status: 0,
          stdout: "100644 blob " + revision + "\tREADME.md\0" + "100644 blob " + revision + "\tscripts/production-server.sh\0",
        };
      }
      if (command === "git" && args[0] === "check-attr") {
        const attributes = [];
        for (const sourcePath of options.input.split("\0").filter(Boolean)) {
          attributes.push(sourcePath, "export-ignore", "unspecified", sourcePath, "export-subst", "unspecified");
        }
        return { status: 0, stdout: attributes.join("\0") + "\0" };
      }
      if (command === "git" && args[0] === "show") return { status: 0, stdout: serverScript };
      if (command === "tar") return { status: 0, stdout: "README.md\nscripts/production-server.sh\n" };
      if (command === "gh" && args[0] === "run" && args[1] === "download") {
        assert.equal(args[2], "54321");
        assert.equal(args[args.indexOf("--repo") + 1], "bielxdh3/BielOS");
        assert.equal(args[args.indexOf("--name") + 1], `bielos-production-images-${revision}-linux-amd64`);
        const targetDirectory = args[args.indexOf("--dir") + 1];
        imageArchivePath = path.join(targetDirectory, "bielos-production-images.tar.gz");
        writeFileSync(imageArchivePath, "gzip image archive");
        return { status: 0, stdout: "" };
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
          assert.match(remotePath, new RegExp(`images-${revision}-${archiveId}\\.tar\\.gz$`, "u"));
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
  assert.deepEqual(sequence.slice(0, 6), ["source", "ci", "git:archive", "git:ls-tree", "git:check-attr", "tar:-tf"]);
  assert.ok(sequence.indexOf("preflight") < sequence.indexOf("gh:run"));
  assert.ok(sequence.indexOf("gh:run") < sequence.findIndex((item) => item.startsWith("scp:")));
  assert.equal(sequence.filter((item) => item.startsWith("scp:")).length, 2);
  assert.equal(sequence.filter((item) => item === "ssh").length, 1);
  assert.equal(existsSync(path.dirname(archivePath)), false);
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
          if (command === "git" && args[0] === "show") return { status: 0, stdout: serverScript };
          if (command === "tar") return { status: 0, stdout: "README.md\n" };
          if (command === "gh") {
            const targetDirectory = args[args.indexOf("--dir") + 1];
            imageArchivePath = path.join(targetDirectory, "bielos-production-images.tar.gz");
            writeFileSync(imageArchivePath, "gzip image archive");
            return { status: 0, stdout: "" };
          }
          if (command === "scp") {
            if (args.at(-2) === archivePath) {
              const remotePath = args.at(-1).split(":").at(-1);
              archiveId = remotePath.match(new RegExp(`source-${revision}-([a-f0-9]{24})\\.tar$`, "u"))?.[1];
              assert.ok(archiveId);
              return { status: 0, stdout: "" };
            }
            assert.equal(args.at(-2), imageArchivePath);
            assert.match(args.at(-1), new RegExp(`images-${revision}-${archiveId}\\.tar\\.gz$`, "u"));
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

test("a secret path in the Git archive blocks transfer and production contact", async () => {
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
        return { status: 0, stdout: "100644 blob " + revision + "\tapps/.env\0" };
      }
      if (command === "git" && args[0] === "show") return { status: 0, stdout: serverScript };
      if (command === "tar") return { status: 0, stdout: "README.md\napps/.env\n" };
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
        return { status: 0, stdout: "120000 blob " + revision + "\t.bielos-release\0" };
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
