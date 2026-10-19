import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { setTimeout as delay } from "node:timers/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const roleSetupPath = path.join(repositoryRoot, "infra", "postgres-init", "10-virki-database-roles.sh");
const e2eRoleSetupPath = path.join(repositoryRoot, "scripts", "e2e", "20-virki-e2e-runtime-test-role.sh");
const postgresImage = "postgres:17@sha256:2d2b8998d31037bf721cfdf764d76ba74171b4fab3431b7f72c27c56ddbdf9e3";
const testRunId = randomBytes(12).toString("hex");

let migrationRunner;
let failure;
try {
  migrationRunner = buildMigrationRunner(testRunId);
  await verifyDatabaseRoles("fresh", migrationRunner, testRunId);
  await verifyDatabaseRoles("interrupted", migrationRunner, testRunId);
  await verifyDatabaseRoles("populated", migrationRunner, testRunId);
} catch (error) {
  failure = error;
}

if (migrationRunner) {
  try {
    removeMigrationRunner(migrationRunner, testRunId);
  } catch (cleanupError) {
    failure = failure
      ? new AggregateError([failure, cleanupError], "PostgreSQL role validation and migration-runner cleanup both failed.")
      : cleanupError;
  }
}
if (failure) throw failure;
console.log("PASS: fresh, interrupted-init, and populated disposable PostgreSQL role separation");

async function verifyDatabaseRoles(kind, migrationRunner, testRunId) {
  const suffix = randomBytes(6).toString("hex");
  const name = `virki-role-${kind}-${suffix}`;
  const network = `${name}-net`;
  const dataVolume = kind === "interrupted" ? `${name}-data` : null;
  const bootstrapPassword = randomBytes(32).toString("hex");
  const runtimePassword = randomBytes(32).toString("hex");
  let migratorPassword = randomBytes(32).toString("hex");
  while ([bootstrapPassword, runtimePassword].includes(migratorPassword)) migratorPassword = randomBytes(32).toString("hex");
  let auditMaintenancePassword = randomBytes(32).toString("hex");
  while ([bootstrapPassword, runtimePassword, migratorPassword].includes(auditMaintenancePassword)) auditMaintenancePassword = randomBytes(32).toString("hex");
  let priorMigratorPassword = randomBytes(32).toString("hex");
  while ([bootstrapPassword, runtimePassword, migratorPassword, auditMaintenancePassword].includes(priorMigratorPassword)) {
    priorMigratorPassword = randomBytes(32).toString("hex");
  }
  let e2ePassword = randomBytes(32).toString("hex");
  while ([bootstrapPassword, runtimePassword, migratorPassword, auditMaintenancePassword, priorMigratorPassword].includes(e2ePassword)) {
    e2ePassword = randomBytes(32).toString("hex");
  }
  const fixtureSecrets = {
    POSTGRES_PASSWORD: bootstrapPassword,
    VIRKI_RUNTIME_DB_PASSWORD: runtimePassword,
    VIRKI_MIGRATOR_DB_PASSWORD: migratorPassword,
    VIRKI_AUDIT_MAINTENANCE_DB_PASSWORD: auditMaintenancePassword,
    AUDIT_LOG_RETENTION_DAYS: "365",
    VIRKI_E2E_DATABASE_PASSWORD: e2ePassword
  };

  const args = [
    "create", "--name", name,
    "--network", network, "--network-alias", "postgres",
    "--label", `virki.role-test.run=${testRunId}`,
    "--label", `virki.role-test.fixture=${name}`,
    "--label", "virki.role-test.kind=postgres",
    "--health-cmd", "pg_isready -h 127.0.0.1 -U virki_bootstrap -d virki_roles_test",
    "--health-interval", "1s", "--health-timeout", "3s", "--health-retries", "60",
    "--env", "POSTGRES_HOST_AUTH_METHOD=scram-sha-256",
    "--env", "POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256",
    "--env", "POSTGRES_DB=virki_roles_test",
    "--env", "POSTGRES_USER=virki_bootstrap",
    "--env=POSTGRES_PASSWORD",
    "--env=VIRKI_RUNTIME_DB_PASSWORD",
    "--env=VIRKI_MIGRATOR_DB_PASSWORD",
    "--env=VIRKI_AUDIT_MAINTENANCE_DB_PASSWORD",
    "--env=AUDIT_LOG_RETENTION_DAYS",
    "--env=VIRKI_E2E_DATABASE_PASSWORD"
  ];
  if (dataVolume) args.push("--mount", `type=volume,source=${dataVolume},target=/var/lib/postgresql/data`);
  else args.push("--tmpfs", "/var/lib/postgresql/data:rw,noexec,nosuid,nodev,size=512m");
  args.push(postgresImage);
  const roleSetupContainerPath = kind === "fresh" || kind === "interrupted"
    ? "/docker-entrypoint-initdb.d/10-virki-database-roles.sh"
    : "/test/10-virki-database-roles.sh";
  const e2eRoleSetupContainerPath = kind === "fresh" || kind === "interrupted"
    ? "/docker-entrypoint-initdb.d/20-virki-e2e-runtime-test-role.sh"
    : "/test/20-virki-e2e-runtime-test-role.sh";
  const initializerFiles = [
    [roleSetupPath, roleSetupContainerPath],
    [e2eRoleSetupPath, e2eRoleSetupContainerPath]
  ];

  let failure;
  try {
    const networkStart = docker([
      "network", "create", "--internal",
      "--label", `virki.role-test.run=${testRunId}`,
      "--label", `virki.role-test.fixture=${name}`,
      network
    ], `create ${kind} isolated PostgreSQL fixture network`);
    assert.ok(networkStart.stdout.trim(), `Could not create the ${kind} isolated PostgreSQL fixture network.`);
    assertFixtureNetwork(network, testRunId, name);
    if (dataVolume) {
      const volumeStart = docker([
        "volume", "create",
        "--label", `virki.role-test.run=${testRunId}`,
        "--label", `virki.role-test.fixture=${name}`,
        dataVolume
      ], `create ${kind} isolated PostgreSQL data volume`);
      assert.equal(volumeStart.stdout.trim(), dataVolume, "The interrupted-init fixture must create only its uniquely named data volume.");
      assertFixtureVolume(dataVolume, testRunId, name);
    }

    const initialSecrets = fixtureSecrets;
    const create = docker(args, `create ${kind} PostgreSQL fixture`, { env: initialSecrets });
    assert.ok(create.stdout.trim(), `Could not create the ${kind} disposable PostgreSQL fixture.`);
    if (kind === "populated") {
      const start = docker(["start", name], `start ${kind} PostgreSQL fixture`);
      assert.equal(start.status, 0, `Could not start the ${kind} disposable PostgreSQL fixture.`);
      docker(["exec", name, "mkdir", "-m", "0700", "/test"], "create private PostgreSQL fixture initializer directory");
      for (const [source, destination] of initializerFiles) {
        docker(["cp", source, `${name}:${destination}`], `copy reviewed ${kind} PostgreSQL initializer`);
      }
    } else {
      for (const [source, destination] of initializerFiles) {
        docker(["cp", source, `${name}:${destination}`], `copy reviewed ${kind} PostgreSQL initializer`);
      }
      const start = docker(["start", name], `start ${kind} PostgreSQL fixture`);
      assert.equal(start.status, 0, `Could not start the ${kind} disposable PostgreSQL fixture.`);
    }
    assertFixtureContainer(name, network, testRunId, name, "postgres");
    await waitForHealthy(name, fixtureSecrets);
    assertPostgresFixtureMounts(name, kind, dataVolume);
    const hostAuthMethods = runPsql(name, "virki_bootstrap", bootstrapPassword, "SELECT string_agg(auth_method, ',' ORDER BY line_number) FROM pg_hba_file_rules WHERE type = 'host';", "verify PostgreSQL fixture uses password authentication for TCP");
    assert.match(hostAuthMethods.trim(), /(?:^|,)scram-sha-256(?:,|$)/u, "PostgreSQL fixture must exercise SCRAM password authentication over TCP.");
    assert.doesNotMatch(hostAuthMethods.trim(), /(?:^|,)trust(?:,|$)/u, "PostgreSQL fixture must never accept unauthenticated TCP connections.");
    const bootstrapUrl = connectionUrl("virki_bootstrap", bootstrapPassword);
    const migratorUrl = connectionUrl("virki_migrator", migratorPassword);
    runPsql(name, "virki_bootstrap", bootstrapPassword, "CREATE ROLE virki_connect_probe NOLOGIN;", "prepare unprivileged database connection probe");

    if (kind === "interrupted") {
      assert.equal(runPsql(name, "virki_migrator", migratorPassword, "SELECT current_user;", "verify configured migrator credential before seeding the stale-volume fixture").trim(), "virki_migrator");
      const seedPriorCredential = docker([
        "exec", "--interactive", "--env=VIRKI_TEST_MIGRATOR_PASSWORD", name,
        "psql", "--no-psqlrc", "--username", "virki_bootstrap", "--dbname", "virki_roles_test",
        "--set", "ON_ERROR_STOP=1"
      ], "seed a stale persisted migrator credential in the disposable fixture", {
        env: { VIRKI_TEST_MIGRATOR_PASSWORD: priorMigratorPassword },
        input: "\\getenv prior_migrator_password VIRKI_TEST_MIGRATOR_PASSWORD\nALTER ROLE virki_migrator PASSWORD :'prior_migrator_password';\n"
      });
      assert.equal(seedPriorCredential.status, 0, "Could not seed the known stale migrator credential in the disposable fixture.");
      assert.equal(runPsql(name, "virki_migrator", priorMigratorPassword, "SELECT current_user;", "prove the prior migrator credential authenticates over TCP").trim(), "virki_migrator");
      const configuredBeforeRecreate = runPsql(name, "virki_migrator", migratorPassword, "SELECT current_user;", "reject the configured migrator credential against the known stale database credential", { allowFailure: true });
      assert.notEqual(configuredBeforeRecreate.status, 0, "The configured migrator credential must fail against the deliberately stale persisted credential.");
      assert.match(configuredBeforeRecreate.stderr ?? "", /password authentication failed/u, "The stale configured credential must fail at PostgreSQL TCP authentication.");
      runPsql(name, "virki_bootstrap", bootstrapPassword, "ALTER ROLE virki_runtime NOLOGIN;", "seed an interrupted role initializer state");
      assertFixtureVolume(dataVolume, testRunId, name);
      const stopped = docker(["stop", name], "stop the initialized PostgreSQL fixture before container recreation");
      assert.equal(stopped.stdout.trim(), name, "The initialized PostgreSQL fixture must stop by its exact name.");
      assertFixtureContainerIdentity(name, testRunId, name, "postgres");
      const removed = docker(["rm", name], "remove only the initialized PostgreSQL fixture container");
      assert.equal(removed.stdout.replace(/^\//u, "").trim(), name, "The exact initialized PostgreSQL fixture container must be removed while preserving its data volume.");
      assert.equal(docker(["ps", "--all", "--quiet", "--filter", `name=^/${name}$`], "verify PostgreSQL fixture container removal").stdout.trim(), "", "The old PostgreSQL fixture container must be absent before recreation.");
      assertFixtureVolume(dataVolume, testRunId, name);
      assert.equal(docker(["ps", "--all", "--quiet", "--filter", `volume=${dataVolume}`], "verify persistent test volume has no consumer before recreation").stdout.trim(), "", "The retained PostgreSQL fixture volume must have no consumer before recreation.");
      const recreated = docker(args, "recreate PostgreSQL fixture against initialized PGDATA", { env: fixtureSecrets });
      assert.equal(recreated.status, 0, "Could not recreate the PostgreSQL fixture against its initialized data volume.");
      assertFixtureContainer(name, network, testRunId, name, "postgres");
      for (const [source, destination] of initializerFiles) {
        docker(["cp", source, `${name}:${destination}`], `copy reviewed ${kind} PostgreSQL initializer after container recreation`);
      }
      const started = docker(["start", name], "start PostgreSQL fixture after container recreation");
      assert.equal(started.stdout.trim(), name, "The recreated PostgreSQL fixture must start before its health check.");
      await waitForHealthy(name, fixtureSecrets);
      assertPostgresFixtureMounts(name, kind, dataVolume);
      const partialRole = runPsql(name, "virki_bootstrap", bootstrapPassword, "SELECT rolcanlogin FROM pg_roles WHERE rolname = 'virki_runtime';", "inspect partial runtime role");
      assert.equal(partialRole.trim(), "f", "The interrupted initializer fixture must retain its deliberately incomplete role.");
      assert.equal(runPsql(name, "virki_migrator", priorMigratorPassword, "SELECT current_user;", "verify initialized PostgreSQL did not rerun its init hook").trim(), "virki_migrator");
      const notYetConfigured = runPsql(name, "virki_migrator", migratorPassword, "SELECT current_user;", "reject the changed configured credential before explicit reconciliation", { allowFailure: true });
      assert.notEqual(notYetConfigured.status, 0, "Recreating a container over initialized PGDATA must not silently rerun the init hook or change the stored migrator credential.");
      assert.match(notYetConfigured.stderr ?? "", /password authentication failed/u, "The changed configured credential must fail at PostgreSQL TCP authentication before reconciliation.");
      const repair = docker([
        "exec",
        "--env=VIRKI_RUNTIME_DB_PASSWORD",
        "--env=VIRKI_MIGRATOR_DB_PASSWORD",
        "--env=VIRKI_AUDIT_MAINTENANCE_DB_PASSWORD",
        name,
        "sh", roleSetupContainerPath
      ], "complete interrupted role initialization", { env: fixtureSecrets });
      assert.equal(repair.status, 0, "The idempotent role initializer could not repair the initialized fixture.");
      const repairedRole = runPsql(name, "virki_bootstrap", bootstrapPassword, "SELECT rolcanlogin FROM pg_roles WHERE rolname = 'virki_runtime';", "verify repaired runtime role");
      assert.equal(repairedRole.trim(), "t", "The initializer must restore the runtime login flag on an existing partial role.");
      assert.equal(runPsql(name, "virki_migrator", migratorPassword, "SELECT current_user;", "verify configured migrator credential authenticates over TCP after reconciliation").trim(), "virki_migrator");
      const staleCredential = runPsql(name, "virki_migrator", priorMigratorPassword, "SELECT current_user;", "reject the stale persisted migrator credential", { allowFailure: true });
      assert.notEqual(staleCredential.status, 0, "The previous migrator credential must stop authenticating after reconciliation.");
      assert.match(staleCredential.stderr ?? "", /password authentication failed/u, "The stale migrator credential must fail at PostgreSQL TCP authentication.");
    }

    if (kind === "populated") {
      runPsql(name, "virki_bootstrap", bootstrapPassword, "CREATE ROLE virki_audit_maintenance NOLOGIN;", "provision audit-maintenance role required by the audit-boundary migration");
      runMigrationsDirect(migrationRunner, network, name, testRunId, bootstrapUrl, "prepare populated legacy fixture");
      runPsql(name, "virki_bootstrap", bootstrapPassword, "CREATE ROLE virki_role_parent NOLOGIN; CREATE ROLE virki_role_child NOLOGIN; CREATE ROLE virki_runtime NOLOGIN; CREATE ROLE virki_migrator NOLOGIN; GRANT CREATE ON DATABASE virki_roles_test TO virki_migrator; GRANT virki_role_parent TO virki_runtime, virki_migrator; GRANT virki_runtime, virki_migrator TO virki_role_child;", "seed pre-existing role memberships and database DDL privilege");
      runPsql(name, "virki_bootstrap", bootstrapPassword, "GRANT TRUNCATE, REFERENCES, TRIGGER ON TABLE public.\"User\" TO virki_runtime, PUBLIC; ALTER DEFAULT PRIVILEGES FOR ROLE virki_migrator GRANT TRUNCATE ON TABLES TO virki_runtime, PUBLIC; ALTER DEFAULT PRIVILEGES FOR ROLE virki_migrator IN SCHEMA public GRANT TRUNCATE ON TABLES TO virki_runtime, PUBLIC; CREATE FUNCTION public.__virki_public_exec_probe() RETURNS integer LANGUAGE sql AS $$ SELECT 1 $$; GRANT EXECUTE ON FUNCTION public.__virki_public_exec_probe() TO PUBLIC; ALTER DEFAULT PRIVILEGES FOR ROLE virki_migrator GRANT EXECUTE ON ROUTINES TO PUBLIC; ALTER DEFAULT PRIVILEGES FOR ROLE virki_migrator IN SCHEMA public GRANT EXECUTE ON ROUTINES TO PUBLIC;", "seed excess existing and default runtime grants");
      runPsql(name, "virki_bootstrap", bootstrapPassword, "CREATE FUNCTION public.__virki_security_definer_probe() RETURNS integer LANGUAGE sql SECURITY DEFINER AS $$ SELECT 1 $$;", "seed unreviewed SECURITY DEFINER routine");
      const unsafeRoutine = docker([
        "exec",
        "--env=VIRKI_RUNTIME_DB_PASSWORD",
        "--env=VIRKI_MIGRATOR_DB_PASSWORD",
        "--env=VIRKI_AUDIT_MAINTENANCE_DB_PASSWORD",
        name,
        "sh", "/test/10-virki-database-roles.sh"
      ], "reject unreviewed SECURITY DEFINER routine", { allowFailure: true, env: fixtureSecrets });
      assert.notEqual(unsafeRoutine.status, 0, "Existing-volume transition must stop when public contains an unreviewed SECURITY DEFINER routine.");
      assert.match(unsafeRoutine.stderr ?? "", /SECURITY DEFINER routines in public schema/u, "Routine rejection must identify the manual-review requirement.");
      runPsql(name, "virki_bootstrap", bootstrapPassword, "DROP FUNCTION public.__virki_security_definer_probe();", "remove SECURITY DEFINER fixture routine");
      runPsql(name, "virki_bootstrap", bootstrapPassword, "CREATE SCHEMA IF NOT EXISTS virki_security AUTHORIZATION virki_migrator; ALTER SCHEMA virki_security OWNER TO virki_bootstrap;", "inject a deterministic role-initializer failure at the protected-schema ownership boundary");
      const interruptedProvision = docker([
        "exec",
        "--env=VIRKI_RUNTIME_DB_PASSWORD",
        "--env=VIRKI_MIGRATOR_DB_PASSWORD",
        "--env=VIRKI_AUDIT_MAINTENANCE_DB_PASSWORD",
        name,
        "sh", "/test/10-virki-database-roles.sh"
      ], "stop role provisioning at the protected-schema ownership boundary", { allowFailure: true, env: fixtureSecrets });
      assert.notEqual(interruptedProvision.status, 0, "Role provisioning must stop rather than take over a security schema owned by another role.");
      assert.match(interruptedProvision.stderr ?? "", /virki_security must be owned by virki_migrator/u, "The deterministic statement-boundary failure must identify the invalid schema owner.");
      const committedBeforeFailure = runPsql(name, "virki_bootstrap", bootstrapPassword, `SELECT
        (SELECT rolcanlogin AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication AND NOT rolbypassrls AND NOT rolinherit AND rolpassword IS NOT NULL FROM pg_roles WHERE rolname = 'virki_runtime')
        AND (SELECT rolcanlogin AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication AND NOT rolbypassrls AND NOT rolinherit AND rolpassword IS NOT NULL FROM pg_roles WHERE rolname = 'virki_migrator')
        AND has_database_privilege('virki_migrator', current_database(), 'CREATE')
        AND NOT has_database_privilege('virki_runtime', current_database(), 'CREATE')
        AND NOT EXISTS (SELECT 1 FROM pg_auth_members WHERE roleid IN (SELECT oid FROM pg_roles WHERE rolname IN ('virki_runtime', 'virki_migrator', 'virki_audit_maintenance')) OR member IN (SELECT oid FROM pg_roles WHERE rolname IN ('virki_runtime', 'virki_migrator', 'virki_audit_maintenance')));`, "inspect committed role state after the injected provisioning failure");
      assert.equal(committedBeforeFailure.trim(), "t", "Statements committed before the protected-schema boundary must remain valid and least-privileged after interruption.");
      runPsql(name, "virki_bootstrap", bootstrapPassword, "ALTER SCHEMA virki_security OWNER TO virki_migrator;", "restore the expected owner before role-provisioning convergence");
      const provision = docker([
        "exec",
        "--env=VIRKI_RUNTIME_DB_PASSWORD",
        "--env=VIRKI_MIGRATOR_DB_PASSWORD",
        "--env=VIRKI_AUDIT_MAINTENANCE_DB_PASSWORD",
        name,
        "sh", "/test/10-virki-database-roles.sh"
      ], "transition populated disposable fixture", { env: fixtureSecrets });
      assert.equal(provision.status, 0, "Could not transition the populated disposable PostgreSQL fixture.");
      assertMigrationLedgerReadDenied(name, "virki_runtime", runtimePassword, "existing-volume runtime role after migration transition");
      const e2eRole = docker([
        "exec",
        "--env=VIRKI_E2E_DATABASE_PASSWORD",
        name,
        "sh", "/test/20-virki-e2e-runtime-test-role.sh"
      ], "provision isolated E2E runtime role", { env: fixtureSecrets });
      assert.equal(e2eRole.status, 0, "Could not provision the isolated E2E runtime role.");
      assertMigrationLedgerReadDenied(name, "virki_runtime_test", e2ePassword, "existing-volume E2E role after migration transition");
      runPsql(name, "virki_bootstrap", bootstrapPassword, "GRANT virki_role_parent TO virki_runtime_test; GRANT virki_runtime_test TO virki_role_child; GRANT TRUNCATE, REFERENCES, TRIGGER ON TABLE public.\"User\" TO virki_runtime_test; CREATE SEQUENCE public.__virki_runtime_test_sequence; GRANT UPDATE ON SEQUENCE public.__virki_runtime_test_sequence TO virki_runtime_test; CREATE FUNCTION public.__virki_runtime_test_exec_probe() RETURNS integer LANGUAGE sql AS $$ SELECT 1 $$; REVOKE ALL PRIVILEGES ON FUNCTION public.__virki_runtime_test_exec_probe() FROM PUBLIC; GRANT EXECUTE ON FUNCTION public.__virki_runtime_test_exec_probe() TO virki_runtime_test; ALTER DEFAULT PRIVILEGES FOR ROLE virki_migrator GRANT TRUNCATE ON TABLES TO virki_runtime_test; ALTER DEFAULT PRIVILEGES FOR ROLE virki_migrator IN SCHEMA public GRANT TRUNCATE ON TABLES TO virki_runtime_test; ALTER DEFAULT PRIVILEGES FOR ROLE virki_migrator GRANT EXECUTE ON ROUTINES TO virki_runtime_test; ALTER DEFAULT PRIVILEGES FOR ROLE virki_migrator IN SCHEMA public GRANT EXECUTE ON ROUTINES TO virki_runtime_test;", "seed stale isolated E2E role memberships and grants");

      const publicRoutinePrivileges = runPsql(name, "virki_bootstrap", bootstrapPassword, `SELECT NOT has_function_privilege('virki_connect_probe', 'public.__virki_public_exec_probe()', 'EXECUTE');`, "inspect legacy public routine grants");
      assert.equal(publicRoutinePrivileges.trim(), "t", "Existing-volume transition must remove direct PUBLIC routine execution.");
      runPsql(name, "virki_bootstrap", bootstrapPassword, "DROP FUNCTION public.__virki_public_exec_probe();", "remove legacy routine fixture");
    }

    runPsql(name, "virki_bootstrap", bootstrapPassword, "UPDATE virki_security.audit_retention_policy SET retention_days = 180 WHERE singleton = true;", "seed a stale but valid audit retention policy before migration reconciliation");
    runMigrationsAsMigrator(migrationRunner, network, name, testRunId, migratorUrl, "apply Prisma migrations as migrator", fixtureSecrets.AUDIT_LOG_RETENTION_DAYS);
    assert.equal(runPsql(name, "virki_migrator", migratorPassword, "SELECT retention_days::text FROM virki_security.audit_retention_policy WHERE singleton = true;", "verify the migration role applies configured audit retention after schema deployment").trim(), fixtureSecrets.AUDIT_LOG_RETENTION_DAYS, "The migration wrapper must reconcile the operator-configured policy after migrations.");
    if (kind === "interrupted") {
      const stopped = docker(["stop", name], "stop PostgreSQL after migration bootstrap");
      assert.equal(stopped.stdout.trim(), name, "The PostgreSQL fixture must stop by its exact name after migration bootstrap.");
      const restarted = docker(["start", name], "restart PostgreSQL after migration bootstrap");
      assert.equal(restarted.stdout.trim(), name, "The PostgreSQL fixture must restart by its exact name after migration bootstrap.");
      await waitForHealthy(name, fixtureSecrets);
      assert.equal(runPsql(name, "virki_migrator", migratorPassword, "SELECT current_user;", "verify migrator TCP login after restart").trim(), "virki_migrator");
      runMigrationStatusAsMigrator(migrationRunner, network, name, testRunId, migratorUrl, "verify migration status after PostgreSQL restart");
    }
    if (kind === "populated") {
      const normalizeE2eRole = docker([
        "exec",
        "--env=VIRKI_E2E_DATABASE_PASSWORD",
        name,
        "sh", e2eRoleSetupContainerPath
      ], "remove stale isolated E2E privileges before the database transition", { env: fixtureSecrets });
      assert.equal(normalizeE2eRole.status, 0, "Isolated E2E privileges must be normalized before database transition checks.");
      const e2eExcessPrivileges = runPsql(name, "virki_bootstrap", bootstrapPassword, `SELECT NOT has_table_privilege('virki_runtime_test', 'public."User"', 'TRUNCATE') AND NOT has_table_privilege('virki_runtime_test', 'public."User"', 'REFERENCES') AND NOT has_table_privilege('virki_runtime_test', 'public."User"', 'TRIGGER') AND NOT has_sequence_privilege('virki_runtime_test', 'public.__virki_runtime_test_sequence', 'UPDATE') AND NOT has_function_privilege('virki_runtime_test', 'public.__virki_runtime_test_exec_probe()', 'EXECUTE');`, "inspect normalized isolated E2E privileges");
      assert.equal(e2eExcessPrivileges.trim(), "t", "The isolated E2E role must lose stale elevated object grants when reprovisioned.");
      const e2eMemberships = runPsql(name, "virki_bootstrap", bootstrapPassword, `SELECT count(*) = 0 FROM pg_auth_members WHERE roleid = (SELECT oid FROM pg_roles WHERE rolname = 'virki_runtime_test') OR member = (SELECT oid FROM pg_roles WHERE rolname = 'virki_runtime_test');`, "inspect normalized isolated E2E role memberships");
      assert.equal(e2eMemberships.trim(), "t", "The isolated E2E role must lose stale role memberships when reprovisioned.");
      runPsql(name, "virki_bootstrap", bootstrapPassword, "DROP FUNCTION public.__virki_runtime_test_exec_probe(); DROP SEQUENCE public.__virki_runtime_test_sequence;", "remove isolated E2E privilege probes before database transition");
    }

    const repeatProvision = docker([
      "exec",
      "--env=VIRKI_RUNTIME_DB_PASSWORD",
      "--env=VIRKI_MIGRATOR_DB_PASSWORD",
      "--env=VIRKI_AUDIT_MAINTENANCE_DB_PASSWORD",
      name,
      "sh", roleSetupContainerPath
    ], "repeat database role transition", { env: fixtureSecrets });
    assert.equal(repeatProvision.status, 0, "Database role transition must be safe to repeat after migrations.");
    const repeatE2eRole = docker([
      "exec",
      "--env=VIRKI_E2E_DATABASE_PASSWORD",
      name,
      "sh", e2eRoleSetupContainerPath
    ], "repeat isolated E2E role provisioning", { env: fixtureSecrets });
    assert.equal(repeatE2eRole.status, 0, "Isolated E2E runtime role provisioning must be safe to repeat.");
    runPsql(name, "virki_migrator", migratorPassword, "BEGIN; ALTER TABLE public.\"User\" ADD COLUMN \"__virkiRoleProbe\" TEXT; ALTER TABLE public.\"User\" DROP COLUMN \"__virkiRoleProbe\"; ROLLBACK;", "migrator can alter migrated objects");

    const rolePolicy = runPsql(name, "virki_bootstrap", bootstrapPassword, `SELECT count(*) = 4 AND bool_and(NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication AND NOT rolbypassrls AND NOT rolinherit) FROM pg_roles WHERE rolname IN ('virki_runtime', 'virki_migrator', 'virki_runtime_test', 'virki_audit_maintenance');`, "inspect restricted database roles");
    assert.equal(rolePolicy.trim(), "t", "Runtime, migrator, isolated E2E, and audit-maintenance roles must not have privileged attributes or inheritance.");

    const memberships = runPsql(name, "virki_bootstrap", bootstrapPassword, `SELECT count(*) = 0 FROM pg_auth_members WHERE roleid IN (SELECT oid FROM pg_roles WHERE rolname IN ('virki_runtime', 'virki_migrator', 'virki_runtime_test', 'virki_audit_maintenance')) OR member IN (SELECT oid FROM pg_roles WHERE rolname IN ('virki_runtime', 'virki_migrator', 'virki_runtime_test', 'virki_audit_maintenance'));`, "inspect role memberships");
    assert.equal(memberships.trim(), "t", "Application roles must not have role memberships.");

    const publicConnect = runPsql(name, "virki_bootstrap", bootstrapPassword, `SELECT NOT has_database_privilege('virki_connect_probe', current_database(), 'CONNECT') AND NOT has_table_privilege('virki_connect_probe', 'public."User"', 'TRUNCATE') AND NOT EXISTS (SELECT 1 FROM pg_database AS db_entry CROSS JOIN LATERAL aclexplode(COALESCE(db_entry.datacl, acldefault('d', db_entry.datdba))) AS privilege WHERE db_entry.datname = current_database() AND privilege.grantee = 0 AND privilege.privilege_type = 'CONNECT');`, "inspect public database connectivity");
    assert.equal(publicConnect.trim(), "t", "Only explicitly provisioned Virki roles and the bootstrap role may connect to the application database.");

    const migratorDatabaseDdl = runPsql(name, "virki_bootstrap", bootstrapPassword, `SELECT has_database_privilege('virki_migrator', current_database(), 'CONNECT') AND has_database_privilege('virki_migrator', current_database(), 'CREATE') AND has_database_privilege('virki_migrator', current_database(), 'TEMPORARY') AND has_schema_privilege('virki_migrator', 'public', 'CREATE') AND NOT has_database_privilege('virki_runtime', current_database(), 'CREATE') AND NOT has_database_privilege('virki_runtime_test', current_database(), 'CREATE') AND NOT has_database_privilege('virki_audit_maintenance', current_database(), 'CREATE') AND NOT has_database_privilege('virki_audit_maintenance', current_database(), 'TEMPORARY') AND NOT EXISTS (SELECT 1 FROM pg_database AS db_entry CROSS JOIN LATERAL aclexplode(COALESCE(db_entry.datacl, acldefault('d', db_entry.datdba))) AS privilege WHERE db_entry.datname = current_database() AND privilege.grantee = 0 AND privilege.privilege_type = 'CREATE');`, "inspect database and schema migration privileges");
    assert.equal(migratorDatabaseDdl.trim(), "t", "Only the one-shot migrator receives database/schema DDL; runtime roles and PUBLIC do not.");

    const sharedApplicationPassword = randomBytes(32).toString("hex");
    const passwordReuseCases = [
      { label: "runtime password reuses bootstrap", runtimePassword: bootstrapPassword, migratorPassword },
      { label: "migrator password reuses bootstrap", runtimePassword, migratorPassword: bootstrapPassword },
      { label: "runtime and migrator passwords match", runtimePassword: sharedApplicationPassword, migratorPassword: sharedApplicationPassword },
      { label: "audit maintenance password reuses runtime", runtimePassword, migratorPassword, auditMaintenancePassword: runtimePassword },
      { label: "audit maintenance password reuses migrator", runtimePassword, migratorPassword, auditMaintenancePassword: migratorPassword },
      { label: "audit maintenance password reuses bootstrap", runtimePassword, migratorPassword, auditMaintenancePassword: bootstrapPassword }
    ];
    for (const { label, runtimePassword: candidateRuntimePassword, migratorPassword: candidateMigratorPassword, auditMaintenancePassword: candidateAuditMaintenancePassword = auditMaintenancePassword } of passwordReuseCases) {
      const rejected = docker([
        "exec",
        "--env=VIRKI_RUNTIME_DB_PASSWORD",
        "--env=VIRKI_MIGRATOR_DB_PASSWORD",
        "--env=VIRKI_AUDIT_MAINTENANCE_DB_PASSWORD",
        name,
        "sh", roleSetupContainerPath
      ], `reject ${label}`, {
        allowFailure: true,
        env: {
          ...fixtureSecrets,
          VIRKI_RUNTIME_DB_PASSWORD: candidateRuntimePassword,
          VIRKI_MIGRATOR_DB_PASSWORD: candidateMigratorPassword,
          VIRKI_AUDIT_MAINTENANCE_DB_PASSWORD: candidateAuditMaintenancePassword
        }
      });
      assert.notEqual(rejected.status, 0, `Role provisioning must reject when ${label}.`);
      assert.match(rejected.stderr ?? "", /bootstrap, runtime, migrator, and audit-maintenance database passwords must differ/u, `Role provisioning must reject ${label} before executing SQL.`);
    }

    const ownership = runPsql(name, "virki_bootstrap", bootstrapPassword, `SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid = 'public."User"'::regclass;`, "inspect application table owner");
    assert.equal(ownership.trim(), "virki_migrator", "The migrator must own the application tables.");

    const migrationLedgerPrivileges = runPsql(name, "virki_bootstrap", bootstrapPassword, `SELECT NOT has_table_privilege('virki_runtime', 'public."_prisma_migrations"', 'SELECT') AND NOT has_table_privilege('virki_runtime', 'public."_prisma_migrations"', 'INSERT') AND NOT has_table_privilege('virki_runtime', 'public."_prisma_migrations"', 'UPDATE') AND NOT has_table_privilege('virki_runtime', 'public."_prisma_migrations"', 'DELETE') AND NOT has_table_privilege('virki_runtime', 'public."_prisma_migrations"', 'TRUNCATE') AND NOT has_table_privilege('virki_runtime', 'public."_prisma_migrations"', 'REFERENCES') AND NOT has_table_privilege('virki_runtime', 'public."_prisma_migrations"', 'TRIGGER') AND NOT has_any_column_privilege('virki_runtime', 'public."_prisma_migrations"', 'SELECT') AND NOT has_any_column_privilege('virki_runtime', 'public."_prisma_migrations"', 'INSERT') AND NOT has_any_column_privilege('virki_runtime', 'public."_prisma_migrations"', 'UPDATE') AND NOT has_any_column_privilege('virki_runtime', 'public."_prisma_migrations"', 'REFERENCES') AND NOT has_table_privilege('virki_runtime_test', 'public."_prisma_migrations"', 'SELECT') AND NOT has_table_privilege('virki_runtime_test', 'public."_prisma_migrations"', 'INSERT') AND NOT has_table_privilege('virki_runtime_test', 'public."_prisma_migrations"', 'UPDATE') AND NOT has_table_privilege('virki_runtime_test', 'public."_prisma_migrations"', 'DELETE') AND NOT has_table_privilege('virki_runtime_test', 'public."_prisma_migrations"', 'TRUNCATE') AND NOT has_table_privilege('virki_runtime_test', 'public."_prisma_migrations"', 'REFERENCES') AND NOT has_table_privilege('virki_runtime_test', 'public."_prisma_migrations"', 'TRIGGER') AND NOT has_any_column_privilege('virki_runtime_test', 'public."_prisma_migrations"', 'SELECT') AND NOT has_any_column_privilege('virki_runtime_test', 'public."_prisma_migrations"', 'INSERT') AND NOT has_any_column_privilege('virki_runtime_test', 'public."_prisma_migrations"', 'UPDATE') AND NOT has_any_column_privilege('virki_runtime_test', 'public."_prisma_migrations"', 'REFERENCES');`, "inspect migration ledger privileges");
    assert.equal(migrationLedgerPrivileges.trim(), "t", "Application roles must not read or mutate Prisma migration history.");
    for (const role of ["virki_runtime", "virki_runtime_test"]) {
      assertMigrationLedgerReadDenied(name, role, role === "virki_runtime" ? runtimePassword : e2ePassword, "final migration ledger privilege check");
    }

    const runtimePrivileges = runPsql(name, "virki_bootstrap", bootstrapPassword, `SELECT has_database_privilege('virki_runtime', current_database(), 'CONNECT') AND NOT has_database_privilege('virki_runtime', current_database(), 'CREATE') AND NOT has_database_privilege('virki_runtime', current_database(), 'TEMPORARY') AND has_schema_privilege('virki_runtime', 'public', 'USAGE') AND NOT has_schema_privilege('virki_runtime', 'public', 'CREATE') AND has_table_privilege('virki_runtime', 'public."User"', 'SELECT') AND has_table_privilege('virki_runtime', 'public."User"', 'INSERT') AND has_table_privilege('virki_runtime', 'public."User"', 'UPDATE') AND has_table_privilege('virki_runtime', 'public."User"', 'DELETE') AND NOT has_table_privilege('virki_runtime', 'public."User"', 'TRUNCATE') AND NOT has_table_privilege('virki_runtime', 'public."User"', 'REFERENCES') AND NOT has_table_privilege('virki_runtime', 'public."User"', 'TRIGGER') AND has_type_privilege('virki_runtime', 'public."UserRole"', 'USAGE') AND NOT has_function_privilege('virki_runtime', 'public.digest(text,text)', 'EXECUTE');`, "inspect runtime grants");
    assert.equal(runtimePrivileges.trim(), "t", "Runtime grants must permit application DML while denying database and schema DDL.");
    const auditPrivileges = runPsql(name, "virki_bootstrap", bootstrapPassword, `SELECT
      has_table_privilege('virki_runtime', 'public."AuditLog"', 'SELECT')
      AND has_column_privilege('virki_runtime', 'public."AuditLog"', 'id', 'INSERT')
      AND has_column_privilege('virki_runtime', 'public."AuditLog"', 'createdAt', 'INSERT')
      AND NOT has_table_privilege('virki_runtime', 'public."AuditLog"', 'UPDATE')
      AND NOT has_table_privilege('virki_runtime', 'public."AuditLog"', 'DELETE')
      AND NOT has_table_privilege('virki_runtime', 'public."AuditLog"', 'TRUNCATE')
      AND NOT has_table_privilege('virki_audit_maintenance', 'public."AuditLog"', 'SELECT')
      AND NOT has_column_privilege('virki_audit_maintenance', 'public."AuditLog"', 'createdAt', 'SELECT')
      AND NOT has_column_privilege('virki_audit_maintenance', 'public."AuditLog"', 'actorUserId', 'SELECT')
      AND NOT has_column_privilege('virki_audit_maintenance', 'public."AuditLog"', 'message', 'SELECT')
      AND NOT has_table_privilege('virki_audit_maintenance', 'public."AuditLog"', 'INSERT')
      AND NOT has_column_privilege('virki_audit_maintenance', 'public."AuditLog"', 'id', 'INSERT')
      AND NOT has_column_privilege('virki_audit_maintenance', 'public."AuditLog"', 'eventType', 'INSERT')
      AND NOT has_column_privilege('virki_audit_maintenance', 'public."AuditLog"', 'createdAt', 'INSERT')
      AND NOT has_table_privilege('virki_audit_maintenance', 'public."AuditLog"', 'DELETE')
      AND NOT has_table_privilege('virki_audit_maintenance', 'public."AuditLog"', 'UPDATE')
      AND NOT has_table_privilege('virki_audit_maintenance', 'public."AuditLog"', 'TRUNCATE')
      AND has_schema_privilege('virki_audit_maintenance', 'virki_security', 'USAGE')
      AND NOT has_schema_privilege('virki_audit_maintenance', 'virki_security', 'CREATE')
      AND NOT has_table_privilege('virki_audit_maintenance', 'virki_security.audit_retention_policy', 'SELECT')
      AND NOT has_table_privilege('virki_audit_maintenance', 'virki_security.audit_retention_policy', 'INSERT')
      AND NOT has_table_privilege('virki_audit_maintenance', 'virki_security.audit_retention_policy', 'UPDATE')
      AND NOT has_table_privilege('virki_audit_maintenance', 'virki_security.audit_retention_policy', 'DELETE')
      AND NOT has_table_privilege('virki_audit_maintenance', 'virki_security.audit_retention_policy', 'TRUNCATE')
      AND NOT has_any_column_privilege('virki_audit_maintenance', 'virki_security.audit_retention_policy', 'SELECT')
      AND NOT has_any_column_privilege('virki_audit_maintenance', 'virki_security.audit_retention_policy', 'INSERT')
      AND NOT has_any_column_privilege('virki_audit_maintenance', 'virki_security.audit_retention_policy', 'UPDATE')
      AND NOT has_any_column_privilege('virki_audit_maintenance', 'virki_security.audit_retention_policy', 'REFERENCES')
      AND NOT has_table_privilege('virki_runtime', 'virki_security.audit_retention_policy', 'SELECT')
      AND NOT has_table_privilege('virki_runtime_test', 'virki_security.audit_retention_policy', 'SELECT')
      AND has_function_privilege('virki_audit_maintenance', 'virki_security.delete_expired_audit_logs()', 'EXECUTE')
      AND NOT has_function_privilege('virki_runtime', 'virki_security.delete_expired_audit_logs()', 'EXECUTE')
      AND NOT has_function_privilege('virki_runtime_test', 'virki_security.delete_expired_audit_logs()', 'EXECUTE')
      AND (SELECT pg_get_userbyid(namespace.nspowner) = 'virki_migrator' FROM pg_namespace AS namespace WHERE namespace.nspname = 'virki_security')
      AND (SELECT pg_get_userbyid(policy.relowner) = 'virki_migrator' FROM pg_class AS policy WHERE policy.oid = 'virki_security.audit_retention_policy'::regclass)
      AND (SELECT retention_days = 365 FROM virki_security.audit_retention_policy WHERE singleton = true)
      AND (SELECT pg_get_userbyid(routine.proowner) = 'virki_migrator' AND routine.prosecdef AND routine.proconfig = ARRAY['search_path=pg_catalog'] FROM pg_proc AS routine WHERE routine.oid = 'virki_security.delete_expired_audit_logs()'::regprocedure)
      AND NOT has_any_column_privilege('virki_audit_maintenance', 'public."User"', 'SELECT')
      AND NOT has_table_privilege('virki_audit_maintenance', 'public."User"', 'DELETE')
      AND has_database_privilege('virki_audit_maintenance', current_database(), 'CONNECT')
      AND has_schema_privilege('virki_audit_maintenance', 'public', 'USAGE')
      AND NOT has_schema_privilege('virki_audit_maintenance', 'public', 'CREATE');`, "inspect audit-specific role grants");
    assert.equal(auditPrivileges.trim(), "t", "Maintenance must have no direct audit or retention-policy table access and may execute only the database-owned cleanup function.");
    const auditWriteBoundaries = runPsql(name, "virki_bootstrap", bootstrapPassword, `SELECT has_column_privilege('virki_runtime', 'public."AuditLog"', 'id', 'INSERT') AND has_column_privilege('virki_runtime', 'public."AuditLog"', 'createdAt', 'INSERT') AND NOT has_table_privilege('virki_runtime', 'public."AuditLog"', 'INSERT') AND EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid = 'public."AuditLog"'::regclass AND tgname = 'virki_audit_log_created_at_guard' AND NOT tgisinternal AND tgenabled = 'O' AND tgfoid = 'virki_security.enforce_audit_log_timestamp()'::regprocedure) AND NOT has_function_privilege('virki_runtime', 'virki_security.enforce_audit_log_timestamp()', 'EXECUTE') AND has_table_privilege('virki_runtime', 'public."SanitizedAuditReference"', 'SELECT') AND NOT has_table_privilege('virki_runtime', 'public."SanitizedAuditReference"', 'INSERT') AND NOT has_table_privilege('virki_runtime', 'public."SanitizedAuditReference"', 'UPDATE') AND NOT has_table_privilege('virki_runtime', 'public."SanitizedAuditReference"', 'DELETE');`, "inspect audit write boundaries");
    assert.equal(auditWriteBoundaries.trim(), "t", "Runtime may provide the timestamp column for Prisma, but PostgreSQL must replace it with its own clock and runtime must not mutate sanitized audit references.");
    const e2ePrivileges = runPsql(name, "virki_bootstrap", bootstrapPassword, `SELECT has_database_privilege('virki_runtime_test', current_database(), 'CONNECT') AND NOT has_database_privilege('virki_runtime_test', current_database(), 'CREATE') AND NOT has_database_privilege('virki_runtime_test', current_database(), 'TEMPORARY') AND has_schema_privilege('virki_runtime_test', 'public', 'USAGE') AND NOT has_schema_privilege('virki_runtime_test', 'public', 'CREATE') AND has_table_privilege('virki_runtime_test', 'public."User"', 'SELECT') AND has_table_privilege('virki_runtime_test', 'public."User"', 'INSERT') AND has_table_privilege('virki_runtime_test', 'public."User"', 'UPDATE') AND has_table_privilege('virki_runtime_test', 'public."User"', 'DELETE') AND has_type_privilege('virki_runtime_test', 'public."UserRole"', 'USAGE') AND NOT has_table_privilege('virki_runtime_test', 'public."AuditLog"', 'UPDATE') AND NOT has_table_privilege('virki_runtime_test', 'public."AuditLog"', 'DELETE');`, "inspect isolated E2E role grants");
    assert.equal(e2ePrivileges.trim(), "t", "The isolated E2E role must support fixture DML without database or schema DDL.");
    runPsql(name, "virki_migrator", migratorPassword, "CREATE TABLE public.__virki_role_probe (id integer PRIMARY KEY, value text NOT NULL); ALTER TABLE public.__virki_role_probe ADD COLUMN changed boolean NOT NULL DEFAULT false;", "create objects with migration role");
    const newObjectPrivileges = runPsql(name, "virki_bootstrap", bootstrapPassword, `SELECT NOT has_table_privilege('virki_runtime', 'public.__virki_role_probe', 'TRUNCATE');`, "inspect future runtime grants");
    assert.equal(newObjectPrivileges.trim(), "t", "Future migration objects must not inherit unexpected runtime privileges.");
    const newE2eObjectPrivileges = runPsql(name, "virki_bootstrap", bootstrapPassword, "SELECT NOT has_table_privilege('virki_runtime_test', 'public.__virki_role_probe', 'TRUNCATE');", "inspect future isolated E2E grants");
    assert.equal(newE2eObjectPrivileges.trim(), "t", "Future migration objects must not inherit stale isolated E2E privileges.");
    runPsql(name, "virki_migrator", migratorPassword, "CREATE FUNCTION public.__virki_role_probe_routine() RETURNS integer LANGUAGE sql AS $$ SELECT 1 $$;", "create future migration routine");
    const newRoutinePrivileges = runPsql(name, "virki_bootstrap", bootstrapPassword, `SELECT has_function_privilege('virki_migrator', 'public.digest(text,text)', 'EXECUTE') AND NOT has_function_privilege('virki_runtime', 'public.__virki_role_probe_routine()', 'EXECUTE');`, "inspect future routine grants");
    assert.equal(newRoutinePrivileges.trim(), "t", "The migrator must retain only its explicit pgcrypto migration access, and future routines must not be executable by runtime.");
    const newE2eRoutinePrivileges = runPsql(name, "virki_bootstrap", bootstrapPassword, "SELECT NOT has_function_privilege('virki_runtime_test', 'public.__virki_role_probe_routine()', 'EXECUTE');", "inspect future isolated E2E routine grants");
    assert.equal(newE2eRoutinePrivileges.trim(), "t", "Future migration routines must not inherit stale isolated E2E execute privileges.");
    runPsql(name, "virki_migrator", migratorPassword, "DROP FUNCTION public.__virki_role_probe_routine();", "remove future routine fixture");
    const pgcryptoMigrationAccess = runPsql(name, "virki_migrator", migratorPassword, "SELECT encode(public.digest('virki-migration-probe', 'sha256'), 'hex');", "verify migrator pgcrypto access");
    assert.match(pgcryptoMigrationAccess, /^[a-f0-9]{64}$/mu, "The migration role must be able to use the pgcrypto digest function required by the committed migration.");
    const runtimeCrud = runPsql(name, "virki_runtime", runtimePassword, "INSERT INTO public.__virki_role_probe (id, value) VALUES (1, 'before'); UPDATE public.__virki_role_probe SET value = 'after' WHERE id = 1; SELECT value FROM public.__virki_role_probe WHERE id = 1; DELETE FROM public.__virki_role_probe WHERE id = 1;", "application CRUD with runtime role");
    assert.match(runtimeCrud, /after/u, "The runtime role must complete application reads and writes.");
    runPsql(name, "virki_runtime", runtimePassword, `INSERT INTO public."AuditLog" ("id", "eventType", "result") VALUES ('runtime-audit-probe', 'probe', 'INFO');`, "append audit row with database timestamp using runtime role");
    const explicitAuditTimestamp = runPsql(name, "virki_runtime", runtimePassword, `WITH inserted AS (INSERT INTO public."AuditLog" ("id", "eventType", "result", "createdAt") VALUES ('runtime-audit-timestamp-probe', 'probe', 'INFO', '2000-01-01T00:00:00Z') RETURNING "createdAt") SELECT (abs(EXTRACT(EPOCH FROM ("createdAt" - pg_catalog.clock_timestamp()::timestamp)) ) < 5)::text || '|' || "createdAt"::text || '|' || pg_catalog.clock_timestamp()::timestamp::text FROM inserted;`, "override caller-selected audit timestamp with the database clock");
    const [timestampEnforced, observedTimestamp, databaseTimestamp] = explicitAuditTimestamp.trim().split("|");
    assert.equal(timestampEnforced, "true", `The database trigger must replace caller-selected AuditLog.createdAt with PostgreSQL time (createdAt=${observedTimestamp}, databaseTime=${databaseTimestamp}).`);
    runPsql(name, "virki_migrator", migratorPassword, `INSERT INTO public."SanitizedAuditReference" ("id", "referenceHash", "category") VALUES ('runtime-reference-probe', repeat('a', 64), 'probe');`, "seed sanitized reference privilege probe");
    for (const [label, sql] of [
      ["insert", `INSERT INTO public."SanitizedAuditReference" ("id", "referenceHash", "category") VALUES ('runtime-reference-insert-probe', repeat('b', 64), 'probe');`],
      ["update", `UPDATE public."SanitizedAuditReference" SET "category" = 'changed' WHERE "id" = 'runtime-reference-probe';`],
      ["delete", `DELETE FROM public."SanitizedAuditReference" WHERE "id" = 'runtime-reference-probe';`]
    ]) {
      const deniedReferenceMutation = runPsql(name, "virki_runtime", runtimePassword, sql, `deny runtime sanitized-reference ${label}`, { allowFailure: true });
      assert.notEqual(deniedReferenceMutation.status, 0, `Runtime must not ${label} sanitized audit references.`);
      assert.match(deniedReferenceMutation.stderr ?? "", /permission denied/u, `Sanitized-reference ${label} must fail due to PostgreSQL privileges.`);
    }
    for (const [label, sql] of [
      ["update", `UPDATE public."AuditLog" SET "message" = 'changed' WHERE "id" = 'runtime-audit-probe';`],
      ["delete", `DELETE FROM public."AuditLog" WHERE "id" = 'runtime-audit-probe';`]
    ]) {
      const deniedAuditMutation = runPsql(name, "virki_runtime", runtimePassword, sql, `deny runtime audit ${label}`, { allowFailure: true });
      assert.notEqual(deniedAuditMutation.status, 0, `Runtime must not ${label} audit records.`);
      assert.match(deniedAuditMutation.stderr ?? "", /permission denied/u, `Runtime ${label} must fail due to PostgreSQL privileges.`);
    }
    const seededAuditRows = runPsql(name, "virki_migrator", migratorPassword, `INSERT INTO public."AuditLog" ("id", "eventType", "result", "createdAt") VALUES ('expired-maintenance-audit-probe', 'probe', 'INFO', '2000-01-01T00:00:00Z'), ('within-retention-maintenance-audit-probe', 'probe', 'INFO', pg_catalog.clock_timestamp() - INTERVAL '30 days');`, "seed expired and within-policy audit rows through migration role");
    assert.match(seededAuditRows, /INSERT 0 2/u, "The disposable fixture must seed one expired and one within-policy audit row.");
    const maintenanceAuditInsert = runPsql(name, "virki_audit_maintenance", auditMaintenancePassword, `INSERT INTO public."AuditLog" ("id", "eventType", "result", "metadata") VALUES ('maintenance-audit-probe', 'FORGED_EVENT', 'SUCCESS', '{}'::jsonb);`, "deny direct maintenance audit insertion", { allowFailure: true });
    assert.notEqual(maintenanceAuditInsert.status, 0, "Maintenance must not forge audit events by direct insert.");
    assert.match(maintenanceAuditInsert.stderr ?? "", /permission denied/u, "Arbitrary maintenance audit inserts must be denied by PostgreSQL privileges.");
    const deniedMaintenanceAuditDelete = runPsql(name, "virki_audit_maintenance", auditMaintenancePassword, `DELETE FROM public."AuditLog" WHERE "id" = 'runtime-audit-probe';`, "deny direct maintenance deletion of an audit row", { allowFailure: true });
    assert.notEqual(deniedMaintenanceAuditDelete.status, 0, "Maintenance must not delete arbitrary audit rows directly.");
    assert.match(deniedMaintenanceAuditDelete.stderr ?? "", /permission denied/u, "Direct audit deletion must be denied by PostgreSQL privileges.");
    const deniedShortRetention = runPsql(name, "virki_audit_maintenance", auditMaintenancePassword, `SELECT virki_security.delete_expired_audit_logs(1);`, "deny caller-selected shorter retention", { allowFailure: true });
    assert.notEqual(deniedShortRetention.status, 0, "Maintenance must not supply a shorter retention period to the database function.");
    assert.match(deniedShortRetention.stderr ?? "", /function .*delete_expired_audit_logs\(integer\) does not exist/u, "A caller-selected retention argument must be unavailable.");
    const stillRetained = runPsql(name, "virki_migrator", migratorPassword, `SELECT "id" FROM public."AuditLog" WHERE "id" = 'within-retention-maintenance-audit-probe';`, "confirm shorter-retention attempt preserved an in-policy row");
    assert.equal(stillRetained.trim(), "within-retention-maintenance-audit-probe", "A caller-selected shorter retention must not delete rows inside the configured policy.");
    runPsql(name, "virki_migrator", migratorPassword, "CREATE TABLE public.audit_retention_policy (retention_days integer NOT NULL); INSERT INTO public.audit_retention_policy VALUES (1);", "create a public-schema retention-policy shadow candidate");
    runPsql(name, "virki_bootstrap", bootstrapPassword, "GRANT TEMPORARY ON DATABASE virki_roles_test TO virki_audit_maintenance;", "allow only the hostile-path fixture to create a temporary shadow relation");
    const maintainedAudit = runPsql(name, "virki_audit_maintenance", auditMaintenancePassword, `CREATE TEMP TABLE "AuditLog" ("id" text NOT NULL);
      INSERT INTO pg_temp."AuditLog" VALUES ('shadow-audit-row');
      CREATE TEMP TABLE audit_retention_policy (retention_days integer NOT NULL);
      INSERT INTO pg_temp.audit_retention_policy VALUES (1);
      SET search_path = public, pg_temp;
      SELECT cleanup.deleted_count, cleanup.retention_days FROM virki_security.delete_expired_audit_logs() AS cleanup;
      SELECT count(*) FROM pg_temp."AuditLog" WHERE "id" = 'shadow-audit-row';`, "invoke the SECURITY DEFINER cleanup with hostile public/temp search_path and shadow relations");
    assert.deepEqual(maintainedAudit.trim().split(/\r?\n/u).slice(-2), ["1|365", "1"], "Cleanup must use the protected policy and qualified AuditLog table even when public and temporary objects are shadow candidates.");
    assert.equal(runPsql(name, "virki_migrator", migratorPassword, "SELECT retention_days FROM public.audit_retention_policy;", "verify the public retention-policy shadow candidate remains intact").trim(), "1", "Cleanup must read the protected policy instead of the public shadow candidate.");
    runPsql(name, "virki_bootstrap", bootstrapPassword, "REVOKE TEMPORARY ON DATABASE virki_roles_test FROM virki_audit_maintenance;", "restore least-privilege temporary-table access after the shadowing attempt");
    runPsql(name, "virki_migrator", migratorPassword, "DROP TABLE public.audit_retention_policy;", "remove the public-schema retention-policy shadow candidate");
    const retainedAudit = runPsql(name, "virki_migrator", migratorPassword, `SELECT "id" FROM public."AuditLog" WHERE "id" IN ('within-retention-maintenance-audit-probe', 'runtime-audit-probe') ORDER BY "id";`, "confirm policy-retained audit rows remain after cleanup");
    assert.deepEqual(retainedAudit.trim().split(/\r?\n/u), ["runtime-audit-probe", "within-retention-maintenance-audit-probe"], "Retention cleanup must preserve rows newer than its protected cutoff.");
    const cleanupAudit = runPsql(name, "virki_migrator", migratorPassword, `SELECT jsonb_build_object('eventType', "eventType", 'result', "result", 'resource', "resource", 'message', "message", 'schemaVersion', "schemaVersion", 'category', "category", 'severity', "severity", 'action', "action", 'reason', "reason", 'metadata', "metadata")::text FROM public."AuditLog" WHERE "eventType" = 'AUTH_AUDIT_LOG_CLEANUP' AND "metadata"->>'source' = 'audit-log-cleanup';`, "inspect the fixed event created by the cleanup function");
    assert.deepEqual(JSON.parse(cleanupAudit.trim()), { eventType: "AUTH_AUDIT_LOG_CLEANUP", result: "SUCCESS", resource: "audit-log", message: "Expired audit logs cleaned up.", schemaVersion: 1, category: "AUTH", severity: "INFO", action: "auth.audit.log.cleanup", reason: "completed", metadata: { source: "audit-log-cleanup", deletedCount: 1, retentionDays: 365 } }, "The database function must append the fixed v1 cleanup record with its actual policy and count.");
    const noOpMaintenance = runPsql(name, "virki_audit_maintenance", auditMaintenancePassword, `SELECT cleanup.deleted_count, cleanup.retention_days FROM virki_security.delete_expired_audit_logs() AS cleanup;`, "verify no-op audit cleanup");
    assert.equal(noOpMaintenance.trim(), "0|365", "An empty cleanup must report the protected retention policy without deleting rows.");
    const cleanupEventCount = runPsql(name, "virki_migrator", migratorPassword, `SELECT count(*) FROM public."AuditLog" WHERE "eventType" = 'AUTH_AUDIT_LOG_CLEANUP' AND "metadata"->>'source' = 'audit-log-cleanup';`, "ensure no-op cleanup does not append another event");
    assert.equal(cleanupEventCount.trim(), "1", "A no-op cleanup must not fabricate a second audit event.");
    const deniedMaintenanceUserDelete = runPsql(name, "virki_audit_maintenance", auditMaintenancePassword, `DELETE FROM public."User" WHERE false;`, "deny maintenance access to User", { allowFailure: true });
    assert.notEqual(deniedMaintenanceUserDelete.status, 0, "Audit-maintenance must not have access to unrelated application tables.");
    assert.match(deniedMaintenanceUserDelete.stderr ?? "", /permission denied/u, "Audit-maintenance access to User must fail due to PostgreSQL privileges.");
    const e2eCrud = runPsql(name, "virki_runtime_test", e2ePassword, "INSERT INTO public.__virki_role_probe (id, value) VALUES (2, 'fixture'); UPDATE public.__virki_role_probe SET value = 'fixture-updated' WHERE id = 2; SELECT value FROM public.__virki_role_probe WHERE id = 2; DELETE FROM public.__virki_role_probe WHERE id = 2;", "isolated E2E fixture CRUD");
    assert.match(e2eCrud, /fixture-updated/u, "The isolated E2E role must complete fixture reads and writes.");

    const forbiddenDdl = docker([
      "exec", "--env=PGPASSWORD", name,
      "psql", "--no-psqlrc", "--host", "127.0.0.1", "--username", "virki_runtime",
      "--dbname", "virki_roles_test", "--set", "ON_ERROR_STOP=1", "--command",
      "CREATE TABLE public.__virki_forbidden_probe (id integer);"
    ], "attempt runtime DDL", { allowFailure: true, env: { PGPASSWORD: runtimePassword } });
    assert.notEqual(forbiddenDdl.status, 0, "The runtime role must not create persistent tables.");
    assert.match(forbiddenDdl.stderr ?? "", /permission denied/u, "Runtime DDL must fail specifically because the role lacks permission.");

    runPsql(name, "virki_migrator", migratorPassword, "DROP TABLE public.__virki_role_probe;", "clean temporary role probe");
  } catch (error) {
    failure = error;
  }

  try {
    cleanupFixture(name, network, testRunId, dataVolume);
  } catch (cleanupError) {
    failure = failure
      ? new AggregateError([failure, cleanupError], "PostgreSQL role validation and fixture cleanup both failed.")
      : cleanupError;
  }

  if (failure) throw failure;
}

async function waitForHealthy(name, fixtureSecrets = {}) {
  const deadline = Date.now() + 90_000;
  while (Date.now() < deadline) {
    const result = docker(["inspect", `--format={{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}starting{{end}}`, name], "check PostgreSQL fixture health");
    if (result.status === 0 && result.stdout.trim() === "running|healthy") return;
    const [state, health] = result.stdout.trim().split("|");
    if (state === "exited" || state === "dead" || health === "unhealthy") {
      const logs = docker(["logs", "--tail", "40", name], "collect sanitized PostgreSQL fixture startup diagnostics", {
        allowFailure: true,
        env: fixtureSecrets
      });
      const detail = [logs.stdout, logs.stderr].filter(Boolean).join("\n");
      throw new Error(`Disposable PostgreSQL fixture stopped before becoming healthy${detail ? `:\n${detail}` : "."}`);
    }
    await delay(500);
  }
  const logs = docker(["logs", "--tail", "40", name], "collect sanitized PostgreSQL fixture startup diagnostics", {
    allowFailure: true,
    env: fixtureSecrets
  });
  const detail = [logs.stdout, logs.stderr].filter(Boolean).join("\n");
  throw new Error(`Disposable PostgreSQL fixture did not become healthy within 90 seconds${detail ? `:\n${detail}` : "."}`);
}

function runPsql(name, role, password, sql, label, { allowFailure = false } = {}) {
  const result = docker([
    "exec", "--env=PGPASSWORD", name,
    "psql", "--no-psqlrc", "--host", "127.0.0.1", "--username", role,
    "--dbname", "virki_roles_test", "--set", "ON_ERROR_STOP=1", "--tuples-only", "--no-align", "--command", sql
  ], label, { allowFailure, env: { PGPASSWORD: password } });
  if (!allowFailure) {
    assert.equal(result.status, 0, `${label} failed.`);
    return result.stdout;
  }
  return result;
}

function assertMigrationLedgerReadDenied(name, role, password, context) {
  const result = runPsql(name, role, password, `SELECT count(*) FROM public."_prisma_migrations";`, `${context}: ${role} read`, { allowFailure: true });
  assert.notEqual(result.status, 0, `${role} must not read Prisma migration history (${context}).`);
  assert.match(result.stderr ?? "", /permission denied for table _prisma_migrations/u, `${role} migration ledger read must fail due to PostgreSQL privileges (${context}).`);
}

function buildMigrationRunner(testRunId) {
  const revision = /^[0-9a-f]{40}$/u.test(process.env.GITHUB_SHA ?? "")
    ? process.env.GITHUB_SHA
    : randomBytes(20).toString("hex");
  const image = `virki-role-test-migrator:${testRunId}`;
  docker([
    "build", "--file", "infra/Dockerfile.prod", "--target", "migrator",
    "--build-arg", `VIRKI_BUILD_REVISION=${revision}`,
    "--label", `virki.role-test.run=${testRunId}`,
    "--tag", image, "."
  ], "build disposable Prisma migration runner", { timeout: 20 * 60 * 1000, maxBuffer: 30 * 1024 * 1024 });
  const metadata = docker([
    "image", "inspect", `--format={{.Id}}|{{index .Config.Labels "virki.role-test.run"}}|{{index .Config.Labels "org.opencontainers.image.revision"}}`, image
  ], "verify disposable Prisma migration runner").stdout.trim();
  assert.match(metadata, new RegExp(`^sha256:[a-f0-9]{64}\\|${testRunId}\\|${revision}$`, "u"), "The migration runner image must be unique to this fixture and its source revision.");
  return { image, imageId: metadata.split("|")[0] };
}

function runMigrationsAsMigrator(runner, network, fixtureName, testRunId, databaseUrl, label, auditRetentionDays) {
  runMigrationCommand(runner, network, fixtureName, testRunId, "MIGRATION_DATABASE_URL", databaseUrl, label, [
    "/app/packages/database/scripts/prisma-migrate.mjs", "deploy"
  ], { AUDIT_LOG_RETENTION_DAYS: auditRetentionDays });
}

function runMigrationStatusAsMigrator(runner, network, fixtureName, testRunId, databaseUrl, label) {
  runMigrationCommand(runner, network, fixtureName, testRunId, "MIGRATION_DATABASE_URL", databaseUrl, label, [
    "/app/packages/database/scripts/prisma-migrate.mjs", "status"
  ]);
}

function runMigrationsDirect(runner, network, fixtureName, testRunId, databaseUrl, label) {
  runMigrationCommand(runner, network, fixtureName, testRunId, "DATABASE_URL", databaseUrl, label, [
    "/app/node_modules/prisma/build/index.js", "migrate", "deploy",
    "--schema", "/app/packages/database/prisma/schema.prisma"
  ]);
}

function runMigrationCommand(runner, network, fixtureName, testRunId, urlKey, databaseUrl, label, command, extraEnv = {}) {
  const name = `${fixtureName}-migrate-${randomBytes(6).toString("hex")}`;
  const result = docker([
    "run", "--name", name, "--network", network,
    "--label", `virki.role-test.run=${testRunId}`,
    "--label", `virki.role-test.fixture=${fixtureName}`,
    "--label", "virki.role-test.kind=migration-runner",
    "--env", urlKey, ...(extraEnv.AUDIT_LOG_RETENTION_DAYS ? ["--env", "AUDIT_LOG_RETENTION_DAYS"] : []), "--entrypoint", "node", runner.image, ...command
  ], label, { allowFailure: true, env: { ...extraEnv, [urlKey]: databaseUrl } });
  if (result.status === 0) assertFixtureContainer(name, network, testRunId, fixtureName, "migration-runner");
  const detail = result.stderr.trim();
  assert.equal(result.status, 0, `${label} failed (exit ${result.status ?? "unknown"})${detail ? `: ${detail}` : ""}.`);
}

function connectionUrl(role, password) {
  return `postgresql://${role}:${password}@postgres:5432/virki_roles_test?schema=public`;
}

function assertFixtureNetwork(network, testRunId, fixtureName) {
  const metadata = docker([
    "network", "inspect", `--format={{.Name}}|{{.Driver}}|{{.Internal}}|{{index .Labels "virki.role-test.run"}}|{{index .Labels "virki.role-test.fixture"}}`, network
  ], "verify isolated PostgreSQL fixture network").stdout.trim();
  assert.equal(metadata, `${network}|bridge|true|${testRunId}|${fixtureName}`, "The PostgreSQL fixture must use only its unique internal bridge network.");
}

function assertFixtureContainer(name, network, testRunId, fixtureName, kind) {
  const metadata = docker([
    "inspect",
    `--format={{range $port, $bindings := .HostConfig.PortBindings}}{{range $bindings}}published{{end}}{{end}}|{{range $port, $bindings := .NetworkSettings.Ports}}{{range $bindings}}published{{end}}{{end}}|{{.HostConfig.NetworkMode}}|{{index .Config.Labels "virki.role-test.run"}}|{{index .Config.Labels "virki.role-test.fixture"}}|{{index .Config.Labels "virki.role-test.kind"}}`,
    name
  ], "verify fixture container network and published ports").stdout.trim();
  assert.equal(metadata, `||${network}|${testRunId}|${fixtureName}|${kind}`, "The fixture container must have no actual published ports and only the isolated network.");
}

function assertPostgresFixtureMounts(name, kind, dataVolume = null) {
  const pgdata = docker([
    "inspect", `--format={{index .HostConfig.Tmpfs "/var/lib/postgresql/data"}}`, name
  ], "verify disposable PostgreSQL data mount").stdout.trim();
  if (dataVolume) {
    assert.equal(pgdata, "", "The persistent interrupted-init fixture must not also use tmpfs for PGDATA.");
    const mountedVolume = docker([
      "inspect", `--format={{range .Mounts}}{{if eq .Destination "/var/lib/postgresql/data"}}{{.Type}}|{{.Name}}|{{.Destination}}{{end}}{{end}}`, name
    ], "verify exact persistent PostgreSQL fixture volume mount").stdout.trim();
    assert.equal(mountedVolume, `volume|${dataVolume}|/var/lib/postgresql/data`, "The interrupted-init fixture must mount only its exact named test volume at PGDATA.");
  } else {
    assert.equal(pgdata, "rw,noexec,nosuid,nodev,size=512m", "PostgreSQL fixture data must use only a disposable tmpfs.");
    const mountedVolume = docker([
      "inspect", `--format={{range .Mounts}}{{if eq .Destination "/var/lib/postgresql/data"}}{{.Type}}{{end}}{{end}}`, name
    ], "reject persistent PostgreSQL data mount on disposable fixture").stdout.trim();
    assert.equal(mountedVolume, "", "Fresh and populated PostgreSQL fixtures must not use a persistent data volume.");
  }
  const bindCount = docker(["inspect", "--format={{len .HostConfig.Binds}}", name], "verify PostgreSQL fixture bind count").stdout.trim();
  assert.equal(bindCount, "0", "PostgreSQL fixtures must not depend on host-path bind mounts.");
  const destinations = kind === "fresh" || kind === "interrupted"
    ? [
      ["/docker-entrypoint-initdb.d/10-virki-database-roles.sh", roleSetupPath],
      ["/docker-entrypoint-initdb.d/20-virki-e2e-runtime-test-role.sh", e2eRoleSetupPath]
    ]
    : [["/test/10-virki-database-roles.sh", roleSetupPath], ["/test/20-virki-e2e-runtime-test-role.sh", e2eRoleSetupPath]];
  for (const [destination, source] of destinations) {
    const copied = docker(["exec", name, "sha256sum", destination], "verify copied PostgreSQL role initializer").stdout.trim().split(/\s+/u)[0];
    const expected = createHash("sha256").update(readFileSync(source)).digest("hex");
    assert.equal(copied, expected, "The fixture must contain the exact reviewed initializer from this repository.");
  }
  const unexpectedDestinations = kind === "fresh" || kind === "interrupted"
    ? ["/test/10-virki-database-roles.sh", "/test/20-virki-e2e-runtime-test-role.sh"]
    : ["/docker-entrypoint-initdb.d/10-virki-database-roles.sh", "/docker-entrypoint-initdb.d/20-virki-e2e-runtime-test-role.sh"];
  for (const destination of unexpectedDestinations) {
    const unexpected = docker(["exec", name, "test", "-e", destination], "reject PostgreSQL initializer copied under an unexpected path", { allowFailure: true });
    assert.notEqual(unexpected.status, 0, "The fixture must not copy its initializer under an unexpected path.");
  }
}

function assertFixtureContainerIdentity(name, testRunId, fixtureName, kind) {
  const identity = docker([
    "inspect", `--format={{.Name}}|{{index .Config.Labels "virki.role-test.run"}}|{{index .Config.Labels "virki.role-test.fixture"}}|{{index .Config.Labels "virki.role-test.kind"}}`, name
  ], "verify exact PostgreSQL fixture container identity").stdout.trim();
  assert.equal(identity, `/${name}|${testRunId}|${fixtureName}|${kind}`, "Refusing to change a PostgreSQL fixture container with unexpected identity or labels.");
}

function assertFixtureVolume(volume, testRunId, fixtureName) {
  const metadata = docker([
    "volume", "inspect", `--format={{.Name}}|{{.Driver}}|{{index .Labels "virki.role-test.run"}}|{{index .Labels "virki.role-test.fixture"}}`, volume
  ], "verify exact PostgreSQL fixture data volume").stdout.trim();
  assert.equal(metadata, `${volume}|local|${testRunId}|${fixtureName}`, "Refusing to use a PostgreSQL data volume with unexpected name, driver, or fixture labels.");
}

function cleanupFixture(name, network, testRunId, dataVolume = null) {
  const containers = docker([
    "ps", "--all", "--quiet", "--filter", `label=virki.role-test.run=${testRunId}`,
    "--filter", `label=virki.role-test.fixture=${name}`
  ], "list exact PostgreSQL fixture containers").stdout.trim().split(/\r?\n/u).filter(Boolean);
  for (const container of containers) {
    const identity = docker([
      "inspect", `--format={{.Name}}|{{index .Config.Labels "virki.role-test.run"}}|{{index .Config.Labels "virki.role-test.fixture"}}|{{index .Config.Labels "virki.role-test.kind"}}`, container
    ], "verify exact PostgreSQL fixture container before removal").stdout.trim();
    const [rawName, observedRunId, observedFixture, kind] = identity.split("|");
    const containerName = rawName.replace(/^\//u, "");
    assert.ok(containerName === name || containerName.startsWith(`${name}-migrate-`), "Refusing to remove a container outside this exact fixture.");
    assert.equal(observedRunId, testRunId, "Refusing to remove a container with an unexpected run label.");
    assert.equal(observedFixture, name, "Refusing to remove a container with an unexpected fixture label.");
    assert.equal(kind, containerName === name ? "postgres" : "migration-runner", "Refusing to remove a container with an unexpected type label.");
    docker(["rm", "--force", container], "remove exact PostgreSQL fixture container");
  }
  const remainingContainers = docker([
    "ps", "--all", "--quiet", "--filter", `label=virki.role-test.run=${testRunId}`,
    "--filter", `label=virki.role-test.fixture=${name}`
  ], "verify PostgreSQL fixture container cleanup").stdout.trim();
  assert.equal(remainingContainers, "", "PostgreSQL fixture containers remain after cleanup.");

  if (dataVolume) {
    assertFixtureVolume(dataVolume, testRunId, name);
    const volumeConsumers = docker(["ps", "--all", "--quiet", "--filter", `volume=${dataVolume}`], "verify no container consumes the exact PostgreSQL test volume").stdout.trim();
    assert.equal(volumeConsumers, "", "Refusing to remove a PostgreSQL test volume with any container consumer.");
    docker(["volume", "rm", dataVolume], "remove only the exact disposable PostgreSQL fixture volume");
    const remainingVolume = docker(["volume", "ls", "--quiet", "--filter", `name=^${dataVolume}$`], "verify PostgreSQL test volume cleanup").stdout.trim();
    assert.equal(remainingVolume, "", "The disposable PostgreSQL fixture volume remains after cleanup.");
  }

  const existingNetwork = docker(["network", "ls", "--quiet", "--filter", `name=^${network}$`], "find exact PostgreSQL fixture network").stdout.trim();
  if (existingNetwork) {
    assert.ok(/^[a-f0-9]{12,64}$/u.test(existingNetwork), "Fixture network identity is invalid.");
    const metadata = docker([
      "network", "inspect", `--format={{.Name}}|{{.Internal}}|{{index .Labels "virki.role-test.run"}}|{{index .Labels "virki.role-test.fixture"}}|{{len .Containers}}`, existingNetwork
    ], "verify exact PostgreSQL fixture network before removal").stdout.trim();
    assert.equal(metadata, `${network}|true|${testRunId}|${name}|0`, "Refusing to remove a network with unexpected identity, labels, or consumers.");
    docker(["network", "rm", existingNetwork], "remove exact PostgreSQL fixture network");
  }
  const remainingNetwork = docker(["network", "ls", "--quiet", "--filter", `name=^${network}$`], "verify PostgreSQL fixture network cleanup").stdout.trim();
  assert.equal(remainingNetwork, "", "The PostgreSQL fixture network remains after cleanup.");
}

function removeMigrationRunner(runner, testRunId) {
  const users = docker(["ps", "--all", "--quiet", "--filter", `ancestor=${runner.imageId}`], "verify no container uses the disposable migration runner").stdout.trim();
  assert.equal(users, "", "Refusing to remove a migration runner image while a container still uses it.");
  const metadata = docker([
    "image", "inspect", `--format={{.Id}}|{{index .Config.Labels "virki.role-test.run"}}`, runner.image
  ], "verify disposable migration runner before removal").stdout.trim();
  assert.equal(metadata, `${runner.imageId}|${testRunId}`, "Refusing to remove an image outside this exact test run.");
  docker(["image", "rm", runner.image], "remove disposable migration runner image");
  const remaining = docker(["image", "inspect", "--format={{.Id}}", runner.image], "verify migration runner image cleanup", { allowFailure: true });
  assert.notEqual(remaining.status, 0, "The disposable migration runner image remains after cleanup.");
}

function docker(args, label, { allowFailure = false, env = {}, input, timeout = 120_000, maxBuffer = 10 * 1024 * 1024 } = {}) {
  for (const [key, value] of Object.entries(env)) {
    if (/(?:password|secret|token|credential|database_url)/iu.test(key) && value && args.some((argument) => argument.includes(value))) {
      throw new Error(`${label} would expose ${key} in Docker process arguments.`);
    }
  }
  const result = spawnSync("docker", args, {
    cwd: repositoryRoot,
    env: { ...process.env, ...env },
    input,
    encoding: "utf8",
    windowsHide: true,
    timeout,
    maxBuffer
  });
  if (result.error) throw new Error(`${label} could not run Docker (${result.error.code ?? "unknown error"}).`);
  const sanitizedResult = {
    ...result,
    stdout: redactDockerDiagnostics(result.stdout ?? "", args, env),
    stderr: redactDockerDiagnostics(result.stderr ?? "", args, env)
  };
  if (!allowFailure && sanitizedResult.status !== 0) {
    const detail = sanitizedResult.stderr;
    throw new Error(`${label} failed in Docker (exit ${sanitizedResult.status ?? "unknown"})${detail ? `: ${detail}` : ""}.`);
  }
  return sanitizedResult;
}

function redactDockerDiagnostics(value, args, env = {}) {
  let output = String(value).trim();
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index] === "--env" ? args[index + 1] : args[index].startsWith("--env=") ? args[index].slice("--env=".length) : "";
    const separator = argument.indexOf("=");
    if (separator >= 0 && argument.slice(separator + 1)) {
      output = output.replaceAll(argument.slice(separator + 1), "[redacted]");
    }
  }
  for (const [key, secret] of Object.entries(env)) {
    if (/(?:password|secret|token|credential|database_url)/iu.test(key) && typeof secret === "string" && secret) {
      output = output.replaceAll(secret, "[redacted]");
    }
  }
  return output.slice(-2000);
}
