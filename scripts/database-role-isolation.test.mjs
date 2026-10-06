import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import { setTimeout as delay } from "node:timers/promises";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const roleSetupPath = path.join(repositoryRoot, "infra", "postgres-init", "10-bielos-database-roles.sh");
const e2eRoleSetupPath = path.join(repositoryRoot, "scripts", "e2e", "20-bielos-e2e-runtime-test-role.sh");
const prismaCliPath = createRequire(import.meta.url).resolve("prisma/build/index.js");
const postgresImage = "postgres:17-alpine@sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24";

await verifyDatabaseRoles("fresh");
await verifyDatabaseRoles("populated");
console.log("PASS: fresh and populated disposable PostgreSQL role separation");

async function verifyDatabaseRoles(kind) {
  const suffix = randomBytes(6).toString("hex");
  const name = `bielos-role-${kind}-${suffix}`;
  const bootstrapPassword = randomBytes(32).toString("hex");
  const runtimePassword = randomBytes(32).toString("hex");
  let migratorPassword = randomBytes(32).toString("hex");
  if (migratorPassword === runtimePassword) migratorPassword = randomBytes(32).toString("hex");
  const e2ePassword = randomBytes(32).toString("hex");

  const args = [
    "run", "--detach", "--rm", "--name", name,
    "--publish", "127.0.0.1::5432",
    "--tmpfs", "/var/lib/postgresql/data:rw,noexec,nosuid,nodev,size=512m",
    "--health-cmd", "pg_isready -h 127.0.0.1 -U bielos_bootstrap -d bielos_roles_test",
    "--health-interval", "1s", "--health-timeout", "3s", "--health-retries", "60",
    "--env", "POSTGRES_DB=bielos_roles_test",
    "--env", "POSTGRES_USER=bielos_bootstrap",
    `--env=POSTGRES_PASSWORD=${bootstrapPassword}`,
    `--env=BIELOS_RUNTIME_DB_PASSWORD=${runtimePassword}`,
    `--env=BIELOS_MIGRATOR_DB_PASSWORD=${migratorPassword}`,
    `--env=BIELOS_E2E_DATABASE_PASSWORD=${e2ePassword}`
  ];
  if (kind === "fresh") {
    args.push(
      "--volume", `${roleSetupPath}:/docker-entrypoint-initdb.d/10-bielos-database-roles.sh:ro`,
      "--volume", `${e2eRoleSetupPath}:/docker-entrypoint-initdb.d/20-bielos-e2e-runtime-test-role.sh:ro`
    );
  } else {
    args.push(
      "--volume", `${roleSetupPath}:/test/10-bielos-database-roles.sh:ro`,
      "--volume", `${e2eRoleSetupPath}:/test/20-bielos-e2e-runtime-test-role.sh:ro`
    );
  }
  args.push(postgresImage);
  const roleSetupContainerPath = kind === "fresh"
    ? "/docker-entrypoint-initdb.d/10-bielos-database-roles.sh"
    : "/test/10-bielos-database-roles.sh";
  const e2eRoleSetupContainerPath = kind === "fresh"
    ? "/docker-entrypoint-initdb.d/20-bielos-e2e-runtime-test-role.sh"
    : "/test/20-bielos-e2e-runtime-test-role.sh";

  const start = docker(args, `start ${kind} PostgreSQL fixture`);
  assert.equal(start.status, 0, `Could not start the ${kind} disposable PostgreSQL fixture.`);

  let failure;
  try {
    await waitForHealthy(name);
    const port = getMappedPort(name);
    const bootstrapUrl = connectionUrl("bielos_bootstrap", bootstrapPassword, port);
    const migratorUrl = connectionUrl("bielos_migrator", migratorPassword, port);
    runPsql(name, "bielos_bootstrap", bootstrapPassword, "CREATE ROLE bielos_connect_probe NOLOGIN;", "prepare unprivileged database connection probe");

    if (kind === "populated") {
      runMigrationsDirect(bootstrapUrl, "prepare populated legacy fixture");
      runPsql(name, "bielos_bootstrap", bootstrapPassword, "CREATE ROLE bielos_role_parent NOLOGIN; CREATE ROLE bielos_role_child NOLOGIN; CREATE ROLE bielos_runtime NOLOGIN; CREATE ROLE bielos_migrator NOLOGIN; GRANT CREATE ON DATABASE bielos_roles_test TO bielos_migrator; GRANT bielos_role_parent TO bielos_runtime, bielos_migrator; GRANT bielos_runtime, bielos_migrator TO bielos_role_child;", "seed pre-existing role memberships and database DDL privilege");
      runPsql(name, "bielos_bootstrap", bootstrapPassword, "GRANT TRUNCATE, REFERENCES, TRIGGER ON TABLE public.\"User\" TO bielos_runtime, PUBLIC; ALTER DEFAULT PRIVILEGES FOR ROLE bielos_migrator GRANT TRUNCATE ON TABLES TO bielos_runtime, PUBLIC; ALTER DEFAULT PRIVILEGES FOR ROLE bielos_migrator IN SCHEMA public GRANT TRUNCATE ON TABLES TO bielos_runtime, PUBLIC; CREATE FUNCTION public.__bielos_public_exec_probe() RETURNS integer LANGUAGE sql AS $$ SELECT 1 $$; GRANT EXECUTE ON FUNCTION public.__bielos_public_exec_probe() TO PUBLIC; ALTER DEFAULT PRIVILEGES FOR ROLE bielos_migrator GRANT EXECUTE ON ROUTINES TO PUBLIC; ALTER DEFAULT PRIVILEGES FOR ROLE bielos_migrator IN SCHEMA public GRANT EXECUTE ON ROUTINES TO PUBLIC;", "seed excess existing and default runtime grants");
      runPsql(name, "bielos_bootstrap", bootstrapPassword, "CREATE FUNCTION public.__bielos_security_definer_probe() RETURNS integer LANGUAGE sql SECURITY DEFINER AS $$ SELECT 1 $$;", "seed unreviewed SECURITY DEFINER routine");
      const unsafeRoutine = docker([
        "exec",
        `--env=BIELOS_RUNTIME_DB_PASSWORD=${runtimePassword}`,
        `--env=BIELOS_MIGRATOR_DB_PASSWORD=${migratorPassword}`,
        name,
        "sh", "/test/10-bielos-database-roles.sh"
      ], "reject unreviewed SECURITY DEFINER routine", { allowFailure: true });
      assert.notEqual(unsafeRoutine.status, 0, "Existing-volume transition must stop when public contains an unreviewed SECURITY DEFINER routine.");
      assert.match(unsafeRoutine.stderr ?? "", /SECURITY DEFINER routines in public schema/u, "Routine rejection must identify the manual-review requirement.");
      runPsql(name, "bielos_bootstrap", bootstrapPassword, "DROP FUNCTION public.__bielos_security_definer_probe();", "remove SECURITY DEFINER fixture routine");
      const provision = docker([
        "exec",
        `--env=BIELOS_RUNTIME_DB_PASSWORD=${runtimePassword}`,
        `--env=BIELOS_MIGRATOR_DB_PASSWORD=${migratorPassword}`,
        name,
        "sh", "/test/10-bielos-database-roles.sh"
      ], "transition populated disposable fixture");
      assert.equal(provision.status, 0, "Could not transition the populated disposable PostgreSQL fixture.");
      const e2eRole = docker([
        "exec",
        `--env=BIELOS_E2E_DATABASE_PASSWORD=${e2ePassword}`,
        name,
        "sh", "/test/20-bielos-e2e-runtime-test-role.sh"
      ], "provision isolated E2E runtime role");
      assert.equal(e2eRole.status, 0, "Could not provision the isolated E2E runtime role.");
      runPsql(name, "bielos_bootstrap", bootstrapPassword, "GRANT bielos_role_parent TO bielos_runtime_test; GRANT bielos_runtime_test TO bielos_role_child; GRANT TRUNCATE, REFERENCES, TRIGGER ON TABLE public.\"User\" TO bielos_runtime_test; CREATE SEQUENCE public.__bielos_runtime_test_sequence; GRANT UPDATE ON SEQUENCE public.__bielos_runtime_test_sequence TO bielos_runtime_test; CREATE FUNCTION public.__bielos_runtime_test_exec_probe() RETURNS integer LANGUAGE sql AS $$ SELECT 1 $$; REVOKE ALL PRIVILEGES ON FUNCTION public.__bielos_runtime_test_exec_probe() FROM PUBLIC; GRANT EXECUTE ON FUNCTION public.__bielos_runtime_test_exec_probe() TO bielos_runtime_test; ALTER DEFAULT PRIVILEGES FOR ROLE bielos_migrator GRANT TRUNCATE ON TABLES TO bielos_runtime_test; ALTER DEFAULT PRIVILEGES FOR ROLE bielos_migrator IN SCHEMA public GRANT TRUNCATE ON TABLES TO bielos_runtime_test; ALTER DEFAULT PRIVILEGES FOR ROLE bielos_migrator GRANT EXECUTE ON ROUTINES TO bielos_runtime_test; ALTER DEFAULT PRIVILEGES FOR ROLE bielos_migrator IN SCHEMA public GRANT EXECUTE ON ROUTINES TO bielos_runtime_test;", "seed stale isolated E2E role memberships and grants");

      const publicRoutinePrivileges = runPsql(name, "bielos_bootstrap", bootstrapPassword, `SELECT NOT has_function_privilege('bielos_connect_probe', 'public.__bielos_public_exec_probe()', 'EXECUTE');`, "inspect legacy public routine grants");
      assert.equal(publicRoutinePrivileges.trim(), "t", "Existing-volume transition must remove direct PUBLIC routine execution.");
      runPsql(name, "bielos_bootstrap", bootstrapPassword, "DROP FUNCTION public.__bielos_public_exec_probe();", "remove legacy routine fixture");
    }

    runMigrationsAsMigrator(migratorUrl, "apply Prisma migrations as migrator");
    if (kind === "populated") {
      const normalizeE2eRole = docker([
        "exec",
        `--env=BIELOS_E2E_DATABASE_PASSWORD=${e2ePassword}`,
        name,
        "sh", e2eRoleSetupContainerPath
      ], "remove stale isolated E2E privileges before the database transition");
      assert.equal(normalizeE2eRole.status, 0, "Isolated E2E privileges must be normalized before database transition checks.");
      const e2eExcessPrivileges = runPsql(name, "bielos_bootstrap", bootstrapPassword, `SELECT NOT has_table_privilege('bielos_runtime_test', 'public."User"', 'TRUNCATE') AND NOT has_table_privilege('bielos_runtime_test', 'public."User"', 'REFERENCES') AND NOT has_table_privilege('bielos_runtime_test', 'public."User"', 'TRIGGER') AND NOT has_sequence_privilege('bielos_runtime_test', 'public.__bielos_runtime_test_sequence', 'UPDATE') AND NOT has_function_privilege('bielos_runtime_test', 'public.__bielos_runtime_test_exec_probe()', 'EXECUTE');`, "inspect normalized isolated E2E privileges");
      assert.equal(e2eExcessPrivileges.trim(), "t", "The isolated E2E role must lose stale elevated object grants when reprovisioned.");
      const e2eMemberships = runPsql(name, "bielos_bootstrap", bootstrapPassword, `SELECT count(*) = 0 FROM pg_auth_members WHERE roleid = (SELECT oid FROM pg_roles WHERE rolname = 'bielos_runtime_test') OR member = (SELECT oid FROM pg_roles WHERE rolname = 'bielos_runtime_test');`, "inspect normalized isolated E2E role memberships");
      assert.equal(e2eMemberships.trim(), "t", "The isolated E2E role must lose stale role memberships when reprovisioned.");
      runPsql(name, "bielos_bootstrap", bootstrapPassword, "DROP FUNCTION public.__bielos_runtime_test_exec_probe(); DROP SEQUENCE public.__bielos_runtime_test_sequence;", "remove isolated E2E privilege probes before database transition");
    }

    const repeatProvision = docker([
      "exec",
      `--env=BIELOS_RUNTIME_DB_PASSWORD=${runtimePassword}`,
      `--env=BIELOS_MIGRATOR_DB_PASSWORD=${migratorPassword}`,
      name,
      "sh", roleSetupContainerPath
    ], "repeat database role transition");
    assert.equal(repeatProvision.status, 0, "Database role transition must be safe to repeat after migrations.");
    const repeatE2eRole = docker([
      "exec",
      `--env=BIELOS_E2E_DATABASE_PASSWORD=${e2ePassword}`,
      name,
      "sh", e2eRoleSetupContainerPath
    ], "repeat isolated E2E role provisioning");
    assert.equal(repeatE2eRole.status, 0, "Isolated E2E runtime role provisioning must be safe to repeat.");
    runPsql(name, "bielos_migrator", migratorPassword, "BEGIN; ALTER TABLE public.\"User\" ADD COLUMN \"__bielosRoleProbe\" TEXT; ALTER TABLE public.\"User\" DROP COLUMN \"__bielosRoleProbe\"; ROLLBACK;", "migrator can alter migrated objects");

    const rolePolicy = runPsql(name, "bielos_bootstrap", bootstrapPassword, `SELECT count(*) = 3 AND bool_and(NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication AND NOT rolbypassrls AND NOT rolinherit) FROM pg_roles WHERE rolname IN ('bielos_runtime', 'bielos_migrator', 'bielos_runtime_test');`, "inspect restricted database roles");
    assert.equal(rolePolicy.trim(), "t", "Runtime, migrator, and isolated E2E roles must not have privileged attributes or inheritance.");

    const memberships = runPsql(name, "bielos_bootstrap", bootstrapPassword, `SELECT count(*) = 0 FROM pg_auth_members WHERE roleid IN (SELECT oid FROM pg_roles WHERE rolname IN ('bielos_runtime', 'bielos_migrator', 'bielos_runtime_test')) OR member IN (SELECT oid FROM pg_roles WHERE rolname IN ('bielos_runtime', 'bielos_migrator', 'bielos_runtime_test'));`, "inspect role memberships");
    assert.equal(memberships.trim(), "t", "Runtime, migrator, and isolated E2E roles must not have role memberships.");

    const publicConnect = runPsql(name, "bielos_bootstrap", bootstrapPassword, `SELECT NOT has_database_privilege('bielos_connect_probe', current_database(), 'CONNECT') AND NOT has_table_privilege('bielos_connect_probe', 'public."User"', 'TRUNCATE') AND NOT EXISTS (SELECT 1 FROM pg_database AS db_entry CROSS JOIN LATERAL aclexplode(COALESCE(db_entry.datacl, acldefault('d', db_entry.datdba))) AS privilege WHERE db_entry.datname = current_database() AND privilege.grantee = 0 AND privilege.privilege_type = 'CONNECT');`, "inspect public database connectivity");
    assert.equal(publicConnect.trim(), "t", "Only the bootstrap, runtime, and migrator roles may connect to the application database.");

    const migratorDatabaseDdl = runPsql(name, "bielos_bootstrap", bootstrapPassword, `SELECT has_database_privilege('bielos_migrator', current_database(), 'CONNECT') AND has_database_privilege('bielos_migrator', current_database(), 'CREATE') AND has_database_privilege('bielos_migrator', current_database(), 'TEMPORARY') AND has_schema_privilege('bielos_migrator', 'public', 'CREATE') AND NOT has_database_privilege('bielos_runtime', current_database(), 'CREATE') AND NOT has_database_privilege('bielos_runtime_test', current_database(), 'CREATE') AND NOT EXISTS (SELECT 1 FROM pg_database AS db_entry CROSS JOIN LATERAL aclexplode(COALESCE(db_entry.datacl, acldefault('d', db_entry.datdba))) AS privilege WHERE db_entry.datname = current_database() AND privilege.grantee = 0 AND privilege.privilege_type = 'CREATE');`, "inspect database and schema migration privileges");
    assert.equal(migratorDatabaseDdl.trim(), "t", "The one-shot migrator needs database CREATE for the committed baseline migration; runtime roles and PUBLIC must not have it.");

    const sharedApplicationPassword = randomBytes(32).toString("hex");
    const passwordReuseCases = [
      { label: "runtime password reuses bootstrap", runtimePassword: bootstrapPassword, migratorPassword },
      { label: "migrator password reuses bootstrap", runtimePassword, migratorPassword: bootstrapPassword },
      { label: "runtime and migrator passwords match", runtimePassword: sharedApplicationPassword, migratorPassword: sharedApplicationPassword }
    ];
    for (const { label, runtimePassword: candidateRuntimePassword, migratorPassword: candidateMigratorPassword } of passwordReuseCases) {
      const rejected = docker([
        "exec",
        `--env=BIELOS_RUNTIME_DB_PASSWORD=${candidateRuntimePassword}`,
        `--env=BIELOS_MIGRATOR_DB_PASSWORD=${candidateMigratorPassword}`,
        name,
        "sh", roleSetupContainerPath
      ], `reject ${label}`, { allowFailure: true });
      assert.notEqual(rejected.status, 0, `Role provisioning must reject when ${label}.`);
      assert.match(rejected.stderr ?? "", /bootstrap, runtime, and migrator database passwords must differ/u, `Role provisioning must reject ${label} before executing SQL.`);
    }

    const ownership = runPsql(name, "bielos_bootstrap", bootstrapPassword, `SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid = 'public."User"'::regclass;`, "inspect application table owner");
    assert.equal(ownership.trim(), "bielos_migrator", "The migrator must own the application tables.");

    const runtimePrivileges = runPsql(name, "bielos_bootstrap", bootstrapPassword, `SELECT has_database_privilege('bielos_runtime', current_database(), 'CONNECT') AND NOT has_database_privilege('bielos_runtime', current_database(), 'CREATE') AND NOT has_database_privilege('bielos_runtime', current_database(), 'TEMPORARY') AND has_schema_privilege('bielos_runtime', 'public', 'USAGE') AND NOT has_schema_privilege('bielos_runtime', 'public', 'CREATE') AND has_table_privilege('bielos_runtime', 'public."User"', 'SELECT') AND has_table_privilege('bielos_runtime', 'public."User"', 'INSERT') AND has_table_privilege('bielos_runtime', 'public."User"', 'UPDATE') AND has_table_privilege('bielos_runtime', 'public."User"', 'DELETE') AND NOT has_table_privilege('bielos_runtime', 'public."User"', 'TRUNCATE') AND NOT has_table_privilege('bielos_runtime', 'public."User"', 'REFERENCES') AND NOT has_table_privilege('bielos_runtime', 'public."User"', 'TRIGGER') AND has_type_privilege('bielos_runtime', 'public."UserRole"', 'USAGE') AND NOT has_function_privilege('bielos_runtime', 'public.digest(text,text)', 'EXECUTE');`, "inspect runtime grants");
    assert.equal(runtimePrivileges.trim(), "t", "Runtime grants must permit application DML while denying database and schema DDL.");
    const e2ePrivileges = runPsql(name, "bielos_bootstrap", bootstrapPassword, `SELECT has_database_privilege('bielos_runtime_test', current_database(), 'CONNECT') AND NOT has_database_privilege('bielos_runtime_test', current_database(), 'CREATE') AND NOT has_database_privilege('bielos_runtime_test', current_database(), 'TEMPORARY') AND has_schema_privilege('bielos_runtime_test', 'public', 'USAGE') AND NOT has_schema_privilege('bielos_runtime_test', 'public', 'CREATE') AND has_table_privilege('bielos_runtime_test', 'public."User"', 'SELECT') AND has_table_privilege('bielos_runtime_test', 'public."User"', 'INSERT') AND has_table_privilege('bielos_runtime_test', 'public."User"', 'UPDATE') AND has_table_privilege('bielos_runtime_test', 'public."User"', 'DELETE') AND has_type_privilege('bielos_runtime_test', 'public."UserRole"', 'USAGE');`, "inspect isolated E2E role grants");
    assert.equal(e2ePrivileges.trim(), "t", "The isolated E2E role must support fixture DML without database or schema DDL.");
    runPsql(name, "bielos_migrator", migratorPassword, "CREATE TABLE public.__bielos_role_probe (id integer PRIMARY KEY, value text NOT NULL); ALTER TABLE public.__bielos_role_probe ADD COLUMN changed boolean NOT NULL DEFAULT false;", "create objects with migration role");
    const newObjectPrivileges = runPsql(name, "bielos_bootstrap", bootstrapPassword, `SELECT NOT has_table_privilege('bielos_runtime', 'public.__bielos_role_probe', 'TRUNCATE');`, "inspect future runtime grants");
    assert.equal(newObjectPrivileges.trim(), "t", "Future migration objects must not inherit unexpected runtime privileges.");
    const newE2eObjectPrivileges = runPsql(name, "bielos_bootstrap", bootstrapPassword, "SELECT NOT has_table_privilege('bielos_runtime_test', 'public.__bielos_role_probe', 'TRUNCATE');", "inspect future isolated E2E grants");
    assert.equal(newE2eObjectPrivileges.trim(), "t", "Future migration objects must not inherit stale isolated E2E privileges.");
    runPsql(name, "bielos_migrator", migratorPassword, "CREATE FUNCTION public.__bielos_role_probe_routine() RETURNS integer LANGUAGE sql AS $$ SELECT 1 $$;", "create future migration routine");
    const newRoutinePrivileges = runPsql(name, "bielos_bootstrap", bootstrapPassword, `SELECT has_function_privilege('bielos_migrator', 'public.digest(text,text)', 'EXECUTE') AND NOT has_function_privilege('bielos_runtime', 'public.__bielos_role_probe_routine()', 'EXECUTE');`, "inspect future routine grants");
    assert.equal(newRoutinePrivileges.trim(), "t", "The migrator must retain only its explicit pgcrypto migration access, and future routines must not be executable by runtime.");
    const newE2eRoutinePrivileges = runPsql(name, "bielos_bootstrap", bootstrapPassword, "SELECT NOT has_function_privilege('bielos_runtime_test', 'public.__bielos_role_probe_routine()', 'EXECUTE');", "inspect future isolated E2E routine grants");
    assert.equal(newE2eRoutinePrivileges.trim(), "t", "Future migration routines must not inherit stale isolated E2E execute privileges.");
    runPsql(name, "bielos_migrator", migratorPassword, "DROP FUNCTION public.__bielos_role_probe_routine();", "remove future routine fixture");
    const pgcryptoMigrationAccess = runPsql(name, "bielos_migrator", migratorPassword, "SELECT encode(public.digest('bielos-migration-probe', 'sha256'), 'hex');", "verify migrator pgcrypto access");
    assert.match(pgcryptoMigrationAccess, /^[a-f0-9]{64}$/mu, "The migration role must be able to use the pgcrypto digest function required by the committed migration.");
    const runtimeCrud = runPsql(name, "bielos_runtime", runtimePassword, "INSERT INTO public.__bielos_role_probe (id, value) VALUES (1, 'before'); UPDATE public.__bielos_role_probe SET value = 'after' WHERE id = 1; SELECT value FROM public.__bielos_role_probe WHERE id = 1; DELETE FROM public.__bielos_role_probe WHERE id = 1;", "application CRUD with runtime role");
    assert.match(runtimeCrud, /after/u, "The runtime role must complete application reads and writes.");
    const e2eCrud = runPsql(name, "bielos_runtime_test", e2ePassword, "INSERT INTO public.__bielos_role_probe (id, value) VALUES (2, 'fixture'); UPDATE public.__bielos_role_probe SET value = 'fixture-updated' WHERE id = 2; SELECT value FROM public.__bielos_role_probe WHERE id = 2; DELETE FROM public.__bielos_role_probe WHERE id = 2;", "isolated E2E fixture CRUD");
    assert.match(e2eCrud, /fixture-updated/u, "The isolated E2E role must complete fixture reads and writes.");

    const forbiddenDdl = docker([
      "exec", `--env=PGPASSWORD=${runtimePassword}`, name,
      "psql", "--no-psqlrc", "--host", "127.0.0.1", "--username", "bielos_runtime",
      "--dbname", "bielos_roles_test", "--set", "ON_ERROR_STOP=1", "--command",
      "CREATE TABLE public.__bielos_forbidden_probe (id integer);"
    ], "attempt runtime DDL", { allowFailure: true });
    assert.notEqual(forbiddenDdl.status, 0, "The runtime role must not create persistent tables.");
    assert.match(forbiddenDdl.stderr ?? "", /permission denied/u, "Runtime DDL must fail specifically because the role lacks permission.");

    runPsql(name, "bielos_migrator", migratorPassword, "DROP TABLE public.__bielos_role_probe;", "clean temporary role probe");
  } catch (error) {
    failure = error;
  }

  try {
    const cleanup = docker(["rm", "--force", name], `remove ${kind} PostgreSQL fixture`, { allowFailure: true });
    if (cleanup.status !== 0) {
      const remaining = docker([
        "container", "ls", "--all", "--quiet", "--filter", `name=^/${name}$`
      ], `verify ${kind} PostgreSQL fixture cleanup`);
      if (remaining.stdout.trim()) {
        const detail = redactDockerDiagnostics(cleanup.stderr ?? "", ["rm", "--force", name]);
        throw new Error(`remove ${kind} PostgreSQL fixture failed in Docker (exit ${cleanup.status ?? "unknown"})${detail ? `: ${detail}` : ""}.`);
      }
    }
  } catch (cleanupError) {
    failure = failure
      ? new AggregateError([failure, cleanupError], "PostgreSQL role validation and fixture cleanup both failed.")
      : cleanupError;
  }

  if (failure) throw failure;
}

async function waitForHealthy(name) {
  const deadline = Date.now() + 90_000;
  while (Date.now() < deadline) {
    const result = docker(["inspect", `--format={{.State.Health.Status}}`, name], "check PostgreSQL fixture health");
    if (result.status === 0 && result.stdout.trim() === "healthy") return;
    if (result.status === 0 && result.stdout.trim() === "unhealthy") break;
    await delay(500);
  }
  throw new Error("Disposable PostgreSQL fixture did not become healthy within 90 seconds.");
}

function getMappedPort(name) {
  const result = docker(["port", name, "5432/tcp"], "resolve PostgreSQL fixture port");
  assert.equal(result.status, 0, "Could not resolve the disposable PostgreSQL fixture port.");
  const match = /127\.0\.0\.1:(\d+)/u.exec(result.stdout);
  assert.ok(match, "Docker did not publish the disposable PostgreSQL fixture on loopback.");
  return Number(match[1]);
}

function runPsql(name, role, password, sql, label) {
  const result = docker([
    "exec", `--env=PGPASSWORD=${password}`, name,
    "psql", "--no-psqlrc", "--host", "127.0.0.1", "--username", role,
    "--dbname", "bielos_roles_test", "--set", "ON_ERROR_STOP=1", "--tuples-only", "--no-align", "--command", sql
  ], label);
  assert.equal(result.status, 0, `${label} failed.`);
  return result.stdout;
}

function runMigrationsAsMigrator(databaseUrl, label) {
  const result = spawnSync(process.execPath, [path.join(repositoryRoot, "packages", "database", "scripts", "prisma-migrate.mjs"), "deploy"], {
    cwd: repositoryRoot,
    env: migrationEnvironment(databaseUrl),
    encoding: "utf8",
    windowsHide: true,
    timeout: 120_000,
    maxBuffer: 10 * 1024 * 1024
  });
  assert.equal(result.error, undefined, `${label} could not start.`);
  assert.equal(result.status, 0, `${label} failed (exit ${result.status ?? "unknown"}).`);
}

function runMigrationsDirect(databaseUrl, label) {
  const result = spawnSync(process.execPath, [prismaCliPath, "migrate", "deploy", "--schema", path.join(repositoryRoot, "packages", "database", "prisma", "schema.prisma")], {
    cwd: repositoryRoot,
    env: migrationEnvironment(databaseUrl),
    encoding: "utf8",
    windowsHide: true,
    timeout: 120_000,
    maxBuffer: 10 * 1024 * 1024
  });
  assert.equal(result.error, undefined, `${label} could not start.`);
  assert.equal(result.status, 0, `${label} failed (exit ${result.status ?? "unknown"}).`);
}

function migrationEnvironment(databaseUrl) {
  const env = {};
  for (const key of ["PATH", "Path", "HOME", "TMPDIR", "TMP", "TEMP", "SYSTEMROOT", "WINDIR", "USERPROFILE", "HOMEDRIVE", "HOMEPATH", "APPDATA", "LOCALAPPDATA", "PATHEXT", "COMSPEC", "LANG", "LC_ALL", "CI"]) {
    if (process.env[key] !== undefined) env[key] = process.env[key];
  }
  env.DATABASE_URL = databaseUrl;
  env.MIGRATION_DATABASE_URL = databaseUrl;
  env.NODE_ENV = "test";
  env.PRISMA_HIDE_UPDATE_MESSAGE = "1";
  return env;
}

function connectionUrl(role, password, port) {
  return `postgresql://${role}:${password}@127.0.0.1:${port}/bielos_roles_test?schema=public`;
}

function docker(args, label, { allowFailure = false } = {}) {
  const result = spawnSync("docker", args, {
    cwd: repositoryRoot,
    encoding: "utf8",
    windowsHide: true,
    timeout: 120_000,
    maxBuffer: 10 * 1024 * 1024
  });
  if (result.error) throw new Error(`${label} could not run Docker (${result.error.code ?? "unknown error"}).`);
  if (!allowFailure && result.status !== 0) {
    const detail = redactDockerDiagnostics(result.stderr ?? "", args);
    throw new Error(`${label} failed in Docker (exit ${result.status ?? "unknown"})${detail ? `: ${detail}` : ""}.`);
  }
  return result;
}

function redactDockerDiagnostics(value, args) {
  let output = String(value).trim();
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index] === "--env" ? args[index + 1] : args[index].startsWith("--env=") ? args[index].slice("--env=".length) : "";
    const separator = argument.indexOf("=");
    if (separator >= 0 && argument.slice(separator + 1)) {
      output = output.replaceAll(argument.slice(separator + 1), "[redacted]");
    }
  }
  return output.slice(-2000);
}
