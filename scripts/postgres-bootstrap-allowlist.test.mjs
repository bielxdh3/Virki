import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import {
  verifyBootstrapPgpassBinding,
  verifyServicePgpassBinding,
  verifyWorkerPgpassBinding,
  verifyWorkerRestorePgpassBinding
} from "./staging-pgpass-bootstrap-binding.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

test("PostgreSQL bootstrap allowlist accepts every table introduced by committed migrations", () => {
  const bootstrap = readFileSync(path.join(root, "infra/postgres-init/10-virki-database-roles.sh"), "utf8");
  const start = bootstrap.indexOf("AND relation.relname NOT IN (");
  assert.ok(start >= 0, "bootstrap must retain its explicit public-schema allowlist");
  const end = bootstrap.indexOf(")\n      AND NOT EXISTS", start);
  assert.ok(end > start, "bootstrap must retain the extension exclusion");
  const allowed = new Set([...bootstrap.slice(start, end).matchAll(/'([^']+)'/gu)].map((match) => match[1]));

  const migrations = path.join(root, "packages/database/prisma/migrations");
  const created = new Set();
  for (const migration of readdirSync(migrations, { withFileTypes: true })) {
    if (!migration.isDirectory()) continue;
    const sql = readFileSync(path.join(migrations, migration.name, "migration.sql"), "utf8");
    for (const match of sql.matchAll(/\bCREATE TABLE(?: IF NOT EXISTS)?\s+(?:public\.)?"([^"]+)"/gu)) {
      created.add(match[1]);
    }
  }
  assert.deepEqual([...created].filter((name) => !allowed.has(name)).sort(), [],
    "schema upgrades must not make bootstrap role reconciliation reject legitimate Virki tables");
});

test("PostgreSQL role bootstrap never waits for an interactive password prompt", () => {
  const bootstrap = readFileSync(path.join(root, "infra/postgres-init/10-virki-database-roles.sh"), "utf8");
  const invocations = bootstrap.split(/\r?\n/u).filter((line) => /^\s*psql\b/u.test(line));
  assert.equal(invocations.length, 2, "both role-management SQL entry points must remain explicit");
  for (const invocation of invocations) {
    assert.match(invocation, /^\s*psql --no-psqlrc --no-password\b/u,
      "peer-auth failure must stop, never hang waiting for a password");
  }
});

test("PostgreSQL role bootstrap clears ambient libpq overrides and pins the local socket", () => {
  const bootstrap = readFileSync(path.join(root, "infra/postgres-init/10-virki-database-roles.sh"), "utf8");
  const workerBootstrap = readFileSync(path.join(root, "infra/postgres-init/11-virki-email-worker-role.sh"), "utf8");
  const requiredOverrides = [
    "PGHOSTADDR", "PGHOST", "PGPORT", "PGSERVICE", "PGSERVICEFILE", "PGOPTIONS", "PGUSER", "PGDATABASE",
    "PGPASSWORD", "PGPASSFILE", "PGSSLMODE", "PGSSLCERT", "PGSSLKEY", "PGSSLROOTCERT", "PGSSLCRL",
    "PGSSLKEYLOGFILE", "SSLKEYLOGFILE",
    "PGSSLMINPROTOCOLVERSION", "PGSSLMAXPROTOCOLVERSION", "PGCHANNELBINDING", "PGCONNECT_TIMEOUT",
    "PGTARGETSESSIONATTRS", "PGAPPNAME", "PGCLIENTENCODING", "PGSSLNEGOTIATION", "PGREQUIREPEER",
    "PGGSSENCMODE", "PGGSSDELEGATION", "PGKRBSRVNAME", "PGREQUIRESSL", "PGSSLCOMPRESSION",
    "PGLOADBALANCEHOSTS", "PGREQUIREAUTH", "PGSSLCERTMODE", "PGSSLCRLDIR", "PGSSLSNI", "PGGSSLIB",
    "PGMINPROTOCOLVERSION", "PGMAXPROTOCOLVERSION", "PGSYSCONFDIR", "PGLOCALEDIR", "PGDATESTYLE",
    "PGTZ", "PGGEQO", "PGOAUTHDEBUG", "PGOAUTHCAFILE"
  ];
  for (const [name, source] of [["role bootstrap", bootstrap], ["worker-role bootstrap", workerBootstrap]]) {
    const cleared = new Set([...source.matchAll(/^\s*unset\s+(.+)$/gmu)]
      .flatMap((match) => match[1].trim().split(/\s+/u)));
    for (const variable of requiredOverrides) {
      assert.ok(cleared.has(variable), `${name} must clear ${variable}`);
    }
    assert.ok(source.indexOf("unset PGHOSTADDR") < source.indexOf("psql --no-psqlrc"),
      `${name} must clear libpq overrides before connecting`);
    assert.ok(source.indexOf("export PGPASSFILE=/dev/null") > source.indexOf("unset PGHOSTADDR") &&
      source.indexOf("export PGPASSFILE=/dev/null") < source.indexOf("psql --no-psqlrc"),
    `${name} must disable libpq's implicit ~/.pgpass fallback before connecting`);
  }
  assert.match(bootstrap, /unset PGHOSTADDR PGHOST PGPORT PGSERVICE PGSERVICEFILE PGOPTIONS PGUSER PGDATABASE/u);
  assert.match(bootstrap, /unset PGPASSWORD PGPASSFILE PGSSLMODE PGSSLCERT PGSSLKEY PGSSLROOTCERT PGSSLCRL/u);
  assert.match(bootstrap, /export PGHOST=\/var\/run\/postgresql\s+export PGPORT=5432/u);
  assert.equal((bootstrap.match(/--host=\/var\/run\/postgresql/g) ?? []).length, 2);
  assert.equal((bootstrap.match(/--port=5432/g) ?? []).length, 2);
  assert.match(bootstrap, /inet_server_addr\(\) IS NOT NULL OR current_setting\('port'\) <> '5432'/u);
});

test("email worker bootstrap rejects excess public and protected schema type USAGE", () => {
  const workerBootstrap = readFileSync(path.join(root, "infra/postgres-init/11-virki-email-worker-role.sh"), "utf8");
  const grants = workerBootstrap.match(/GRANT USAGE ON TYPE public\."OutboxMessageStatus", public\."DeliveryAttemptStatus", public\."EmailMessageKind" TO virki_email_worker;/gu);
  assert.equal(grants?.length, 1, "the mail worker must need only its three enum types");
  assert.equal((workerBootstrap.match(/has_type_privilege\('virki_email_worker', type\.oid, 'USAGE'\)/gu) ?? []).length, 2,
    "both public and protected schemas must reject inherited and latent extra type grants");
  assert.match(workerBootstrap, /type\.typname NOT IN \('OutboxMessageStatus', 'DeliveryAttemptStatus', 'EmailMessageKind'\)/u);
  assert.match(workerBootstrap, /namespace\.nspname <> 'public'\s+AND namespace\.nspname <> 'information_schema'\s+AND left\(namespace\.nspname, 3\) <> 'pg_'/u);
});

test("staging runbook binds remote HBA to exact SCRAM rules and rejects every include directive", () => {
  const runbook = readFileSync(path.join(root, "docs/security/pr118-staging-operator-runbook-20261114.md"), "utf8");
  const activeSql = readFileSync(path.join(root, "scripts/staging-remote-hba-active.sql"), "utf8");
  const rulesSql = readFileSync(path.join(root, "scripts/staging-remote-hba-rules.sql"), "utf8");
  const localSql = readFileSync(path.join(root, "scripts/staging-local-hba-peer.sql"), "utf8");
  assert.equal((runbook.match(/--file=scripts\/staging-remote-hba-active\.sql/gu) ?? []).length, 2);
  assert.equal((runbook.match(/--file=scripts\/staging-remote-hba-rules\.sql/gu) ?? []).length, 2);
  assert.equal((runbook.match(/--file=scripts\/staging-local-hba-peer\.sql/gu) ?? []).length, 1);
  for (const [name, sql] of [["remote active", activeSql], ["remote rules", rulesSql], ["local peer", localSql]]) {
    assert.equal((sql.match(/pg_hba_file_rules/gu) ?? []).length, 1,
      `${name} must materialize one parsed HBA-rule snapshot and reuse it for every count`);
    assert.match(sql, /hba_rules AS MATERIALIZED/u);
  }
  for (const [name, sql] of [["remote active", activeSql], ["local peer", localSql]]) {
    assert.ok(sql.includes("regexp_split_to_table(") &&
      sql.includes(String.raw`replace(hba_file.contents, chr(92) || E'\r\n', '')`) &&
      sql.includes(String.raw`chr(92) || E'\n'`),
      `${name} must collapse PostgreSQL backslash-newline continuations before scanning physical records`);
    assert.ok(sql.includes("E'\\n'"),
      `${name} must split the normalized canonical HBA file on actual newline characters`);
    assert.ok(sql.includes("regexp_replace(hba_line.line, '^[[:space:]]+', '')"),
      `${name} must detect directives with leading tabs and other whitespace`);
    assert.ok(sql.includes("'^(include|include_if_exists|include_dir)([[:space:]]|$)'"),
      `${name} must reject every include directive, not similarly prefixed tokens`);
  }
  assert.match(rulesSql, /LEFT JOIN hba_rules AS r/u);
  assert.match(rulesSql, /hba_state AS MATERIALIZED/u);
  assert.match(rulesSql,
    /checks_summary AS MATERIALIZED\s*\(\s*SELECT count\(\*\) FILTER \(WHERE bad_rules = 0 AND scram_matches = 1\) AS passed,\s*count\(\*\) AS expected\s*FROM checks\s*\)/u,
    "the pass count must be aggregated separately from the one-row HBA state");
  assert.match(rulesSql,
    /SELECT passed::text \|\| '\|' \|\| expected::text[\s\S]*FROM checks_summary CROSS JOIN hba_state;/u,
    "the final HBA verdict must combine scalar summaries without mixing grouped and ungrouped columns");
  assert.doesNotMatch(rulesSql, /FROM pg_hba_file_rules WHERE/u,
    "counts must not reread the dynamic pg_hba_file_rules view outside the materialized snapshot");
  assert.equal((runbook.match(/\$hba_includes" == "0"/gu) ?? []).length, 2);
  assert.match(localSql, /restore_peer_rules/u);
  assert.match(localSql, /'peer'/u);
  assert.equal((rulesSql.match(/r\.auth_method = 'scram-sha-256'/gu) ?? []).length, 2,
    "both HBA rule gates must require SCRAM on exact remote rules");
  assert.equal((rulesSql.match(/r\.address::inet = inet_client_addr\(\)/gu) ?? []).length, 2,
    "remote HBA sources must be the exact observed client IP");
  assert.equal((rulesSql.match(/r\.netmask::inet = CASE family\(inet_client_addr\(\)\)/gu) ?? []).length, 2,
    "remote HBA sources must be /32 IPv4 or /128 IPv6, never broad CIDRs");
  assert.equal((rulesSql.match(/'replication' = ANY\(coalesce\(database, ARRAY\[\]::text\[\]\)\)/gu) ?? []).length, 1,
    "the shared remote HBA rule gate must reject replication-database rules");
  assert.equal((rulesSql.match(/count\(\*\)::text FROM hba_rules WHERE type <> 'local'/gu) ?? []).length, 1,
    "both HBA gates must reject any non-local rule outside the exact eight-entry allowlist");
  assert.equal((runbook.match(/\[\[ "\$result" == "8\|8\|0\|0\|8\|true" \]\]/gu) ?? []).length, 2);
  assert.equal((runbook.match(/^verify_remote_hba_rules$/gmu) ?? []).length, 5,
    "HBA rules must be rechecked after initial and restore-database connection probes");
  assert.equal((runbook.match(/^verify_remote_hba_active$/gmu) ?? []).length, 5,
    "loaded-file mtime, include directives, endpoint and client identity must be rechecked after each probe group");
  assert.equal((runbook.match(/negative-passfile\.XXXXXX/gu) ?? []).length, 2,
    "both remote SCRAM probe implementations must create a private wrong-password passfile");
  assert.equal((runbook.match(/password authentication failed/gu) ?? []).length, 2,
    "a failed probe must prove an actual password-authentication rejection, not any connection error");
  assert.equal((runbook.match(/^\s*unset PGPASSWORD$/gmu) ?? []).length, 2,
    "both negative probes must leave PGPASSFILE as the only password source");
  assert.doesNotMatch(runbook, /PGPASSFILE="\$negative_pass_file" PGPASSWORD=/u,
    "an empty PGPASSWORD override must not bypass the deliberately incorrect passfile");
  assert.equal((runbook.match(/hostaddr=\$VIRKI_STAGING_APPROVED_DB_SERVER_ADDR/gu) ?? []).length, 4,
    "positive and negative probes must pin the approved server address while retaining TLS host verification");
  const includeScanner = (contents) => contents.replace(/\\\r?\n/gu, "").split(/\r?\n/u).some((line) =>
    /^(include|include_if_exists|include_dir)(?:[\s]|$)/iu.test(line.replace(/^[\s]+/u, "")));
  for (const directive of [
    "\tinclude /etc/postgresql/extra.conf",
    " \tinclude_if_exists /tmp/extra.conf",
    "include_dir /tmp/hba.d",
    "incl\\\nude /tmp/continued.conf",
    "include_if_\\\r\nexists /tmp/continued-optional.conf",
    "include_\\\ndir /tmp/continued-directory"
  ]) {
    assert.equal(includeScanner(directive), true, directive);
  }
  assert.equal(includeScanner("# include /tmp/commented.conf"), false);
  assert.equal(includeScanner("includeish /tmp/not-a-directive"), false);
  assert.match(runbook, /"\$node_bin" scripts\/staging-toolchain-preflight\.mjs/u,
    "staging toolchain preflight must use the approved Node binary rather than PATH");
  assert.equal((runbook.match(/test -x \/usr\/bin\/git/gu) ?? []).length, 2,
    "both staging and rollback phases must require the pinned system Git executable");
  assert.doesNotMatch(runbook, /command -v git/u,
    "runbook source and cleanliness gates must not trust a PATH-selected Git shim");
  assert.ok((runbook.match(/\/usr\/bin\/git (?:rev-parse|status)/gu) ?? []).length >= 6,
    "all exact-SHA and clean-tree checks must use the pinned Git executable");
  assert.doesNotMatch(runbook, /Number\(process\.versions\.node\.split\("\."\)\[0\]\) < 22/u,
    "runbook must enforce both exact Node and npm engine ranges");
  assert.match(runbook, /PGPASSFILE=\/dev\/null/u,
    "role bootstrap must explicitly disable libpq's implicit per-user passfile");
  assert.match(runbook, /exact approved Git tree \(not the mutable filesystem directory\)/u);
  assert.match(runbook, /VIRKI_AUDIT_MAINTENANCE_DB_PASSWORD/u);
  assert.match(runbook, /VIRKI_EMAIL_WORKER_DB_SCRAM_VERIFIER/u);
  const helperCalls = [...runbook.matchAll(/"\$node_bin" scripts\/staging-pgpass-bootstrap-binding\.mjs/g)]
    .map((match) => match.index);
  assert.equal(helperCalls.length, 2, "preflight and rollback must both verify PGPASS bindings");
  assert.match(runbook, /\| "\$node_bin" scripts\/staging-prisma-migration-ledger-binding\.mjs/u,
    "the rollback migration ledger must run with the independently approved Node binary");
  const rollbackSectionStart = runbook.indexOf("## 4. Physical rollback");
  assert.ok(rollbackSectionStart >= 0 && rollbackSectionStart < helperCalls[1]);
  const rollbackEnvironment = runbook.slice(rollbackSectionStart, helperCalls[1]);
  for (const variable of [
    "VIRKI_RUNTIME_DB_PASSWORD", "VIRKI_MIGRATOR_DB_PASSWORD",
    "VIRKI_AUDIT_MAINTENANCE_DB_PASSWORD", "VIRKI_EMAIL_WORKER_DB_SCRAM_VERIFIER"
  ]) {
    assert.ok(rollbackEnvironment.includes(`: "\${${variable}:?`),
      `rollback must require ${variable} before the PGPASS helper`);
    assert.match(rollbackEnvironment, new RegExp(`\\bexport\\b[^\\n]*\\b${variable}\\b`, "u"),
      `rollback must export ${variable} before the PGPASS helper`);
  }
  assert.ok(rollbackEnvironment.includes("export VIRKI_STAGING_APPROVED_SOURCE_SHA"),
    "rollback must export the exact approved SHA to the migration-ledger CLI");
  const rollbackLocalStart = runbook.indexOf('export POSTGRES_DB="$VIRKI_STAGING_RESTORE_DB"');
  const rollbackRemoteRestore = runbook.indexOf('export PGPASSFILE="$pass_file"', rollbackLocalStart);
  assert.ok(rollbackLocalStart >= 0 && rollbackRemoteRestore > rollbackLocalStart);
  const rollbackLocalCommands = runbook.slice(rollbackLocalStart, rollbackRemoteRestore);
  assert.ok(rollbackLocalCommands.indexOf("export PGPASSFILE=/dev/null") <
    rollbackLocalCommands.indexOf("psql --no-psqlrc --no-password"),
  "all parent-process local rollback psql commands must disable implicit ~/.pgpass lookup");
  assert.doesNotMatch(runbook, /grep\s+-[^\n]*\\\\\*/u,
    "PGPASS password fields may contain a literal asterisk or backslash-asterisk");
});

const bootstrapHost = "pg.staging.example.invalid";
const bootstrapPort = "5432";
const bootstrapUser = "virki_staging_bootstrap";
const bootstrapPassword = "staging:\\*bootstrap\\credential";
const workerPassword = "staging:worker\\*credential\\secret";
const runtimePassword = "staging:runtime\\*credential\\secret";
const migratorPassword = "staging:migrator\\*credential\\secret";
const restoreDatabase = "virki_stage_restore_abcdef123456";
const approvedDatabase = "virki_staging";
const workerUser = "virki_email_worker";
const serviceFileText = `[virki-staging-bootstrap]\nhost=${bootstrapHost}\nport=${bootstrapPort}\ndbname=postgres\nuser=${bootstrapUser}\nsslmode=verify-full\n\n[virki-staging-worker]\nhost=${bootstrapHost}\nport=${bootstrapPort}\ndbname=${approvedDatabase}\nuser=${workerUser}\nsslmode=verify-full\n\n[virki-staging-hub]\nhost=${bootstrapHost}\nport=${bootstrapPort}\ndbname=${approvedDatabase}\nuser=virki_runtime\nsslmode=verify-full\n\n[virki-staging-migrator]\nhost=${bootstrapHost}\nport=${bootstrapPort}\ndbname=${approvedDatabase}\nuser=virki_migrator\nsslmode=verify-full\n`;
const escapePgpassField = (value) => value.replaceAll("\\", "\\\\").replaceAll(":", "\\:");
const passFileText = [
  ["postgres", bootstrapUser, bootstrapPassword],
  [restoreDatabase, bootstrapUser, bootstrapPassword],
  [approvedDatabase, workerUser, workerPassword],
  [restoreDatabase, workerUser, workerPassword],
  [approvedDatabase, "virki_runtime", runtimePassword],
  [restoreDatabase, "virki_runtime", runtimePassword],
  [approvedDatabase, "virki_migrator", migratorPassword],
  [restoreDatabase, "virki_migrator", migratorPassword]
].map(([database, user, password]) =>
  `${[bootstrapHost, bootstrapPort, database, user, escapePgpassField(password)].join(":")}\n`
).join("");
const verifyBinding = (overrides = {}) => verifyBootstrapPgpassBinding({
  serviceFileText,
  passFileText,
  expectedHost: bootstrapHost,
  expectedPort: bootstrapPort,
  expectedUser: bootstrapUser,
  bootstrapPassword,
  restoreDatabase,
  ...overrides
});
const verifyWorkerBinding = (overrides = {}) => verifyWorkerRestorePgpassBinding({
  serviceFileText,
  passFileText,
  expectedHost: bootstrapHost,
  expectedPort: bootstrapPort,
  expectedDatabase: approvedDatabase,
  expectedUser: workerUser,
  workerPassword,
  restoreDatabase,
  ...overrides
});
const verifyWorkerPreflightBinding = (overrides = {}) => verifyWorkerPgpassBinding({
  serviceFileText,
  passFileText,
  expectedHost: bootstrapHost,
  expectedPort: bootstrapPort,
  expectedDatabase: approvedDatabase,
  expectedUser: workerUser,
  workerPassword,
  ...overrides
});

test("bootstrap PGPASSFILE binding accepts the exact credential for the service and restore database", () => {
  assert.equal(verifyBinding(), true);
});

test("PGPASS parser preserves a literal backslash-asterisk in every password field", () => {
  for (const password of [bootstrapPassword, workerPassword, runtimePassword, migratorPassword]) {
    assert.ok(passFileText.includes(escapePgpassField(password)),
      "the PGPASS fixture must contain the escaped literal backslash-star bytes");
  }
  assert.equal(verifyBinding(), true);
  assert.equal(verifyWorkerBinding(), true);
  assert.equal(verifyWorkerPreflightBinding(), true);
  for (const [serviceName, expectedUser, password, failurePrefix] of [
    ["virki-staging-hub", "virki_runtime", runtimePassword, "RUNTIME"],
    ["virki-staging-migrator", "virki_migrator", migratorPassword, "MIGRATOR"]
  ]) {
    assert.equal(verifyServicePgpassBinding({
      serviceFileText, passFileText, serviceName,
      expectedHost: bootstrapHost, expectedPort: bootstrapPort,
      expectedDatabase: approvedDatabase, expectedUser, credential: password,
      restoreDatabase, failurePrefix
    }), true);
  }
});

test("bootstrap PGPASSFILE binding rejects a POSTGRES_PASSWORD decoy", () => {
  assert.throws(() => verifyBinding({ bootstrapPassword: "different-secret" }), {
    code: "BOOTSTRAP_PASSWORD_MISMATCH"
  });
});

test("bootstrap PGPASSFILE binding rejects service target, user, or TLS drift", () => {
  for (const replacement of [
    "host=pg.production.example.invalid",
    "port=5433",
    "dbname=virki_production",
    "user=virki_runtime",
    "sslmode=require"
  ]) {
    const key = replacement.split("=", 1)[0];
    const changed = serviceFileText.replace(new RegExp(`^${key}=.*$`, "mu"), replacement);
    assert.throws(() => verifyBinding({ serviceFileText: changed }), {
      code: "BOOTSTRAP_SERVICE_TARGET_MISMATCH"
    }, replacement);
  }
});

test("bootstrap PGPASSFILE binding rejects wildcard and duplicate matching entries", () => {
  assert.throws(() => verifyBinding({ passFileText: "" }), {
    code: "BOOTSTRAP_PGPASS_MATCH_COUNT"
  });
  assert.throws(() => verifyBinding({ passFileText: `${passFileText}*:*:*:*:other\n` }), {
    code: "PGPASS_WILDCARD_FORBIDDEN"
  });
  assert.throws(() => verifyBinding({ passFileText: `${passFileText}${passFileText}` }), {
    code: "BOOTSTRAP_PGPASS_MATCH_COUNT"
  });
});

test("bootstrap PGPASSFILE binding rejects a missing or mismatched restore-database credential", () => {
  const restoreLine = passFileText.split("\n").find((line) => line.includes(`:${restoreDatabase}:`));
  assert.ok(restoreLine);
  assert.throws(() => verifyBinding({
    passFileText: passFileText.replace(`${restoreLine}\n`, "")
  }), { code: "BOOTSTRAP_PGPASS_MATCH_COUNT" });
  assert.throws(() => verifyBinding({
    passFileText: passFileText.replace(restoreLine, restoreLine.replace(escapePgpassField(bootstrapPassword), "wrong-password"))
  }), { code: "BOOTSTRAP_PASSWORD_MISMATCH" });
  assert.throws(() => verifyBinding({
    passFileText: `${passFileText}${restoreLine}\n`
  }), { code: "BOOTSTRAP_PGPASS_MATCH_COUNT" });
});

test("worker PGPASSFILE binding accepts the approved and restore database credentials", () => {
  assert.equal(verifyWorkerBinding(), true);
});

test("worker PGPASSFILE preflight accepts only the exact approved-database credential", () => {
  assert.equal(verifyWorkerPreflightBinding(), true);
  assert.throws(() => verifyWorkerPreflightBinding({
    passFileText: passFileText.replace(
      passFileText.split("\n").find((line) => line.includes(`:${approvedDatabase}:${workerUser}:`)),
      `${[bootstrapHost, bootstrapPort, approvedDatabase, workerUser, "wrong-password"].join(":")}`
    )
  }), { code: "WORKER_PASSWORD_MISMATCH" });
});

test("Hub runtime and migrator PGPASSFILE entries bind exact TLS services and credentials", () => {
  for (const [serviceName, expectedUser, password, failurePrefix] of [
    ["virki-staging-hub", "virki_runtime", runtimePassword, "RUNTIME"],
    ["virki-staging-migrator", "virki_migrator", migratorPassword, "MIGRATOR"]
  ]) {
    assert.equal(verifyServicePgpassBinding({
      serviceFileText,
      passFileText,
      serviceName,
      expectedHost: bootstrapHost,
      expectedPort: bootstrapPort,
      expectedDatabase: approvedDatabase,
      expectedUser,
      credential: password,
      restoreDatabase,
      failurePrefix
    }), true);
    assert.throws(() => verifyServicePgpassBinding({
      serviceFileText,
      passFileText,
      serviceName,
      expectedHost: bootstrapHost,
      expectedPort: bootstrapPort,
      expectedDatabase: approvedDatabase,
      expectedUser,
      credential: "decoy-password",
      restoreDatabase,
      failurePrefix
    }), { code: `${failurePrefix}_PASSWORD_MISMATCH` });
    assert.throws(() => verifyServicePgpassBinding({
      serviceFileText: serviceFileText.replace(`[${serviceName}]`, `[${serviceName}]\nhost=pg.production.example.invalid`),
      passFileText,
      serviceName,
      expectedHost: bootstrapHost,
      expectedPort: bootstrapPort,
      expectedDatabase: approvedDatabase,
      expectedUser,
      credential: password,
      restoreDatabase,
      failurePrefix
    }), { code: "DUPLICATE_SERVICE_KEY" });
    const restoreLine = passFileText.split("\n").find((line) => line.includes(`:${restoreDatabase}:${expectedUser}:`));
    assert.ok(restoreLine);
    assert.throws(() => verifyServicePgpassBinding({
      serviceFileText,
      passFileText: passFileText.replace(`${restoreLine}\n`, ""),
      serviceName,
      expectedHost: bootstrapHost,
      expectedPort: bootstrapPort,
      expectedDatabase: approvedDatabase,
      expectedUser,
      credential: password,
      restoreDatabase,
      failurePrefix
    }), { code: `${failurePrefix}_PGPASS_MATCH_COUNT` });
    assert.throws(() => verifyServicePgpassBinding({
      serviceFileText,
      passFileText: passFileText.replace(restoreLine, restoreLine.replace(escapePgpassField(password), "wrong-password")),
      serviceName,
      expectedHost: bootstrapHost,
      expectedPort: bootstrapPort,
      expectedDatabase: approvedDatabase,
      expectedUser,
      credential: password,
      restoreDatabase,
      failurePrefix
    }), { code: `${failurePrefix}_PASSWORD_MISMATCH` });
  }
});

test("worker PGPASSFILE binding rejects a missing, duplicate, or mismatched restore credential", () => {
  const restoreLine = passFileText.split("\n").find((line) => line.includes(`:${restoreDatabase}:${workerUser}:`));
  assert.ok(restoreLine);
  assert.throws(() => verifyWorkerBinding({
    passFileText: passFileText.replace(`${restoreLine}\n`, "")
  }), { code: "WORKER_PGPASS_MATCH_COUNT" });
  assert.throws(() => verifyWorkerBinding({
    passFileText: passFileText.replace(restoreLine, restoreLine.replace(escapePgpassField(workerPassword), "wrong-password"))
  }), { code: "WORKER_PASSWORD_MISMATCH" });
  assert.throws(() => verifyWorkerBinding({
    passFileText: `${passFileText}${restoreLine}\n`
  }), { code: "WORKER_PGPASS_MATCH_COUNT" });
});

test("bootstrap PGPASSFILE binding rejects duplicate service sections and keys", () => {
  assert.throws(() => verifyBinding({ serviceFileText: `${serviceFileText}${serviceFileText}` }), {
    code: "SERVICE_SECTION_COUNT"
  });
  assert.throws(() => verifyBinding({
    serviceFileText: serviceFileText.replace("sslmode=verify-full", "sslmode=verify-full\nsslmode=disable")
  }), { code: "DUPLICATE_SERVICE_KEY" });
});

test("bootstrap service rejects hostaddr, embedded credentials, and client-certificate auth inputs", () => {
  for (const key of ["hostaddr", "password", "passfile", "sslcert", "sslkey", "sslpassword", "options", "target_session_attrs", "servicefile"]) {
    const changed = serviceFileText.replace("\n[virki-staging-worker]", `\n${key}=unapproved\n\n[virki-staging-worker]`);
    assert.throws(() => verifyBinding({ serviceFileText: changed }), {
      code: key === "hostaddr" || key === "password" || key === "passfile" || key === "sslcert" || key === "sslkey" || key === "sslpassword"
        ? "FORBIDDEN_SERVICE_KEY"
        : "UNAPPROVED_SERVICE_KEY"
    }, key);
  }
  assert.throws(() => verifyBinding({ serviceFileText: `include=/tmp/unapproved.conf\n${serviceFileText}` }), {
    code: "INVALID_SERVICE_FILE"
  });
});

test("bootstrap PGPASSFILE CLI proves equality without printing the credential", () => {
  const directory = mkdtempSync(path.join(tmpdir(), "virki-pgpass-binding-"));
  try {
    const servicePath = path.join(directory, "pg_service.conf");
    const passPath = path.join(directory, "pgpass");
    writeFileSync(servicePath, serviceFileText, { mode: 0o600 });
    writeFileSync(passPath, passFileText, { mode: 0o600 });
    const script = "scripts/staging-pgpass-bootstrap-binding.mjs";
    const env = {
      ...process.env,
      PGSERVICEFILE: servicePath,
      PGPASSFILE: passPath,
      VIRKI_STAGING_APPROVED_DB_HOST: bootstrapHost,
      VIRKI_STAGING_APPROVED_DB_PORT: bootstrapPort,
      VIRKI_STAGING_APPROVED_DB_NAME: approvedDatabase,
      VIRKI_STAGING_RESTORE_DB: restoreDatabase,
      POSTGRES_USER: bootstrapUser,
      POSTGRES_PASSWORD: bootstrapPassword,
      VIRKI_EMAIL_WORKER_DB_PASSWORD: workerPassword,
      VIRKI_RUNTIME_DB_PASSWORD: runtimePassword,
      VIRKI_MIGRATOR_DB_PASSWORD: migratorPassword
    };
    const accepted = spawnSync(process.execPath, [script], { cwd: root, encoding: "utf8", env });
    assert.equal(accepted.status, 0);
    assert.equal(accepted.stdout, "STAGING_BOOTSTRAP_PASSFILE_BINDING=PASS\nSTAGING_WORKER_RESTORE_PASSFILE_BINDING=PASS\nSTAGING_RUNTIME_PASSFILE_BINDING=PASS\nSTAGING_MIGRATOR_PASSFILE_BINDING=PASS\n");
    assert.equal(accepted.stderr, "");
    assert.ok(!accepted.stdout.includes(bootstrapPassword));
    assert.ok(!accepted.stderr.includes(bootstrapPassword));
    for (const secret of [workerPassword, runtimePassword, migratorPassword]) {
      assert.ok(!accepted.stdout.includes(secret));
      assert.ok(!accepted.stderr.includes(secret));
    }

    writeFileSync(passPath, `${passFileText}pg.production.example.invalid:5432:production:postgres:unexpected-secret\n`, { mode: 0o600 });
    const extraCredential = spawnSync(process.execPath, [script], { cwd: root, encoding: "utf8", env });
    assert.equal(extraCredential.status, 1);
    assert.equal(extraCredential.stdout, "");
    assert.equal(extraCredential.stderr, "BLOCK:STAGING_PGPASSFILE_BINDING\n");

    writeFileSync(passPath, passFileText, { mode: 0o600 });
    writeFileSync(servicePath, `${serviceFileText}[virki-production]\nhost=pg.production.example.invalid\n`, { mode: 0o600 });
    const extraService = spawnSync(process.execPath, [script], { cwd: root, encoding: "utf8", env });
    assert.equal(extraService.status, 1);
    assert.equal(extraService.stdout, "");
    assert.equal(extraService.stderr, "BLOCK:STAGING_PGPASSFILE_BINDING\n");
    writeFileSync(servicePath, serviceFileText, { mode: 0o600 });

    const workerPreflight = spawnSync(process.execPath, [script, "--worker-preflight"], {
      cwd: root,
      encoding: "utf8",
      env
    });
    assert.equal(workerPreflight.status, 0);
    assert.equal(workerPreflight.stdout, "STAGING_WORKER_PGPASSFILE_BINDING=PASS\n");
    assert.equal(workerPreflight.stderr, "");
    assert.ok(!workerPreflight.stdout.includes(workerPassword));
    assert.ok(!workerPreflight.stderr.includes(workerPassword));

    writeFileSync(passPath, passFileText.replaceAll(escapePgpassField(workerPassword), "wrong-password"), { mode: 0o600 });
    const rejected = spawnSync(process.execPath, [script], { cwd: root, encoding: "utf8", env });
    assert.equal(rejected.status, 1);
    assert.equal(rejected.stdout, "");
    assert.equal(rejected.stderr, "BLOCK:STAGING_PGPASSFILE_BINDING\n");
    assert.ok(!rejected.stdout.includes(bootstrapPassword));
    assert.ok(!rejected.stderr.includes(bootstrapPassword));
    assert.ok(!rejected.stdout.includes(workerPassword));
    assert.ok(!rejected.stderr.includes(workerPassword));
    assert.ok(!rejected.stdout.includes(runtimePassword));
    assert.ok(!rejected.stderr.includes(runtimePassword));
    assert.ok(!rejected.stdout.includes(migratorPassword));
    assert.ok(!rejected.stderr.includes(migratorPassword));
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
