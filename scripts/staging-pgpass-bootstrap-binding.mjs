import { readFileSync } from "node:fs";
import { isIP } from "node:net";
import { pathToFileURL } from "node:url";

function fail(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}

const ALLOWED_SERVICE_KEYS = new Set(["host", "port", "dbname", "user", "sslmode", "sslrootcert"]);
// An immutable staging-only image must contain the approved CA at this exact
// path. Merely setting PGSSLROOTCERT/NODE_EXTRA_CA_CERTS does not configure
// the Prisma query engine, and labels alone do not attest image file bytes.
export const STAGING_PRISMA_CA_PATH = "/app/ca/staging-db-root.pem";

function parseServiceSection(source, sectionName) {
  let active = false;
  let inSection = false;
  let sectionCount = 0;
  const values = Object.create(null);

  for (const rawLine of source.split(/\r?\n/u)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    if (line.startsWith("[")) {
      if (!line.endsWith("]")) fail("INVALID_SERVICE_FILE");
      inSection = true;
      active = line.slice(1, -1) === sectionName;
      if (active && ++sectionCount > 1) fail("SERVICE_SECTION_COUNT");
      continue;
    }
    if (!inSection) fail("INVALID_SERVICE_FILE");
    if (!active) continue;
    const match = /^([A-Za-z][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/u.exec(line);
    if (!match) fail("INVALID_SERVICE_FILE");
    const key = match[1].toLowerCase();
    if (["hostaddr", "password", "passfile", "sslcert", "sslkey", "sslpassword"].includes(key)) {
      fail("FORBIDDEN_SERVICE_KEY");
    }
    if (!ALLOWED_SERVICE_KEYS.has(key)) {
      fail("UNAPPROVED_SERVICE_KEY");
    }
    if (Object.hasOwn(values, key)) fail("DUPLICATE_SERVICE_KEY");
    values[key] = match[2];
  }

  if (sectionCount !== 1) fail("SERVICE_SECTION_COUNT");
  for (const forbidden of ["hostaddr", "password", "passfile", "sslcert", "sslkey", "sslpassword"]) {
    if (Object.hasOwn(values, forbidden)) fail("FORBIDDEN_SERVICE_KEY");
  }
  for (const required of ["host", "port", "dbname", "user", "sslmode"]) {
    if (typeof values[required] !== "string" || values[required] === "") fail("MISSING_SERVICE_TARGET");
  }
  return values;
}

function parsePgpassLine(line) {
  const fields = [];
  let field = "";
  let escaped = false;
  for (const character of line) {
    if (escaped) {
      // libpq documents only \: and \\ as pass-file escapes. Refuse ambiguous
      // sequences such as \* instead of guessing their wildcard semantics.
      if (character !== ":" && character !== "\\") fail("INVALID_PGPASS_ESCAPE");
      field += character;
      escaped = false;
    } else if (character === "\\") {
      escaped = true;
    } else if (character === ":") {
      fields.push(field);
      field = "";
    } else {
      field += character;
    }
  }
  if (escaped) fail("INVALID_PGPASS_ENTRY");
  fields.push(field);
  if (fields.length !== 5) fail("INVALID_PGPASS_ENTRY");
  return fields;
}

function normalizedHost(value) {
  const literal = value.startsWith("[") && value.endsWith("]") ? value.slice(1, -1) : value;
  if (isIP(literal) === 6) {
    return new URL(`http://[${literal}]`).hostname.slice(1, -1);
  }
  return value.toLowerCase();
}

function parsePgpassEntries(passFileText) {
  const entries = [];
  for (const line of passFileText.split(/\r?\n/u)) {
    if (!line || line.startsWith("#")) continue;
    const fields = parsePgpassLine(line);
    if (fields.slice(0, 4).some((field) => field.includes("*"))) fail("PGPASS_WILDCARD_FORBIDDEN");
    entries.push(fields);
  }
  return entries;
}

function requireExactServiceInventory(serviceFileText) {
  const names = [];
  for (const rawLine of serviceFileText.split(/\r?\n/u)) {
    const line = rawLine.trim();
    if (!line.startsWith("[")) continue;
    if (!line.endsWith("]")) fail("INVALID_SERVICE_FILE");
    names.push(line.slice(1, -1));
  }
  const expected = [
    "virki-staging-bootstrap", "virki-staging-worker", "virki-staging-hub", "virki-staging-migrator"
  ];
  if (names.length !== expected.length || new Set(names).size !== expected.length ||
      expected.some((name) => !names.includes(name))) {
    fail("UNEXPECTED_SERVICE_INVENTORY");
  }
}

function requireExactPassfileInventory(entries, expectedEntries) {
  if (entries.length !== expectedEntries.length) fail("UNEXPECTED_PGPASS_INVENTORY");
  const remaining = new Map(expectedEntries.map((entry) => [entry.join("\0"), 1]));
  for (const entry of entries) {
    const key = entry.join("\0");
    if (remaining.get(key) !== 1) fail("UNEXPECTED_PGPASS_INVENTORY");
    remaining.delete(key);
  }
  if (remaining.size !== 0) fail("UNEXPECTED_PGPASS_INVENTORY");
}

function requireSinglePassfileCredential(entries, { host, port, database, user, credential, failurePrefix }) {
  const matches = entries.filter(([entryHost, entryPort, entryDatabase, entryUser]) =>
    entryHost === host && entryPort === port && entryDatabase === database && entryUser === user);
  if (matches.length !== 1) fail(`${failurePrefix}_PGPASS_MATCH_COUNT`);
  if (matches[0][4] !== credential) fail(`${failurePrefix}_PASSWORD_MISMATCH`);
}

/**
 * Proves one protected libpq service resolves to the approved target and that
 * its only exact PGPASSFILE match is the credential supplied by the operator.
 */
export function verifyServicePgpassBinding({
  serviceFileText,
  passFileText,
  serviceName,
  expectedHost,
  expectedPort,
  expectedDatabase,
  expectedUser,
  credential,
  restoreDatabase,
  failurePrefix = "SERVICE"
}) {
  for (const [name, value] of Object.entries({
    serviceFileText, passFileText, serviceName, expectedHost, expectedPort,
    expectedDatabase, expectedUser, credential
  })) {
    if (typeof value !== "string" || value.length === 0) fail(`MISSING_${name.toUpperCase()}`);
  }
  if (!/^[1-9][0-9]{0,4}$/u.test(expectedPort) || Number(expectedPort) > 65_535) fail("INVALID_EXPECTED_PORT");
  if (restoreDatabase !== undefined &&
      (typeof restoreDatabase !== "string" || !/^virki_stage_restore_[a-f0-9]{8,16}$/u.test(restoreDatabase))) {
    fail("INVALID_RESTORE_DATABASE");
  }

  const service = parseServiceSection(serviceFileText, serviceName);
  if (normalizedHost(service.host) !== normalizedHost(expectedHost) ||
      service.port !== expectedPort || service.dbname !== expectedDatabase ||
      service.user !== expectedUser || service.sslmode !== "verify-full") {
    fail(`${failurePrefix}_SERVICE_TARGET_MISMATCH`);
  }

  const entries = parsePgpassEntries(passFileText);
  for (const database of restoreDatabase === undefined ? [service.dbname] : [service.dbname, restoreDatabase]) {
    requireSinglePassfileCredential(entries, {
      host: service.host,
      port: service.port,
      database,
      user: service.user,
      credential,
      failurePrefix
    });
  }
  return true;
}

/**
 * Proves the role-script POSTGRES_PASSWORD is the exact password libpq will
 * use for both the protected virki-staging-bootstrap service's default
 * database and the restore database selected by a connection-string override.
 * Never returns or logs the credential.
 */
export function verifyBootstrapPgpassBinding({
  serviceFileText,
  passFileText,
  expectedHost,
  expectedPort,
  expectedUser,
  bootstrapPassword,
  restoreDatabase
}) {
  for (const [name, value] of Object.entries({
    serviceFileText, passFileText, expectedHost, expectedPort, expectedUser, bootstrapPassword, restoreDatabase
  })) {
    if (typeof value !== "string" || (name !== "passFileText" && value.length === 0)) {
      fail(`MISSING_${name.toUpperCase()}`);
    }
  }
  if (!/^[1-9][0-9]{0,4}$/u.test(expectedPort) || Number(expectedPort) > 65_535) fail("INVALID_EXPECTED_PORT");
  if (!/^virki_stage_restore_[a-f0-9]{8,16}$/u.test(restoreDatabase)) fail("INVALID_RESTORE_DATABASE");

  const service = parseServiceSection(serviceFileText, "virki-staging-bootstrap");
  if (normalizedHost(service.host) !== normalizedHost(expectedHost) ||
      service.port !== expectedPort || service.dbname !== "postgres" ||
      service.user !== expectedUser || service.sslmode !== "verify-full") {
    fail("BOOTSTRAP_SERVICE_TARGET_MISMATCH");
  }

  const entries = parsePgpassEntries(passFileText);
  for (const database of [service.dbname, restoreDatabase]) {
    requireSinglePassfileCredential(entries, {
      host: service.host,
      port: service.port,
      database,
      user: service.user,
      credential: bootstrapPassword,
      failurePrefix: "BOOTSTRAP"
    });
  }
  return true;
}

/**
 * Proves the worker pass-file entries used by the rollback identity check for
 * both the approved staging DB and its explicit restore-database override.
 */
export function verifyWorkerRestorePgpassBinding({
  serviceFileText,
  passFileText,
  expectedHost,
  expectedPort,
  expectedDatabase,
  expectedUser,
  workerPassword,
  restoreDatabase
}) {
  for (const [name, value] of Object.entries({
    serviceFileText, passFileText, expectedHost, expectedPort, expectedDatabase,
    expectedUser, workerPassword
  })) {
    if (typeof value !== "string" || (name !== "passFileText" && value.length === 0)) {
      fail(`MISSING_${name.toUpperCase()}`);
    }
  }
  if (!/^[1-9][0-9]{0,4}$/u.test(expectedPort) || Number(expectedPort) > 65_535) fail("INVALID_EXPECTED_PORT");
  if (restoreDatabase !== undefined &&
      (typeof restoreDatabase !== "string" || !/^virki_stage_restore_[a-f0-9]{8,16}$/u.test(restoreDatabase))) {
    fail("INVALID_RESTORE_DATABASE");
  }

  const service = parseServiceSection(serviceFileText, "virki-staging-worker");
  if (normalizedHost(service.host) !== normalizedHost(expectedHost) ||
      service.port !== expectedPort || service.dbname !== expectedDatabase ||
      service.user !== expectedUser || service.sslmode !== "verify-full") {
    fail("WORKER_SERVICE_TARGET_MISMATCH");
  }

  const entries = parsePgpassEntries(passFileText);
  for (const database of restoreDatabase === undefined ? [service.dbname] : [service.dbname, restoreDatabase]) {
    requireSinglePassfileCredential(entries, {
      host: service.host,
      port: service.port,
      database,
      user: service.user,
      credential: workerPassword,
      failurePrefix: "WORKER"
    });
  }
  return true;
}

export function verifyWorkerPgpassBinding(options) {
  return verifyWorkerRestorePgpassBinding({ ...options, restoreDatabase: undefined });
}

/** Proves that a container DATABASE_URL uses the same TLS target and credential as the protected pass file. */
export function verifyDatabaseUrlBinding({
  databaseUrl, expectedHost, expectedPort, expectedDatabase, expectedUser,
  credential, failurePrefix = "DATABASE"
}) {
  for (const [name, value] of Object.entries({
    databaseUrl, expectedHost, expectedPort, expectedDatabase, expectedUser, credential
  })) {
    if (typeof value !== "string" || value.length === 0) fail(`MISSING_${name.toUpperCase()}`);
  }
  if (!/^[1-9][0-9]{0,4}$/u.test(expectedPort) || Number(expectedPort) > 65_535) fail("INVALID_EXPECTED_PORT");

  let url;
  let database;
  let user;
  let password;
  try {
    url = new URL(databaseUrl);
    database = decodeURIComponent(url.pathname.slice(1));
    user = decodeURIComponent(url.username);
    password = decodeURIComponent(url.password);
  } catch {
    fail(`${failurePrefix}_DATABASE_URL_INVALID`);
  }
  if (!["postgres:", "postgresql:"].includes(url.protocol) || !url.hostname || !url.username ||
      !url.password || !url.pathname.startsWith("/") || !database || url.hash ||
      [...url.searchParams].length !== 3 ||
      [...url.searchParams.keys()][0] !== "sslmode" ||
      [...url.searchParams.keys()][1] !== "sslaccept" ||
      [...url.searchParams.keys()][2] !== "sslcert" ||
      url.searchParams.get("sslmode") !== "require" ||
      url.searchParams.get("sslaccept") !== "strict" ||
      url.searchParams.get("sslcert") !== STAGING_PRISMA_CA_PATH) {
    fail(`${failurePrefix}_DATABASE_URL_INVALID`);
  }
  if (normalizedHost(url.hostname) !== normalizedHost(expectedHost) ||
      (url.port || "5432") !== expectedPort || database !== expectedDatabase || user !== expectedUser) {
    fail(`${failurePrefix}_DATABASE_URL_TARGET_MISMATCH`);
  }
  if (password !== credential) fail(`${failurePrefix}_DATABASE_URL_PASSWORD_MISMATCH`);
  return true;
}

function runCli(environment = process.env) {
  try {
    if (environment.PGSSLKEYLOGFILE || environment.SSLKEYLOGFILE) fail("UNSAFE_TLS_KEY_LOGGING");
    if (process.argv[2] && !["--worker-preflight", "--require-runtime-urls"].includes(process.argv[2])) {
      fail("INVALID_BINDING_MODE");
    }
    const serviceFileText = readFileSync(environment.PGSERVICEFILE, "utf8");
    const passFileText = readFileSync(environment.PGPASSFILE, "utf8");
    if (process.argv[2] === "--worker-preflight") {
      verifyWorkerPgpassBinding({
        serviceFileText,
        passFileText,
        expectedHost: environment.VIRKI_STAGING_APPROVED_DB_HOST,
        expectedPort: environment.VIRKI_STAGING_APPROVED_DB_PORT,
        expectedDatabase: environment.VIRKI_STAGING_APPROVED_DB_NAME,
        expectedUser: "virki_email_worker",
        workerPassword: environment.VIRKI_EMAIL_WORKER_DB_PASSWORD
      });
      if (environment.VIRKI_STAGING_EMAIL_WORKER_DATABASE_URL) {
        verifyDatabaseUrlBinding({
          databaseUrl: environment.VIRKI_STAGING_EMAIL_WORKER_DATABASE_URL,
          expectedHost: environment.VIRKI_STAGING_APPROVED_DB_HOST,
          expectedPort: environment.VIRKI_STAGING_APPROVED_DB_PORT,
          expectedDatabase: environment.VIRKI_STAGING_APPROVED_DB_NAME,
          expectedUser: "virki_email_worker",
          credential: environment.VIRKI_EMAIL_WORKER_DB_PASSWORD,
          failurePrefix: "WORKER"
        });
      }
      process.stdout.write("STAGING_WORKER_PGPASSFILE_BINDING=PASS\n");
      return 0;
    }
    verifyBootstrapPgpassBinding({
      serviceFileText,
      passFileText,
      expectedHost: environment.VIRKI_STAGING_APPROVED_DB_HOST,
      expectedPort: environment.VIRKI_STAGING_APPROVED_DB_PORT,
      expectedUser: environment.POSTGRES_USER,
      bootstrapPassword: environment.POSTGRES_PASSWORD,
      restoreDatabase: environment.VIRKI_STAGING_RESTORE_DB
    });
    verifyWorkerRestorePgpassBinding({
      serviceFileText,
      passFileText,
      expectedHost: environment.VIRKI_STAGING_APPROVED_DB_HOST,
      expectedPort: environment.VIRKI_STAGING_APPROVED_DB_PORT,
      expectedDatabase: environment.VIRKI_STAGING_APPROVED_DB_NAME,
      expectedUser: "virki_email_worker",
      workerPassword: environment.VIRKI_EMAIL_WORKER_DB_PASSWORD,
      restoreDatabase: environment.VIRKI_STAGING_RESTORE_DB
    });
    verifyServicePgpassBinding({
      serviceFileText,
      passFileText,
      serviceName: "virki-staging-hub",
      expectedHost: environment.VIRKI_STAGING_APPROVED_DB_HOST,
      expectedPort: environment.VIRKI_STAGING_APPROVED_DB_PORT,
      expectedDatabase: environment.VIRKI_STAGING_APPROVED_DB_NAME,
      expectedUser: "virki_runtime",
      credential: environment.VIRKI_RUNTIME_DB_PASSWORD,
      restoreDatabase: environment.VIRKI_STAGING_RESTORE_DB,
      failurePrefix: "RUNTIME"
    });
    verifyServicePgpassBinding({
      serviceFileText,
      passFileText,
      serviceName: "virki-staging-migrator",
      expectedHost: environment.VIRKI_STAGING_APPROVED_DB_HOST,
      expectedPort: environment.VIRKI_STAGING_APPROVED_DB_PORT,
      expectedDatabase: environment.VIRKI_STAGING_APPROVED_DB_NAME,
      expectedUser: "virki_migrator",
      credential: environment.VIRKI_MIGRATOR_DB_PASSWORD,
      restoreDatabase: environment.VIRKI_STAGING_RESTORE_DB,
      failurePrefix: "MIGRATOR"
    });
    requireExactServiceInventory(serviceFileText);
    const bootstrap = parseServiceSection(serviceFileText, "virki-staging-bootstrap");
    const worker = parseServiceSection(serviceFileText, "virki-staging-worker");
    const hub = parseServiceSection(serviceFileText, "virki-staging-hub");
    const migrator = parseServiceSection(serviceFileText, "virki-staging-migrator");
    requireExactPassfileInventory(parsePgpassEntries(passFileText), [
      [bootstrap.host, bootstrap.port, "postgres", bootstrap.user, environment.POSTGRES_PASSWORD],
      [bootstrap.host, bootstrap.port, environment.VIRKI_STAGING_RESTORE_DB, bootstrap.user, environment.POSTGRES_PASSWORD],
      [worker.host, worker.port, worker.dbname, worker.user, environment.VIRKI_EMAIL_WORKER_DB_PASSWORD],
      [worker.host, worker.port, environment.VIRKI_STAGING_RESTORE_DB, worker.user, environment.VIRKI_EMAIL_WORKER_DB_PASSWORD],
      [hub.host, hub.port, hub.dbname, hub.user, environment.VIRKI_RUNTIME_DB_PASSWORD],
      [hub.host, hub.port, environment.VIRKI_STAGING_RESTORE_DB, hub.user, environment.VIRKI_RUNTIME_DB_PASSWORD],
      [migrator.host, migrator.port, migrator.dbname, migrator.user, environment.VIRKI_MIGRATOR_DB_PASSWORD],
      [migrator.host, migrator.port, environment.VIRKI_STAGING_RESTORE_DB, migrator.user, environment.VIRKI_MIGRATOR_DB_PASSWORD]
    ]);
    if (process.argv[2] === "--require-runtime-urls" || environment.VIRKI_STAGING_EMAIL_WORKER_DATABASE_URL ||
        environment.VIRKI_STAGING_HUB_DATABASE_URL) {
      verifyDatabaseUrlBinding({
        databaseUrl: environment.VIRKI_STAGING_EMAIL_WORKER_DATABASE_URL,
        expectedHost: environment.VIRKI_STAGING_APPROVED_DB_HOST,
        expectedPort: environment.VIRKI_STAGING_APPROVED_DB_PORT,
        expectedDatabase: environment.VIRKI_STAGING_APPROVED_DB_NAME,
        expectedUser: "virki_email_worker",
        credential: environment.VIRKI_EMAIL_WORKER_DB_PASSWORD,
        failurePrefix: "WORKER"
      });
      verifyDatabaseUrlBinding({
        databaseUrl: environment.VIRKI_STAGING_HUB_DATABASE_URL,
        expectedHost: environment.VIRKI_STAGING_APPROVED_DB_HOST,
        expectedPort: environment.VIRKI_STAGING_APPROVED_DB_PORT,
        expectedDatabase: environment.VIRKI_STAGING_APPROVED_DB_NAME,
        expectedUser: "virki_runtime",
        credential: environment.VIRKI_RUNTIME_DB_PASSWORD,
        failurePrefix: "RUNTIME"
      });
    }
    process.stdout.write("STAGING_BOOTSTRAP_PASSFILE_BINDING=PASS\n");
    process.stdout.write("STAGING_WORKER_RESTORE_PASSFILE_BINDING=PASS\n");
    process.stdout.write("STAGING_RUNTIME_PASSFILE_BINDING=PASS\n");
    process.stdout.write("STAGING_MIGRATOR_PASSFILE_BINDING=PASS\n");
    return 0;
  } catch {
    process.stderr.write("BLOCK:STAGING_PGPASSFILE_BINDING\n");
    return 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = runCli();
}
