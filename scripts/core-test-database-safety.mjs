const ALLOWED_TEST_HOSTS = new Set([
  "127.0.0.1",
  "localhost",
  "::1",
  "postgres",
  "core-test-postgres"
]);

export const CORE_TEST_DATABASE_CONFIRMATION = "disposable";

export function assertDisposableCoreTestDatabase(databaseUrl, environment = process.env) {
  if (environment.NODE_ENV === "production") {
    throw new Error("Core database tests refuse production mode.");
  }

  if (environment.BIELOS_CORE_TEST_DATABASE_CONFIRM !== CORE_TEST_DATABASE_CONFIRMATION) {
    throw new Error("Core database tests require an explicit disposable-database marker.");
  }

  let target;

  try {
    target = new URL(databaseUrl);
  } catch {
    throw new Error("Core database test target is invalid.");
  }

  if (target.protocol !== "postgresql:" && target.protocol !== "postgres:") {
    throw new Error("Core database tests require PostgreSQL.");
  }

  const databaseName = decodeURIComponent(target.pathname.replace(/^\//, ""));
  const userName = decodeURIComponent(target.username);

  if (!ALLOWED_TEST_HOSTS.has(target.hostname)) {
    throw new Error("Core database tests require a local or isolated CI host.");
  }

  if (!/(?:^|[_-])test(?:$|[_-])/i.test(databaseName) || !/test/i.test(userName)) {
    throw new Error("Core database tests require explicit test database and user names.");
  }

  return target;
}

export function sanitizeCoreTestOutput(output, databaseUrl) {
  let sanitized = String(output ?? "");

  try {
    const target = new URL(databaseUrl);
    const sensitiveParts = [databaseUrl, target.password, target.username, target.host];

    for (const part of sensitiveParts) {
      if (part) {
        sanitized = sanitized.replaceAll(part, "[disposable-test-database]");
      }
    }
  } catch {
    return "Core database test command failed.";
  }

  return sanitized;
}
