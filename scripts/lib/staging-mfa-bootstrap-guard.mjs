/**
 * Pure, staging-only guard for creating the first disposable ADMIN.
 * No database connection or mutation is made by this module. Production's
 * separate first-admin bootstrap guard is intentionally left unchanged.
 */
import { createHash } from "node:crypto";

// SHA-256 of "virki-staging-mfa-origin-pair-v1\n" followed by the two
// owner-approved canonical HTTPS origins (Hub then Portal, newline terminated).
// Pinning this independently reviewed identity prevents environment variables
// from silently switching the credential destination to another staging-like
// hostname. The account-specific hostnames stay out of tracked configuration.
const APPROVED_ORIGIN_PAIR_SHA256 = "750e9b34bfa6d24b315034d7eb4f5f65698db788000a41cfaea35129c0978253";
export class StagingMfaBootstrapError extends Error {
  constructor() {
    super("STAGING_MFA_GUARD_REJECTED");
    this.name = "StagingMfaBootstrapError";
  }
}

function reject() {
  throw new StagingMfaBootstrapError();
}

function canonicalOrigin(value, hostname) {
  try {
    const parsed = new URL(value);
    return parsed.protocol === "https:" &&
      parsed.hostname === hostname &&
      parsed.username === "" &&
      parsed.password === "" &&
      parsed.port === "" &&
      parsed.pathname === "/" &&
      parsed.search === "" &&
      parsed.hash === "";
  } catch {
    return false;
  }
}

/**
 * Accepts only a private loopback PostgreSQL database named for a disposable
 * MFA test, never the normal Virki production DB. Secrets are checked only for
 * shape and segregation; none are returned or formatted in an error.
 */
export function assertStagingMfaBootstrapEnvironment(env) {
  if (env.NODE_ENV !== "production" ||
      env.VIRKI_STAGING_MFA_BOOTSTRAP !== "enabled" ||
      env.VIRKI_HUB_PERIMETER_MODE !== "native" ||
      env.VIRKI_ADMIN_PASSKEYS_ENABLED !== "false" ||
      env.VIRKI_PASSKEYS_ENABLED !== "false" ||
      ![undefined, "", "false"].includes(env.VIRKI_STAGING_PASSKEY_RP_ENABLED) ||
      Boolean(env.MIGRATION_DATABASE_URL)) reject();

  const hostname = env.VIRKI_HUB_HOSTNAME;
  const portal = env.VIRKI_PORTAL_HOSTNAME;
  if (typeof hostname !== "string" || !/^hub-staging\.[a-z0-9.-]+$/u.test(hostname) ||
      typeof portal !== "string" || portal !== hostname.replace(/^hub-staging\./u, "portal-staging.") ||
      !canonicalOrigin(env.VIRKI_HUB_URL, hostname) ||
      !canonicalOrigin(env.VIRKI_PORTAL_URL, portal)) reject();
  const observedOriginDigest = createHash("sha256")
    .update(`virki-staging-mfa-origin-pair-v1\nhttps://${hostname}\nhttps://${portal}\n`)
    .digest("hex");
  if (observedOriginDigest !== APPROVED_ORIGIN_PAIR_SHA256) reject();

  const recipient = env.VIRKI_STAGING_MFA_TEST_EMAIL?.trim().toLowerCase();
  if (!recipient || recipient.length > 320 ||
      !/^[a-z0-9.!#$%&'*+/=?^`{|}~-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+$/u.test(recipient)) reject();

  const keyNames = [
    "VIRKI_CSRF_SIGNING_KEY",
    "VIRKI_TOTP_ENCRYPTION_KEY",
    "VIRKI_AUDIT_HASH_SECRET",
    "VIRKI_RATE_LIMIT_HASH_SECRET",
    "VIRKI_EMAIL_OUTBOX_KEY"
  ];
  const keys = keyNames.map((name) => env[name]);
  if (keys.some((value) => typeof value !== "string" || !/^[a-f0-9]{64}$/iu.test(value)) ||
      new Set(keys.map((value) => value.toLowerCase())).size !== keys.length) reject();

  let url;
  try {
    url = new URL(env.DATABASE_URL);
  } catch {
    reject();
  }
  const database = decodeURIComponent(url.pathname.slice(1));
  const port = Number(url.port);
  if (url.protocol !== "postgresql:" ||
      url.hostname !== "127.0.0.1" ||
      !Number.isInteger(port) || port < 1024 || port > 65535 ||
      decodeURIComponent(url.username) !== "virki_runtime" ||
      decodeURIComponent(url.password).length < 20 ||
      !/^stage_mfa_[0-9]{8}$/u.test(database) ||
      url.hash !== "" ||
      Array.from(url.searchParams.keys()).some((key) => key !== "schema") ||
      url.searchParams.getAll("schema").length !== 1 ||
      url.searchParams.get("schema") !== "public") reject();

  return { database, hostname, port, recipient };
}

/** Second, live guard. Call with server-observed properties of the connection. */
export function assertStagingMfaRuntimeIdentity(actual, expected) {
  if (!actual || typeof actual !== "object" ||
      actual.database !== expected.database ||
      actual.role !== "virki_runtime" ||
      actual.host !== "127.0.0.1" ||
      Number(actual.port) !== expected.port ||
      actual.owner !== "virki_migrator" ||
      actual.migratorPresent !== true ||
      actual.runtimeCanCreate !== false ||
      actual.migrationLedgerRestricted !== true ||
      actual.schemaReady !== true) reject();
}
