// Dedicated one-test runner. Only the signed local Docker runner may set the
// exclusive marker after creating a fresh tmpfs PostgreSQL and internal network.
import { randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const suite = "packages/auth/src/email-smtp-wire.integration.test.ts";
const testName = "real worker sends queued recovery OTP over verified loopback STARTTLS AUTH and rejects replay";

export function assertDedicatedSmtpWireTarget(env) {
  if (env.NODE_ENV === "production" || env.VIRKI_CORE_TEST_DATABASE_CONFIRM !== "disposable" ||
      env.VIRKI_EMAIL_WIRE_DEDICATED_DB !== "confirmed" ||
      env.VIRKI_EMAIL_WIRE_NETWORK_ISOLATED !== "confirmed") {
    throw new Error("A physically isolated local Docker SMTP test is required.");
  }
  let url;
  try { url = new URL(env.VIRKI_INTEGRATION_DATABASE_URL ?? ""); }
  catch { throw new Error("A dedicated PostgreSQL URL is required."); }
  if (!/^(?:postgresql|postgres):$/u.test(url.protocol) || url.hostname !== "127.0.0.1" ||
      url.port !== "5432" || url.username !== "virki_runtime_test" ||
      !/^[a-f0-9]{64}$/u.test(decodeURIComponent(url.password)) ||
      url.pathname !== "/virki_e2e_test" || url.search !== "?schema=public" || url.hash) {
    throw new Error("Refusing non-loopback, shared or unrestricted PostgreSQL.");
  }
  const forbidden = Object.keys(env).filter((key) =>
    key.startsWith("VIRKI_EMAIL_SMTP_") || key === "VIRKI_EMAIL_TRANSPORT" ||
    key === "VIRKI_EMAIL_OUTBOX_KEY" || key === "NODE_EXTRA_CA_CERTS");
  if (forbidden.length > 0) throw new Error("Refusing ambient SMTP, outbox or TLS configuration.");
  return url;
}

export function assertSmtpWireTap(output) {
  const count = (label) => {
    const matches = [...output.matchAll(new RegExp(`^# ${label} ([0-9]+)$`, "gmu"))];
    if (matches.length !== 1) throw new Error("Missing or ambiguous SMTP TAP summary.");
    return Number(matches[0][1]);
  };
  if (count("tests") !== 1 || count("pass") !== 1 || count("fail") !== 0 ||
      count("skipped") !== 0 || count("cancelled") !== 0 ||
      output.split(/\r?\n/u).filter((line) => line === `ok 1 - ${testName}`).length !== 1) {
    throw new Error("Real SMTP wire proof must PASS once with no SKIP.");
  }
}

export function runSmtpWireIntegration(env = process.env) {
  const url = assertDedicatedSmtpWireTarget(env);
  const tsx = path.join(root, "node_modules", "tsx", "dist", "cli.mjs");
  const childEnvironment = {
    NODE_ENV: "test",
    DATABASE_URL: url.href,
    VIRKI_INTEGRATION_DATABASE_URL: url.href,
    VIRKI_CORE_TEST_DATABASE_CONFIRM: "disposable",
    VIRKI_INTEGRATION_ENABLED: "true",
    VIRKI_EMAIL_WIRE_DEDICATED_DB: "confirmed",
    VIRKI_EMAIL_WIRE_NETWORK_ISOLATED: "confirmed",
    VIRKI_PORTAL_URL: "http://localhost:3000",
    VIRKI_HUB_URL: "http://localhost:3001",
    VIRKI_OIDC_ADAPTER_KEY: randomBytes(32).toString("hex"),
    PATH: "/usr/bin:/bin",
    LANG: "C"
  };
  const child = spawnSync(process.execPath,
    [tsx, "--test", "--test-concurrency=1", "--test-reporter=tap", suite], {
      cwd: root, encoding: "utf8", timeout: 120_000, maxBuffer: 1024 * 1024,
      windowsHide: true, env: childEnvironment
    });
  const scrub = (value) => (value ?? "")
    .replaceAll(url.href, "[DISPOSABLE_DB_URL]")
    .replaceAll(decodeURIComponent(url.password), "[DISPOSABLE_DB_PASSWORD]")
    .replace(/(duration_ms:\s*)[0-9.]+/giu, "$1[OMITTED]")
    .replace(/\b[0-9]{6}\b/gu, "[REDACTED_OTP]");
  if (child.stdout) process.stdout.write(scrub(child.stdout));
  if (child.stderr) process.stderr.write(scrub(child.stderr));
  if (child.error || child.status !== 0) throw new Error("SMTP wire physical integration failed.");
  assertSmtpWireTap(child.stdout ?? "");
  console.log("LOCAL_SMTP_WIRE_PASS: 1 passed, 0 failed, 0 skipped; no external delivery implied.");
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { runSmtpWireIntegration(); }
  catch (error) {
    console.error(error instanceof Error ? error.message : "SMTP wire runner rejected.");
    process.exitCode = 1;
  }
}
