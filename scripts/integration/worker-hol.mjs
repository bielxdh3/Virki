// Required, fail-closed runner for the exclusive physical PostgreSQL HOL/CAS
// regression. Only a freshly provisioned DB is suitable: a generic CI DB
// could hide the test behind a SKIP or consume another suite's pending mail.
import { randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const suite = "packages/auth/src/email-worker-hol.integration.test.ts";
const names = [
  "three exhausted head rows never delay a genuine queued OTP",
  "concurrent workers cannot both claim or deliver the same OTP"
];

export function assertExclusiveWorkerDatabaseTarget(env) {
  if (env.NODE_ENV === "production" || env.VIRKI_CORE_TEST_DATABASE_CONFIRM !== "disposable" ||
      env.VIRKI_EMAIL_WORKER_DEDICATED_DB !== "confirmed") {
    throw new Error("An explicitly confirmed, isolated disposable worker database is required.");
  }
  let url;
  try { url = new URL(env.VIRKI_INTEGRATION_DATABASE_URL ?? ""); }
  catch { throw new Error("A valid dedicated PostgreSQL URL is required."); }
  if (!/^(?:postgresql|postgres):$/u.test(url.protocol) || url.hostname !== "127.0.0.1" ||
      !/^[1-9][0-9]{0,4}$/u.test(url.port) || Number(url.port) > 65535 ||
      url.username !== "virki_runtime_test" || url.password.length < 32 ||
      !/^\/virki_email_worker_hol_[a-f0-9]{12}$/u.test(url.pathname) ||
      url.search !== "?schema=public" || url.hash) {
    throw new Error("Refusing a non-exclusive or non-loopback PostgreSQL test target.");
  }
  return url;
}

export function assertMandatoryHolTap(output) {
  const count = (label) => {
    const match = output.match(new RegExp(`^# ${label} (\\d+)$`, "gmu"));
    if (match?.length !== 1) throw new Error(`Missing or ambiguous TAP ${label} summary.`);
    return Number(match[0].split(" ").at(-1));
  };
  if (count("tests") !== names.length || count("pass") !== names.length ||
      count("fail") !== 0 || count("skipped") !== 0 || count("cancelled") !== 0) {
    throw new Error("Mandatory HOL integration tests must all PASS without SKIP.");
  }
  for (const name of names) {
    const ok = output.split(/\r?\n/u).filter((line) => /^ok [0-9]+ - /u.test(line) &&
      line.replace(/^ok [0-9]+ - /u, "") === name);
    if (ok.length !== 1) throw new Error(`Mandatory HOL regression did not PASS: ${name}.`);
  }
}

export function runMandatoryHolIntegration(env = process.env) {
  const url = assertExclusiveWorkerDatabaseTarget(env);
  // Bypass the generic suite discovery guard intentionally: that guard must
  // reject this test to prevent running it on a shared integration database.
  // Require TAP explicitly so a reporter change cannot silently bypass the
  // proof that both physical tests actually ran and did not SKIP.
  const tsx = path.join(root, "node_modules", "tsx", "dist", "cli.mjs");
  const child = spawnSync(process.execPath, [tsx, "--test", "--test-concurrency=1", "--test-reporter=tap", suite], {
    cwd: root, encoding: "utf8", timeout: 120_000, maxBuffer: 4 * 1024 * 1024,
    windowsHide: true, env: { ...env, DATABASE_URL: url.href,
      NODE_ENV: "test", VIRKI_INTEGRATION_ENABLED: "true",
      VIRKI_PORTAL_URL: "http://localhost:3000", VIRKI_HUB_URL: "http://localhost:3001",
      VIRKI_OIDC_ADAPTER_KEY: env.VIRKI_OIDC_ADAPTER_KEY ?? randomBytes(32).toString("hex"),
      VIRKI_EMAIL_WORKER_DEDICATED_DB: "confirmed" }
  });
  // This output is from test fixtures only; redact the DB URL and its password
  // before presenting errors in CI logs or the user's terminal.
  const safe = (text) => (text ?? "").replaceAll(url.href, "[DISPOSABLE_DB_URL]")
    .replaceAll(decodeURIComponent(url.password), "[DISPOSABLE_DB_PASSWORD]");
  if (child.stdout) process.stdout.write(safe(child.stdout));
  if (child.stderr) process.stderr.write(safe(child.stderr));
  if (child.error || child.status !== 0) {
    throw new Error("Mandatory HOL PostgreSQL integration failed or could not run.");
  }
  assertMandatoryHolTap(child.stdout ?? "");
  console.log("MANDATORY_EMAIL_WORKER_HOL_PG_PASS: 2 passed, 0 failed, 0 skipped.");
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { runMandatoryHolIntegration(); }
  catch (error) { console.error(error instanceof Error ? error.message : "HOL runner failure."); process.exitCode = 1; }
}
