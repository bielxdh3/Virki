import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const ansiColor = new RegExp(`${String.fromCharCode(27)}\\[[0-9;]*m`, "gu");

/** Fail closed on the actual Playwright list reporter output, not just test discovery. */
export function verifyPasskeyBrowserGate(output) {
  if (typeof output !== "string" || output.length === 0) {
    throw new Error("The mandatory passkey browser result is missing.");
  }
  const lines = output.replace(ansiColor, "").split(/\r?\n/u);
  const success = lines.some((line) =>
    /(?:^|\s)✓\s+\d+\s+.*›\s+USER PASSKEY_ADMIN: signed Portal passkey\b/u.test(line));
  if (!success) {
    throw new Error("The USER PASSKEY_ADMIN browser test did not physically PASS.");
  }
  const passed = lines.flatMap((line) => {
    const match = /^\s*([1-9]\d*) passed \([^)]+\)\s*$/u.exec(line);
    return match ? [Number(match[1])] : [];
  });
  if (passed.length !== 1 || !Number.isSafeInteger(passed[0])) {
    throw new Error("The browser PASS summary is missing or ambiguous.");
  }
  if (lines.some((line) => /^\s*[1-9]\d* (?:skipped|failed|flaky|interrupted|did not run)\b/iu.test(line))) {
    throw new Error("The mandatory passkey browser run has a non-PASS result.");
  }
  return passed[0];
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    if (process.argv.length !== 3) throw new Error("Exactly one runner-log path is required.");
    const passed = verifyPasskeyBrowserGate(readFileSync(process.argv[2], "utf8"));
    process.stdout.write(`MANDATORY_USER_PASSKEY_ADMIN_BROWSER_PASS: ${passed} passed, 0 failed, 0 skipped.\n`);
  } catch {
    // Playwright output may contain private fixture data. Never echo it, a
    // filename, a secret, or a provider response in a release-gate error.
    process.stderr.write("Mandatory USER PASSKEY_ADMIN browser gate did not pass.\n");
    process.exitCode = 1;
  }
}
