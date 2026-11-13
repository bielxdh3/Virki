import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

test("anonymous recovery errors use the same public ID generator as real and synthetic requests", () => {
  const source = readFileSync(new URL("./actions.ts", import.meta.url), "utf8");
  assert.match(source, /generateRecoveryPublicRequestId\s*,\s*startMultiMethodRecovery/u);
  assert.match(source, /requestId:\s*generateRecoveryPublicRequestId\(\)/u);
  assert.doesNotMatch(source, /requestId:\s*`c\$\{/u);
});

test("indeterminate recovery validation preserves existing cookies without authorizing a browser", () => {
  const action = readFileSync(new URL("./actions.ts", import.meta.url), "utf8");
  const backend = readFileSync(new URL("../../../../../packages/auth/src/recovery-methods.ts", import.meta.url), "utf8");
  assert.match(backend, /if \(error === FAILURE\) return false;\s*throw error;/u);
  assert.match(action, /catch \{[\s\S]*?retentionUnavailable = true;/u);
  assert.match(action, /if \(!canRetain && !retentionUnavailable\) try \{/u);
  const denied = action.indexOf('if (retentionUnavailable) {');
  const redirectToRetry = action.indexOf('redirect("/recover?error=1");', denied);
  const mintNewCookies = action.indexOf("setMultiMethodRecoveryCookies(cookieStore, recovery.requestKey");
  assert.ok(denied !== -1 && redirectToRetry > denied && mintNewCookies > redirectToRetry,
    "unknown backend status must return a generic retry before any capability overwrite");
});
