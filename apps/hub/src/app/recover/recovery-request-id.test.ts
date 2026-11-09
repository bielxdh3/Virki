import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

test("anonymous recovery errors use the same public ID generator as real and synthetic requests", () => {
  const source = readFileSync(new URL("./actions.ts", import.meta.url), "utf8");
  assert.match(source, /generateRecoveryPublicRequestId\s*,\s*startMultiMethodRecovery/u);
  assert.match(source, /requestId:\s*generateRecoveryPublicRequestId\(\)/u);
  assert.doesNotMatch(source, /requestId:\s*`c\$\{/u);
});
