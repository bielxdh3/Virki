import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

test("Server Action raw request bodies are explicitly capped at the existing 1 MiB default", () => {
  const source = readFileSync(new URL("../../next.config.mjs", import.meta.url), "utf8");
  assert.match(source, /serverActions:\s*\{\s*bodySizeLimit:\s*"1mb"\s*\}/u);
});
