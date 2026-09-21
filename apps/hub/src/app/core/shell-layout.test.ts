import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import test from "node:test";

const globalsCss = readFileSync(fileURLToPath(new URL("../globals.css", import.meta.url)), "utf8");

test("shell layout keeps the dock usable and scoped to docked shells", () => {
  assert.match(globalsCss, /\.hub-shell--docked\s*\{\s*grid-template-columns:\s*minmax\(240px, 280px\) minmax\(0, 1fr\);/);
  assert.match(globalsCss, /\.dock-nav a,\s*\.dock-nav strong\s*\{[\s\S]*?white-space:\s*nowrap;[\s\S]*?word-break:\s*normal;/);
  assert.match(globalsCss, /html:root \.hub-shell--docked\s*\{\s*grid-template-columns:\s*minmax\(240px, 280px\) minmax\(0, 1fr\);/);
  assert.match(globalsCss, /@media \(max-width: 880px\) \{[\s\S]*?html:root \.hub-shell--docked\s*\{\s*grid-template-columns: 1fr;/);
  assert.doesNotMatch(globalsCss, /h1, h2, h3, p, dt, dd, span, strong\s*\{\s*overflow-wrap:\s*anywhere/);
  assert.doesNotMatch(globalsCss, /html:root \.hub-shell\s*\{\s*grid-template-columns:/);
});
