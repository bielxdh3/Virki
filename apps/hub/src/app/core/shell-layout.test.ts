import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import test from "node:test";

const globalsCss = readFileSync(fileURLToPath(new URL("../globals.css", import.meta.url)), "utf8");

test("shell layout keeps the dock usable and scoped to docked shells", () => {
  assert.match(globalsCss, /\.hub-shell--docked\s*\{\s*grid-template-columns:\s*minmax\(240px, 280px\) minmax\(0, 1fr\);/);
  assert.match(globalsCss, /\.dock-nav a,\s*\.dock-nav strong\s*\{[\s\S]*?white-space:\s*nowrap;[\s\S]*?word-break:\s*normal;/);
  assert.match(globalsCss, /@media \(max-width: 980px\) \{[\s\S]*?html:root \.hub-shell--docked\s*\{\s*grid-template-columns: 1fr;/);
  assert.match(globalsCss, /\.hub-workspace > \*\s*\{[\s\S]*?min-width:\s*0;[\s\S]*?max-width:\s*100%;/);
  assert.match(globalsCss, /\.dashboard-grid\s*\{[\s\S]*?grid-template-columns:\s*repeat\(3, minmax\(0, 1fr\)\);/);
  assert.match(globalsCss, /\.hub-registry-group \.module-grid\s*\{[\s\S]*?grid-template-columns:\s*repeat\(3, minmax\(0, 1fr\)\);/);
  assert.doesNotMatch(globalsCss, /h1, h2, h3, p, dt, dd, span, strong\s*\{\s*overflow-wrap:\s*anywhere/);
  assert.doesNotMatch(globalsCss, /html:root \.hub-shell\s*\{\s*grid-template-columns:/);
  assert.doesNotMatch(globalsCss, /html:root \.hub-shell--docked\s*\{\s*grid-template-columns:\s*minmax/);
});
