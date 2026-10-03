import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const adminDirectory = fileURLToPath(new URL("../app/admin", import.meta.url));

function listAdminPages(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const fullPath = path.join(directory, entry.name);
    if (entry.isDirectory()) return listAdminPages(fullPath);
    return entry.name === "page.tsx" ? [fullPath] : [];
  });
}

test("every admin page that renders data runs requireAdminPage itself instead of trusting the layout", () => {
  const pages = listAdminPages(adminDirectory);
  assert.ok(pages.length >= 5, "admin pages were discovered");
  for (const page of pages) {
    const source = readFileSync(page, "utf8");
    const redirectOnly = !source.includes("prisma") && !source.includes("View(") && /redirect\(/u.test(source);
    if (redirectOnly) continue;
    assert.match(source, /await requireAdminPage\(\)/u, `${path.relative(adminDirectory, page)} must call requireAdminPage()`);
  }
});

test("the admin layout uses the same guard as the pages", () => {
  const layout = readFileSync(path.join(adminDirectory, "layout.tsx"), "utf8");
  assert.match(layout, /await requireAdminPage\(\)/u);
});
