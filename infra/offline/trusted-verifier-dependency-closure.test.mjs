import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { copyFileSync, lstatSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { AUDITED_VERIFIER_FILES, inspectAuditedVerifierFiles } from "./trusted-host-installer.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url));
const HOST_ENTRIES = Object.freeze([
  "infra/offline/trusted-host-installer.mjs",
  "infra/offline/trusted-host-entry.mjs",
  "infra/offline/trusted-image-loader.mjs",
  "infra/offline/trusted-source-git.mjs",
]);
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

// Fail closed on any executable dependency we cannot statically account for.
// All installed host files use static, literal ESM imports; intentionally
// reject import attributes, dynamic imports, package imports and CJS escapes.
function importsIn(source) {
  // A regex for `import ` misses legal minified syntax such as `import"x"`
  // or `export*from"x"`; use the actual JavaScript grammar instead.
  const parsed = ts.createSourceFile("audited-verifier.mjs", source,
    ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);
  assert.equal(parsed.parseDiagnostics.length, 0, "unparseable verifier source is forbidden");
  const dependencies = [];
  function visit(node) {
    if (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) {
      if (node.moduleSpecifier) {
        assert.ok(ts.isStringLiteral(node.moduleSpecifier) &&
          !node.attributes && !node.assertClause,
        "verifier modules require literal imports without attributes");
        dependencies.push(node.moduleSpecifier.text);
      }
    }
    assert.ok(!ts.isImportEqualsDeclaration(node) && !ts.isImportTypeNode(node),
      "unreviewed module import syntax is forbidden");
    if (ts.isCallExpression(node)) {
      assert.notEqual(node.expression.kind, ts.SyntaxKind.ImportKeyword,
        "dynamic import is forbidden");
      if (ts.isIdentifier(node.expression)) {
        assert.ok(!["require", "createRequire", "eval", "Function"].includes(node.expression.text),
          "dynamic module evaluation and CommonJS loading are forbidden");
      }
    }
    if (ts.isNewExpression(node) && ts.isIdentifier(node.expression)) {
      assert.notEqual(node.expression.text, "Function", "dynamic evaluation is forbidden");
    }
    ts.forEachChild(node, visit);
  }
  visit(parsed);
  return dependencies;
}

function discoverClosure(sourceRoot, entries = HOST_ENTRIES) {
  const pending = [...entries];
  const found = new Set();
  while (pending.length) {
    const relative = pending.pop();
    if (found.has(relative)) continue;
    assert.match(relative, /^(?:infra\/offline|scripts\/lib)\/[a-z0-9-]+\.mjs$/u,
      "unexpected executable verifier path");
    const full = path.join(sourceRoot, ...relative.split("/"));
    const stat = lstatSync(full);
    assert.ok(stat.isFile() && !stat.isSymbolicLink(), `missing or linked dependency ${relative}`);
    found.add(relative);
    const source = readFileSync(full, "utf8");
    for (const specifier of importsIn(source)) {
      if (specifier.startsWith("node:")) continue;
      assert.ok(specifier.startsWith("./") || specifier.startsWith("../"),
        `untrusted package/builtin dependency: ${specifier}`);
      assert.ok(specifier.endsWith(".mjs") && !specifier.includes("?") && !specifier.includes("#"),
        `local dependency must be a pinned .mjs module: ${specifier}`);
      const target = path.posix.normalize(path.posix.join(path.posix.dirname(relative), specifier));
      assert.ok(!target.startsWith("../") && target !== "..", "dependency escapes verifier root");
      pending.push(target);
    }
  }
  return [...found].sort();
}

function copyAuditedTo(t) {
  const dest = mkdtempSync(path.join(os.tmpdir(), "virki-verifier-deps-"));
  t.after(() => rmSync(dest, { recursive: true, force: true }));
  for (const relative of new Set([...AUDITED_VERIFIER_FILES, ...HOST_ENTRIES])) {
    const target = path.join(dest, ...relative.split("/"));
    mkdirSync(path.dirname(target), { recursive: true });
    copyFileSync(path.join(root, ...relative.split("/")), target);
  }
  return dest;
}

test("installed host entries have an exactly pinned, deterministic and closed executable ESM graph", () => {
  const graph = discoverClosure(root);
  assert.deepEqual(AUDITED_VERIFIER_FILES, graph,
    "every executable transitive dependency must be independently pinned in sorted order");
  assert.ok(graph.includes("infra/offline/trusted-source-git.mjs"));
  assert.ok(graph.includes("scripts/lib/offline-source-tar-verifier.mjs"));
  assert.ok(!graph.includes("scripts/lib/offline-release-bundle.mjs"),
    "builder/CI modules cannot be evaluated by host-native source verification");
});

test("unreviewed static import, dynamic import, package import and vanished import all fail closed", (t) => {
  const dest = copyAuditedTo(t);
  const target = path.join(dest, "infra", "offline", "trusted-source-git.mjs");
  const original = readFileSync(target, "utf8");
  for (const altered of [
    `${original}\nimport "./not-a-pinned-module.mjs";\n`,
    `${original}\nimport"./not-a-pinned-module.mjs";\n`,
    `${original}\n;import"./not-a-pinned-module.mjs";\n`,
    `${original}\nawait import("./surprise.mjs");\n`,
    `${original}\nconst bypass = import /* hidden */ ("./surprise.mjs");\n`,
    `${original}\nimport unexpected from "outside-package";\n`,
    `${original}\nconst injected = require("fs");\n`,
    `${original}\nexport { injected } from "./not-a-pinned-module.mjs";\n`,
    `${original}\nexport{injected}from"./not-a-pinned-module.mjs";\n`,
    `${original}\nexport*from"./not-a-pinned-module.mjs";\n`,
  ]) {
    writeFileSync(target, altered);
    assert.throws(() => {
      const closure = discoverClosure(dest);
      assert.deepEqual(closure, AUDITED_VERIFIER_FILES);
    });
  }
  writeFileSync(target, original);
  const missing = path.join(dest, "scripts", "lib", "offline-source-tar-verifier.mjs");
  rmSync(missing);
  assert.throws(() => discoverClosure(dest));
});

test("changed source checker or TAR parser bytes fail independent source digest pins", (t) => {
  const dest = copyAuditedTo(t);
  const pins = AUDITED_VERIFIER_FILES.map((relative) => ({
    path: relative, sha256: sha256(readFileSync(path.join(dest, ...relative.split("/")))),
  }));
  assert.equal(inspectAuditedVerifierFiles({ sourceDirectory: dest, files: pins }).files.length,
    AUDITED_VERIFIER_FILES.length);
  for (const relative of ["infra/offline/trusted-source-git.mjs", "scripts/lib/offline-source-tar-verifier.mjs"]) {
    const target = path.join(dest, ...relative.split("/"));
    const before = readFileSync(target);
    writeFileSync(target, Buffer.concat([before, Buffer.from("\n// altered parser bytes\n")]));
    assert.throws(() => inspectAuditedVerifierFiles({ sourceDirectory: dest, files: pins }),
      /SHA-256 mismatch/u);
    writeFileSync(target, before);
  }
});
