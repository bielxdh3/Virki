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
  "infra/offline/trusted-image-import.mjs",
  "infra/offline/trusted-image-loader.mjs",
  "infra/offline/trusted-manual-source.mjs",
  "infra/offline/trusted-release-coordinator.mjs",
  "infra/offline/trusted-source-git.mjs",
]);
// Native verifier modules use only these builtins. In particular, loading
// node:module, node:vm or worker_threads would allow aliased code-loaders to
// evade a static ESM dependency inventory without a new security review.
const AUDITED_NODE_BUILTINS = new Set([
  "node:child_process", "node:crypto", "node:fs", "node:fs/promises",
  "node:os", "node:path", "node:url",
]);
// A static import inventory is meaningful only if the host source cannot
// silently obtain a runtime evaluator or an unreviewed process launcher.
// This is defense in depth; it is NOT an authorization to install or deploy.
const FORBIDDEN_RUNTIME_IDENTIFIERS = new Set([
  "Function", "AsyncFunction", "GeneratorFunction", "AsyncGeneratorFunction",
  "eval", "require", "createRequire", "getBuiltinModule", "globalThis", "global", "Reflect",
]);
const FORBIDDEN_RUNTIME_PROPERTIES = new Set([
  "constructor", "mainModule", "_linkedBinding", "binding", "dlopen",
]);
const AUDITED_PROCESS_PROPERTIES = new Set([
  "platform", "arch", "getuid", "argv", "stderr", "exitCode",
]);
const TRUSTED_GIT_SOURCE = "infra/offline/trusted-source-git.mjs";
const TRUSTED_IMAGE_IMPORT = "infra/offline/trusted-image-import.mjs";
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

// Fail closed on any executable dependency we cannot statically account for.
// All installed host files use static, literal ESM imports; intentionally
// reject import attributes, dynamic imports, package imports and CJS escapes.
function importsIn(source, relative) {
  // A regex for `import ` misses legal minified syntax such as `import"x"`
  // or `export*from"x"`; use the actual JavaScript grammar instead.
  const parsed = ts.createSourceFile("audited-verifier.mjs", source,
    ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);
  assert.equal(parsed.parseDiagnostics.length, 0, "unparseable verifier source is forbidden");
  if (relative === TRUSTED_IMAGE_IMPORT) {
    for (const [name, literal] of [
      ["DOCKER_EXE", "/run/virki-offline-import/docker"],
      ["DOCKER_SOCKET", "/run/virki-offline-import/docker.sock"],
      ["DOCKER_EXE_PIN", "/etc/virki/offline-import-cli.sha256"],
    ]) {
      const declarations = parsed.statements
        .filter(ts.isVariableStatement)
        .flatMap((entry) => [...entry.declarationList.declarations])
        .filter((entry) => ts.isIdentifier(entry.name) && entry.name.text === name);
      assert.ok(declarations.length === 1 && ts.isStringLiteral(declarations[0].initializer) &&
        declarations[0].initializer.text === literal,
      "native import executable, signature pin and dedicated daemon paths are immutable");
    }
  }
  const dependencies = [];
  let gitExecCalls = 0;
  let dockerSpawnCalls = 0;
  function visit(node) {
    if (ts.isIdentifier(node)) {
      assert.ok(!FORBIDDEN_RUNTIME_IDENTIFIERS.has(node.text),
        `runtime evaluator or dynamic loader identifier is forbidden: ${node.text}`);
      if (node.text === "process") {
        assert.ok(ts.isPropertyAccessExpression(node.parent) &&
          node.parent.expression === node &&
          AUDITED_PROCESS_PROPERTIES.has(node.parent.name.text),
        "process must be used only through reviewed direct properties; aliases are forbidden");
      }
      if (node.text === "execFileSync") {
        const imported = ts.isImportSpecifier(node.parent) && node.parent.name === node &&
          !node.parent.propertyName;
        const directCall = ts.isCallExpression(node.parent) && node.parent.expression === node;
        assert.ok(relative === TRUSTED_GIT_SOURCE && (imported || directCall),
          "execFileSync may only be imported or directly invoked by trusted source Git");
      }
      if (node.text === "spawnSync") {
        const imported = ts.isImportSpecifier(node.parent) && node.parent.name === node &&
          !node.parent.propertyName;
        const directCall = ts.isCallExpression(node.parent) && node.parent.expression === node;
        assert.ok(relative === TRUSTED_IMAGE_IMPORT && (imported || directCall),
          "spawnSync is permitted only in trusted native image import");
      }
    }
    if (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) {
      if (node.moduleSpecifier) {
        assert.ok(ts.isStringLiteral(node.moduleSpecifier) &&
          !node.attributes && !node.assertClause,
        "verifier modules require literal imports without attributes");
        dependencies.push(node.moduleSpecifier.text);
        if (node.moduleSpecifier.text === "node:child_process") {
          const imports = ts.isImportDeclaration(node) && node.importClause?.namedBindings;
          const expectedName = relative === TRUSTED_GIT_SOURCE ? "execFileSync"
            : relative === TRUSTED_IMAGE_IMPORT ? "spawnSync" : null;
          assert.ok(expectedName && imports &&
            ts.isNamedImports(imports) && imports.elements.length === 1 &&
            imports.elements[0].name.text === expectedName &&
            !imports.elements[0].propertyName && !node.importClause.name,
          "child_process must be an exact pinned Git or image-import command");
        }
      }
    }
    assert.ok(!ts.isImportEqualsDeclaration(node) && !ts.isImportTypeNode(node),
      "unreviewed module import syntax is forbidden");
    if (ts.isCallExpression(node)) {
      assert.notEqual(node.expression.kind, ts.SyntaxKind.ImportKeyword,
        "dynamic import is forbidden");
      if (ts.isIdentifier(node.expression) && node.expression.text === "execFileSync") {
        gitExecCalls++;
        let enclosing = node.parent;
        while (enclosing && !ts.isFunctionLike(enclosing)) enclosing = enclosing.parent;
        const argv = node.arguments[1];
        const gitDir = ts.isArrayLiteralExpression(argv) && argv.elements[1];
        const trailing = ts.isArrayLiteralExpression(argv) && argv.elements[2];
        assert.ok(relative === TRUSTED_GIT_SOURCE &&
          ts.isFunctionDeclaration(enclosing) && enclosing.name?.text === "git" &&
          node.arguments.length === 3 &&
          ts.isStringLiteral(node.arguments[0]) &&
          node.arguments[0].text === "/usr/bin/git" &&
          ts.isArrayLiteralExpression(argv) && argv.elements.length === 3 &&
          ts.isStringLiteral(argv.elements[0]) && argv.elements[0].text === "--no-pager" &&
          ts.isTemplateExpression(gitDir) && gitDir.head.text === "--git-dir=" &&
          gitDir.templateSpans.length === 1 &&
          ts.isIdentifier(gitDir.templateSpans[0].expression) &&
          gitDir.templateSpans[0].expression.text === "repo" &&
          gitDir.templateSpans[0].literal.text === "" &&
          ts.isSpreadElement(trailing) && ts.isIdentifier(trailing.expression) &&
          trailing.expression.text === "args" &&
          ts.isObjectLiteralExpression(node.arguments[2]) &&
          node.arguments[2].properties.length === 6 &&
          node.arguments[2].properties.every((property, index) =>
            ts.isPropertyAssignment(property) &&
            ts.isIdentifier(property.name) &&
            property.name.text === ["env", "encoding", "timeout", "maxBuffer", "windowsHide", "stdio"][index]) &&
          ts.isIdentifier(node.arguments[2].properties[0].initializer) &&
          node.arguments[2].properties[0].initializer.text === "GIT_ENV" &&
          ts.isStringLiteral(node.arguments[2].properties[1].initializer) &&
          node.arguments[2].properties[1].initializer.text === "buffer" &&
          ts.isNumericLiteral(node.arguments[2].properties[2].initializer) &&
          node.arguments[2].properties[2].initializer.text === "30000" &&
          node.arguments[2].properties[3].initializer.getText(parsed).replace(/\s+/gu, "") === "32*1024*1024" &&
          node.arguments[2].properties[4].initializer.kind === ts.SyntaxKind.TrueKeyword &&
          ts.isArrayLiteralExpression(node.arguments[2].properties[5].initializer) &&
          node.arguments[2].properties[5].initializer.elements.length === 3 &&
          node.arguments[2].properties[5].initializer.elements.every((entry, index) =>
            ts.isStringLiteral(entry) && entry.text === ["ignore", "pipe", "pipe"][index]),
        "only the fixed native /usr/bin/git invocation is permitted");
      }
      if (ts.isIdentifier(node.expression) && node.expression.text === "spawnSync") {
        dockerSpawnCalls++;
        let enclosing = node.parent;
        while (enclosing && !ts.isFunctionLike(enclosing)) enclosing = enclosing.parent;
        assert.ok(relative === TRUSTED_IMAGE_IMPORT &&
          ts.isFunctionDeclaration(enclosing) && enclosing.name?.text === "docker" &&
          node.arguments.length === 3 &&
          ts.isIdentifier(node.arguments[0]) && node.arguments[0].text === "DOCKER_EXE" &&
          node.arguments[1].getText(parsed).replace(/\s+/gu, "") ===
            '["--host",DOCKER_HOST,...args]' &&
          ts.isObjectLiteralExpression(node.arguments[2]) &&
          node.arguments[2].properties.some((property) =>
            ts.isPropertyAssignment(property) && property.name.getText(parsed) === "shell" &&
            property.initializer.kind === ts.SyntaxKind.FalseKeyword),
        "Docker spawn must use only the reviewed fixed executable and host without shell");
      }
      if (ts.isIdentifier(node.expression)) {
        assert.ok(!["require", "createRequire", "eval", "Function"].includes(node.expression.text),
          "dynamic module evaluation and CommonJS loading are forbidden");
      }
    }
    if (ts.isNewExpression(node) && ts.isIdentifier(node.expression)) {
      assert.notEqual(node.expression.text, "Function", "dynamic evaluation is forbidden");
    }
    if (ts.isPropertyAccessExpression(node)) {
      assert.notEqual(node.name.text, "getBuiltinModule", "dynamic builtin loader is forbidden");
      assert.ok(!FORBIDDEN_RUNTIME_PROPERTIES.has(node.name.text),
        "runtime executable access through reflective properties is forbidden");
    }
    if (ts.isElementAccessExpression(node) && node.argumentExpression &&
        ts.isStringLiteral(node.argumentExpression)) {
      assert.notEqual(node.argumentExpression.text, "getBuiltinModule",
        "dynamic builtin loader is forbidden");
      assert.ok(!FORBIDDEN_RUNTIME_PROPERTIES.has(node.argumentExpression.text),
        "runtime executable access through reflective properties is forbidden");
    }
    if (ts.isElementAccessExpression(node) && ts.isIdentifier(node.expression) &&
        node.expression.text === "process") {
      assert.fail("computed process builtin and executable module access is forbidden");
    }
    ts.forEachChild(node, visit);
  }
  visit(parsed);
  assert.equal(gitExecCalls, relative === TRUSTED_GIT_SOURCE ? 1 : 0,
    "exactly one audited Git subprocess invocation is required");
  assert.equal(dockerSpawnCalls, relative === TRUSTED_IMAGE_IMPORT ? 1 : 0,
    "exactly one audited native Docker subprocess invocation is required");
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
    for (const specifier of importsIn(source, relative)) {
      if (specifier.startsWith("node:")) {
        assert.ok(AUDITED_NODE_BUILTINS.has(specifier),
          `unreviewed native builtin dependency: ${specifier}`);
        continue;
      }
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
  assert.ok(graph.includes("infra/offline/trusted-release-coordinator.mjs"));
  assert.ok(graph.includes("infra/offline/trusted-image-import.mjs"));
  assert.ok(graph.includes("scripts/lib/offline-release-ledger.mjs"));
  assert.ok(graph.includes("scripts/lib/offline-source-tar-verifier.mjs"));
  assert.ok(!graph.includes("scripts/lib/offline-release-bundle.mjs"),
    "builder/CI modules cannot be evaluated by host-native source verification");
});

test("native manual owner source verifier and its CI parser are in the owner-installed executable closure", () => {
  const manual = "infra/offline/trusted-manual-source.mjs";
  const ci = "scripts/lib/offline-ci-evidence.mjs";
  assert.ok(AUDITED_VERIFIER_FILES.includes(manual),
    "manual verifier is currently only source code and must be independently pinned at installation");
  assert.ok(AUDITED_VERIFIER_FILES.includes(ci),
    "manual-source CI parser must not load unaudited bytes from the upload");
  assert.deepEqual(AUDITED_VERIFIER_FILES, discoverClosure(root, [...HOST_ENTRIES, manual]),
    "all imports of the installed manual entry must be included in the pinned inventory");
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
    `${original}\nimport { createRequire as cr } from "node:module"; const load = cr(import.meta.url); load("./nonpinned.cjs");\n`,
    `${original}\nconst load = process.getBuiltinModule("module").createRequire(import.meta.url); load("./nonpinned.cjs");\n`,
    `${original}\nimport { runInNewContext as run } from "node:vm"; run("require('./nonpinned.cjs')");\n`,
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

test("host static audit refuses executable loader aliases and unauthorized subprocess launches", (t) => {
  const dest = copyAuditedTo(t);
  const target = path.join(dest, "infra", "offline", "trusted-source-git.mjs");
  const original = readFileSync(target, "utf8");
  const injections = [
    'const F = Function; F("return import(\\"./nonpinned.mjs\\")")();',
    'const F = globalThis["Function"]; F("return import(\\"./nonpinned.mjs\\")")();',
    'const F = global["Function"]; F("return import(\\"./nonpinned.mjs\\")")();',
    'const launch = process["get" + "BuiltinModule"]("child_process").spawnSync; launch("/bin/sh", ["-c", "id"]);',
    'const p = process; p["get" + "BuiltinModule"]("child_process").spawnSync("/bin/true", []);',
    'const { getBuiltinModule: load } = process; load("child_process").spawnSync("/bin/true", []);',
    'import { spawnSync as launch } from "node:child_process"; launch(process.execPath, ["./nonpinned.mjs"]);',
    'import { execFileSync as run } from "node:child_process"; run(process.execPath, ["./nonpinned.mjs"]);',
    'const run = execFileSync; run(process.execPath, ["./nonpinned.mjs"]);',
    'execFileSync(process.execPath, ["./nonpinned.mjs"]);',
    'execFileSync("/usr/bin/git", ["--no-pager"], {});',
    'function unreviewedGit() { return execFileSync("/usr/bin/git", ["--no-pager"], {}); }',
  ];
  for (const injected of injections) {
    writeFileSync(target, `${original}\n${injected}\n`);
    assert.throws(() => {
      const closure = discoverClosure(dest);
      assert.deepEqual(closure, AUDITED_VERIFIER_FILES);
    }, `must reject unauthorized execution: ${injected}`);
  }
  for (const [before, after] of [
    ["timeout: 30000", "timeout: 0"],
    ["windowsHide: true", "windowsHide: false"],
    ['encoding: "buffer"', 'encoding: "utf8"'],
    ['stdio: ["ignore", "pipe", "pipe"]', 'stdio: ["inherit", "inherit", "inherit"]'],
  ]) {
    assert.ok(original.includes(before), `missing expected audited native Git option: ${before}`);
    writeFileSync(target, original.replace(before, after));
    assert.throws(() => discoverClosure(dest), `must refuse changed native Git option: ${before}`);
  }
});

test("native Docker invocation must remain a single audited fixed-executable, fixed-endpoint spawn", (t) => {
  const dest = copyAuditedTo(t);
  const filename = path.join(dest, "infra", "offline", "trusted-image-import.mjs");
  const original = readFileSync(filename, "utf8");
  for (const modified of [
    original.replace('const DOCKER_EXE = "/run/virki-offline-import/docker";',
      'const DOCKER_EXE = "/bin/sh";'),
    original.replace('["--host", DOCKER_HOST, ...args]',
      '["-c", "id", ...args]'),
    original.replace("shell: false,", "shell: true,"),
    original + '\nimport { execFileSync } from "node:child_process";\n',
    original + '\nconst attack = spawnSync;\n',
  ]) {
    writeFileSync(filename, modified);
    assert.throws(() => {
      const closure = discoverClosure(dest);
      assert.deepEqual(closure, AUDITED_VERIFIER_FILES);
      assert.match(readFileSync(filename, "utf8"), /DOCKER_EXE/u);
    });
  }
});

test("changed source checker or TAR parser bytes fail independent source digest pins", (t) => {
  const dest = copyAuditedTo(t);
  const pins = AUDITED_VERIFIER_FILES.map((relative) => ({
    path: relative, sha256: sha256(readFileSync(path.join(dest, ...relative.split("/")))),
  }));
  assert.equal(inspectAuditedVerifierFiles({ sourceDirectory: dest, files: pins }).files.length,
    AUDITED_VERIFIER_FILES.length);
  for (const relative of ["infra/offline/trusted-source-git.mjs", "scripts/lib/offline-source-tar-verifier.mjs",
    "infra/offline/trusted-release-coordinator.mjs", "scripts/lib/offline-release-ledger.mjs",
    "infra/offline/trusted-image-import.mjs"]) {
    const target = path.join(dest, ...relative.split("/"));
    const before = readFileSync(target);
    writeFileSync(target, Buffer.concat([before, Buffer.from("\n// altered parser bytes\n")]));
    assert.throws(() => inspectAuditedVerifierFiles({ sourceDirectory: dest, files: pins }),
      /SHA-256 mismatch/u);
    writeFileSync(target, before);
  }
});
