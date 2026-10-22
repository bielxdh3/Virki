export const assertion = String.raw`
const fs = require("node:fs");
const path = require("node:path");
const runtimeUid = typeof process.getuid === "function" ? process.getuid() : -1;
const forbidden = ["prisma", "@prisma/config", "deepmerge-ts"];
const moduleRoots = findNodeModulesRoots("/app");
const forbiddenFound = moduleRoots.flatMap((root) => forbidden.filter((name) => fs.existsSync(packagePath(root, name))));
const prismaBinaryFound = moduleRoots.some((root) => fs.existsSync(path.join(root, ".bin", "prisma")));
const requiredClient = moduleRoots.some((root) => fs.existsSync(packagePath(root, "@prisma/client/package.json")));
const oidcProvider = moduleRoots.some((root) => fs.existsSync(packagePath(root, "oidc-provider/package.json")));
const argon2WrapperBinary = [
  "/app/node_modules/@node-rs/argon2/argon2.linux-x64-musl.node",
  "/app/node_modules/@node-rs/argon2/argon2.linux-arm64-musl.node"
].some((binary) => fs.existsSync(binary));
const argon2PlatformDirectory = [
  ["/app/node_modules/@node-rs/argon2-linux-x64-musl/package.json", "/app/node_modules/@node-rs/argon2-linux-x64-musl/argon2.linux-x64-musl.node"],
  ["/app/node_modules/@node-rs/argon2-linux-arm64-musl/package.json", "/app/node_modules/@node-rs/argon2-linux-arm64-musl/argon2.linux-arm64-musl.node"]
].some(([packageJson, binary]) => fs.existsSync(packageJson) && fs.existsSync(binary));
let argon2Loadable = false;
try {
  const argon2 = require("/app/node_modules/@node-rs/argon2");
  const digest = typeof argon2.hashSync === "function" ? argon2.hashSync("virki-runtime-boundary-check") : null;
  argon2Loadable = typeof digest === "string" && digest.length > 0;
} catch {}
const runtimeClosure = [
  fs.existsSync("/app/node_modules/tsx/package.json"),
  fs.existsSync("/app/node_modules/esbuild/package.json"),
  fs.existsSync("/app/node_modules/.bin/tsx"),
  fs.existsSync("/app/node_modules/@node-rs/argon2/package.json"),
  argon2WrapperBinary || argon2PlatformDirectory,
  argon2Loadable
].every(Boolean);
const linuxBinary = moduleRoots.some((root) => fs.existsSync(path.join(root, "@esbuild", "linux-x64", "bin", "esbuild")) || fs.existsSync(path.join(root, "@esbuild", "linux-arm64", "bin", "esbuild")));
const generatedClient = [
  "/app/apps/hub/node_modules/.prisma/client",
  "/app/node_modules/.prisma/client"
].some((root) => fs.existsSync(path.join(root, "default.js")) && (fs.existsSync(path.join(root, "client.js")) || fs.existsSync(path.join(root, "index.js"))));
if (runtimeUid !== 1000 || forbiddenFound.length > 0 || prismaBinaryFound || !requiredClient || !oidcProvider || !generatedClient || !runtimeClosure || !linuxBinary) process.exit(1);
function packagePath(root, name) { return path.join(root, ...name.split("/")); }
function findNodeModulesRoots(root) {
  const roots = [];
  const pending = [root];
  while (pending.length > 0) {
    const current = pending.pop();
    let entries;
    try { entries = fs.readdirSync(current, { withFileTypes: true }); } catch { continue; }
    for (const entry of entries) {
      if (!entry.isDirectory() || entry.isSymbolicLink()) continue;
      if ([".git", ".next", "build", "coverage", "dist", "out"].includes(entry.name)) continue;
      const child = path.join(current, entry.name);
      if (entry.name === "node_modules") roots.push(child);
      pending.push(child);
    }
  }
  return roots;
}
`;
