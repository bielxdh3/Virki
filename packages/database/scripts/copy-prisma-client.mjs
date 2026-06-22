import { access, cp, mkdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const workspaceRoot = path.resolve(scriptDir, "../../..");
const sourceCandidates = [
  path.join(workspaceRoot, "packages", "database", "node_modules", ".prisma", "client"),
  path.join(workspaceRoot, "node_modules", ".prisma", "client")
];
const hubTarget = path.join(
  workspaceRoot,
  "apps",
  "hub",
  "node_modules",
  ".prisma",
  "client"
);

const source = await findExistingPath(sourceCandidates);

await mkdir(path.dirname(hubTarget), { recursive: true });
await cp(source, hubTarget, { recursive: true, force: true });

async function findExistingPath(paths) {
  for (const currentPath of paths) {
    if (await access(currentPath).then(() => true).catch(() => false)) {
      return currentPath;
    }
  }

  throw new Error(`Prisma client output was not found in: ${paths.join(", ")}`);
}
