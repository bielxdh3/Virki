import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

const legacy = ["biel", "os"].join("");
const files = execFileSync("git", ["ls-files", "-z"], { encoding: "utf8" })
  .split("\0")
  .filter(Boolean);

const binaryExtensions = /\.(?:png|jpe?g|gif|ico|webp|woff2?|ttf|eot|pdf|zip|gz|tar|bin)$/i;
const violations = [];

for (const path of files) {
  if (path.toLowerCase().includes(legacy)) {
    violations.push(`${path}: legacy identifier remains in path`);
  }
  if (binaryExtensions.test(path)) continue;

  const buffer = readFileSync(path);
  if (buffer.includes(0)) continue;
  const content = buffer.toString("utf8").toLowerCase();
  if (content.includes(legacy)) {
    violations.push(`${path}: legacy identifier remains in content`);
  }
}

if (violations.length > 0) {
  console.error("Virki identity verification failed:");
  for (const violation of violations) console.error(`- ${violation}`);
  process.exit(1);
}

console.log("Virki identity verification passed.");
