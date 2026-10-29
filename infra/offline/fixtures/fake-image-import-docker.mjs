#!/usr/local/bin/node
// Disposable Docker CLI sink. Copied only into the dedicated /run tmpfs
// inside a --network none, read-only root regression container.
import { createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync, appendFileSync } from "node:fs";
const root = "/run/virki-offline-import/";
const args = process.argv.slice(2);
const host = "unix:///run/virki-offline-import/docker.sock";
if (args[0] !== "--host" || args[1] !== host) {
  process.exit(19);
}
if (args.length === 5 && args[2] === "version" &&
    args[3] === "--format" && args[4] === "{{.Server.Version}}") {
  appendFileSync(root + "calls", args.join(" ") + "\n");
  if (existsSync(root + "daemon-unavailable")) process.exit(125);
  process.stdout.write("29.6.2\n");
  process.exit(0);
}
if (args[2] !== "image" || !["inspect", "load"].includes(args[3])) process.exit(19);
appendFileSync(root + "calls", args.join(" ") + "\n");
if (args[3] === "inspect") {
  if (args.length !== 7 || args[4] !== "--type" || args[5] !== "image" ||
      !/^sha256:[a-f0-9]{64}$/u.test(args[6])) process.exit(20);
  if (existsSync(root + "daemon-unavailable")) process.exit(125);
  if (existsSync(root + "inspect-error")) {
    process.stderr.write("Error: Docker daemon connection refused\n");
    process.exit(1);
  }
  const loaded = existsSync(root + "loaded.json")
    ? JSON.parse(readFileSync(root + "loaded.json", "utf8")) : [];
  const matched = loaded.find(({ Id }) => Id === args[6]);
  if (!matched) {
    process.stderr.write("Error: No such image: " + args[6] + "\n");
    process.exit(1);
  }
  if (existsSync(root + "wrong-inspect")) matched.Config.User = "root";
  process.stdout.write(JSON.stringify([matched]));
  process.exit(0);
}
if (args.length !== 5 || args[4] !== "--quiet") process.exit(21);
// Mutate the ORIGINAL candidate pathname before consuming stdin. The isolated
// coordinator must already have detached its verified read-only copy.
if (existsSync(root + "mutate-source") && !existsSync(root + "source-mutated")) {
  const pathname = readFileSync(root + "mutate-source", "utf8");
  const content = readFileSync(pathname);
  content[content.length - 1] = content[content.length - 1] ^ 1;
  writeFileSync(pathname, content);
  writeFileSync(root + "source-mutated", "1");
}
const archive = readFileSync(0);
appendFileSync(root + "consumed.sha256",
  createHash("sha256").update(archive).digest("hex") + "\n");
// A failed or interrupted daemon load must leave the release attempt locked.
const count = readFileSync(root + "consumed.sha256", "utf8").trim().split("\n").length;
if (existsSync(root + "fail-load") ||
    (existsSync(root + "fail-second-load") && count === 2)) process.exit(23);
// The fixture TAR places the image config before its other members.
const name = archive.subarray(0, 100).toString("ascii").replace(/\0.*$/u, "");
if (!/^[a-f0-9]{64}\.json$/u.test(name)) process.exit(22);
const length = Number.parseInt(archive.subarray(124, 136).toString("ascii").replace(/\0.*$/u, "").trim(), 8);
const config = JSON.parse(archive.subarray(512, 512 + length).toString("utf8"));
const loaded = existsSync(root + "loaded.json")
  ? JSON.parse(readFileSync(root + "loaded.json", "utf8")) : [];
loaded.push({
  Id: "sha256:" + name.slice(0, 64),
  Os: config.os, Architecture: config.architecture,
  Config: { User: config.config.User, Labels: config.config.Labels },
  RepoTags: null, RepoDigests: null,
});
writeFileSync(root + "loaded.json", JSON.stringify(loaded));
process.stdout.write("Loaded untagged image");
