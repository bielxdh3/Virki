import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

// Explicit opt-in for the destructive fixed-path test fixture. Never run the
// test with host privileges or mounted host /etc or /var/lib directories.
// The image ref pins Node 22.23.3 by immutable Docker manifest digest.
const IMAGE = "node:22.23.3-bookworm@sha256:0e5f906573693feaa1e21057ebdcfdb5bd5021f050b2dc7c9deceb629c7da2a8";
const sourceRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const args = [
  "run", "--rm", "--pull=never", "--platform=linux/amd64",
  "--network=none", "--read-only", "--cap-drop=ALL",
  "--security-opt=no-new-privileges", "--pids-limit=128",
  "--tmpfs", "/etc:rw,nosuid,nodev,noexec,size=16m,mode=755",
  "--tmpfs", "/var/lib:rw,nosuid,nodev,noexec,size=256m,mode=755",
  "--tmpfs", "/usr/local/lib/virki:rw,nosuid,nodev,noexec,size=16m,mode=700",
  "--tmpfs", "/run:rw,exec,nosuid,nodev,size=32m,mode=755",
  "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=64m,mode=1777",
  "--mount", `type=bind,src=${sourceRoot},dst=/workspace,readonly`,
  "--workdir", "/workspace",
  "--env", "VIRKI_COORDINATOR_DISPOSABLE_CONTAINER=1",
  "--env", "VIRKI_OWNER_INSTALL_DISPOSABLE_FIXTURE=1",
  IMAGE, "node", "--test", "infra/offline/trusted-release-coordinator.test.mjs",
  "infra/offline/trusted-owner-installation.test.mjs",
];
const result = spawnSync("docker", args, {
  cwd: sourceRoot, stdio: "inherit", shell: false, timeout: 60_000,
});
if (result.error) {
  process.stderr.write("Isolated coordinator test launcher failed: " + result.error.message + "\n");
  process.exitCode = 1;
} else {
  process.exitCode = result.status === 0 ? 0 : 1;
}
