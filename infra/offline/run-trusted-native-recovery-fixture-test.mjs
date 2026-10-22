import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

// Launch ONLY a disposable, isolated root fixture. No Docker socket is mounted
// inside and this script never uses any production host path or Docker service.
const IMAGE = "node:22.23.3-bookworm@sha256:0e5f906573693feaa1e21057ebdcfdb5bd5021f050b2dc7c9deceb629c7da2a8";
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const result = spawnSync("docker", [
  "run", "--rm", "--pull=never", "--platform=linux/amd64",
  "--network=none", "--read-only", "--cap-drop=ALL",
  "--security-opt=no-new-privileges", "--pids-limit=128",
  "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=128m,mode=1777",
  "--mount", `type=bind,src=${root},dst=/workspace,readonly`,
  "--workdir", "/workspace",
  "--env", "VIRKI_NATIVE_RECOVERY_DISPOSABLE_TEST=1",
  IMAGE, "node", "--test", "infra/offline/trusted-native-recovery-fixture.test.mjs",
], { cwd: root, stdio: "inherit", shell: false, timeout: 90000 });
if (result.error) {
  process.stderr.write("Isolated native recovery test launch failed: " + result.error.message + "\n");
  process.exitCode = 1;
} else {
  process.exitCode = result.status === 0 ? 0 : 1;
}
