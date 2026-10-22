import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

// The Docker Engine only launches an isolated disposable fixture. Never
// mount the host daemon socket or host credentials. No production operations.
const IMAGE = "node:22.23.3-bookworm@sha256:0e5f906573693feaa1e21057ebdcfdb5bd5021f050b2dc7c9deceb629c7da2a8";
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const result = spawnSync("docker", [
  "run", "--rm", "--pull=never", "--platform=linux/amd64",
  "--network=none", "--read-only", "--cap-drop=ALL",
  "--security-opt=no-new-privileges", "--user", "0:0",
  "--pids-limit=128", "--memory=512m",
  // C probe executes only inside a transient private tmpfs, whereas all
  // project source files are bound read-only.
  "--tmpfs", "/tmp:rw,exec,nosuid,nodev,size=64m,mode=1777",
  "--mount", "type=bind,src=" + root + ",dst=/workspace,readonly",
  "--workdir", "/workspace",
  "--env", "VIRKI_DISPOSABLE_PEER_PROBE=1",
  IMAGE, "node", "--test", "infra/offline/native-peer/native-peer-probe.test.mjs",
], {
  cwd: root, stdio: "inherit", shell: false, timeout: 45000,
  env: {
    PATH: process.env.PATH ?? "",
    SystemRoot: process.env.SystemRoot ?? "",
    DOCKER_HOST: process.env.DOCKER_HOST ?? "",
  },
});
if (result.error) {
  process.stderr.write("Disposable Linux peer proof failed: " + result.error.message + "\n");
  process.exitCode = 1;
} else {
  process.exitCode = result.status === 0 ? 0 : 1;
}
