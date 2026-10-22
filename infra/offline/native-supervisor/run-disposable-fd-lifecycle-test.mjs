import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

// Launches a root-owned test process in a disposable fixed Linux container.
// No host Docker socket is mounted. The C fixture never launches dockerd or
// contacts a real Docker daemon, and it exposes no authorization entrypoint.
const IMAGE = "node:22.23.3-bookworm@sha256:0e5f906573693feaa1e21057ebdcfdb5bd5021f050b2dc7c9deceb629c7da2a8";
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const args = [
  "run", "--rm", "--pull=never", "--platform=linux/amd64",
  "--network=none", "--read-only", "--cap-drop=ALL",
  "--security-opt=no-new-privileges", "--user", "0:0",
  "--pids-limit=128", "--memory=512m",
  "--tmpfs", "/tmp:rw,exec,nosuid,nodev,size=64m,mode=1777",
  "--mount", "type=bind,src=" + root + ",dst=/workspace,readonly",
  "--workdir", "/workspace",
  "--env", "VIRKI_DISPOSABLE_SUPERVISOR_TEST=1",
  IMAGE, "node", "--test", "infra/offline/native-supervisor/fd-lifecycle-fixture.test.mjs",
];
const result = spawnSync("docker", args, {
  cwd: root, stdio: "inherit", shell: false, timeout: 45000,
});
if (result.error) {
  process.stderr.write("Disposable native supervisor test failed: " + result.error.message + "\n");
  process.exitCode = 1;
} else {
  process.exitCode = result.status === 0 ? 0 : 1;
}
